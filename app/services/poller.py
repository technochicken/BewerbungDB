import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from app.database import get_db, record_history
from app.services.arbeitsagentur import search_jobs, get_job_details, parse_listing, enrich_with_details, get_refnr
from app.services.scraper import fetch_url, extract_text

logger = logging.getLogger(__name__)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


async def check_and_maybe_close(job_id: int, url: str, keyword: Optional[str], initial_status: str = "new") -> bool:
    """
    Fetch the URL and close the job if unreachable or keyword missing.
    Returns True if the job was closed.
    """
    from app.services.alerts import fire_status_change

    status_code, html = await fetch_url(url)
    now = utcnow()

    should_close = False
    if status_code in (404, 410):
        should_close = True
        logger.info(f"Job {job_id} closed on create – HTTP {status_code} for {url}")
    elif status_code == 0:
        should_close = True
        logger.info(f"Job {job_id} closed on create – unreachable {url}")
    elif status_code == 200 and keyword and html:
        if keyword.lower() not in extract_text(html).lower():
            should_close = True
            logger.info(f"Job {job_id} closed on create – keyword '{keyword}' not found at {url}")

    with get_db() as conn:
        conn.execute(
            "UPDATE jobs SET last_checked_at = ?, updated_at = ? WHERE id = ?",
            (now, now, job_id),
        )
        if should_close:
            record_history(conn, job_id, "status", initial_status, "closed", now)
            conn.execute(
                "UPDATE jobs SET status = 'closed', last_changed_at = ?, updated_at = ? WHERE id = ?",
                (now, now, job_id),
            )
            job_row = conn.execute(
                "SELECT title, company FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()

    if should_close and job_row:
        await fire_status_change(dict(job_row), initial_status, "closed")

    return should_close


async def run_search(config_id: int) -> dict:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM search_configs WHERE id = ?", (config_id,)).fetchone()
        if not row:
            return {"error": "not found"}
        config = dict(row)

    keywords    = config["keywords"]
    location    = config.get("location")
    radius      = config.get("radius") or 30
    angebotsart = config.get("angebotsart") or 1
    arbeitszeit = config.get("arbeitszeit")
    tags        = json.loads(config.get("tags") or "[]")
    match_words = json.loads(config.get("match_words") or "[]")

    all_listings = []
    for page in range(1, 11):
        try:
            result = await search_jobs(
                keywords=keywords, location=location, radius=radius,
                page=page, size=100, angebotsart=angebotsart, arbeitszeit=arbeitszeit,
            )
        except Exception as e:
            logger.error(f"BA API error for config {config_id}: {e}")
            break
        batch = result.get("stellenangebote") or []
        all_listings.extend(batch)
        if len(batch) < 100:
            break

    new_count = 0
    skipped = 0
    to_check: list = []       # (job_id, url, keyword) for URL checks
    _new_jobs_data: list = [] # job dicts for alert firing

    for listing in all_listings:
        refnr = get_refnr(listing)
        if not refnr:
            logger.warning(f"Listing without refnr: {list(listing.keys())}")
            continue

        title_text = " ".join(filter(None, [
            listing.get("stellenangebotsTitel"),
            listing.get("titel"),
            listing.get("beruf"),
        ])).lower()
        if match_words and not any(w.lower() in title_text for w in match_words):
            skipped += 1
            continue

        with get_db() as conn:
            existing = conn.execute(
                "SELECT id FROM jobs WHERE external_id = ? AND source = 'arbeitsagentur'",
                (refnr,),
            ).fetchone()
        if existing:
            continue

        job_data = parse_listing(listing)

        try:
            details = await get_job_details(refnr)
            job_data = enrich_with_details(job_data, details)
        except Exception as e:
            logger.warning(f"Could not fetch details for {refnr}: {e}")

        now = utcnow()
        with get_db() as conn:
            cursor = conn.execute(
                """INSERT OR IGNORE INTO jobs (
                    external_id, source, title, company, location,
                    description, requirements, salary, job_type, url,
                    raw_api_data, search_config_id, status,
                    first_seen_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?)""",
                (
                    job_data["external_id"], job_data["source"],
                    job_data["title"], job_data.get("company"), job_data.get("location"),
                    job_data.get("description"), job_data.get("requirements"),
                    job_data.get("salary"), job_data.get("job_type"), job_data.get("url"),
                    job_data.get("raw_api_data"), config_id,
                    now, now, now,
                ),
            )
            job_id = cursor.lastrowid
            if cursor.rowcount:
                for tag in tags:
                    conn.execute(
                        "INSERT OR IGNORE INTO job_tags (job_id, tag) VALUES (?, ?)",
                        (job_id, tag.strip()),
                    )
                # Log the addition
                conn.execute(
                    "INSERT INTO job_history (job_id, field, old_value, new_value, changed_at) "
                    "VALUES (?, '_added', NULL, ?, ?)",
                    (job_id, config["name"], now),
                )
                new_count += 1
                url_to_check = job_data.get("check_url") or job_data.get("url")
                if url_to_check:
                    to_check.append((job_id, url_to_check, job_data.get("check_keyword")))
                # Queue alert for new listing (deduped per poll run, sent after loop)
                _new_jobs_data.append({**job_data, "id": job_id})

    # Fire new-listing alerts
    if _new_jobs_data:
        from app.services.alerts import fire_new_listing
        for jd in _new_jobs_data:
            await fire_new_listing(jd, source=config["name"])

    # Check URLs concurrently (max 10 at a time) to set initial status
    if to_check:
        sem = asyncio.Semaphore(10)

        async def _guarded(job_id, url, kw):
            async with sem:
                try:
                    await check_and_maybe_close(job_id, url, kw, "new")
                except Exception as e:
                    logger.warning(f"URL check failed for job {job_id}: {e}")

        await asyncio.gather(*[_guarded(jid, u, kw) for jid, u, kw in to_check])

    with get_db() as conn:
        conn.execute(
            "UPDATE search_configs SET last_polled_at = ?, total_found = total_found + ?, updated_at = ? WHERE id = ?",
            (utcnow(), new_count, utcnow(), config_id),
        )

    logger.info(
        f"Config {config_id} '{config['name']}': {new_count} new from "
        f"{len(all_listings)} listings ({skipped} filtered)"
    )
    return {"new": new_count, "total": len(all_listings), "filtered": skipped}


async def poll_all_active():
    with get_db() as conn:
        configs = conn.execute(
            "SELECT id FROM search_configs WHERE active = 1"
        ).fetchall()
    for row in configs:
        await run_search(row["id"])


async def check_all_urls():
    from app.services.alerts import fire_status_change

    with get_db() as conn:
        jobs = conn.execute(
            """SELECT id, title, company, url, check_url, check_keyword, status FROM jobs
               WHERE (url IS NOT NULL OR check_url IS NOT NULL)
                 AND status NOT IN ('closed', 'accepted', 'irrelevant', 'rejected')""",
        ).fetchall()

    for job in jobs:
        job_id = job["id"]
        target = job["check_url"] or job["url"]
        if not target:
            continue
        now = utcnow()
        status_code, html = await fetch_url(target)
        if status_code == 0:
            continue

        old_status = job["status"]
        closed = False
        with get_db() as conn:
            conn.execute(
                "UPDATE jobs SET last_checked_at = ?, updated_at = ? WHERE id = ?",
                (now, now, job_id),
            )
            if status_code in (404, 410):
                record_history(conn, job_id, "status", old_status, "closed", now)
                conn.execute(
                    "UPDATE jobs SET status = 'closed', last_changed_at = ?, updated_at = ? WHERE id = ?",
                    (now, now, job_id),
                )
                closed = True
                logger.info(f"Job {job_id} marked closed (HTTP {status_code})")
            elif status_code == 200 and html and job["check_keyword"]:
                if job["check_keyword"].lower() not in extract_text(html).lower():
                    record_history(conn, job_id, "check_keyword", "found", "not found", now)
                    record_history(conn, job_id, "status", old_status, "closed", now)
                    conn.execute(
                        "UPDATE jobs SET status = 'closed', last_changed_at = ?, updated_at = ? WHERE id = ?",
                        (now, now, job_id),
                    )
                    closed = True
                    logger.info(f"Job {job_id} marked closed (keyword not found)")

        if closed:
            await fire_status_change({"title": job["title"], "company": job["company"]}, old_status, "closed")
