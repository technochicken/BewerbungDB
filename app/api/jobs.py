import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import require_api_key
from app.database import get_db, get_job_with_tags, record_history
from app.models import JobCreate, JobUpdate
from app.services.scraper import fetch_url, extract_text

router = APIRouter(
    prefix="/api/v1/jobs",
    tags=["jobs"],
    dependencies=[Depends(require_api_key)],
)

# All editable columns (except tags which are a separate table)
JOB_FIELDS = [
    "title", "company", "location", "description", "requirements",
    "salary", "job_type", "url", "check_url", "check_keyword",
    "html_content", "notes", "expires_at", "external_id",
    "contact_first_name", "contact_last_name", "contact_salutation", "contact_title",
    "contact_email", "contact_street", "contact_street_nr", "contact_plz", "contact_city",
    "job_name_personalized", "company_floskel", "application_date", "bewerbungstext",
]

SORT_MAP = {
    "created_desc":  "j.created_at DESC",
    "created_asc":   "j.created_at ASC",
    "changed_desc":  "j.last_changed_at DESC NULLS LAST",
    "changed_asc":   "j.last_changed_at ASC NULLS LAST",
    "checked_desc":  "j.last_checked_at DESC NULLS LAST",
    "title_asc":     "j.title ASC",
    "title_desc":    "j.title DESC",
    "company_asc":   "j.company ASC NULLS LAST",
    "company_desc":  "j.company DESC NULLS LAST",
    "status":        "j.status ASC, j.created_at DESC",
    "expires_asc":   "j.expires_at ASC NULLS LAST",
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("")
def list_jobs(
    status: Optional[str] = None,
    tag: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    sort: str = "created_desc",
    limit: int = Query(500, le=2000),
    offset: int = 0,
):
    order = SORT_MAP.get(sort, "j.created_at DESC")
    with get_db() as conn:
        query = f"""SELECT j.*,
                    (SELECT GROUP_CONCAT(tag ORDER BY tag) FROM job_tags WHERE job_id = j.id) as _tags
                    FROM jobs j WHERE 1=1"""
        params: list = []
        if status:
            statuses = status.split(",")
            placeholders = ",".join("?" * len(statuses))
            query += f" AND j.status IN ({placeholders})"
            params.extend(statuses)
        if source:
            query += " AND j.source = ?"
            params.append(source)
        if search:
            s = f"%{search}%"
            query += " AND (j.title LIKE ? OR j.company LIKE ? OR j.location LIKE ? OR j.description LIKE ?)"
            params.extend([s, s, s, s])
        if tag:
            query += " AND j.id IN (SELECT job_id FROM job_tags WHERE tag = ?)"
            params.append(tag)
        query += f" ORDER BY {order} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["tags"] = d.pop("_tags", "").split(",") if d.get("_tags") else []
            result.append(d)
        return result


@router.post("", status_code=201)
def create_job(job: JobCreate):
    now = utcnow()
    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO jobs (
                title, company, location, description, requirements,
                salary, job_type, url, check_url, check_keyword,
                html_content, status, notes, expires_at, external_id,
                source, first_seen_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual', ?, ?, ?)""",
            (
                job.title, job.company, job.location, job.description, job.requirements,
                job.salary, job.job_type, job.url, job.check_url, job.check_keyword,
                job.html_content, job.status.value, job.notes, job.expires_at, job.external_id,
                now, now, now,
            ),
        )
        job_id = cursor.lastrowid
        for tag in job.tags:
            conn.execute(
                "INSERT OR IGNORE INTO job_tags (job_id, tag) VALUES (?, ?)",
                (job_id, tag.strip()),
            )
    return {"id": job_id}


@router.get("/stats")
def job_stats():
    with get_db() as conn:
        rows = conn.execute("SELECT status, COUNT(*) as count FROM jobs GROUP BY status").fetchall()
        tags = conn.execute(
            "SELECT tag, COUNT(*) as count FROM job_tags GROUP BY tag ORDER BY count DESC LIMIT 20"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) as c FROM jobs").fetchone()["c"]
        recent = conn.execute(
            "SELECT id, title, company, status, created_at FROM jobs ORDER BY created_at DESC LIMIT 5"
        ).fetchall()
    return {
        "total": total,
        "by_status": {r["status"]: r["count"] for r in rows},
        "top_tags": [{"tag": r["tag"], "count": r["count"]} for r in tags],
        "recent": [dict(r) for r in recent],
    }


@router.get("/tags")
def list_tags():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT tag, COUNT(*) as count FROM job_tags GROUP BY tag ORDER BY count DESC"
        ).fetchall()
    return [{"tag": r["tag"], "count": r["count"]} for r in rows]


@router.get("/{job_id}")
def get_job(job_id: int):
    with get_db() as conn:
        job = get_job_with_tags(conn, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.patch("/{job_id}")
def update_job(job_id: int, update: JobUpdate):
    now = utcnow()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        old = dict(row)

        fields: dict = {}
        for attr in JOB_FIELDS:
            val = getattr(update, attr, None)
            if val is not None:
                fields[attr] = val
        if update.status is not None:
            fields["status"] = update.status.value

        changed = False
        for field, new_val in fields.items():
            if record_history(conn, job_id, field, old.get(field), new_val, now):
                changed = True

        if fields:
            set_clause = ", ".join(f"{k} = ?" for k in fields)
            values = list(fields.values()) + [now, job_id]
            conn.execute(f"UPDATE jobs SET {set_clause}, updated_at = ? WHERE id = ?", values)
            if changed:
                conn.execute("UPDATE jobs SET last_changed_at = ? WHERE id = ?", (now, job_id))

        if update.tags is not None:
            old_tags = [r["tag"] for r in conn.execute(
                "SELECT tag FROM job_tags WHERE job_id = ?", (job_id,)
            ).fetchall()]
            new_tags = [t.strip() for t in update.tags if t.strip()]
            if set(old_tags) != set(new_tags):
                record_history(conn, job_id, "tags", ", ".join(sorted(old_tags)), ", ".join(sorted(new_tags)), now)
                conn.execute("DELETE FROM job_tags WHERE job_id = ?", (job_id,))
                for tag in new_tags:
                    conn.execute(
                        "INSERT OR IGNORE INTO job_tags (job_id, tag) VALUES (?, ?)",
                        (job_id, tag),
                    )
    return {"status": "updated"}


@router.delete("/{job_id}", status_code=204)
def delete_job(job_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))


@router.get("/{job_id}/history")
def get_history(job_id: int):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM job_history WHERE job_id = ? ORDER BY changed_at DESC",
            (job_id,),
        ).fetchall()
    return [dict(r) for r in rows]


@router.post("/{job_id}/check-url")
async def check_url_now(job_id: int):
    with get_db() as conn:
        row = conn.execute(
            "SELECT url, check_url, check_keyword, status FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Job not found")

    target_url = row["check_url"] or row["url"]
    if not target_url:
        raise HTTPException(400, "No URL configured for this job")

    status_code, html = await fetch_url(target_url)
    now = utcnow()
    result: dict = {"url": target_url, "status_code": status_code, "reachable": status_code == 200}

    with get_db() as conn:
        conn.execute(
            "UPDATE jobs SET last_checked_at = ?, updated_at = ? WHERE id = ?",
            (now, now, job_id),
        )
        current_status = row["status"]
        if status_code in (404, 410):
            if current_status not in ("closed", "accepted", "rejected"):
                record_history(conn, job_id, "status", current_status, "closed", now)
                conn.execute(
                    "UPDATE jobs SET status = 'closed', last_changed_at = ?, updated_at = ? WHERE id = ?",
                    (now, now, job_id),
                )
                result["auto_closed"] = True
        elif status_code == 200 and html and row["check_keyword"]:
            text = extract_text(html)
            keyword_found = row["check_keyword"].lower() in text.lower()
            result["keyword"] = row["check_keyword"]
            result["keyword_found"] = keyword_found
            if not keyword_found:
                record_history(conn, job_id, "check_keyword", "found", "not found", now)
                if current_status not in ("closed", "accepted", "rejected"):
                    record_history(conn, job_id, "status", current_status, "closed", now)
                    conn.execute(
                        "UPDATE jobs SET status = 'closed', last_changed_at = ?, updated_at = ? WHERE id = ?",
                        (now, now, job_id),
                    )
                    result["auto_closed"] = True

    return result
