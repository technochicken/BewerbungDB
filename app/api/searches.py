import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks

from app.auth import require_api_key
from app.database import get_db
from app.models import SearchConfigCreate, SearchConfigUpdate
from app.services.poller import run_search
from app.services.arbeitsagentur import search_jobs

router = APIRouter(
    prefix="/api/v1/searches",
    tags=["searches"],
    dependencies=[Depends(require_api_key)],
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def row_to_config(row) -> dict:
    d = dict(row)
    d["tags"] = json.loads(d.get("tags") or "[]")
    d["match_words"] = json.loads(d.get("match_words") or "[]")
    d["active"] = bool(d.get("active", 1))
    return d


@router.get("")
def list_searches():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM search_configs ORDER BY created_at DESC").fetchall()
    return [row_to_config(r) for r in rows]


@router.post("", status_code=201)
def create_search(cfg: SearchConfigCreate):
    now = utcnow()
    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO search_configs (
                name, keywords, location, radius, tags, match_words,
                source, active, poll_interval, angebotsart, arbeitszeit,
                total_found, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)""",
            (
                cfg.name, cfg.keywords, cfg.location, cfg.radius,
                json.dumps(cfg.tags), json.dumps(cfg.match_words),
                cfg.source, int(cfg.active), cfg.poll_interval,
                cfg.angebotsart, cfg.arbeitszeit,
                now, now,
            ),
        )
    return {"id": cursor.lastrowid}


@router.get("/{cfg_id}")
def get_search(cfg_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM search_configs WHERE id = ?", (cfg_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Search config not found")
    return row_to_config(row)


@router.patch("/{cfg_id}")
def update_search(cfg_id: int, update: SearchConfigUpdate):
    now = utcnow()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM search_configs WHERE id = ?", (cfg_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Search config not found")

        fields: dict = {}
        for attr in ["name", "keywords", "location", "radius", "poll_interval", "angebotsart", "arbeitszeit"]:
            val = getattr(update, attr, None)
            if val is not None:
                fields[attr] = val
        if update.active is not None:
            fields["active"] = int(update.active)
        if update.tags is not None:
            fields["tags"] = json.dumps(update.tags)
        if update.match_words is not None:
            fields["match_words"] = json.dumps(update.match_words)

        if fields:
            set_clause = ", ".join(f"{k} = ?" for k in fields)
            values = list(fields.values()) + [now, cfg_id]
            conn.execute(f"UPDATE search_configs SET {set_clause}, updated_at = ? WHERE id = ?", values)
    return {"status": "updated"}


@router.delete("/{cfg_id}", status_code=204)
def delete_search(cfg_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM search_configs WHERE id = ?", (cfg_id,))


@router.post("/{cfg_id}/poll")
async def trigger_poll(cfg_id: int, background_tasks: BackgroundTasks):
    with get_db() as conn:
        row = conn.execute("SELECT id FROM search_configs WHERE id = ?", (cfg_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Search config not found")

    result = await run_search(cfg_id)
    return result


@router.get("/{cfg_id}/raw-results")
async def raw_api_results(cfg_id: int, page: int = 1):
    """Returns raw BA API response for debugging field names / structure."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM search_configs WHERE id = ?", (cfg_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Search config not found")
    cfg = dict(row)

    data = await search_jobs(
        keywords=cfg["keywords"],
        location=cfg.get("location"),
        radius=cfg.get("radius") or 30,
        page=page,
        size=5,
        angebotsart=cfg.get("angebotsart") or 1,
        arbeitszeit=cfg.get("arbeitszeit"),
    )
    listings = data.get("stellenangebote") or []
    # Show all top-level keys (excluding the potentially huge stellenangebote list)
    top_level_keys = {k: type(v).__name__ for k, v in data.items() if k != "stellenangebote"}
    return {
        "maxErgebnisse": data.get("maxErgebnisse"),
        "top_level_keys": top_level_keys,
        "listings_count": len(listings),
        "first_listing_keys": list(listings[0].keys()) if listings else [],
        "sample_listings": listings[:2],
    }
