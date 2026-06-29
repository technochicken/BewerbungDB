"""
MCP tool definitions for BewerbungsDB.

Exposes list_jobs, get_job, and update_job via the Model Context Protocol.

The FastMCP instance (`mcp`) is imported by app/main.py, which mounts it
as an HTTP transport at /mcp (used by Claude.ai remote connections).

For Claude Desktop (stdio transport), run via the top-level entry point:
    python run.py --mcp

Claude Desktop config (~/.claude/claude_desktop_config.json):
{
  "mcpServers": {
    "bewerbungsdb": {
      "command": "python",
      "args": ["/path/to/bewerbungsdb/run.py", "--mcp"]
    }
  }
}
"""

import json

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from app.database import get_db, get_job_with_tags

# DNS-rebinding protection is disabled because this server is accessed over
# HTTPS with its own Bearer-token auth layer (see _MCPBearerAuth in main.py).
mcp = FastMCP(
    "BewerbungsDB",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

ALL_STATUSES = [
    "new", "reviewing", "applied", "interview",
    "offer", "accepted", "rejected", "closed", "irrelevant",
]

UPDATABLE_FIELDS = {
    "title", "company", "location", "description", "requirements",
    "salary", "job_type", "url", "status", "notes", "bewerbungstext",
    "contact_first_name", "contact_last_name", "contact_salutation",
    "contact_title", "contact_email", "contact_street", "contact_street_nr",
    "contact_plz", "contact_city", "job_name_personalized", "company_floskel",
    "application_date", "tags",
}


@mcp.tool()
def list_jobs(
    status: str = "",
    search: str = "",
    limit: int = 50,
) -> str:
    """List job applications.

    Args:
        status: Filter by status (new, reviewing, applied, interview, offer,
                accepted, rejected, closed, irrelevant). Leave empty for all.
        search: Search in title, company, location or ID.
        limit:  Maximum number of results (default 50, max 200).
    """
    limit = min(max(1, limit), 200)
    conditions: list[str] = []
    params: list = []

    if status and status in ALL_STATUSES:
        conditions.append("j.status = ?")
        params.append(status)

    if search:
        like = f"%{search}%"
        conditions.append(
            "(j.title LIKE ? OR j.company LIKE ? OR j.location LIKE ? OR CAST(j.id AS TEXT) LIKE ?)"
        )
        params.extend([like, like, like, like])

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"""
        SELECT j.id, j.title, j.company, j.location, j.status,
               j.salary, j.job_type, j.url,
               j.application_date, j.created_at, j.last_changed_at,
               GROUP_CONCAT(t.tag) AS tags
        FROM jobs j
        LEFT JOIN job_tags t ON t.job_id = j.id
        {where}
        GROUP BY j.id
        ORDER BY j.created_at DESC
        LIMIT ?
    """
    params.append(limit)

    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()

    jobs = []
    for row in rows:
        d = dict(row)
        d["tags"] = d["tags"].split(",") if d["tags"] else []
        jobs.append(d)

    return json.dumps(jobs, ensure_ascii=False, indent=2)


@mcp.tool()
def get_job(job_id: int) -> str:
    """Get full details of a single job application.

    Args:
        job_id: The integer ID of the job.
    """
    with get_db() as conn:
        job = get_job_with_tags(conn, job_id)

    if job is None:
        return json.dumps({"error": f"Job {job_id} not found"})

    return json.dumps(job, ensure_ascii=False, indent=2)


@mcp.tool()
def update_job(job_id: int, updates: str) -> str:
    """Update fields of a job application.

    Args:
        job_id:  The integer ID of the job to update.
        updates: JSON string of field→value pairs to update.
                 Updatable fields: title, company, location, description,
                 requirements, salary, job_type, url, status, notes,
                 bewerbungstext, contact_first_name, contact_last_name,
                 contact_salutation, contact_title, contact_email,
                 contact_street, contact_street_nr, contact_plz,
                 contact_city, job_name_personalized, company_floskel,
                 application_date, tags (list of strings).
    """
    try:
        data = json.loads(updates)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})

    if not isinstance(data, dict):
        return json.dumps({"error": "updates must be a JSON object"})

    tags_update = None
    if "tags" in data:
        tags_raw = data.pop("tags")
        if isinstance(tags_raw, list):
            tags_update = [str(t).strip() for t in tags_raw if str(t).strip()]
        else:
            return json.dumps({"error": "'tags' must be a list of strings"})

    unknown = set(data.keys()) - UPDATABLE_FIELDS
    if unknown:
        return json.dumps({"error": f"Unknown fields: {sorted(unknown)}"})

    if data.get("status") and data["status"] not in ALL_STATUSES:
        return json.dumps({"error": f"Invalid status. Valid values: {ALL_STATUSES}"})

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with get_db() as conn:
        existing = conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not existing:
            return json.dumps({"error": f"Job {job_id} not found"})

        if data:
            set_clause = ", ".join(f"{k} = ?" for k in data)
            values = list(data.values()) + [now, now, job_id]
            conn.execute(
                f"UPDATE jobs SET {set_clause}, last_changed_at = ?, updated_at = ? WHERE id = ?",
                values,
            )

        if tags_update is not None:
            conn.execute("DELETE FROM job_tags WHERE job_id = ?", (job_id,))
            for tag in tags_update:
                conn.execute(
                    "INSERT OR IGNORE INTO job_tags (job_id, tag) VALUES (?, ?)",
                    (job_id, tag),
                )

        updated_job = get_job_with_tags(conn, job_id)

    return json.dumps({"success": True, "job": updated_job}, ensure_ascii=False, indent=2)
