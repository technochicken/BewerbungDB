import logging
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from app.config import DB_PATH, DATA_DIR

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    external_id TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    title TEXT NOT NULL,
    company TEXT,
    location TEXT,
    description TEXT,
    requirements TEXT,
    salary TEXT,
    job_type TEXT,
    url TEXT,
    check_url TEXT,
    check_keyword TEXT,
    html_content TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    notes TEXT,
    raw_api_data TEXT,
    search_config_id INTEGER,
    first_seen_at TEXT NOT NULL,
    last_checked_at TEXT,
    last_changed_at TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_external
    ON jobs(external_id, source) WHERE external_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);

CREATE TABLE IF NOT EXISTS job_tags (
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (job_id, tag)
);

CREATE TABLE IF NOT EXISTS job_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    field TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_job ON job_history(job_id, changed_at DESC);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alert_configs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    event_type  TEXT NOT NULL,
    from_status TEXT,
    to_status   TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS search_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    keywords TEXT NOT NULL,
    location TEXT,
    radius INTEGER DEFAULT 30,
    tags TEXT NOT NULL DEFAULT '[]',
    match_words TEXT DEFAULT '[]',
    source TEXT DEFAULT 'arbeitsagentur',
    active INTEGER DEFAULT 1,
    poll_interval INTEGER DEFAULT 3600,
    last_polled_at TEXT,
    total_found INTEGER DEFAULT 0,
    angebotsart INTEGER DEFAULT 1,
    arbeitszeit TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    key_prefix   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    expires_at   TEXT,
    is_active    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS oidc_providers (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL UNIQUE,
    provider_type  TEXT NOT NULL DEFAULT 'generic',
    discovery_url  TEXT NOT NULL,
    client_id      TEXT NOT NULL,
    client_secret  TEXT NOT NULL,
    scopes         TEXT NOT NULL DEFAULT 'openid profile email',
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash  TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    used_at    TEXT
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key    TEXT NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT
);
"""

# Columns added after initial release — applied as safe migrations
MIGRATIONS = [
    ("jobs", "check_url",              "ALTER TABLE jobs ADD COLUMN check_url TEXT"),
    ("jobs", "check_keyword",          "ALTER TABLE jobs ADD COLUMN check_keyword TEXT"),
    ("jobs", "contact_first_name",     "ALTER TABLE jobs ADD COLUMN contact_first_name TEXT"),
    ("jobs", "contact_last_name",      "ALTER TABLE jobs ADD COLUMN contact_last_name TEXT"),
    ("jobs", "contact_salutation",     "ALTER TABLE jobs ADD COLUMN contact_salutation TEXT"),
    ("jobs", "contact_title",          "ALTER TABLE jobs ADD COLUMN contact_title TEXT"),
    ("jobs", "contact_email",          "ALTER TABLE jobs ADD COLUMN contact_email TEXT"),
    ("jobs", "contact_street",         "ALTER TABLE jobs ADD COLUMN contact_street TEXT"),
    ("jobs", "contact_street_nr",      "ALTER TABLE jobs ADD COLUMN contact_street_nr TEXT"),
    ("jobs", "contact_plz",            "ALTER TABLE jobs ADD COLUMN contact_plz TEXT"),
    ("jobs", "contact_city",           "ALTER TABLE jobs ADD COLUMN contact_city TEXT"),
    ("jobs", "job_name_personalized",  "ALTER TABLE jobs ADD COLUMN job_name_personalized TEXT"),
    ("jobs", "company_floskel",        "ALTER TABLE jobs ADD COLUMN company_floskel TEXT"),
    ("jobs", "application_date",       "ALTER TABLE jobs ADD COLUMN application_date TEXT"),
    ("jobs", "bewerbungstext",         "ALTER TABLE jobs ADD COLUMN bewerbungstext TEXT"),
]


def new_job_id() -> str:
    """Short random job ID (10 hex chars of a UUID4)."""
    return uuid.uuid4().hex[:10]


def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def get_db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create/upgrade the database. Runs on every start, so deploying a new
    image is enough: pending schema migrations are applied automatically
    (after an automatic backup). See the MIGRATIONS section below."""
    conn = get_connection()
    fresh = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='jobs'").fetchone() is None
    conn.close()
    with get_db() as conn:
        conn.executescript(SCHEMA)
    if fresh:
        _set_schema_version(LATEST_SCHEMA_VERSION)  # SCHEMA is already the newest layout
    else:
        _apply_schema_migrations()
    _run_migrations()
    from app.auth import init_auth
    init_auth()


def _mig_001_text_job_ids(conn):
    """Rebuild jobs/job_tags/job_history from INTEGER ids to short random text ids."""
    col = next((r for r in conn.execute("PRAGMA table_info(jobs)") if r["name"] == "id"), None)
    if col is None or col["type"].upper() != "INTEGER":
        return  # already migrated (or fresh database)
    logger.info("Migrating job IDs to short UUIDs")
    old_ids = [r[0] for r in conn.execute("SELECT id FROM jobs ORDER BY id")]
    mapping = {}
    used = set()
    for oid in old_ids:
        nid = new_job_id()
        while nid in used:
            nid = new_job_id()
        used.add(nid)
        mapping[oid] = nid
    conn.execute("CREATE TEMP TABLE _job_id_map (old INTEGER PRIMARY KEY, new TEXT NOT NULL)")
    conn.executemany("INSERT INTO _job_id_map VALUES (?, ?)", list(mapping.items()))

    cols = [r["name"] for r in conn.execute("PRAGMA table_info(jobs)") if r["name"] != "id"]
    col_list = ", ".join(cols)
    conn.execute("ALTER TABLE jobs RENAME TO jobs_old")
    conn.execute("DROP INDEX IF EXISTS idx_jobs_external")
    conn.execute("DROP INDEX IF EXISTS idx_jobs_status")
    conn.execute("DROP INDEX IF EXISTS idx_jobs_created")
    conn.execute("ALTER TABLE job_tags RENAME TO job_tags_old")
    conn.execute("ALTER TABLE job_history RENAME TO job_history_old")
    conn.execute("DROP INDEX IF EXISTS idx_history_job")
    # recreate tables with text ids (statement by statement: executescript would commit)
    for stmt in SCHEMA.split(";"):
        if stmt.strip():
            conn.execute(stmt)
    new_cols = {r["name"] for r in conn.execute("PRAGMA table_info(jobs)")}
    for table, column, sql in MIGRATIONS:
        if table == "jobs" and column in cols and column not in new_cols:
            conn.execute(sql)
    conn.execute(
        f"INSERT INTO jobs (id, {col_list}) "
        f"SELECT m.new, {', '.join('o.' + c for c in cols)} "
        "FROM jobs_old o JOIN _job_id_map m ON m.old = o.id"
    )
    conn.execute(
        "INSERT INTO job_tags (job_id, tag) "
        "SELECT m.new, t.tag FROM job_tags_old t JOIN _job_id_map m ON m.old = t.job_id"
    )
    conn.execute(
        "INSERT INTO job_history (id, job_id, field, old_value, new_value, changed_at) "
        "SELECT h.id, m.new, h.field, h.old_value, h.new_value, h.changed_at "
        "FROM job_history_old h JOIN _job_id_map m ON m.old = h.job_id"
    )
    conn.execute("DROP TABLE job_tags_old")
    conn.execute("DROP TABLE job_history_old")
    conn.execute("DROP TABLE jobs_old")
    conn.execute("DROP TABLE _job_id_map")


# ── Versioned schema migrations ───────────────────────────────────────────────
#
# HOW TO CHANGE THE DATABASE IN THE FUTURE
#   1. Update SCHEMA above so brand-new installs get the final layout.
#   2. Append ONE entry to SCHEMA_MIGRATIONS with the next version number and a
#      function taking an open connection that upgrades an existing database.
#      (A plain new nullable column can instead go into MIGRATIONS above.)
#   3. Push to master. The image is rebuilt; when the container starts it backs
#      up the database to data/backups/ and applies the pending migrations.
#      If a migration fails, it is rolled back, the old data stays untouched
#      and the container exits with the error (restore from data/backups/).
#
# The applied version is stored in SQLite's PRAGMA user_version.
SCHEMA_MIGRATIONS = [
    (1, "job ids: integer -> short text ids", _mig_001_text_job_ids),
]
LATEST_SCHEMA_VERSION = SCHEMA_MIGRATIONS[-1][0]
KEEP_BACKUPS = 5


def _get_schema_version(conn) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def _set_schema_version(version: int) -> None:
    conn = get_connection()
    try:
        conn.execute(f"PRAGMA user_version = {int(version)}")
    finally:
        conn.close()


def _backup_database(from_version: int) -> None:
    """Copy the live database to data/backups/ (consistent, via the SQLite backup API)."""
    backup_dir = DATA_DIR / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = backup_dir / f"jobs-v{from_version}-{stamp}.db"
    src = sqlite3.connect(str(DB_PATH))
    dst = sqlite3.connect(str(target))
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    for old in sorted(backup_dir.glob("jobs-v*.db"))[:-KEEP_BACKUPS]:
        old.unlink()
    logger.info("Database backed up to %s", target)


def _apply_schema_migrations():
    conn = get_connection()
    conn.isolation_level = None  # manage transactions manually
    try:
        current = _get_schema_version(conn)
        pending = [m for m in SCHEMA_MIGRATIONS if m[0] > current]
        if not pending:
            return
        conn.close()
        _backup_database(current)
        conn = get_connection()
        conn.isolation_level = None
        # foreign keys must be off while tables are rebuilt (cannot change inside a transaction)
        conn.execute("PRAGMA foreign_keys = OFF")
        for version, description, fn in pending:
            logger.info("Applying schema migration %d: %s", version, description)
            conn.execute("BEGIN")
            try:
                fn(conn)
                conn.execute(f"PRAGMA user_version = {version}")
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                logger.error("Schema migration %d failed – rolled back; backup is in %s", version, DATA_DIR / "backups")
                raise
    finally:
        try:
            conn.execute("PRAGMA foreign_keys = ON")
        except sqlite3.Error:
            pass
        conn.close()


def _run_migrations():
    with get_db() as conn:
        for table, column, sql in MIGRATIONS:
            existing = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
            if column not in existing:
                conn.execute(sql)
                logger.info(f"Migration applied: {table}.{column}")


def get_job_with_tags(conn, job_id: str):
    row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        return None
    tags = [r["tag"] for r in conn.execute(
        "SELECT tag FROM job_tags WHERE job_id = ? ORDER BY tag", (job_id,)
    ).fetchall()]
    d = dict(row)
    d["tags"] = tags
    return d


def _insert_rows(conn, table: str, rows: list[dict]) -> None:
    """Bulk-insert dict rows into table, preserving whatever columns each row has
    (so an older export missing newer columns still imports cleanly).

    `table` is always a hardcoded literal from trusted call sites. Row keys,
    however, come from an uploaded import file and are untrusted — they're
    validated against the table's real columns before being interpolated into
    SQL, so a crafted key can never inject arbitrary SQL text."""
    if not rows:
        return
    allowed = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    cols = [c for c in rows[0].keys() if c in allowed]
    if not cols:
        return
    col_list = ", ".join(cols)
    placeholders = ", ".join("?" for _ in cols)
    conn.executemany(
        f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})",
        [tuple(r.get(c) for c in cols) for r in rows],
    )


# ── DB reset / export / import (jobs + related data) ───────────────────────────

def reset_jobs_data() -> None:
    """Wipe all job/search/alert data. Does not touch settings, auth, or passkeys."""
    with get_db() as conn:
        conn.execute("DELETE FROM jobs")  # cascades to job_tags, job_history
        conn.execute("DELETE FROM search_configs")
        conn.execute("DELETE FROM alert_configs")


def export_jobs_data() -> dict:
    with get_db() as conn:
        return {
            "jobs":           [dict(r) for r in conn.execute("SELECT * FROM jobs").fetchall()],
            "job_tags":       [dict(r) for r in conn.execute("SELECT * FROM job_tags").fetchall()],
            "job_history":    [dict(r) for r in conn.execute("SELECT * FROM job_history").fetchall()],
            "search_configs": [dict(r) for r in conn.execute("SELECT * FROM search_configs").fetchall()],
            "alert_configs":  [dict(r) for r in conn.execute("SELECT * FROM alert_configs").fetchall()],
        }


def describe_jobs_import(data: dict) -> dict:
    return {
        "jobs":           len(data.get("jobs", [])),
        "search_configs": len(data.get("search_configs", [])),
        "alert_configs":  len(data.get("alert_configs", [])),
    }


def import_jobs_data(data: dict) -> None:
    """Replace all job/search/alert data with the given export bundle."""
    with get_db() as conn:
        conn.execute("DELETE FROM jobs")  # cascades to job_tags, job_history
        conn.execute("DELETE FROM search_configs")
        conn.execute("DELETE FROM alert_configs")
        _insert_rows(conn, "jobs", data.get("jobs", []))
        _insert_rows(conn, "job_tags", data.get("job_tags", []))
        _insert_rows(conn, "job_history", data.get("job_history", []))
        _insert_rows(conn, "search_configs", data.get("search_configs", []))
        _insert_rows(conn, "alert_configs", data.get("alert_configs", []))


def record_history(conn, job_id: str, field: str, old_val, new_val, now: str):
    old_s = str(old_val) if old_val is not None else None
    new_s = str(new_val) if new_val is not None else None
    if old_s != new_s:
        conn.execute(
            "INSERT INTO job_history (job_id, field, old_value, new_value, changed_at) VALUES (?, ?, ?, ?, ?)",
            (job_id, field, old_s, new_s, now),
        )
        return True
    return False
