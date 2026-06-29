import logging
import sqlite3
from contextlib import contextmanager
from app.config import DB_PATH

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (job_id, tag)
);

CREATE TABLE IF NOT EXISTS job_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
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
    with get_db() as conn:
        conn.executescript(SCHEMA)
    _run_migrations()
    from app.auth import init_auth
    init_auth()


def _run_migrations():
    with get_db() as conn:
        for table, column, sql in MIGRATIONS:
            existing = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
            if column not in existing:
                conn.execute(sql)
                logger.info(f"Migration applied: {table}.{column}")


def get_job_with_tags(conn, job_id: int):
    row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        return None
    tags = [r["tag"] for r in conn.execute(
        "SELECT tag FROM job_tags WHERE job_id = ? ORDER BY tag", (job_id,)
    ).fetchall()]
    d = dict(row)
    d["tags"] = tags
    return d


def record_history(conn, job_id: int, field: str, old_val, new_val, now: str):
    old_s = str(old_val) if old_val is not None else None
    new_s = str(new_val) if new_val is not None else None
    if old_s != new_s:
        conn.execute(
            "INSERT INTO job_history (job_id, field, old_value, new_value, changed_at) VALUES (?, ?, ?, ?, ?)",
            (job_id, field, old_s, new_s, now),
        )
        return True
    return False
