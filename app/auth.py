import hashlib
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException, Header, Query, Request
from itsdangerous import URLSafeTimedSerializer, BadData


# ── Password hashing (PBKDF2-SHA256, 260k rounds) ────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2$sha256${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, algo, salt, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(algo, password.encode(), salt.encode(), 260_000)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ── app_settings key-value helpers ───────────────────────────────────────────

def _get(key: str) -> Optional[str]:
    from app.database import get_db
    with get_db() as conn:
        row = conn.execute(
            "SELECT value FROM app_settings WHERE key = ?", (key,)
        ).fetchone()
    return row["value"] if row else None


def _set(key: str, value: str) -> None:
    from app.database import get_db
    with get_db() as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def get_password_hash() -> Optional[str]:
    return _get("password_hash")


def set_password(plain: str) -> None:
    _set("password_hash", hash_password(plain))


# ── Multi-key API key management ──────────────────────────────────────────────

def _key_hash(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def create_api_key(name: str, expires_at: Optional[str] = None) -> str:
    """Generate a new key, store its SHA-256 hash, return the raw key (shown once)."""
    raw = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    from app.database import get_db
    with get_db() as conn:
        conn.execute(
            "INSERT INTO api_keys (name, key_hash, key_prefix, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, _key_hash(raw), raw[:8], now, expires_at),
        )
    return raw


def list_api_keys() -> list[dict]:
    """Return all keys (id, name, key_prefix, created_at, last_used_at, expires_at, is_active)."""
    from app.database import get_db
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, key_prefix, created_at, last_used_at, expires_at, is_active "
            "FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def revoke_api_key(key_id: int) -> None:
    """Set is_active=0 for the given key id."""
    from app.database import get_db
    with get_db() as conn:
        conn.execute("UPDATE api_keys SET is_active = 0 WHERE id = ?", (key_id,))


def delete_api_key(key_id: int) -> None:
    """Hard-delete a key row."""
    from app.database import get_db
    with get_db() as conn:
        conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))


def verify_api_key(raw_key: str) -> Optional[dict]:
    """Hash raw_key, look up in api_keys, update last_used_at, return row or None."""
    h = _key_hash(raw_key)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    from app.database import get_db
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1", (h,)
        ).fetchone()
        if not row:
            return None
        if row["expires_at"] and row["expires_at"] < now:
            return None
        conn.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row["id"])
        )
    return dict(row)


# ── Initialization ────────────────────────────────────────────────────────────

def init_auth() -> None:
    """Seed DB with initial password and API key on first run; migrate legacy key."""
    import logging
    logger = logging.getLogger(__name__)

    if not get_password_hash():
        password = secrets.token_urlsafe(12)
        set_password(password)
        _set("needs_password_change", "true")
        banner = (
            "\n" + "=" * 60
            + f"\n  INITIAL PASSWORD: {password}"
            + "\n  Change this immediately in Settings → Password"
            + "\n" + "=" * 60
        )
        print(banner)
        logger.warning(banner)

    from app.database import get_db
    with get_db() as conn:
        key_count = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]

    if key_count == 0:
        legacy = _get("api_key")
        if legacy:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            from app.database import get_db
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO api_keys (name, key_hash, key_prefix, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    ("Default (migrated)", _key_hash(legacy), legacy[:8], now),
                )
            logger.info("Migrated legacy API key to api_keys table")
        else:
            raw = create_api_key("Default")
            banner = (
                "\n" + "=" * 60
                + f"\n  DEFAULT API KEY: {raw}"
                + "\n  Save this — it won't be shown again."
                + "\n" + "=" * 60
            )
            print(banner)
            logger.warning(banner)

    if not _get("mcp_token"):
        _set("mcp_token", secrets.token_urlsafe(32))


# ── CSRF helpers (itsdangerous, already in requirements) ─────────────────────

def _csrf_serializer() -> URLSafeTimedSerializer:
    from app.config import SESSION_SECRET
    return URLSafeTimedSerializer(SESSION_SECRET, salt="csrf")


def generate_csrf_token(session: dict) -> str:
    if "_csrf_seed" not in session:
        session["_csrf_seed"] = secrets.token_hex(16)
    return _csrf_serializer().dumps(session["_csrf_seed"])


def validate_csrf_token(session: dict, token: str) -> bool:
    seed = session.get("_csrf_seed")
    if not seed or not token:
        return False
    try:
        value = _csrf_serializer().loads(token, max_age=7200)
        return secrets.compare_digest(str(value), str(seed))
    except BadData:
        return False


# ── Brute-force guard (in-memory, resets on restart) ─────────────────────────

_failed: dict[str, tuple[int, float]] = {}
_MAX_ATTEMPTS = 10
_WINDOW_SECS  = 300  # 5 minutes


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def is_rate_limited(request: Request) -> bool:
    ip  = _client_ip(request)
    now = time.time()
    count, start = _failed.get(ip, (0, now))
    if now - start > _WINDOW_SECS:
        return False
    return count >= _MAX_ATTEMPTS


def record_failed(request: Request) -> None:
    ip  = _client_ip(request)
    now = time.time()
    count, start = _failed.get(ip, (0, now))
    if now - start > _WINDOW_SECS:
        _failed[ip] = (1, now)
    else:
        _failed[ip] = (count + 1, start)


def clear_failed(request: Request) -> None:
    _failed.pop(_client_ip(request), None)


# ── API key FastAPI dependency ────────────────────────────────────────────────

async def require_api_key(
    request: Request,
    api_key: Optional[str] = Query(None),
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
) -> None:
    provided = api_key or x_api_key
    if authorization and authorization.startswith("Bearer "):
        provided = authorization[7:].strip()

    if not provided:
        raise HTTPException(
            401,
            "Missing API key. Use ?api_key=KEY, X-Api-Key header, or Authorization: Bearer KEY",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_api_key(provided):
        raise HTTPException(
            401,
            "Invalid, revoked, or expired API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )
