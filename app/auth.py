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


# ── TOTP two-factor authentication ────────────────────────────────────────────

def get_totp_enabled() -> bool:
    return _get("totp_enabled") == "true"


def get_totp_secret() -> Optional[str]:
    return _get("totp_secret")


def verify_totp_code(code: str) -> bool:
    secret = get_totp_secret()
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit():
        return False
    import pyotp
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def enable_totp(secret: str) -> None:
    _set("totp_secret", secret)
    _set("totp_enabled", "true")


def disable_totp() -> None:
    _set("totp_enabled", "false")
    _set("totp_secret", "")
    from app.database import get_db
    with get_db() as conn:
        conn.execute("DELETE FROM totp_backup_codes")


# ── TOTP backup codes ─────────────────────────────────────────────────────────

def _format_backup_code(raw_hex: str) -> str:
    return f"{raw_hex[0:4]}-{raw_hex[4:8]}-{raw_hex[8:12]}"


def generate_backup_codes(n: int = 10) -> list[str]:
    """Replace all existing backup codes with n new ones. Returns raw codes (shown once)."""
    from app.database import get_db
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    codes = []
    with get_db() as conn:
        conn.execute("DELETE FROM totp_backup_codes")
        for _ in range(n):
            raw = secrets.token_hex(6).upper()
            codes.append(_format_backup_code(raw))
            conn.execute(
                "INSERT INTO totp_backup_codes (code_hash, created_at) VALUES (?, ?)",
                (_key_hash(raw), now),
            )
    return codes


def verify_backup_code(code: str) -> bool:
    raw = (code or "").strip().upper().replace("-", "").replace(" ", "")
    if not raw:
        return False
    h = _key_hash(raw)
    from app.database import get_db
    with get_db() as conn:
        row = conn.execute(
            "SELECT id FROM totp_backup_codes WHERE code_hash = ? AND used_at IS NULL", (h,)
        ).fetchone()
        if not row:
            return False
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn.execute("UPDATE totp_backup_codes SET used_at = ? WHERE id = ?", (now, row["id"]))
    return True


def count_unused_backup_codes() -> int:
    from app.database import get_db
    with get_db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM totp_backup_codes WHERE used_at IS NULL"
        ).fetchone()[0]


# ── WebAuthn passkeys (trusted devices) ───────────────────────────────────────

def get_webauthn_user_id() -> bytes:
    """Stable random user handle for this single-account app, generated once."""
    hex_id = _get("webauthn_user_id")
    if not hex_id:
        hex_id = secrets.token_hex(16)
        _set("webauthn_user_id", hex_id)
    return bytes.fromhex(hex_id)


def list_webauthn_credentials() -> list[dict]:
    from app.database import get_db
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, created_at, last_used_at FROM webauthn_credentials "
            "ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def list_webauthn_credential_ids() -> list[str]:
    """Base64url credential IDs (as sent by the browser), for login allow_credentials."""
    from app.database import get_db
    with get_db() as conn:
        rows = conn.execute("SELECT credential_id FROM webauthn_credentials").fetchall()
    return [r["credential_id"] for r in rows]


def get_webauthn_credential_by_cred_id(credential_id_b64: str) -> Optional[dict]:
    from app.database import get_db
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id = ?", (credential_id_b64,)
        ).fetchone()
    return dict(row) if row else None


def create_webauthn_credential(
    name: str, credential_id_b64: str, public_key_b64: str, sign_count: int
) -> None:
    from app.database import get_db
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO webauthn_credentials "
            "(name, credential_id, public_key, sign_count, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, credential_id_b64, public_key_b64, sign_count, now),
        )


def update_webauthn_credential_usage(credential_id_b64: str, new_sign_count: int) -> None:
    from app.database import get_db
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_db() as conn:
        conn.execute(
            "UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE credential_id = ?",
            (new_sign_count, now, credential_id_b64),
        )


def delete_webauthn_credential(cred_row_id: int) -> None:
    from app.database import get_db
    with get_db() as conn:
        conn.execute("DELETE FROM webauthn_credentials WHERE id = ?", (cred_row_id,))


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
