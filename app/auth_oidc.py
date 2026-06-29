"""
OIDC SSO integration for BewerbungsDB.

Supports Authelia, Authentik, Nextcloud, and any generic OIDC-compliant provider.
To add a new provider type, append an entry to PROVIDER_PRESETS — no other code changes needed.
"""

import base64
import hashlib
import secrets
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlencode

import httpx


# ── Provider presets ──────────────────────────────────────────────────────────
# Each entry defines UI hints for the Settings page.
# provider_type is stored in the DB so future presets apply retroactively.

PROVIDER_PRESETS: dict[str, dict] = {
    "authelia": {
        "display": "Authelia",
        "scopes": "openid profile email groups",
        "discovery_hint": "https://auth.example.com/.well-known/openid-configuration",
    },
    "authentik": {
        "display": "Authentik",
        "scopes": "openid profile email",
        "discovery_hint": "https://authentik.example.com/application/o/<app-slug>/.well-known/openid-configuration",
    },
    "nextcloud": {
        "display": "Nextcloud",
        "scopes": "openid profile email",
        "discovery_hint": "https://nextcloud.example.com/index.php/apps/user_oidc/",
    },
    "generic": {
        "display": "Custom OIDC",
        "scopes": "openid profile email",
        "discovery_hint": "https://provider.example.com/.well-known/openid-configuration",
    },
}

# ── Discovery document cache ──────────────────────────────────────────────────
# Keyed by discovery URL; entries expire after 1 hour.

_discovery_cache: dict[str, tuple[dict, float]] = {}
_CACHE_TTL = 3600


async def fetch_oidc_config(discovery_url: str) -> dict:
    """Fetch and cache the OIDC discovery document."""
    cached = _discovery_cache.get(discovery_url)
    if cached and (time.time() - cached[1]) < _CACHE_TTL:
        return cached[0]
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        config = resp.json()
    _discovery_cache[discovery_url] = (config, time.time())
    return config


# ── Database helpers ──────────────────────────────────────────────────────────

def list_oidc_providers() -> list[dict]:
    from app.database import get_db
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, provider_type, discovery_url, client_id, scopes, enabled "
            "FROM oidc_providers ORDER BY name"
        ).fetchall()
    return [dict(r) for r in rows]


def get_oidc_provider(provider_id: int) -> Optional[dict]:
    from app.database import get_db
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM oidc_providers WHERE id = ?", (provider_id,)
        ).fetchone()
    return dict(row) if row else None


def get_oidc_provider_by_name(name: str) -> Optional[dict]:
    from app.database import get_db
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM oidc_providers WHERE name = ? AND enabled = 1", (name,)
        ).fetchone()
    return dict(row) if row else None


def create_oidc_provider(name: str, provider_type: str, discovery_url: str,
                          client_id: str, client_secret: str, scopes: str) -> int:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    from app.database import get_db
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO oidc_providers "
            "(name, provider_type, discovery_url, client_id, client_secret, scopes, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, provider_type, discovery_url, client_id, client_secret, scopes, now, now),
        )
        return cur.lastrowid


def update_oidc_provider(provider_id: int, **kwargs) -> None:
    allowed = {"name", "provider_type", "discovery_url", "client_id", "client_secret", "scopes", "enabled"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    updates["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    from app.database import get_db
    with get_db() as conn:
        conn.execute(
            f"UPDATE oidc_providers SET {set_clause} WHERE id = ?",
            list(updates.values()) + [provider_id],
        )


def delete_oidc_provider(provider_id: int) -> None:
    from app.database import get_db
    with get_db() as conn:
        conn.execute("DELETE FROM oidc_providers WHERE id = ?", (provider_id,))


# ── PKCE helpers ──────────────────────────────────────────────────────────────

def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge_S256)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ── Authorization URL builder ─────────────────────────────────────────────────

async def build_auth_url(provider: dict, state: str, redirect_uri: str) -> tuple[str, str]:
    """
    Build the PKCE authorization URL.
    Returns (auth_url, code_verifier) — caller must store code_verifier in the session.
    """
    config = await fetch_oidc_config(provider["discovery_url"])
    verifier, challenge = _pkce_pair()

    params = {
        "response_type": "code",
        "client_id": provider["client_id"],
        "redirect_uri": redirect_uri,
        "scope": provider["scopes"],
        "state": state,
        "nonce": secrets.token_urlsafe(16),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{config['authorization_endpoint']}?{urlencode(params)}", verifier


# ── Token exchange ─────────────────────────────────────────────────────────────

async def exchange_code(provider: dict, code: str, code_verifier: str, redirect_uri: str) -> dict:
    """Exchange an authorization code for tokens using PKCE."""
    config = await fetch_oidc_config(provider["discovery_url"])
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            config["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": provider["client_id"],
                "client_secret": provider["client_secret"],
                "code_verifier": code_verifier,
            },
        )
        resp.raise_for_status()
        return resp.json()


# ── User info ─────────────────────────────────────────────────────────────────

async def get_user_info(provider: dict, access_token: str) -> dict:
    """Fetch user info from the OIDC userinfo endpoint."""
    config = await fetch_oidc_config(provider["discovery_url"])
    endpoint = config.get("userinfo_endpoint")
    if not endpoint:
        return {}
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )
        resp.raise_for_status()
        return resp.json()
