import asyncio
import base64
import hashlib
import io
import json
import logging
import secrets
import secrets as _secrets_mod
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import pyotp
import qrcode
import qrcode.image.svg
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from fastapi import BackgroundTasks, FastAPI, Request, Form, HTTPException, Query, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.auth import (
    verify_password, set_password, get_password_hash,
    is_rate_limited, record_failed, clear_failed,
    _get as settings_get, _set as settings_set,
    generate_csrf_token, validate_csrf_token,
    create_api_key, list_api_keys, revoke_api_key, delete_api_key,
    get_totp_enabled, enable_totp, disable_totp, verify_totp_code,
    generate_backup_codes, verify_backup_code, count_unused_backup_codes,
    get_webauthn_user_id, list_webauthn_credentials, list_webauthn_credential_ids,
    get_webauthn_credential_by_cred_id, create_webauthn_credential,
    update_webauthn_credential_usage, delete_webauthn_credential,
    reset_settings_data, export_settings_data, describe_settings_import, import_settings_data,
)
from app.auth_oidc import (
    list_oidc_providers, get_oidc_provider, get_oidc_provider_by_name,
    create_oidc_provider, update_oidc_provider, delete_oidc_provider,
    build_auth_url, exchange_code, get_user_info, PROVIDER_PRESETS,
)
from app.config import POLL_INTERVAL_SECS, URL_CHECK_INTERVAL_SECS, SESSION_SECRET, APP_BASE_URL, DATA_DIR
from app.database import (
    get_db, get_job_with_tags, init_db, record_history,
    reset_jobs_data, export_jobs_data, describe_jobs_import, import_jobs_data,
)
from app.models import ALL_STATUSES, STATUS_COLORS
from app.api.jobs import router as jobs_router, SORT_MAP
from app.api.searches import router as searches_router
from app.services.poller import poll_all_active, check_all_urls

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── WebAuthn (passkey trusted devices) config ──────────────────────────────────
WEBAUTHN_RP_ID   = urlparse(APP_BASE_URL).hostname or "localhost"
WEBAUTHN_RP_NAME = "BewerbungsDB"
WEBAUTHN_ORIGIN  = APP_BASE_URL


DANGER_ACTIONS = {
    "reset-db":        {"title": "Datenbank zurücksetzen",   "kind": "reset",  "scope": "db"},
    "reset-settings":  {"title": "Einstellungen zurücksetzen", "kind": "reset",  "scope": "settings"},
    "import-db":       {"title": "Datenbank importieren",    "kind": "import", "scope": "db"},
    "import-settings": {"title": "Einstellungen importieren", "kind": "import", "scope": "settings"},
}

IMPORT_TMP_DIR = DATA_DIR / "tmp_imports"
IMPORT_TMP_DIR.mkdir(parents=True, exist_ok=True)
MAX_IMPORT_SIZE = 20 * 1024 * 1024


def _danger_challenge_key(action: str) -> str:
    return f"danger_challenge_{action}"


def _pending_import_key(scope: str) -> str:
    return f"pending_import_{scope}"


def _cleanup_stale_imports() -> None:
    cutoff = time.time() - 3600
    for f in IMPORT_TMP_DIR.glob("*.json"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
        except FileNotFoundError:
            pass


def _totp_qr_svg(otpauth_uri: str) -> str:
    qr = qrcode.QRCode(image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    buf = io.BytesIO()
    qr.make_image().save(buf)
    return buf.getvalue().decode("utf-8")


async def _background_loop(func, interval_secs: int, name: str):
    logger.info(f"Background loop '{name}' started (interval={interval_secs}s)")
    while True:
        await asyncio.sleep(interval_secs)
        try:
            await func()
        except Exception as e:
            logger.error(f"Background loop '{name}' error: {e}")


# Holds the MCP session manager once the mount block initialises it.
# The lifespan function must call .run() on this before handling requests.
_mcp_session_manager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if not settings_get("mcp_token"):
        import secrets as _sec
        settings_set("mcp_token", _sec.token_urlsafe(32))

    # Start the MCP session-manager task group (required by the SDK).
    # _mcp_session_manager is set later in the module, but the closure reads
    # the current value at call-time, so it will already be populated.
    _sm_ctx = _mcp_session_manager.run() if _mcp_session_manager is not None else None
    if _sm_ctx is not None:
        await _sm_ctx.__aenter__()
        logger.info("MCP session manager started")

    poll_task = asyncio.create_task(
        _background_loop(poll_all_active, POLL_INTERVAL_SECS, "poll_searches")
    )
    check_task = asyncio.create_task(
        _background_loop(check_all_urls, URL_CHECK_INTERVAL_SECS, "check_urls")
    )
    logger.info(f"Scheduler started (poll={POLL_INTERVAL_SECS}s, url_check={URL_CHECK_INTERVAL_SECS}s)")
    try:
        yield
    finally:
        poll_task.cancel()
        check_task.cancel()
        try:
            await asyncio.gather(poll_task, check_task, return_exceptions=True)
        except Exception:
            pass
        if _sm_ctx is not None:
            try:
                await _sm_ctx.__aexit__(None, None, None)
            except Exception:
                pass


app = FastAPI(title="BewerbungsDB", lifespan=lifespan)

# ── Middleware (order matters: last added = outermost = runs first) ───────────

# Auth middleware — runs second (after session is populated)
_PUBLIC_PATHS    = {"/login", "/logout", "/login/2fa"}
_PUBLIC_PREFIXES = ("/api/", "/mcp", "/.well-known", "/oauth", "/auth/oidc", "/auth/passkey")

class _LoginMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in _PUBLIC_PATHS or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)
        if not request.session.get("authenticated"):
            return RedirectResponse(f"/login?next={path}", status_code=303)
        return await call_next(request)

app.add_middleware(_LoginMiddleware)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

# Session middleware — runs second
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="bwdb_session",
    max_age=7 * 24 * 3600,   # 7 days
    https_only=False,
    same_site="lax",
)

# Proxy headers middleware — runs second (reads X-Forwarded-* from trusted proxies).
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# Security headers middleware — outermost, runs first, sets headers on every response.
app.add_middleware(_SecurityHeadersMiddleware)

BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

templates.env.globals["STATUS_COLORS"] = STATUS_COLORS
templates.env.globals["ALL_STATUSES"] = ALL_STATUSES
templates.env.globals["SORT_OPTIONS"] = {
    "created_desc":  "Neueste zuerst",
    "created_asc":   "Älteste zuerst",
    "changed_desc":  "Zuletzt geändert",
    "title_asc":     "Titel A→Z",
    "title_desc":    "Titel Z→A",
    "company_asc":   "Firma A→Z",
    "status":        "Nach Status",
    "expires_asc":   "Eintrittsdatum",
}


def _tojson_pretty(value, indent=2):
    from markupsafe import Markup
    text = json.dumps(value, ensure_ascii=False, indent=indent)
    text = text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    return Markup(text)

templates.env.filters["tojson"] = _tojson_pretty

app.include_router(jobs_router)
app.include_router(searches_router)

# ── MCP HTTP transport ────────────────────────────────────────────────────────

class _MCPBearerAuth:
    """ASGI wrapper: accepts token via Authorization header OR ?token= query param."""
    def __init__(self, app):
        self._app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            auth_header = headers.get(b"authorization", b"").decode()

            from urllib.parse import parse_qs
            qs_params = parse_qs(scope.get("query_string", b"").decode())
            token_param = qs_params.get("token", [""])[0]

            token = settings_get("mcp_token") or ""
            auth_ok = (auth_header == f"Bearer {token}") or (token_param == token)

            if token and not auth_ok:
                body = b"Unauthorized"
                await send({"type": "http.response.start", "status": 401,
                            "headers": [[b"content-length", str(len(body)).encode()]]})
                await send({"type": "http.response.body", "body": body})
                return
        await self._app(scope, receive, send)


class _MCPPathRewrite:
    """Rewrites the empty/root path to /mcp so the sub-app's route matches."""
    def __init__(self, app):
        self._app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("path", "/") in ("", "/"):
            scope = {**scope, "path": "/mcp"}
        await self._app(scope, receive, send)


try:
    from app.mcp import mcp as _mcp_instance
    from starlette.routing import Route as _StarletteRoute

    _mcp_http_app = _mcp_instance.streamable_http_app()

    # Extract the session manager so the lifespan can call .run() on it
    # before any MCP requests are handled (required by the SDK).
    try:
        _mcp_session_manager = _mcp_http_app.routes[0].endpoint.session_manager
        logger.info("MCP session manager extracted successfully")
    except (AttributeError, IndexError) as _sm_err:
        logger.warning(f"Could not extract MCP session manager: {_sm_err}")

    _mcp_asgi = _MCPBearerAuth(_MCPPathRewrite(_mcp_http_app))

    # Mount handles /mcp/ and /mcp/* (with trailing slash / sub-paths)
    app.mount("/mcp", _mcp_asgi)

    # Route added at index 0 handles exactly /mcp (no trailing slash) without
    # the 307 redirect that Starlette's Mount emits for exact-path matches.
    # Class-instance endpoint is used as raw ASGI by Starlette (no wrapping).
    app.router.routes.insert(0, _StarletteRoute("/mcp", endpoint=_mcp_asgi))

    logger.info("MCP server mounted at /mcp (streamable-http transport)")
except Exception as _mcp_err:
    logger.warning(f"MCP server not available: {_mcp_err}")


# ── OAuth 2.0 server (required by Claude.ai remote MCP) ─────────────────────
# In-memory stores — cleared on restart; clients re-register automatically.
_oauth_clients: dict = {}   # client_id → {redirect_uris, client_name}
_oauth_codes: dict = {}     # code → {client_id, redirect_uri, code_challenge, expires_at}


@app.get("/.well-known/oauth-authorization-server")
def oauth_metadata(request: Request):
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["mcp"],
    })


@app.post("/oauth/register")
async def oauth_register(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    client_id = _secrets_mod.token_urlsafe(16)
    _oauth_clients[client_id] = {
        "redirect_uris": body.get("redirect_uris", []),
        "client_name": body.get("client_name", ""),
    }
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }, status_code=201)


def _issue_code_redirect(redirect_uri: str, client_id: str, state: str,
                          code_challenge: str, code_challenge_method: str):
    code = _secrets_mod.token_urlsafe(32)
    _oauth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": time.time() + 300,
    }
    sep = "&" if "?" in redirect_uri else "?"
    dest = f"{redirect_uri}{sep}code={code}"
    if state:
        dest += f"&state={state}"
    return RedirectResponse(dest, status_code=303)


@app.get("/oauth/authorize")
def oauth_authorize(
    request: Request,
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    response_type: str = Query("code"),
    state: str = Query(""),
    code_challenge: str = Query(""),
    code_challenge_method: str = Query("S256"),
    scope: str = Query(""),
):
    if not request.session.get("authenticated"):
        request.session["oauth_pending"] = {
            "client_id": client_id, "redirect_uri": redirect_uri,
            "state": state, "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        return RedirectResponse("/login?next=/oauth/complete", status_code=303)
    return _issue_code_redirect(redirect_uri, client_id, state,
                                code_challenge, code_challenge_method)


@app.get("/oauth/complete")
def oauth_complete(request: Request):
    """Finishes the OAuth flow after the user has logged in."""
    if not request.session.get("authenticated"):
        return RedirectResponse("/login?next=/oauth/complete", status_code=303)
    pending = request.session.pop("oauth_pending", None)
    if not pending:
        return RedirectResponse("/", status_code=303)
    return _issue_code_redirect(
        pending["redirect_uri"], pending["client_id"],
        pending.get("state", ""), pending.get("code_challenge", ""),
        pending.get("code_challenge_method", "S256"),
    )


@app.post("/oauth/token")
async def oauth_token(request: Request):
    content_type = request.headers.get("content-type", "")
    if "json" in content_type:
        body = await request.json()
        grant_type = body.get("grant_type")
        code = body.get("code", "")
        code_verifier = body.get("code_verifier", "")
    else:
        form = await request.form()
        grant_type = form.get("grant_type")
        code = form.get("code", "")
        code_verifier = form.get("code_verifier", "")

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code_data = _oauth_codes.pop(code, None)
    if not code_data or time.time() > code_data["expires_at"]:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    # Verify PKCE S256
    challenge = code_data.get("code_challenge", "")
    if challenge and code_verifier:
        digest = hashlib.sha256(code_verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if computed != challenge:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

    access_token = settings_get("mcp_token") or ""
    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 31_536_000,
        "scope": "mcp",
    })


# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/"):
    if request.session.get("authenticated"):
        return RedirectResponse("/", status_code=303)
    providers = [p for p in list_oidc_providers() if p["enabled"]]
    return templates.TemplateResponse("login.html", {
        "request": request,
        "next": next,
        "error": None,
        "oidc_providers": providers,
        "has_passkeys": bool(list_webauthn_credential_ids()),
        "csrf_token": generate_csrf_token(request.session),
    })


@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    password: str = Form(...),
    next: str = Form("/"),
    csrf: str = Form(""),
):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")

    if is_rate_limited(request):
        providers = [p for p in list_oidc_providers() if p["enabled"]]
        return templates.TemplateResponse("login.html", {
            "request": request, "next": next,
            "error": "Zu viele Fehlversuche. Bitte 5 Minuten warten.",
            "oidc_providers": providers,
            "has_passkeys": bool(list_webauthn_credential_ids()),
            "csrf_token": generate_csrf_token(request.session),
        }, status_code=429)

    stored = get_password_hash()
    if stored and verify_password(password, stored):
        clear_failed(request)
        next_url = next if next.startswith("/") else "/"
        if get_totp_enabled():
            request.session["totp_pending"] = True
            request.session["login_next"] = next_url
            return RedirectResponse("/login/2fa", status_code=303)
        request.session["authenticated"] = True
        if request.session.get("oauth_pending"):
            return RedirectResponse("/oauth/complete", status_code=303)
        return RedirectResponse(next_url, status_code=303)

    record_failed(request)
    providers = [p for p in list_oidc_providers() if p["enabled"]]
    return templates.TemplateResponse("login.html", {
        "request": request, "next": next,
        "error": "Falsches Passwort.",
        "oidc_providers": providers,
        "has_passkeys": bool(list_webauthn_credential_ids()),
        "csrf_token": generate_csrf_token(request.session),
    }, status_code=401)


@app.get("/login/2fa", response_class=HTMLResponse)
def login_2fa_page(request: Request):
    if request.session.get("authenticated"):
        return RedirectResponse("/", status_code=303)
    if not request.session.get("totp_pending"):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("login_2fa.html", {
        "request": request,
        "error": None,
        "csrf_token": generate_csrf_token(request.session),
    })


@app.post("/login/2fa", response_class=HTMLResponse)
def login_2fa_submit(request: Request, code: str = Form(...), csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    if not request.session.get("totp_pending"):
        return RedirectResponse("/login", status_code=303)

    if is_rate_limited(request):
        return templates.TemplateResponse("login_2fa.html", {
            "request": request,
            "error": "Zu viele Fehlversuche. Bitte 5 Minuten warten.",
            "csrf_token": generate_csrf_token(request.session),
        }, status_code=429)

    if verify_totp_code(code) or verify_backup_code(code):
        clear_failed(request)
        request.session.pop("totp_pending", None)
        next_url = request.session.pop("login_next", "/")
        request.session["authenticated"] = True
        if request.session.get("oauth_pending"):
            return RedirectResponse("/oauth/complete", status_code=303)
        return RedirectResponse(next_url, status_code=303)

    record_failed(request)
    return templates.TemplateResponse("login_2fa.html", {
        "request": request,
        "error": "Ungültiger Code.",
        "csrf_token": generate_csrf_token(request.session),
    }, status_code=401)


@app.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ─── Passkey login (public — trusted-device shortcut, skips password + 2FA) ───

@app.get("/auth/passkey/login-options")
def passkey_login_options(request: Request):
    cred_ids = list_webauthn_credential_ids()
    if not cred_ids:
        raise HTTPException(404, "No passkeys registered")
    options = webauthn.generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=webauthn.base64url_to_bytes(cid))
            for cid in cred_ids
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    request.session["webauthn_auth_challenge"] = webauthn.helpers.bytes_to_base64url(options.challenge)
    return JSONResponse(content=json.loads(webauthn.options_to_json(options)))


@app.post("/auth/passkey/login-verify")
async def passkey_login_verify(request: Request):
    if is_rate_limited(request):
        raise HTTPException(429, "Zu viele Fehlversuche. Bitte 5 Minuten warten.")

    body = await request.json()
    credential = body.get("credential")
    next_url = body.get("next") or "/"
    if not isinstance(next_url, str) or not next_url.startswith("/"):
        next_url = "/"

    challenge_str = request.session.pop("webauthn_auth_challenge", None)
    if not challenge_str or not credential:
        record_failed(request)
        raise HTTPException(400, "No pending passkey challenge")

    cred_id = credential.get("id") if isinstance(credential, dict) else None
    stored = get_webauthn_credential_by_cred_id(cred_id) if cred_id else None
    if not stored:
        record_failed(request)
        raise HTTPException(401, "Unknown passkey")

    try:
        result = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=webauthn.base64url_to_bytes(challenge_str),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            credential_public_key=base64.b64decode(stored["public_key"]),
            credential_current_sign_count=stored["sign_count"],
        )
    except Exception as e:
        logger.warning(f"Passkey login verify failed: {e}")
        record_failed(request)
        raise HTTPException(401, "Passkey verification failed")

    update_webauthn_credential_usage(cred_id, result.new_sign_count)
    clear_failed(request)
    request.session["authenticated"] = True
    if request.session.get("oauth_pending"):
        return JSONResponse({"redirect": "/oauth/complete"})
    return JSONResponse({"redirect": next_url})


# ─── OIDC SSO routes ──────────────────────────────────────────────────────────

@app.get("/auth/oidc/{provider_name}/login")
async def oidc_login(request: Request, provider_name: str):
    provider = get_oidc_provider_by_name(provider_name)
    if not provider:
        raise HTTPException(404, "OIDC provider not found or disabled")
    state = secrets.token_urlsafe(16)
    redirect_uri = f"{APP_BASE_URL}/auth/oidc/callback"
    try:
        auth_url, verifier = await build_auth_url(provider, state, redirect_uri)
    except Exception as e:
        logger.error(f"OIDC build_auth_url error for {provider_name}: {e}")
        return RedirectResponse("/login?error=oidc_config", status_code=303)
    request.session["oidc_state"]    = state
    request.session["oidc_verifier"] = verifier
    request.session["oidc_provider"] = provider["id"]
    request.session["oidc_next"]     = request.query_params.get("next", "/")
    return RedirectResponse(auth_url, status_code=303)


@app.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
):
    if error:
        logger.warning(f"OIDC provider returned error: {error}")
        return RedirectResponse(f"/login?error=oidc_{error}", status_code=303)

    session_state = request.session.pop("oidc_state", None)
    if not session_state or not secrets.compare_digest(session_state, state):
        return RedirectResponse("/login?error=invalid_state", status_code=303)

    verifier    = request.session.pop("oidc_verifier", None)
    provider_id = request.session.pop("oidc_provider", None)
    next_url    = request.session.pop("oidc_next", "/")

    provider = get_oidc_provider(provider_id) if provider_id else None
    if not provider:
        return RedirectResponse("/login?error=provider_not_found", status_code=303)

    try:
        redirect_uri = f"{APP_BASE_URL}/auth/oidc/callback"
        tokens = await exchange_code(provider, code, verifier, redirect_uri)
        access_token = tokens.get("access_token", "")
        user_info = await get_user_info(provider, access_token) if access_token else {}
        display = user_info.get("name") or user_info.get("email") or user_info.get("sub", "unknown")
        logger.info(f"OIDC login: {display} via {provider['name']}")
    except Exception as e:
        logger.error(f"OIDC callback error: {e}")
        return RedirectResponse("/login?error=oidc_failed", status_code=303)

    request.session["authenticated"] = True
    if request.session.get("oauth_pending"):
        return RedirectResponse("/oauth/complete", status_code=303)
    return RedirectResponse(next_url if next_url.startswith("/") else "/", status_code=303)


# ─── Settings ─────────────────────────────────────────────────────────────────

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    _cleanup_stale_imports()
    ck = settings_get("claude_api_key") or ""
    mcp_token = settings_get("mcp_token") or ""
    new_key = request.session.pop("flash_new_key", None)

    totp_enabled = get_totp_enabled()
    totp_setup = None
    setup_secret = request.session.get("totp_setup_secret")
    if setup_secret and not totp_enabled:
        uri = pyotp.TOTP(setup_secret).provisioning_uri(name="admin", issuer_name="BewerbungsDB")
        totp_setup = {
            "secret": setup_secret,
            "otpauth_uri": uri,
            "qr_svg": _totp_qr_svg(uri),
        }

    return templates.TemplateResponse("settings.html", {
        "request": request,
        "claude_api_key": ck[:8] + "••••••••" if len(ck) > 8 else ck,
        "claude_api_key_full": ck,
        "user_gender": settings_get("user_gender") or "männlich",
        "mcp_token": mcp_token,
        "saved": request.query_params.get("saved"),
        "error": request.query_params.get("error"),
        "app_base_url": APP_BASE_URL,
        "api_keys": list_api_keys(),
        "new_api_key": new_key,
        "oidc_providers": list_oidc_providers(),
        "oidc_presets": PROVIDER_PRESETS,
        "needs_password_change": settings_get("needs_password_change") == "true",
        "totp_enabled": totp_enabled,
        "totp_setup": totp_setup,
        "backup_codes_remaining": count_unused_backup_codes() if totp_enabled else 0,
        "flash_backup_codes": request.session.pop("flash_backup_codes", None),
        "webauthn_credentials": list_webauthn_credentials(),
        "csrf_token": generate_csrf_token(request.session),
    })


@app.post("/settings/password", response_class=HTMLResponse)
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password2: str = Form(...),
    csrf: str = Form(""),
):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    stored = get_password_hash()
    if not stored or not verify_password(current_password, stored):
        return RedirectResponse("/settings?error=wrong_password", status_code=303)
    if new_password != new_password2:
        return RedirectResponse("/settings?error=mismatch", status_code=303)
    if len(new_password) < 6:
        return RedirectResponse("/settings?error=too_short", status_code=303)
    set_password(new_password)
    settings_set("needs_password_change", "false")
    return RedirectResponse("/settings?saved=password", status_code=303)


@app.post("/settings/2fa/start-setup", response_class=HTMLResponse)
def totp_start_setup(request: Request, csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    if get_totp_enabled():
        return RedirectResponse("/settings#security", status_code=303)
    request.session["totp_setup_secret"] = pyotp.random_base32()
    return RedirectResponse("/settings#security", status_code=303)


@app.post("/settings/2fa/cancel-setup", response_class=HTMLResponse)
def totp_cancel_setup(request: Request, csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    request.session.pop("totp_setup_secret", None)
    return RedirectResponse("/settings#security", status_code=303)


@app.post("/settings/2fa/confirm-setup", response_class=HTMLResponse)
def totp_confirm_setup(request: Request, code: str = Form(""), csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    setup_secret = request.session.get("totp_setup_secret")
    if not setup_secret:
        return RedirectResponse("/settings#security", status_code=303)
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and pyotp.TOTP(setup_secret).verify(code, valid_window=1)):
        return RedirectResponse("/settings?error=2fa_code#security", status_code=303)
    enable_totp(setup_secret)
    request.session.pop("totp_setup_secret", None)
    request.session["flash_backup_codes"] = generate_backup_codes()
    return RedirectResponse("/settings?saved=2fa#security", status_code=303)


@app.post("/settings/2fa/disable", response_class=HTMLResponse)
def totp_disable(request: Request, current_password: str = Form(...), csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    stored = get_password_hash()
    if not stored or not verify_password(current_password, stored):
        return RedirectResponse("/settings?error=wrong_password#security", status_code=303)
    disable_totp()
    return RedirectResponse("/settings?saved=2fa_disabled#security", status_code=303)


@app.post("/settings/2fa/regenerate-backup-codes", response_class=HTMLResponse)
def totp_regen_backup_codes(request: Request, current_password: str = Form(...), csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    stored = get_password_hash()
    if not stored or not verify_password(current_password, stored):
        return RedirectResponse("/settings?error=wrong_password#security", status_code=303)
    if not get_totp_enabled():
        return RedirectResponse("/settings#security", status_code=303)
    request.session["flash_backup_codes"] = generate_backup_codes()
    return RedirectResponse("/settings?saved=2fa_codes#security", status_code=303)


# ─── Passkey (trusted device) management ──────────────────────────────────────

@app.get("/settings/passkeys/register-options")
def passkey_register_options(request: Request):
    existing = list_webauthn_credential_ids()
    options = webauthn.generate_registration_options(
        rp_id=WEBAUTHN_RP_ID,
        rp_name=WEBAUTHN_RP_NAME,
        user_id=get_webauthn_user_id(),
        user_name="admin",
        user_display_name="BewerbungsDB Admin",
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=webauthn.base64url_to_bytes(cid))
            for cid in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    request.session["webauthn_reg_challenge"] = webauthn.helpers.bytes_to_base64url(options.challenge)
    return JSONResponse(content=json.loads(webauthn.options_to_json(options)))


@app.post("/settings/passkeys/register-verify")
async def passkey_register_verify(request: Request):
    body = await request.json()
    if not validate_csrf_token(request.session, body.get("csrf", "")):
        raise HTTPException(403, "Invalid CSRF token")

    credential = body.get("credential")
    name = (body.get("name") or "").strip()[:100] or "Unbenanntes Gerät"
    challenge_str = request.session.pop("webauthn_reg_challenge", None)
    if not challenge_str or not credential:
        raise HTTPException(400, "No pending registration challenge")

    try:
        result = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=webauthn.base64url_to_bytes(challenge_str),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
        )
    except Exception as e:
        logger.warning(f"Passkey registration verify failed: {e}")
        raise HTTPException(400, "Registrierung fehlgeschlagen")

    create_webauthn_credential(
        name=name,
        credential_id_b64=webauthn.helpers.bytes_to_base64url(result.credential_id),
        public_key_b64=base64.b64encode(result.credential_public_key).decode(),
        sign_count=result.sign_count,
    )
    return JSONResponse({"ok": True})


@app.post("/settings/passkeys/{cred_id}/delete", response_class=HTMLResponse)
def passkey_delete(request: Request, cred_id: int, csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    delete_webauthn_credential(cred_id)
    return RedirectResponse("/settings?saved=passkey#security", status_code=303)


# ─── Export ─────────────────────────────────────────────────────────────────

def _export_response(scope: str, data: dict) -> Response:
    payload = {
        "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": scope,
        "data": data,
    }
    fname = f"bewerbungsdb-{scope}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
    return Response(
        content=json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.post("/settings/export/db")
def export_db(request: Request, csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    return _export_response("db", export_jobs_data())


@app.post("/settings/export/settings")
def export_settings(
    request: Request,
    include_credentials: str = Form(""),
    current_password: str = Form(""),
    csrf: str = Form(""),
):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    want_credentials = include_credentials == "on"
    if want_credentials:
        stored = get_password_hash()
        if not stored or not verify_password(current_password, stored):
            return RedirectResponse("/settings?error=wrong_password#danger-zone", status_code=303)
    return _export_response("settings", export_settings_data(include_credentials=want_credentials))


# ─── Import upload (stages a file, then requires the danger-zone ceremony) ───

@app.post("/settings/import/{scope}/upload", response_class=HTMLResponse)
async def import_upload(
    request: Request, scope: str, file: UploadFile = File(...), csrf: str = Form("")
):
    if scope not in ("db", "settings"):
        raise HTTPException(404)
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")

    raw = await file.read()
    if len(raw) > MAX_IMPORT_SIZE:
        return RedirectResponse("/settings?error=import_too_large#danger-zone", status_code=303)
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict) or parsed.get("scope") != scope:
            raise ValueError("scope mismatch")
        data = parsed["data"]
        if not isinstance(data, dict):
            raise ValueError("bad data")
    except Exception:
        return RedirectResponse("/settings?error=import_invalid#danger-zone", status_code=303)

    old_token = request.session.get(_pending_import_key(scope))
    if old_token:
        (IMPORT_TMP_DIR / f"{old_token}.json").unlink(missing_ok=True)
    token = secrets.token_hex(16)
    (IMPORT_TMP_DIR / f"{token}.json").write_text(json.dumps(data))
    request.session[_pending_import_key(scope)] = token

    return RedirectResponse(f"/settings/danger/import-{scope}/confirm", status_code=303)


# ─── Danger zone: reset / import confirmation (password + TOTP + typed phrase) ─

@app.get("/settings/danger/{action}/confirm", response_class=HTMLResponse)
def danger_confirm_page(request: Request, action: str):
    meta = DANGER_ACTIONS.get(action)
    if not meta:
        raise HTTPException(404)

    import_summary = None
    if meta["kind"] == "import":
        token = request.session.get(_pending_import_key(meta["scope"]))
        path = IMPORT_TMP_DIR / f"{token}.json" if token else None
        if not token or not path.exists():
            request.session.pop(_pending_import_key(meta["scope"]), None)
            return RedirectResponse("/settings?error=import_expired#danger-zone", status_code=303)
        try:
            data = json.loads(path.read_text())
        except Exception:
            request.session.pop(_pending_import_key(meta["scope"]), None)
            path.unlink(missing_ok=True)
            return RedirectResponse("/settings?error=import_invalid#danger-zone", status_code=303)
        import_summary = (
            describe_jobs_import(data) if meta["scope"] == "db" else describe_settings_import(data)
        )

    totp_enabled = get_totp_enabled()
    challenge = None
    if totp_enabled:
        challenge = "".join(secrets.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(10))
        request.session[_danger_challenge_key(action)] = challenge

    return templates.TemplateResponse("danger_confirm.html", {
        "request": request,
        "action": action,
        "meta": meta,
        "totp_enabled": totp_enabled,
        "challenge": challenge,
        "import_summary": import_summary,
        "error": request.query_params.get("error"),
        "csrf_token": generate_csrf_token(request.session),
    })


@app.post("/settings/danger/{action}/confirm", response_class=HTMLResponse)
def danger_confirm_submit(
    request: Request,
    action: str,
    current_password: str = Form(...),
    totp_code: str = Form(""),
    phrase: str = Form(...),
    csrf: str = Form(""),
):
    meta = DANGER_ACTIONS.get(action)
    if not meta:
        raise HTTPException(404)
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    if not get_totp_enabled():
        return RedirectResponse("/settings#security", status_code=303)

    def fail(reason: str):
        request.session.pop(_danger_challenge_key(action), None)
        return RedirectResponse(f"/settings/danger/{action}/confirm?error={reason}", status_code=303)

    if is_rate_limited(request):
        return fail("rate_limited")

    stored = get_password_hash()
    if not stored or not verify_password(current_password, stored):
        record_failed(request)
        return fail("wrong_password")

    if not verify_totp_code(totp_code):
        record_failed(request)
        return fail("wrong_code")

    expected = request.session.get(_danger_challenge_key(action))
    if not expected or not secrets.compare_digest((phrase or "").strip(), expected):
        record_failed(request)
        return fail("wrong_phrase")

    clear_failed(request)
    request.session.pop(_danger_challenge_key(action), None)

    if meta["kind"] == "reset":
        if meta["scope"] == "db":
            reset_jobs_data()
        else:
            reset_settings_data()
        return RedirectResponse(f"/settings?saved=reset_{meta['scope']}#danger-zone", status_code=303)

    # import
    scope = meta["scope"]
    token = request.session.pop(_pending_import_key(scope), None)
    if not token:
        return RedirectResponse("/settings#danger-zone", status_code=303)
    path = IMPORT_TMP_DIR / f"{token}.json"
    try:
        data = json.loads(path.read_text())
        if scope == "db":
            import_jobs_data(data)
        else:
            import_settings_data(data)
    finally:
        path.unlink(missing_ok=True)

    return RedirectResponse(f"/settings?saved=import_{scope}#danger-zone", status_code=303)


@app.post("/settings/regenerate-mcp-token", response_class=HTMLResponse)
def renew_mcp_token(request: Request, csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    settings_set("mcp_token", secrets.token_urlsafe(32))
    return RedirectResponse("/settings?saved=mcp", status_code=303)


@app.post("/settings/claude", response_class=HTMLResponse)
def save_claude_settings(
    request: Request,
    claude_api_key: str = Form(""),
    user_gender: str = Form("männlich"),
    csrf: str = Form(""),
):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    if claude_api_key.strip():
        settings_set("claude_api_key", claude_api_key.strip())
    settings_set("user_gender", user_gender)
    return RedirectResponse("/settings?saved=claude", status_code=303)


# ─── API key management ───────────────────────────────────────────────────────

@app.post("/settings/api-keys/create", response_class=HTMLResponse)
def api_key_create(
    request: Request,
    name: str = Form("API Key"),
    expires_at: str = Form(""),
    csrf: str = Form(""),
):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    raw = create_api_key(name.strip() or "API Key", expires_at.strip() or None)
    request.session["flash_new_key"] = raw
    return RedirectResponse("/settings?saved=apikey#api-keys", status_code=303)


@app.post("/settings/api-keys/{key_id}/revoke", response_class=HTMLResponse)
def api_key_revoke(request: Request, key_id: int, csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    revoke_api_key(key_id)
    return RedirectResponse("/settings?saved=apikey#api-keys", status_code=303)


@app.post("/settings/api-keys/{key_id}/delete", response_class=HTMLResponse)
def api_key_delete(request: Request, key_id: int, csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    delete_api_key(key_id)
    return RedirectResponse("/settings?saved=apikey#api-keys", status_code=303)


# ─── OIDC provider management ─────────────────────────────────────────────────

@app.post("/settings/oidc/create", response_class=HTMLResponse)
def oidc_provider_create(
    request: Request,
    name: str = Form(...),
    provider_type: str = Form("generic"),
    discovery_url: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scopes: str = Form("openid profile email"),
    csrf: str = Form(""),
):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    try:
        create_oidc_provider(
            name.strip(), provider_type, discovery_url.strip(),
            client_id.strip(), client_secret.strip(), scopes.strip(),
        )
    except Exception as e:
        logger.error(f"OIDC provider create error: {e}")
        return RedirectResponse("/settings?error=oidc_exists#oidc", status_code=303)
    return RedirectResponse("/settings?saved=oidc#oidc", status_code=303)


@app.post("/settings/oidc/{provider_id}/toggle", response_class=HTMLResponse)
def oidc_provider_toggle(request: Request, provider_id: int, csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    from app.database import get_db
    with get_db() as conn:
        row = conn.execute("SELECT enabled FROM oidc_providers WHERE id = ?", (provider_id,)).fetchone()
    if row:
        update_oidc_provider(provider_id, enabled=0 if row["enabled"] else 1)
    return RedirectResponse("/settings?saved=oidc#oidc", status_code=303)


@app.post("/settings/oidc/{provider_id}/delete", response_class=HTMLResponse)
def oidc_provider_delete(request: Request, provider_id: int, csrf: str = Form("")):
    if not validate_csrf_token(request.session, csrf):
        raise HTTPException(403, "Invalid CSRF token")
    delete_oidc_provider(provider_id)
    return RedirectResponse("/settings?saved=oidc#oidc", status_code=303)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── Helper ───────────────────────────────────────────────────────────────────

def _build_job_list(conn, status=None, tag=None, search=None, sort="created_desc"):
    order = SORT_MAP.get(sort, "j.created_at DESC")
    query = """SELECT j.*, (SELECT GROUP_CONCAT(tag ORDER BY tag) FROM job_tags WHERE job_id = j.id) as _tags
               FROM jobs j WHERE 1=1"""
    params: list = []
    if status:
        statuses = status.split(",")
        placeholders = ",".join("?" * len(statuses))
        query += f" AND j.status IN ({placeholders})"
        params.extend(statuses)
    if search:
        s = f"%{search}%"
        query += " AND (j.title LIKE ? OR j.company LIKE ? OR j.location LIKE ? OR CAST(j.id AS TEXT) LIKE ?)"
        params.extend([s, s, s, s])
    if tag:
        query += " AND j.id IN (SELECT job_id FROM job_tags WHERE tag = ?)"
        params.append(tag)
    query += f" ORDER BY {order}"
    rows = conn.execute(query, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["tags"] = d.pop("_tags", "").split(",") if d.get("_tags") else []
        result.append(d)
    return result


# ─── Web UI ───────────────────────────────────────────────────────────────────

def _base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


@app.get("/log", response_class=HTMLResponse)
def activity_log(
    request: Request,
    event: Optional[str] = None,
    limit: int = 300,
):
    with get_db() as conn:
        if event == "added":
            where = "AND h.field = '_added'"
        elif event == "status":
            where = "AND h.field = 'status'"
        else:
            where = "AND h.field IN ('_added', 'status')"

        rows = conn.execute(
            f"""SELECT h.id, h.job_id, h.field, h.old_value, h.new_value, h.changed_at,
                       j.title, j.company, j.status AS current_status
                FROM job_history h
                LEFT JOIN jobs j ON j.id = h.job_id
                {where}
                ORDER BY h.changed_at DESC
                LIMIT ?""",
            (limit,),
        ).fetchall()

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return templates.TemplateResponse("log.html", {
        "request": request,
        "entries": [dict(r) for r in rows],
        "current_event": event,
        "limit": limit,
        "today": today,
    })


@app.get("/api-docs", response_class=HTMLResponse)
def api_docs(request: Request):
    return templates.TemplateResponse("api_docs.html", {
        "request": request,
        "base_url": _base_url(request),
    })


@app.post("/jobs/{job_id}/check-url", response_class=HTMLResponse)
async def check_url_form(request: Request, job_id: int):
    from app.services.scraper import fetch_url, extract_text
    from app.services.alerts import fire_status_change
    now = utcnow()
    with get_db() as conn:
        row = conn.execute(
            "SELECT title, company, url, check_url, check_keyword, status FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Job not found")
    target = row["check_url"] or row["url"]
    old_status = row["status"]
    closed = False
    if target:
        status_code, html = await fetch_url(target)
        with get_db() as conn:
            conn.execute("UPDATE jobs SET last_checked_at = ?, updated_at = ? WHERE id = ?", (now, now, job_id))
            if status_code in (404, 410):
                record_history(conn, job_id, "status", old_status, "closed", now)
                conn.execute(
                    "UPDATE jobs SET status='closed', last_changed_at=?, updated_at=? WHERE id=?",
                    (now, now, job_id),
                )
                closed = True
            elif status_code == 200 and html and row["check_keyword"]:
                if row["check_keyword"].lower() not in extract_text(html).lower():
                    record_history(conn, job_id, "check_keyword", "found", "not found", now)
                    record_history(conn, job_id, "status", old_status, "closed", now)
                    conn.execute(
                        "UPDATE jobs SET status='closed', last_changed_at=?, updated_at=? WHERE id=?",
                        (now, now, job_id),
                    )
                    closed = True
    if closed:
        await fire_status_change({"id": job_id, "title": row["title"], "company": row["company"]}, old_status, "closed")
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    with get_db() as conn:
        status_rows = conn.execute("SELECT status, COUNT(*) as count FROM jobs GROUP BY status").fetchall()
        recent = conn.execute(
            """SELECT j.id, j.title, j.company, j.status, j.created_at,
                      (SELECT GROUP_CONCAT(tag) FROM job_tags WHERE job_id = j.id) as tags
               FROM jobs j ORDER BY j.created_at DESC LIMIT 10"""
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) as c FROM jobs").fetchone()["c"]
        search_count = conn.execute("SELECT COUNT(*) as c FROM search_configs WHERE active = 1").fetchone()["c"]

    by_status = {r["status"]: r["count"] for r in status_rows}
    recent_list = []
    for r in recent:
        d = dict(r)
        d["tags"] = d["tags"].split(",") if d["tags"] else []
        recent_list.append(d)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "by_status": by_status,
        "recent": recent_list,
        "total": total,
        "active_searches": search_count,
    })


@app.get("/jobs", response_class=HTMLResponse)
def jobs_list(
    request: Request,
    status: Optional[str] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    sort: str = "created_desc",
):
    with get_db() as conn:
        jobs = _build_job_list(conn, status=status, tag=tag, search=search, sort=sort)
        all_tags = [r["tag"] for r in conn.execute(
            "SELECT DISTINCT tag FROM job_tags ORDER BY tag"
        ).fetchall()]

    return templates.TemplateResponse("jobs/list.html", {
        "request": request,
        "jobs": jobs,
        "all_tags": all_tags,
        "current_status": status,
        "current_tag": tag,
        "current_search": search or "",
        "current_sort": sort,
    })


@app.get("/jobs/new", response_class=HTMLResponse)
def new_job_form(request: Request):
    return templates.TemplateResponse("jobs/new.html", {"request": request})


@app.post("/jobs/new", response_class=HTMLResponse)
async def create_job_form(
    request: Request,
    background_tasks: BackgroundTasks,
    title: str = Form(...),
    company: str = Form(""),
    location: str = Form(""),
    description: str = Form(""),
    requirements: str = Form(""),
    salary: str = Form(""),
    job_type: str = Form(""),
    url: str = Form(""),
    check_url: str = Form(""),
    check_keyword: str = Form(""),
    html_content: str = Form(""),
    notes: str = Form(""),
    tags: str = Form(""),
    status: str = Form("new"),
    expires_at: str = Form(""),
    contact_first_name: str = Form(""),
    contact_last_name: str = Form(""),
    contact_salutation: str = Form(""),
    contact_title: str = Form(""),
    contact_email: str = Form(""),
    contact_street: str = Form(""),
    contact_street_nr: str = Form(""),
    contact_plz: str = Form(""),
    contact_city: str = Form(""),
    job_name_personalized: str = Form(""),
    company_floskel: str = Form(""),
    application_date: str = Form(""),
    bewerbungstext: str = Form(""),
):
    now = utcnow()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO jobs (
                title, company, location, description, requirements,
                salary, job_type, url, check_url, check_keyword,
                html_content, status, notes, expires_at,
                contact_first_name, contact_last_name, contact_salutation, contact_title,
                contact_email, contact_street, contact_street_nr, contact_plz, contact_city,
                job_name_personalized, company_floskel, application_date, bewerbungstext,
                source, first_seen_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      'manual', ?, ?, ?)""",
            (
                title, company or None, location or None, description or None,
                requirements or None, salary or None, job_type or None,
                url or None, check_url or None, check_keyword or None,
                html_content or None, status, notes or None, expires_at or None,
                contact_first_name or None, contact_last_name or None,
                contact_salutation or None, contact_title or None,
                contact_email or None, contact_street or None, contact_street_nr or None,
                contact_plz or None, contact_city or None,
                job_name_personalized or None, company_floskel or None,
                application_date or None, bewerbungstext or None,
                now, now, now,
            ),
        )
        job_id = cursor.lastrowid
        for tag in tag_list:
            conn.execute("INSERT OR IGNORE INTO job_tags (job_id, tag) VALUES (?, ?)", (job_id, tag))
        conn.execute(
            "INSERT INTO job_history (job_id, field, old_value, new_value, changed_at) "
            "VALUES (?, '_added', NULL, 'manuell', ?)",
            (job_id, now),
        )

    target = check_url or url
    if target:
        from app.services.poller import check_and_maybe_close
        background_tasks.add_task(check_and_maybe_close, job_id, target, check_keyword or None, status)

    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail(request: Request, job_id: int):
    with get_db() as conn:
        job = get_job_with_tags(conn, job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        history = conn.execute(
            "SELECT * FROM job_history WHERE job_id = ? ORDER BY changed_at DESC",
            (job_id,),
        ).fetchall()
        raw = job.get("raw_api_data")
        api_data = json.loads(raw) if raw else None

    return templates.TemplateResponse("jobs/detail.html", {
        "request": request,
        "job": job,
        "history": [dict(h) for h in history],
        "api_data": api_data,
    })


@app.post("/jobs/{job_id}/edit", response_class=HTMLResponse)
async def edit_job_form(
    request: Request,
    background_tasks: BackgroundTasks,
    job_id: int,
    title: str = Form(...),
    company: str = Form(""),
    location: str = Form(""),
    description: str = Form(""),
    requirements: str = Form(""),
    salary: str = Form(""),
    job_type: str = Form(""),
    url: str = Form(""),
    check_url: str = Form(""),
    check_keyword: str = Form(""),
    html_content: str = Form(""),
    notes: str = Form(""),
    tags: str = Form(""),
    status: str = Form("new"),
    expires_at: str = Form(""),
    external_id: str = Form(""),
    contact_first_name: str = Form(""),
    contact_last_name: str = Form(""),
    contact_salutation: str = Form(""),
    contact_title: str = Form(""),
    contact_email: str = Form(""),
    contact_street: str = Form(""),
    contact_street_nr: str = Form(""),
    contact_plz: str = Form(""),
    contact_city: str = Form(""),
    job_name_personalized: str = Form(""),
    company_floskel: str = Form(""),
    application_date: str = Form(""),
    bewerbungstext: str = Form(""),
):
    now = utcnow()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        old = dict(row)

        fields = {
            "title": title,
            "company": company or None,
            "location": location or None,
            "description": description or None,
            "requirements": requirements or None,
            "salary": salary or None,
            "job_type": job_type or None,
            "url": url or None,
            "check_url": check_url or None,
            "check_keyword": check_keyword or None,
            "html_content": html_content or None,
            "notes": notes or None,
            "status": status,
            "expires_at": expires_at or None,
            "external_id": external_id or None,
            "contact_first_name": contact_first_name or None,
            "contact_last_name": contact_last_name or None,
            "contact_salutation": contact_salutation or None,
            "contact_title": contact_title or None,
            "contact_email": contact_email or None,
            "contact_street": contact_street or None,
            "contact_street_nr": contact_street_nr or None,
            "contact_plz": contact_plz or None,
            "contact_city": contact_city or None,
            "job_name_personalized": job_name_personalized or None,
            "company_floskel": company_floskel or None,
            "application_date": application_date or None,
            "bewerbungstext": bewerbungstext or None,
        }

        changed = False
        for field, new_val in fields.items():
            if record_history(conn, job_id, field, old.get(field), new_val, now):
                changed = True

        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [now, job_id]
        conn.execute(f"UPDATE jobs SET {set_clause}, updated_at = ? WHERE id = ?", values)
        if changed:
            conn.execute("UPDATE jobs SET last_changed_at = ? WHERE id = ?", (now, job_id))

        # Tags
        old_tags = [r["tag"] for r in conn.execute(
            "SELECT tag FROM job_tags WHERE job_id = ?", (job_id,)
        ).fetchall()]
        new_tags = [t.strip() for t in tags.split(",") if t.strip()]
        if set(old_tags) != set(new_tags):
            record_history(conn, job_id, "tags", ", ".join(sorted(old_tags)), ", ".join(sorted(new_tags)), now)
            conn.execute("DELETE FROM job_tags WHERE job_id = ?", (job_id,))
            for tag in new_tags:
                conn.execute("INSERT OR IGNORE INTO job_tags (job_id, tag) VALUES (?, ?)", (job_id, tag))

    # Fire alert if status changed
    if old.get("status") != status:
        from app.services.alerts import fire_status_change
        background_tasks.add_task(fire_status_change, {"id": job_id, "title": title, "company": company}, old["status"], status)

    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.post("/jobs/{job_id}/status", response_class=HTMLResponse)
async def update_status(request: Request, background_tasks: BackgroundTasks, job_id: int, status: str = Form(...)):
    now = utcnow()
    old_status = None
    with get_db() as conn:
        row = conn.execute("SELECT status, title, company FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row:
            old_status = row["status"]
            record_history(conn, job_id, "status", old_status, status, now)
            conn.execute(
                "UPDATE jobs SET status = ?, last_changed_at = ?, updated_at = ? WHERE id = ?",
                (status, now, now, job_id),
            )
    if old_status and old_status != status:
        from app.services.alerts import fire_status_change
        background_tasks.add_task(fire_status_change, {"id": job_id, "title": row["title"], "company": row["company"]}, old_status, status)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@app.post("/jobs/{job_id}/delete")
def delete_job_form(job_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
    return RedirectResponse("/jobs", status_code=303)


# ─── JSON Import ──────────────────────────────────────────────────────────────

_IMPORT_FIELDS = [
    "title", "company", "location", "description", "requirements",
    "salary", "job_type", "url", "check_url", "check_keyword",
    "html_content", "notes", "status", "expires_at",
    "contact_first_name", "contact_last_name", "contact_salutation",
    "contact_title", "contact_email", "contact_street", "contact_street_nr",
    "contact_plz", "contact_city", "job_name_personalized",
    "company_floskel", "application_date", "bewerbungstext",
]

_EXAMPLE_JSON = {
    "title": "Einkäufer für Bauartikel (m/w/d)",
    "company": "ABC GmbH",
    "location": "München, Bayern",
    "status": "new",
    "job_type": "Vollzeit",
    "salary": "50.000 – 60.000 € / Jahr",
    "expires_at": "2026-07-01",
    "url": "https://example.com/jobs/stelle-123",
    "description": "Wir suchen einen engagierten Einkäufer...(complete job description as stated)",
    "requirements": "Abgeschlossene kaufmännische Ausbildung...",
    "notes": "Persönliche Notizen hier",
    "contact_salutation": "Frau",
    "contact_title": "Dr.",
    "contact_first_name": "Maria",
    "contact_last_name": "Mustermann",
    "contact_email": "bewerbung@abc-gmbh.de",
    "contact_street": "Musterstraße",
    "contact_street_nr": "42",
    "contact_plz": "80331",
    "contact_city": "München",
    "company_floskel": "bei der ABC GmbH",
}

_LLM_PROMPT = (
    "This is the json format for a job db. "
    "Extract all info from the pasted listing and fill the info into the json "
    "and output a json as printed text in the chat"
)


def _insert_job_from_dict(data: dict) -> int:
    now = utcnow()
    fields = {f: data.get(f) or None for f in _IMPORT_FIELDS}
    if not fields.get("status"):
        fields["status"] = "new"
    tag_list = [t.strip() for t in str(data.get("tags", "")).split(",") if t.strip()]

    cols = ", ".join(fields.keys())
    placeholders = ", ".join("?" * len(fields))
    with get_db() as conn:
        cursor = conn.execute(
            f"INSERT INTO jobs ({cols}, source, first_seen_at, created_at, updated_at) "
            f"VALUES ({placeholders}, 'import', ?, ?, ?)",
            list(fields.values()) + [now, now, now],
        )
        job_id = cursor.lastrowid
        for tag in tag_list:
            conn.execute("INSERT OR IGNORE INTO job_tags (job_id, tag) VALUES (?, ?)", (job_id, tag))
        conn.execute(
            "INSERT INTO job_history (job_id, field, old_value, new_value, changed_at) "
            "VALUES (?, '_added', NULL, 'json-import', ?)",
            (job_id, now),
        )
    return job_id


@app.get("/import", response_class=HTMLResponse)
def import_job_form(request: Request):
    return templates.TemplateResponse("jobs/import.html", {
        "request": request,
        "example_json": _EXAMPLE_JSON,
        "prompt_text": _LLM_PROMPT,
        "error": None,
    })


@app.post("/import", response_class=HTMLResponse)
async def import_job_submit(request: Request):
    form = await request.form()
    import_mode = form.get("import_mode", "paste")
    raw = ""
    if import_mode == "file":
        f = form.get("json_file")
        if f and hasattr(f, "read"):
            content = await f.read()
            raw = content.decode("utf-8", errors="replace")
    else:
        raw = str(form.get("json_text", "")).strip()

    if not raw:
        return templates.TemplateResponse("jobs/import.html", {
            "request": request,
            "example_json": _EXAMPLE_JSON,
            "prompt_text": _LLM_PROMPT,
            "error": "Kein JSON übergeben.",
        }, status_code=400)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return templates.TemplateResponse("jobs/import.html", {
            "request": request,
            "example_json": _EXAMPLE_JSON,
            "prompt_text": _LLM_PROMPT,
            "error": f"Ungültiges JSON: {e}",
        }, status_code=400)

    if not data.get("title"):
        return templates.TemplateResponse("jobs/import.html", {
            "request": request,
            "example_json": _EXAMPLE_JSON,
            "prompt_text": _LLM_PROMPT,
            "error": 'Pflichtfeld "title" fehlt im JSON.',
        }, status_code=400)

    job_id = _insert_job_from_dict(data)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


# ─── Claude AI auto-parse ─────────────────────────────────────────────────────

@app.post("/jobs/{job_id}/auto-parse")
async def auto_parse_job_route(job_id: int):
    from app.services.claude_ai import auto_parse_job
    with get_db() as conn:
        job = get_job_with_tags(conn, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    try:
        suggestions = await auto_parse_job(job)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return JSONResponse(suggestions)


@app.get("/searches", response_class=HTMLResponse)
def searches_list(request: Request):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM search_configs ORDER BY created_at DESC").fetchall()

    configs = []
    for r in rows:
        d = dict(r)
        d["tags"] = json.loads(d.get("tags") or "[]")
        d["match_words"] = json.loads(d.get("match_words") or "[]")
        configs.append(d)

    return templates.TemplateResponse("searches/list.html", {
        "request": request,
        "configs": configs,
    })


@app.post("/searches/new", response_class=HTMLResponse)
def create_search_form(
    name: str = Form(...),
    keywords: str = Form(...),
    location: str = Form(""),
    radius: int = Form(30),
    tags: str = Form(""),
    match_words: str = Form(""),
    poll_interval: int = Form(3600),
    angebotsart: int = Form(1),
    arbeitszeit: str = Form(""),
):
    now = utcnow()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    word_list = [w.strip() for w in match_words.split(",") if w.strip()]
    with get_db() as conn:
        conn.execute(
            """INSERT INTO search_configs (
                name, keywords, location, radius, tags, match_words,
                source, active, poll_interval, angebotsart, arbeitszeit,
                total_found, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'arbeitsagentur', 1, ?, ?, ?, 0, ?, ?)""",
            (
                name, keywords, location or None, radius,
                json.dumps(tag_list), json.dumps(word_list),
                poll_interval, angebotsart, arbeitszeit or None,
                now, now,
            ),
        )
    return RedirectResponse("/searches", status_code=303)


@app.post("/searches/{cfg_id}/edit", response_class=HTMLResponse)
def edit_search_form(
    cfg_id: int,
    name: str = Form(...),
    keywords: str = Form(...),
    location: str = Form(""),
    radius: int = Form(30),
    tags: str = Form(""),
    match_words: str = Form(""),
    poll_interval: int = Form(3600),
    angebotsart: int = Form(1),
    arbeitszeit: str = Form(""),
):
    now = utcnow()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    word_list = [w.strip() for w in match_words.split(",") if w.strip()]
    with get_db() as conn:
        conn.execute(
            """UPDATE search_configs SET
                name=?, keywords=?, location=?, radius=?, tags=?, match_words=?,
                poll_interval=?, angebotsart=?, arbeitszeit=?, updated_at=?
               WHERE id=?""",
            (
                name, keywords, location or None, radius,
                json.dumps(tag_list), json.dumps(word_list),
                poll_interval, angebotsart, arbeitszeit or None,
                now, cfg_id,
            ),
        )
    return RedirectResponse("/searches", status_code=303)


@app.post("/searches/{cfg_id}/toggle")
def toggle_search(cfg_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT active FROM search_configs WHERE id = ?", (cfg_id,)).fetchone()
        if row:
            conn.execute(
                "UPDATE search_configs SET active = ?, updated_at = ? WHERE id = ?",
                (0 if row["active"] else 1, utcnow(), cfg_id),
            )
    return RedirectResponse("/searches", status_code=303)


@app.post("/searches/{cfg_id}/delete")
def delete_search_form(cfg_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM search_configs WHERE id = ?", (cfg_id,))
    return RedirectResponse("/searches", status_code=303)


@app.post("/searches/{cfg_id}/poll-now", response_class=HTMLResponse)
async def poll_now_form(request: Request, cfg_id: int):
    from app.services.poller import run_search
    result = await run_search(cfg_id)
    return RedirectResponse(f"/searches?poll_result={result.get('new', 0)}", status_code=303)


# ─── Alerts ───────────────────────────────────────────────────────────────────

@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request):
    with get_db() as conn:
        alert_rows = conn.execute(
            "SELECT * FROM alert_configs ORDER BY created_at DESC"
        ).fetchall()
        settings_rows = conn.execute("SELECT key, value FROM app_settings").fetchall()

    settings = {r["key"]: r["value"] for r in settings_rows}
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "alerts": [dict(a) for a in alert_rows],
        "telegram_token": settings.get("telegram_bot_token", ""),
        "telegram_chat_id": settings.get("telegram_chat_id", ""),
    })


@app.post("/alerts/settings", response_class=HTMLResponse)
def save_alert_settings(
    telegram_bot_token: str = Form(""),
    telegram_chat_id: str = Form(""),
):
    with get_db() as conn:
        for key, val in [
            ("telegram_bot_token", telegram_bot_token.strip()),
            ("telegram_chat_id",   telegram_chat_id.strip()),
        ]:
            conn.execute(
                "INSERT INTO app_settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, val),
            )
    return RedirectResponse("/alerts?saved=1", status_code=303)


@app.post("/alerts/test", response_class=HTMLResponse)
async def test_alert(request: Request):
    from app.services.alerts import send_telegram
    ok, err = await send_telegram("✅ <b>BewerbungsDB</b>\nTest-Nachricht erfolgreich!")
    return RedirectResponse(
        f"/alerts?test={'ok' if ok else 'fail'}&err={err}",
        status_code=303,
    )


@app.post("/alerts/new", response_class=HTMLResponse)
def create_alert(
    name: str = Form(...),
    event_type: str = Form(...),
    from_status: str = Form(""),
    to_status: str = Form(""),
):
    now = utcnow()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO alert_configs (name, enabled, event_type, from_status, to_status, created_at, updated_at) "
            "VALUES (?, 1, ?, ?, ?, ?, ?)",
            (
                name, event_type,
                from_status or None, to_status or None,
                now, now,
            ),
        )
    return RedirectResponse("/alerts", status_code=303)


@app.post("/alerts/{alert_id}/toggle")
def toggle_alert(alert_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT enabled FROM alert_configs WHERE id = ?", (alert_id,)).fetchone()
        if row:
            conn.execute(
                "UPDATE alert_configs SET enabled = ?, updated_at = ? WHERE id = ?",
                (0 if row["enabled"] else 1, utcnow(), alert_id),
            )
    return RedirectResponse("/alerts", status_code=303)


@app.post("/alerts/{alert_id}/delete")
def delete_alert(alert_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM alert_configs WHERE id = ?", (alert_id,))
    return RedirectResponse("/alerts", status_code=303)
