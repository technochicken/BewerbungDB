import logging
from typing import Dict, Any, Optional

import httpx

from app.config import APP_BASE_URL
from app.database import get_db

logger = logging.getLogger(__name__)

STATUS_LABELS: Dict[str, str] = {
    'new': 'Neu', 'reviewing': 'Prüfen', 'applied': 'Beworben',
    'interview': 'Gespräch', 'offer': 'Angebot', 'accepted': 'Angenommen',
    'rejected': 'Abgelehnt', 'closed': 'Geschlossen', 'irrelevant': 'Irrelevant',
}


def get_telegram_config() -> tuple[str, str]:
    """Returns (bot_token, chat_id). Either may be empty string if not configured."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT key, value FROM app_settings WHERE key IN ('telegram_bot_token', 'telegram_chat_id')"
        ).fetchall()
    cfg = {r["key"]: r["value"] for r in rows}
    return cfg.get("telegram_bot_token", ""), cfg.get("telegram_chat_id", "")


async def send_telegram(text: str) -> tuple[bool, str]:
    """
    Send a message via the configured Telegram bot.
    Returns (success, error_message).
    """
    token, chat_id = get_telegram_config()
    if not token or not chat_id:
        return False, "Telegram nicht konfiguriert (Bot-Token oder Chat-ID fehlt)"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            )
        if resp.status_code == 200:
            return True, ""
        body = resp.json()
        return False, body.get("description", f"HTTP {resp.status_code}")
    except Exception as e:
        logger.error(f"Telegram send failed: {e}")
        return False, str(e)


def _get_matching_alerts(event_type: str, from_status: Optional[str] = None, to_status: Optional[str] = None) -> list:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM alert_configs WHERE enabled = 1 AND event_type = ?",
            (event_type,),
        ).fetchall()

    if event_type != "status_change":
        return list(rows)

    matched = []
    for alert in rows:
        a_from = alert["from_status"]
        a_to = alert["to_status"]
        if a_from and a_from != from_status:
            continue
        if a_to and a_to != to_status:
            continue
        matched.append(alert)
    return matched


async def fire_new_listing(job: Dict[str, Any], source: str = ""):
    alerts = _get_matching_alerts("new_listing")
    if not alerts:
        return

    title   = job.get("title") or "?"
    company = job.get("company") or ""
    location = job.get("location") or ""
    url     = job.get("url") or ""

    job_id = job.get("id")
    app_link = f'{APP_BASE_URL}/jobs/{job_id}' if APP_BASE_URL and job_id else None

    lines = ["🆕 <b>Neue Stelle gefunden</b>"]
    if app_link:
        lines.append(f'<a href="{app_link}"><b>{title}</b></a>')
    else:
        lines.append(f"<b>{title}</b>")
    if company:
        lines.append(f"🏢 {company}")
    if location:
        lines.append(f"📍 {location}")
    if source:
        lines.append(f"🔍 Quelle: {source}")
    if url:
        lines.append(f"🔗 {url}")

    text = "\n".join(lines)
    ok, err = await send_telegram(text)
    if not ok:
        logger.warning(f"Alert send failed: {err}")


async def fire_status_change(job: Dict[str, Any], from_status: str, to_status: str):
    if from_status == to_status:
        return
    alerts = _get_matching_alerts("status_change", from_status, to_status)
    if not alerts:
        return

    title   = job.get("title") or "?"
    company = job.get("company") or ""
    from_l  = STATUS_LABELS.get(from_status, from_status)
    to_l    = STATUS_LABELS.get(to_status, to_status)

    if to_status == "closed":
        icon = "🔒"
    elif to_status in ("accepted", "offer"):
        icon = "✅"
    elif to_status == "rejected":
        icon = "❌"
    elif to_status == "applied":
        icon = "📤"
    elif to_status == "interview":
        icon = "🗣"
    else:
        icon = "🔄"

    job_id = job.get("id")
    app_link = f'{APP_BASE_URL}/jobs/{job_id}' if APP_BASE_URL and job_id else None

    lines = [f"{icon} <b>Statusänderung</b>"]
    if app_link:
        lines.append(f'<a href="{app_link}"><b>{title}</b></a>')
    else:
        lines.append(f"<b>{title}</b>")
    if company:
        lines.append(f"🏢 {company}")
    lines.append(f"{from_l}  →  {to_l}")

    text = "\n".join(lines)
    ok, err = await send_telegram(text)
    if not ok:
        logger.warning(f"Alert send failed: {err}")
