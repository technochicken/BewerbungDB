import json
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── Provider metadata (label + free-text model suggestions for the UI) ────────

PROVIDERS = {
    "claude": {
        "label": "Claude (Anthropic)",
        "needs_api_key": True,
        "needs_base_url": False,
        "default_model": "claude-haiku-4-5-20251001",
        "model_suggestions": [
            "claude-haiku-4-5-20251001",
            "claude-sonnet-5",
            "claude-opus-5",
        ],
    },
    "openai": {
        "label": "ChatGPT (OpenAI)",
        "needs_api_key": True,
        "needs_base_url": False,
        "default_model": "gpt-4o-mini",
        "model_suggestions": [
            "gpt-4o-mini",
            "gpt-4o",
            "gpt-4.1-mini",
            "gpt-4.1",
            "o4-mini",
        ],
    },
    "ollama": {
        "label": "Ollama (lokal)",
        "needs_api_key": False,
        "needs_base_url": True,
        "default_model": "llama3.1",
        "default_base_url": "http://localhost:11434",
        "model_suggestions": [
            "llama3.1",
            "qwen2.5",
            "mistral",
            "phi4",
        ],
    },
}

ALLOWED_FIELDS = {
    "contact_salutation", "contact_title", "contact_first_name", "contact_last_name",
    "contact_email", "contact_street", "contact_street_nr", "contact_plz", "contact_city",
    "job_name_personalized", "company_floskel",
}


def _get_ai_settings() -> dict:
    from app.auth import _get
    provider = _get("ai_provider") or "claude"
    if provider not in PROVIDERS:
        provider = "claude"
    return {
        "provider": provider,
        "gender": _get("user_gender") or "männlich",
        "claude_api_key": _get("claude_api_key") or "",
        "claude_model": _get("claude_model") or PROVIDERS["claude"]["default_model"],
        "openai_api_key": _get("openai_api_key") or "",
        "openai_model": _get("openai_model") or PROVIDERS["openai"]["default_model"],
        "ollama_base_url": _get("ollama_base_url") or PROVIDERS["ollama"]["default_base_url"],
        "ollama_model": _get("ollama_model") or PROVIDERS["ollama"]["default_model"],
    }


def _personalized_example(gender: str) -> str:
    if gender == "weiblich":
        return "Einkäuferin für Bauartikel"
    if gender == "divers":
        return "Einkaufskraft für Bauartikel"
    return "Einkäufer für Bauartikel"


def _build_prompts(job: dict, gender: str) -> tuple[str, str]:
    existing = {
        k: v for k, v in job.items()
        if v and k in (
            "title", "company", "location", "description", "requirements",
            "notes", "bewerbungstext",
            "contact_first_name", "contact_last_name", "contact_salutation",
            "contact_title", "contact_email", "contact_street", "contact_street_nr",
            "contact_plz", "contact_city",
            "job_name_personalized", "company_floskel",
        )
    }

    gender_instruction = {
        "weiblich": "weiblich (z.B. Einkäuferin, Entwicklerin, Managerin)",
        "divers": "divers/neutral (kein Geschlecht, z.B. 'Einkaufsperson' oder die neutrale Form ohne Suffix)",
    }.get(gender, "männlich (z.B. Einkäufer, Entwickler, Manager)")

    system_prompt = (
        "Du bist ein präziser Assistent für deutsches Bewerbungsmanagement. "
        "Extrahiere nur Informationen, die direkt im Text stehen. Erfinde nichts."
    )

    user_prompt = f"""Analysiere die folgenden Jobdaten und extrahiere fehlende Informationen.

Bereits vorhandene Daten:
{json.dumps(existing, ensure_ascii=False, indent=2)}

Aufgaben (nur wenn die Information aus dem Text ableitbar ist):
1. Kontaktperson: Extrahiere Anrede (Herr/Frau), Titel (Dr./Prof.), Vorname, Nachname, E-Mail, Straße, Hausnr, PLZ, Ort
2. job_name_personalized: Stellenbezeichnung in grammatikalisch korrekter Form für das Anschreiben, Geschlecht: {gender_instruction}. Beispiel: "Einkäufer für Bauartikel (m/w/d)" → "{_personalized_example(gender)}". Ohne (m/w/d) Suffix.
3. company_floskel: Kurzformulierung für das Anschreiben, z.B. "bei der ABC GmbH" (GmbH, AG, SE → "der"), "bei dem XYZ e.V." (e.V., gGmbH → "dem"), "bei der XYZ GbR" usw.

Antworte NUR mit einem gültigen JSON-Objekt. Felder mit leeren oder unbekannten Werten weglassen. Keine Erklärungen.

Beispiel-Antwort:
{{
  "contact_salutation": "Frau",
  "contact_first_name": "Maria",
  "contact_last_name": "Mustermann",
  "contact_email": "bewerbung@example.com",
  "job_name_personalized": "Einkäuferin für Bauartikel",
  "company_floskel": "bei der ABC GmbH"
}}"""
    return system_prompt, user_prompt


# ── Provider-specific calls — each returns the raw text response ──────────────

async def _call_claude(system_prompt: str, user_prompt: str, api_key: str, model: str) -> str:
    if not api_key:
        raise ValueError("Kein Claude API-Key konfiguriert (Einstellungen → KI-Anbieter)")
    payload = {
        "model": model,
        "max_tokens": 512,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=payload,
        )
    if resp.status_code != 200:
        logger.error("Claude API error %s: %s", resp.status_code, resp.text)
        raise ValueError(f"Claude API Fehler {resp.status_code}: {resp.text[:200]}")
    return resp.json()["content"][0]["text"].strip()


async def _call_openai(system_prompt: str, user_prompt: str, api_key: str, model: str) -> str:
    if not api_key:
        raise ValueError("Kein OpenAI API-Key konfiguriert (Einstellungen → KI-Anbieter)")
    payload = {
        "model": model,
        "max_tokens": 512,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "content-type": "application/json",
            },
            json=payload,
        )
    if resp.status_code != 200:
        logger.error("OpenAI API error %s: %s", resp.status_code, resp.text)
        raise ValueError(f"OpenAI API Fehler {resp.status_code}: {resp.text[:200]}")
    return resp.json()["choices"][0]["message"]["content"].strip()


async def _call_ollama(system_prompt: str, user_prompt: str, base_url: str, model: str) -> str:
    if not base_url:
        raise ValueError("Keine Ollama-URL konfiguriert (Einstellungen → KI-Anbieter)")
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    url = base_url.rstrip("/") + "/api/chat"
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(url, json=payload)
    except httpx.RequestError as e:
        raise ValueError(f"Ollama unter {base_url} nicht erreichbar: {e}")
    if resp.status_code != 200:
        logger.error("Ollama API error %s: %s", resp.status_code, resp.text)
        raise ValueError(f"Ollama Fehler {resp.status_code}: {resp.text[:200]}")
    return resp.json()["message"]["content"].strip()


# ── Public entry point ─────────────────────────────────────────────────────────

async def auto_parse_job(job: dict) -> dict:
    """Call the configured AI provider to extract/suggest missing job fields.
    Returns a dict of {field: suggested_value} for non-empty suggestions."""
    settings = _get_ai_settings()
    system_prompt, user_prompt = _build_prompts(job, settings["gender"])

    provider = settings["provider"]
    if provider == "claude":
        content = await _call_claude(
            system_prompt, user_prompt, settings["claude_api_key"], settings["claude_model"]
        )
    elif provider == "openai":
        content = await _call_openai(
            system_prompt, user_prompt, settings["openai_api_key"], settings["openai_model"]
        )
    elif provider == "ollama":
        content = await _call_ollama(
            system_prompt, user_prompt, settings["ollama_base_url"], settings["ollama_model"]
        )
    else:
        raise ValueError(f"Unbekannter KI-Anbieter: {provider}")

    if "```" in content:
        start = content.find("{")
        end = content.rfind("}") + 1
        content = content[start:end]

    try:
        result = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error("AI provider returned invalid JSON: %s", content)
        raise ValueError(f"KI antwortete mit ungültigem JSON: {e}")

    return {k: str(v).strip() for k, v in result.items() if k in ALLOWED_FIELDS and v and str(v).strip()}
