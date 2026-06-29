import json
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-haiku-4-5-20251001"


def _get_settings() -> tuple[Optional[str], str]:
    from app.auth import _get
    return _get("claude_api_key"), (_get("user_gender") or "männlich")


async def auto_parse_job(job: dict) -> dict:
    """Call Claude API to extract/suggest missing job fields.
    Returns a dict of {field: suggested_value} for non-empty suggestions."""
    api_key, gender = _get_settings()
    if not api_key:
        raise ValueError("Kein Claude API-Key konfiguriert (Einstellungen → Claude AI)")

    # Build a summary of existing data
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

    payload = {
        "model": MODEL,
        "max_tokens": 512,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            CLAUDE_API_URL,
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

    content = resp.json()["content"][0]["text"].strip()

    # Extract JSON block if wrapped in markdown code fences
    if "```" in content:
        start = content.find("{")
        end = content.rfind("}") + 1
        content = content[start:end]

    try:
        result = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error("Claude returned invalid JSON: %s", content)
        raise ValueError(f"Claude antwortete mit ungültigem JSON: {e}")

    # Filter to only allowed fields with non-empty values
    allowed = {
        "contact_salutation", "contact_title", "contact_first_name", "contact_last_name",
        "contact_email", "contact_street", "contact_street_nr", "contact_plz", "contact_city",
        "job_name_personalized", "company_floskel",
    }
    return {k: str(v).strip() for k, v in result.items() if k in allowed and v and str(v).strip()}


def _personalized_example(gender: str) -> str:
    if gender == "weiblich":
        return "Einkäuferin für Bauartikel"
    if gender == "divers":
        return "Einkaufskraft für Bauartikel"
    return "Einkäufer für Bauartikel"
