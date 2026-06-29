import base64
import json
import logging
from typing import Optional, Dict, Any, List

import httpx

from app.config import BA_API_BASE, BA_API_KEY

logger = logging.getLogger(__name__)

HEADERS = {
    "X-API-Key": BA_API_KEY,
    "User-Agent": "BewerbungsDB/1.0",
}

ARBEITSZEIT_MAP = {
    "VOLLZEIT": "Vollzeit",
    "TEILZEIT": "Teilzeit",
    "HEIM_TELEARBEIT": "Homeoffice",
    "SCHICHT_NACHTARBEIT_WOCHENENDE": "Schicht/Nacht/WE",
    "MINIJOB": "Minijob",
    "vz": "Vollzeit",
    "tz": "Teilzeit",
    "ho": "Homeoffice",
    "snw": "Schicht/Nacht/WE",
    "mj": "Minijob",
}


async def search_jobs(
    keywords: str,
    location: Optional[str] = None,
    radius: int = 30,
    page: int = 1,
    size: int = 100,
    angebotsart: int = 1,
    arbeitszeit: Optional[str] = None,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {
        "was": keywords,
        "page": page,
        "size": size,
        "angebotsart": angebotsart,
    }
    if location:
        params["wo"] = location
        params["umkreis"] = radius
    if arbeitszeit:
        params["arbeitszeit"] = arbeitszeit

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{BA_API_BASE}/pc/v6/jobs",
            params=params,
            headers=HEADERS,
        )
        resp.raise_for_status()
        data = resp.json()

    total = data.get("maxErgebnisse", "?")

    # Scan for the listings array — field name differs between API versions
    LISTING_CANDIDATES = ["stellenangebote", "jobs", "angebote", "jobList", "items", "results"]
    listings_key = next((k for k in LISTING_CANDIDATES if isinstance(data.get(k), list)), None)

    if listings_key is None:
        # Fallback: pick the first non-empty list value in the response
        for k, v in data.items():
            if isinstance(v, list) and len(v) > 0:
                listings_key = k
                logger.warning(f"Using undocumented field '{k}' as listings array")
                break

    listings = data.get(listings_key, []) if listings_key else []
    logger.info(
        f"BA API page={page}: maxErgebnisse={total}, field='{listings_key}', returned={len(listings)}"
    )

    if listings:
        logger.info(f"First listing keys: {list(listings[0].keys())}")
    elif int(str(total).replace(',', '').replace('.', '') or 0) > 0:
        logger.warning(
            f"maxErgebnisse={total} but no listings parsed! "
            f"Response top-level keys: {list(data.keys())}"
        )

    # Normalize to always use 'stellenangebote' key for downstream consumers
    data["stellenangebote"] = listings
    return data


async def get_job_details(refnr: str) -> Dict[str, Any]:
    encoded = base64.b64encode(refnr.encode()).decode()
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{BA_API_BASE}/pc/v4/jobdetails/{encoded}",
            headers=HEADERS,
        )
        resp.raise_for_status()
        return resp.json()


def get_refnr(listing: Dict[str, Any]) -> Optional[str]:
    # v6/jobs uses 'referenznummer', v4/app/jobs uses 'refnr'
    return listing.get("referenznummer") or listing.get("refnr")


def _parse_location(listing: Dict[str, Any]) -> Optional[str]:
    # v6 search: stellenlokationen[].adresse
    stellenlokationen: List[Dict] = listing.get("stellenlokationen") or []
    if stellenlokationen:
        adresse = stellenlokationen[0].get("adresse") or {}
        parts = [adresse.get("ort", ""), adresse.get("plz", "")]
        return ", ".join(p for p in parts if p) or None

    # v4 details: arbeitsorte[]
    arbeitsorte: List[Dict] = listing.get("arbeitsorte") or []
    if arbeitsorte:
        ao = arbeitsorte[0]
        parts = [ao.get("ort", ""), ao.get("region", "")]
        return ", ".join(p for p in parts if p) or None

    # Fallback: single arbeitsort object
    arbeitsort = listing.get("arbeitsort") or {}
    parts = [arbeitsort.get("ort", ""), arbeitsort.get("region", "")]
    return ", ".join(p for p in parts if p) or None


def _parse_job_type(listing: Dict[str, Any]) -> Optional[str]:
    # v4 details: arbeitszeitmodelle list
    modelle = listing.get("arbeitszeitmodelle") or listing.get("arbeitszeitModels") or []
    if modelle:
        return ", ".join(ARBEITSZEIT_MAP.get(t, t) for t in modelle) or None

    # v6 search: boolean flags
    V6_FLAGS = [
        ("arbeitszeitVollzeit",              "Vollzeit"),
        ("arbeitszeitTeilzeitVormittag",     "Teilzeit"),
        ("arbeitszeitTeilzeitNachmittag",    "Teilzeit"),
        ("arbeitszeitTeilzeitAbend",         "Teilzeit"),
        ("arbeitszeitTeilzeitFlexibel",      "Teilzeit"),
        ("arbeitszeitSchichtNachtWochenende","Schicht/Nacht/WE"),
    ]
    types = []
    seen = set()
    for flag, label in V6_FLAGS:
        if listing.get(flag) and label not in seen:
            types.append(label)
            seen.add(label)
    if listing.get("homeofficemoeglich") and listing.get("homeofficetyp") not in (None, "KEIN_HOMEOFFICE"):
        types.append("Homeoffice")
    if types:
        return ", ".join(types)

    # Fallback: single 'arbeitszeit' field
    raw = listing.get("arbeitszeit")
    return ARBEITSZEIT_MAP.get(raw, raw) if raw else None


def parse_listing(listing: Dict[str, Any]) -> Dict[str, Any]:
    # Title: v6 uses 'stellenangebotsTitel', v4 details use 'titel', fallback 'beruf'
    title = (
        listing.get("stellenangebotsTitel")
        or listing.get("titel")
        or listing.get("beruf")
        or ""
    )

    # Company: v6 uses 'firma', v4 uses 'arbeitgeber'
    company = listing.get("firma") or listing.get("arbeitgeber")

    # Description: available in v6 search result directly
    description = (
        listing.get("stellenangebotsBeschreibung")
        or listing.get("stellenbeschreibung")
    )

    # Entry date: v6 uses eintrittszeitraum.von, v4 uses eintrittsdatum
    eintrittszeitraum = listing.get("eintrittszeitraum") or {}
    expires_at = eintrittszeitraum.get("von") or listing.get("eintrittsdatum")

    return {
        "external_id": get_refnr(listing),
        "source": "arbeitsagentur",
        "title": title,
        "company": company,
        "location": _parse_location(listing),
        "url": listing.get("externeUrl") or listing.get("allianzpartnerUrl"),
        "job_type": _parse_job_type(listing),
        "expires_at": expires_at,
        "description": description,
        "raw_api_data": json.dumps(listing, ensure_ascii=False),
    }


def enrich_with_details(job_data: Dict[str, Any], details: Dict[str, Any]) -> Dict[str, Any]:
    job_data = dict(job_data)

    # Description: prefer what parse_listing already found, fall back to details fields
    if not job_data.get("description"):
        job_data["description"] = (
            details.get("stellenbeschreibung")
            or details.get("stellenangebotsBeschreibung")
        )

    # Title: detail response is often more specific
    detail_title = details.get("titel") or details.get("stellenangebotsTitel")
    if detail_title:
        job_data["title"] = detail_title

    # Location from details (only override if we don't have one yet)
    if not job_data.get("location"):
        loc = _parse_location(details)
        if loc:
            job_data["location"] = loc

    # Job type from details (more authoritative than boolean flags)
    detail_job_type = _parse_job_type(details)
    if detail_job_type:
        job_data["job_type"] = detail_job_type

    # Salary
    verguetung = details.get("verguetung")
    if verguetung and str(verguetung) not in ("KEINE_ANGABEN", ""):
        job_data["salary"] = str(verguetung)

    # Merge raw data
    try:
        existing = json.loads(job_data.get("raw_api_data") or "{}")
    except json.JSONDecodeError:
        existing = {}
    job_data["raw_api_data"] = json.dumps({**existing, **details}, ensure_ascii=False)
    return job_data
