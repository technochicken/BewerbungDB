import logging
from typing import Tuple, Optional

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
}

# Explicit per-phase timeouts: 8s to connect, 20s to read the body
_TIMEOUT = httpx.Timeout(connect=8.0, read=20.0, write=8.0, pool=5.0)


async def fetch_url(url: str) -> Tuple[int, Optional[str]]:
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            resp = await client.get(url, headers=HEADERS)
            return resp.status_code, resp.text

    except httpx.ConnectTimeout:
        logger.warning(f"Connect timeout for {url}")
        return 0, None
    except httpx.ReadTimeout:
        logger.warning(f"Read timeout for {url}")
        return 0, None
    except httpx.ConnectError as e:
        logger.warning(f"Connect error for {url}: {e}")
        return 0, None
    except httpx.TooManyRedirects:
        logger.warning(f"Too many redirects for {url}")
        return 0, None
    except httpx.HTTPStatusError as e:
        # raised only if raise_for_status() is called; shouldn't happen here, but guard anyway
        return e.response.status_code, None
    except Exception as e:
        logger.warning(f"Unexpected error fetching {url}: {type(e).__name__}: {e}")
        return 0, None


def extract_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header", "noscript"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())


def is_job_still_active(html: str, match_words: list[str]) -> bool:
    if not match_words:
        return True
    text = extract_text(html).lower()
    return any(w.lower() in text for w in match_words)
