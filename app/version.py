"""Application version and build info.

VERSION (repo root) holds the release number. The commit and build date are
injected at image build time (BUILD_SHA / BUILD_DATE build args → env vars);
local runs without them show "dev".
"""
import os
import re
from pathlib import Path

REPO_URL = "https://github.com/technochicken/BewerbungDB"


def _read_version() -> str:
    try:
        return (Path(__file__).parent.parent / "VERSION").read_text().strip() or "0.0.0"
    except OSError:
        return "0.0.0"


VERSION = _read_version()


def build_info() -> dict:
    sha = os.getenv("BUILD_SHA", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{7,40}", sha):
        sha = ""
    date = os.getenv("BUILD_DATE", "").strip()
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}):\d{2}Z", date)
    return {
        "version": VERSION,
        "sha": sha[:7] if sha else "dev",
        "commit_url": f"{REPO_URL}/commit/{sha}" if sha else None,
        "date": f"{m.group(1)} {m.group(2)} UTC" if m else (date or None),
        "repo_url": REPO_URL,
    }
