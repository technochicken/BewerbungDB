import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "jobs.db"

BA_API_BASE = "https://rest.arbeitsagentur.de/jobboerse/jobsuche-service"
BA_API_KEY = os.getenv("BA_API_KEY", "jobboerse-jobsuche")

POLL_INTERVAL_SECS = int(os.getenv("POLL_INTERVAL", "3600"))
URL_CHECK_INTERVAL_SECS = int(os.getenv("URL_CHECK_INTERVAL", "86400"))
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# Session signing secret — set SESSION_SECRET env var for persistence across restarts.
# Without it a new secret is generated each start (users must re-login after restart).
SESSION_SECRET = os.getenv("SESSION_SECRET") or secrets.token_hex(32)

APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
