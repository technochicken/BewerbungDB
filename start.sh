#!/bin/sh
set -e
python -m venv /app/.venv 2>/dev/null || true
/app/.venv/bin/pip install --quiet -r /app/requirements.txt
exec /app/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
