FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Injected by the GitHub Actions build; shown on the About page and login screen.
ARG BUILD_SHA=""
ARG BUILD_DATE=""
ENV BUILD_SHA=$BUILD_SHA BUILD_DATE=$BUILD_DATE

RUN mkdir -p data

EXPOSE 8000

HEALTHCHECK --interval=60s --timeout=10s --start-period=60s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Dependencies are installed at build time, so the container starts without internet access.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
