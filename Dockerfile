# ─── Build stage ─────────────────────────────────────────────────────
# Install dependencies in a separate stage so the final image doesn't
# carry pip's wheel cache or build tooling.
FROM python:3.12-slim AS builder

# Ensure wheels build cleanly and pip doesn't write cache (smaller layers).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install dependencies first for better layer caching — requirements.txt
# changes far less often than application code, so this layer is reused
# across most builds.
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# ─── Runtime stage ───────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    # Tell the app it's running behind a trusted reverse proxy so it reads
    # X-Forwarded-* headers correctly. Override TRUSTED_PROXIES for custom
    # setups (nginx, Cloudflare Tunnel, etc.).
    PYTHONPATH="/app"

# curl is needed by the Docker HEALTHCHECK below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the pre-built virtualenv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

# Create a non-root user to run the app.
RUN groupadd --system app && useradd --system --gid app --home-dir /app app

WORKDIR /app

# Copy application code. .dockerignore ensures .env, .git, caches, and
# media files never enter the image.
COPY --chown=app:app . .

# Ensure the /app directory itself is owned by the app user so they can write control sockets/temp files
RUN chown app:app /app

USER app

EXPOSE 8000

# Healthcheck hits the unauthenticated health endpoint (/). The container
# is considered unhealthy only after 3 consecutive failures (~45s), which
# avoids spurious restarts during slow dependency resolution on first boot.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8000}/" || exit 1

# Gunicorn with Uvicorn workers (uvicorn.workers.UvicornWorker).
# Built on FastAPI with asynchronous event loop concurrency (httpx + asyncio).
#
#   --workers           scales with CPU cores (configured in gunicorn.conf.py)
#   --timeout 300       covers long streaming downloads + transcode polling
#   --graceful-timeout  gives in-flight requests time to finish on shutdown
CMD ["gunicorn", "--config", "gunicorn.conf.py", "api.index:app"]
