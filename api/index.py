"""
api/index.py — TeraBridge API entry point.

This file is intentionally slim. It:
  1. Creates the FastAPI app and attaches middleware.
  2. Registers all route routers.
  3. Wires together the shared proxy client, config loader, and startup/shutdown
     lifecycle via the ASGI lifespan context.

All business logic lives in the modules under api/.
"""
import asyncio
import logging
import os
import sys
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

# ── Logger ────────────────────────────────────────────────────────────
logger = logging.getLogger("terabridge.api")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(_handler)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

# ── Project root on sys.path (resolves downloader module) ─────────────
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Internal modules ──────────────────────────────────────────────────
from api.config import ALLOWED_ORIGINS, API_KEY, REQUIRE_API_KEY
from api.middleware import (
    ConfigRefreshMiddleware,
    check_safe_redirect,
    set_config_loader,
)
from api.account_manager import load_config_from_redis
from api.rate_limiter import rate_limiter
from api.redis_client import redis_client
from downloader import close_session

# ── Route routers ─────────────────────────────────────────────────────
from api.routes.resolve  import router as resolve_router
from api.routes.stream   import router as stream_router,   set_proxy_client as stream_set_client
from api.routes.download import router as download_router, set_proxy_client as download_set_client
from api.routes.admin    import router as admin_router,    set_start_time

# ─── Shared proxy client ─────────────────────────────────────────────
# One AsyncClient for all proxy routes — persistent connection pooling,
# HTTP/2 multiplexing, and no per-request TCP/TLS handshake overhead.
_proxy_client = httpx.AsyncClient(
    follow_redirects=True,
    event_hooks={"response": [check_safe_redirect]},
    timeout=120.0,
    http2=True,
    limits=httpx.Limits(
        max_connections=200,
        max_keepalive_connections=50,
        keepalive_expiry=90,
    ),
)


# ─── Periodic housekeeping ───────────────────────────────────────────

async def _periodic_cleanup():
    while True:
        await asyncio.sleep(300)
        rate_limiter.cleanup()


# ─── ASGI lifespan ───────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────
    _server_start = time.time()
    set_start_time(_server_start)

    # Inject the shared proxy client into the routes that stream bytes
    stream_set_client(_proxy_client)
    download_set_client(_proxy_client)

    # Wire the periodic config-refresh middleware loader
    set_config_loader(load_config_from_redis)

    # Load initial Terabox credentials from Redis pool (no-op if no Redis)
    load_config_from_redis()

    cleanup_task = asyncio.create_task(_periodic_cleanup())

    if not API_KEY and not REQUIRE_API_KEY:
        logger.warning(
            "API_KEY is not set and REQUIRE_API_KEY is disabled — "
            "all endpoints are OPEN. Do not expose this instance to the internet."
        )

    yield  # ── application running ─────────────────────────────────

    # ── Shutdown ─────────────────────────────────────────────────────
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

    await _proxy_client.aclose()
    await close_session()
    if redis_client:
        redis_client.close()


# ─── App ─────────────────────────────────────────────────────────────

app = FastAPI(title="TeraBridge API", version="2.0.0", lifespan=lifespan)

# ── Middleware stack ─────────────────────────────────────────────────
# Starlette wraps middleware inside-out, so the last add_middleware() call
# becomes the outermost layer.  We want: GZip → CORS → ConfigRefresh.

app.add_middleware(ConfigRefreshMiddleware)

_allow_origins = list(ALLOWED_ORIGINS) if ALLOWED_ORIGINS else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=500)

# ── Routers ───────────────────────────────────────────────────────────

app.include_router(resolve_router)
app.include_router(stream_router)
app.include_router(download_router)
app.include_router(admin_router)


# ─── Health check ────────────────────────────────────────────────────

@app.get("/")
def home():
    from api.routes import admin as _admin
    return {
        "status":         "online",
        "message":        "TeraBridge API is running!",
        "version":        "2.0.0",
        "uptime_seconds": int(time.time() - _admin._start_time),
        "endpoints": {
            "/api/resolve":         "Resolve share links. Params: url (required), mode [download|stream|list]",
            "/api/stats":           "Cache, rate-limiter and server statistics (admin only)",
            "/api/stream/manifest": "HLS master playlist for a share link",
            "/api/download":        "Proxied file download (HMAC-signed URL)",
            "/api/thumbnail":       "Proxied thumbnail image (HMAC-signed URL)",
        },
    }


# ─── Dev server entry point ──────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting TeraBridge API on 0.0.0.0:%d", port)
    uvicorn.run("api.index:app", host="0.0.0.0", port=port, reload=False, workers=1)
