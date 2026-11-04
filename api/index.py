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
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response

# ── Logger ────────────────────────────────────────────────────────────
logger = logging.getLogger("terabridge.api")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(_handler)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

# ── Clean up Uvicorn Access Logs (Truncate long thumbnail URLs & hide rsa_pub probes) ──
class AccessLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, "args") and isinstance(record.args, tuple) and len(record.args) >= 3:
            raw_path = str(record.args[2])
            # Hide noise from client / browser probes like /rsa_pub and /favicon.ico
            if raw_path in ("/rsa_pub", "/favicon.ico") or raw_path.startswith("/rsa_pub?"):
                return False
            # Truncate extremely long query URLs (such as /api/thumbnail or /api/download) in access logs
            if len(raw_path) > 75 and ("thumbnail" in raw_path or "url=" in raw_path):
                short_path = raw_path[:65] + "...[truncated]"
                args_list = list(record.args)
                args_list[2] = short_path
                record.args = tuple(args_list)
        return True

logging.getLogger("uvicorn.access").addFilter(AccessLogFilter())

# ── Project root on sys.path (resolves downloader module) ─────────────
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Internal modules ──────────────────────────────────────────────────
from api.config import (
    ALLOWED_ORIGINS,
    API_KEY,
    REQUIRE_API_KEY,
    OUTBOUND_PROXY,
    PROXY_DOWNLOADS,
)
from api.middleware import (
    ConfigRefreshMiddleware,
    AnalyticsMetricsMiddleware,
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
# Lazily created inside lifespan (post-fork) to prevent SSL/socket inheritance issues.
_proxy_client: httpx.AsyncClient | None = None


def get_proxy_client() -> httpx.AsyncClient:
    """Return the shared proxy AsyncClient, creating it lazily if needed."""
    global _proxy_client
    if _proxy_client is None or _proxy_client.is_closed:
        _proxy_client = httpx.AsyncClient(
            follow_redirects=True,
            event_hooks={"response": [check_safe_redirect]},
            timeout=120.0,
            http2=True if not (OUTBOUND_PROXY and PROXY_DOWNLOADS) else False,
            proxy=OUTBOUND_PROXY if PROXY_DOWNLOADS else None,
            limits=httpx.Limits(
                max_connections=200,
                max_keepalive_connections=50,
                keepalive_expiry=90,
            ),
        )
    return _proxy_client


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
    try:
        from api.metrics import set_metrics_start_time
        set_metrics_start_time(_server_start)
    except Exception:
        pass

    # Inject the shared proxy client into the routes that stream bytes
    client = get_proxy_client()
    stream_set_client(client)
    download_set_client(client)

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

    if _proxy_client is not None and not _proxy_client.is_closed:
        await _proxy_client.aclose()
    await close_session()
    try:
        from api.proxy_manager import proxy_manager
        await proxy_manager.close_all()
    except Exception:
        pass
    from api.redis_client import async_redis_client
    if async_redis_client:
        try:
            await async_redis_client.close()
        except Exception:
            pass
    if redis_client:
        try:
            redis_client.close()
        except Exception:
            pass


# ─── App ─────────────────────────────────────────────────────────────

app = FastAPI(title="TeraBridge API", version="2.0.0", lifespan=lifespan)

# ── Middleware stack ─────────────────────────────────────────────────
# Starlette wraps middleware inside-out, so the last add_middleware() call
# becomes the outermost layer.  We want: GZip → CORS → ConfigRefresh.

app.add_middleware(AnalyticsMetricsMiddleware)
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
            "/healthz":             "Liveness & readiness health probe",
            "/api/resolve":         "Resolve share links. Params: url (required), mode [download|stream|list]",
            "/api/stats":           "Cache, rate-limiter and server statistics (admin only)",
            "/api/stream/manifest": "HLS master playlist for a share link",
            "/api/download":        "Proxied file download (HMAC-signed URL)",
            "/api/thumbnail":       "Proxied thumbnail image (HMAC-signed URL)",
            "/admin":               "Cloudvids file management dashboard",
        },
    }


@app.get("/healthz")
@app.get("/api/health")
def healthz():
    """Standardized liveness & readiness probe for Docker, Railway, Render."""
    from api.routes import admin as _admin
    from api.proxy_manager import proxy_manager
    from api.redis_client import redis_client

    total_proxies = proxy_manager.get_total_count()
    healthy_proxies = proxy_manager.get_healthy_count()

    return {
        "status": "healthy",
        "service": "terabridge-api",
        "uptime_seconds": int(time.time() - _admin._start_time),
        "redis": "connected" if redis_client else "in-memory",
        "proxies": {
            "total": total_proxies,
            "healthy": healthy_proxies,
        },
    }


@app.get("/rsa_pub")
@app.get("/favicon.ico")
def ignore_browser_probes():
    """Silently answer browser/client probes without 404 spam in the logs."""
    return Response(status_code=204)


def _is_admin_authorized(request: Request) -> bool:
    """Check whether the request carries valid Admin API Key credentials."""
    if not API_KEY and not REQUIRE_API_KEY:
        return True
    if not API_KEY:
        return False

    key = (
        request.headers.get("X-API-Key")
        or request.query_params.get("key")
        or request.query_params.get("api_key")
        or request.cookies.get("terabridge_admin_key")
    )
    if not key:
        auth_h = request.headers.get("Authorization") or ""
        if auth_h.startswith("Bearer "):
            key = auth_h[7:].strip()

    import hmac
    if key and hmac.compare_digest(key, API_KEY):
        return True
    return False


_ADMIN_LOCK_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>TeraBridge — Cloudvids Manager (Admin Access)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", system-ui, sans-serif;
      background: #000000;
      color: #F5F5F7;
    }
    .glass-card {
      background: rgba(26, 26, 32, 0.75);
      backdrop-filter: blur(28px) saturate(180%);
      border: 0.5px solid rgba(255, 255, 255, 0.12);
      border-radius: 20px;
      box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.7);
    }
  </style>
</head>
<body class="flex items-center justify-center min-h-screen p-4">
  <div class="glass-card max-w-md w-full p-8 text-center space-y-6">
    <div class="w-14 h-14 bg-gradient-to-tr from-[#0A84FF] to-[#64D2FF] rounded-2xl mx-auto flex items-center justify-center shadow-lg shadow-[#0A84FF]/25">
      <svg class="w-7 h-7 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
      </svg>
    </div>
    <div>
      <h1 class="text-xl font-semibold tracking-tight text-white">TeraBridge</h1>
      <p class="text-xs text-white/50 mt-1 uppercase tracking-wider font-medium">Cloudvids Manager — Admin Console</p>
    </div>
    <form id="loginForm" onsubmit="handleLogin(event)" class="space-y-4">
      <div>
        <input id="keyInput" type="password" placeholder="Enter Admin API Key (X-API-Key)" required
          class="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-sm text-white placeholder-white/30 focus:outline-none focus:border-[#0A84FF] focus:ring-1 focus:ring-[#0A84FF] transition-all" />
      </div>
      <button type="submit"
        class="w-full py-3 bg-[#0A84FF] hover:bg-[#0077ED] active:scale-[0.98] text-white font-medium text-sm rounded-xl transition-all shadow-md shadow-[#0A84FF]/20">
        Unlock Dashboard
      </button>
      <p id="errorMsg" class="text-xs text-[#FF453A] hidden">Invalid key format or authentication rejected.</p>
    </form>
    <p class="text-[11px] text-white/30">Protected by TeraBridge secure HMAC & session safeguards.</p>
  </div>
  <script>
    function handleLogin(e) {
      e.preventDefault();
      const val = document.getElementById('keyInput').value.trim();
      if (!val) return;
      sessionStorage.setItem('terabridge_api_key', val);
      document.cookie = 'terabridge_admin_key=' + encodeURIComponent(val) + '; Path=/; Max-Age=2592000; SameSite=Lax';
      window.location.href = window.location.pathname + '?key=' + encodeURIComponent(val);
    }
  </script>
</body>
</html>"""


@app.get("/admin", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard(request: Request):
    if not _is_admin_authorized(request):
        return HTMLResponse(_ADMIN_LOCK_HTML, status_code=200)

    dashboard_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "dashboard.html")
    if os.path.exists(dashboard_path):
        resp = FileResponse(dashboard_path, media_type="text/html")
        key = request.query_params.get("key") or request.query_params.get("api_key")
        if key:
            resp.set_cookie("terabridge_admin_key", key, max_age=2592000, httponly=True, samesite="lax")
        return resp
    return HTMLResponse("<h3>Dashboard file not found.</h3>", status_code=404)


# ─── Dev server entry point ──────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting TeraBridge API on 0.0.0.0:%d", port)
    uvicorn.run("api.index:app", host="0.0.0.0", port=port, reload=False, workers=1)
