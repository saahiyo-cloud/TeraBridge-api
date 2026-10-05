"""
api/middleware.py — Request-level helpers and middleware for TeraBridge API.

Contains:
  - SSRF protection helpers (_is_allowed_stream_host, _validate_safe_outbound_url)
  - Client-IP resolution (handles Vercel, Render, and custom trusted-proxy CIDRs)
  - Base-URL helper for building absolute proxy URLs
  - ConfigRefreshMiddleware — periodically reloads credentials from Redis
"""
import ipaddress
import logging
import time
import urllib.parse

import httpx
from fastapi import HTTPException, Request

from api.config import (
    ALLOWED_STREAM_SUFFIXES,
    CONFIG_CHECK_INTERVAL,
    ON_RENDER,
    ON_VERCEL,
    TRUSTED_PROXY_CIDRS,
)

logger = logging.getLogger("terabridge.middleware")

# ─── SSRF protection ─────────────────────────────────────────────────

def _is_allowed_stream_host(host: str) -> bool:
    if not host:
        return False
    host = host.lower()
    for suffix in ALLOWED_STREAM_SUFFIXES:
        if suffix.startswith("."):
            if host == suffix[1:] or host.endswith(suffix):
                return True
        elif host == suffix:
            return True
    return False


def _is_private_or_local_host(hostname: str) -> bool:
    if not hostname:
        return True
    hostname = hostname.lower()
    if (
        hostname in ("localhost", "127.0.0.1", "::1", "metadata.google.internal")
        or hostname.endswith(".local")
    ):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    except ValueError:
        pass
    return False


def validate_safe_outbound_url(target_url: str) -> bool:
    """Return True iff ``target_url`` is a safe, allowlisted outbound destination."""
    try:
        parsed = urllib.parse.urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname or _is_private_or_local_host(hostname):
            return False
        return _is_allowed_stream_host(hostname)
    except Exception:
        return False


async def check_safe_redirect(response: httpx.Response):
    """httpx event hook — blocks redirects to non-allowlisted hosts."""
    if response.is_redirect and "location" in response.headers:
        loc = response.headers["location"]
        if loc.startswith("http://") or loc.startswith("https://"):
            if not validate_safe_outbound_url(loc):
                logger.warning("[SSRF] Prohibited redirect destination blocked: %s", loc)
                raise HTTPException(
                    status_code=403,
                    detail="Redirect to untrusted destination blocked.",
                )


# ─── IP resolution ────────────────────────────────────────────────────

_LOOPBACK_CIDRS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


def _peer_ip(request: Request):
    addr = request.client.host if request.client else None
    if not addr:
        return None
    try:
        return ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return None


def _is_trusted_peer(request: Request, peer=None) -> bool:
    if ON_VERCEL or ON_RENDER:
        return True
    if peer is None:
        peer = _peer_ip(request)
    if peer is None:
        return False
    if any(peer in cidr for cidr in _LOOPBACK_CIDRS):
        return True
    if TRUSTED_PROXY_CIDRS and any(peer in cidr for cidr in TRUSTED_PROXY_CIDRS):
        return True
    return False


def _resolve_client_ip(request: Request) -> str:
    if ON_VERCEL:
        v = request.headers.get("X-Vercel-Forwarded-For")
        if v:
            return v.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    peer = _peer_ip(request)
    if peer is None:
        return request.client.host if request.client else "unknown"

    if not _is_trusted_peer(request, peer):
        return str(peer)

    xff = request.headers.get("X-Forwarded-For", "")
    if not xff:
        return str(peer)

    if ON_RENDER or (
        not TRUSTED_PROXY_CIDRS and any(peer in c for c in _LOOPBACK_CIDRS)
    ):
        return xff.split(",")[-1].strip()

    chain = [h.strip() for h in xff.split(",") if h.strip()]
    candidate = str(peer)
    for hop in reversed(chain):
        try:
            hop_ip = ipaddress.ip_address(hop.split("%")[0])
        except ValueError:
            return hop
        if any(hop_ip in cidr for cidr in TRUSTED_PROXY_CIDRS):
            continue
        return str(hop_ip)
    return candidate


def client_ip(request: Request) -> str:
    """Return the real client IP, respecting trusted proxy headers."""
    cached = getattr(request.state, "_cached_client_ip", None)
    if cached is not None:
        return cached
    resolved = _resolve_client_ip(request)
    request.state._cached_client_ip = resolved
    return resolved


def request_base_url(request: Request) -> str:
    """Return the scheme+host base URL for building absolute proxy URLs."""
    scheme = request.url.scheme
    if ON_RENDER or ON_VERCEL:
        scheme = "https"
    elif _is_trusted_peer(request):
        forwarded_proto = request.headers.get("X-Forwarded-Proto")
        if forwarded_proto:
            scheme = forwarded_proto.split(",")[0].strip()
    return f"{scheme}://{request.url.netloc}"


# ─── Dynamic config refresh middleware ───────────────────────────────

_last_config_check: float = 0.0
_config_loader = None  # injected at startup via set_config_loader()


def set_config_loader(loader_fn):
    """Register the credential-reload callable. Called once during app startup."""
    global _config_loader
    _config_loader = loader_fn


class ConfigRefreshMiddleware:
    """
    Starlette-compatible ASGI middleware that periodically reloads Terabox
    credentials from Redis without blocking the event loop.

    The reload callable is registered via :func:`set_config_loader` at startup
    to avoid circular imports at module load time.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("method") != "OPTIONS":
            global _last_config_check
            now = time.time()
            if now - _last_config_check > CONFIG_CHECK_INTERVAL and _config_loader:
                _config_loader()
                _last_config_check = now
        await self.app(scope, receive, send)


class LogQueryTruncateMiddleware:
    """
    Truncates exceptionally long query strings (like /api/thumbnail?url=https://dm-data...)
    in ASGI scope before Uvicorn formats the access log line.
    """

    def __init__(self, app, max_len: int = 40):
        self.app = app
        self.max_len = max_len

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            raw_qs = scope.get("query_string", b"")
            path = scope.get("path", "")
            if path in ("/api/thumbnail", "/api/stream/thumbnail") and raw_qs:
                # Keep a short clean preview in Uvicorn access log (e.g. ?url=https://dm-data...[truncated])
                if len(raw_qs) > self.max_len:
                    original_qs = raw_qs
                    # Store original on scope for route handlers
                    scope["original_query_string"] = original_qs
                    shortened = raw_qs[:self.max_len] + b"..."
                    scope["query_string"] = shortened

                    async def wrapped_receive():
                        return await receive()

                    try:
                        await self.app(scope, receive, send)
                    finally:
                        scope["query_string"] = original_qs
                    return
        await self.app(scope, receive, send)
