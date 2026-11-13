"""
api/middleware.py — Request-level helpers and middleware for TeraBridge API.

Contains:
  - SSRF protection helpers (_is_allowed_stream_host, _validate_safe_outbound_url)
  - Client-IP resolution (handles Vercel, Render, and custom trusted-proxy CIDRs)
  - Base-URL helper for building absolute proxy URLs
  - ConfigRefreshMiddleware — periodically reloads credentials from Redis
"""
import asyncio
import ipaddress
import json
import logging
import time
import urllib.parse

import httpx
from fastapi import HTTPException, Request, Response
from starlette.datastructures import MutableHeaders

from api.config import (
    ALLOWED_STREAM_SUFFIXES,
    CONFIG_CHECK_INTERVAL,
    MAX_REQUEST_BODY_SIZE_BYTES,
    ON_RENDER,
    ON_VERCEL,
    REQUEST_TIMEOUT_SECONDS,
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
_PRIVATE_PROXY_CIDRS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
)


# Published Cloudflare edge ranges (https://www.cloudflare.com/ips/).
_CLOUDFLARE_CIDRS = tuple(
    ipaddress.ip_network(c)
    for c in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    )
)


def _parse_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip().split("%")[0])
    except ValueError:
        return None


def _is_cloudflare(ip) -> bool:
    return ip is not None and any(ip in cidr for cidr in _CLOUDFLARE_CIDRS)


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
    if any(peer in cidr for cidr in _LOOPBACK_CIDRS) or any(peer in cidr for cidr in _PRIVATE_PROXY_CIDRS):
        return True
    # A Cloudflare edge as peer: either Cloudflare connects directly, or the
    # ASGI server's proxy-headers handling already rewrote the peer to the
    # last XFF hop (it only does so for its own trusted forwarders).
    if _is_cloudflare(peer):
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
    chain = [h.strip() for h in xff.split(",") if h.strip()]

    # Cloudflare in front of the platform proxy: the right-most XFF hop (or the
    # peer) is a Cloudflare edge node, whose address changes from request to
    # request. Keying the rate limiter on it splits one client across many
    # counters. CF-Connecting-IP carries the real client, and is only honoured
    # when the immediate upstream really is a Cloudflare address, so a client
    # that reaches the origin some other way cannot forge it.
    # Note: uvicorn/gunicorn's proxy-headers support may already have replaced
    # the peer with the right-most XFF hop (the edge node), so check both.
    cf_client = request.headers.get("CF-Connecting-IP", "").strip()
    if cf_client:
        upstream = _parse_ip(chain[-1]) if chain else peer
        client = _parse_ip(cf_client)
        if client is not None and (_is_cloudflare(upstream) or _is_cloudflare(peer)):
            return str(client)

    if not chain:
        return str(peer)

    # Walk the chain from the proxy side: skip our own trusted proxies and
    # Cloudflare edge hops; the first remaining hop is the client.
    for hop in reversed(chain):
        hop_ip = _parse_ip(hop)
        if hop_ip is None:
            return hop
        if _is_cloudflare(hop_ip) or any(hop_ip in cidr for cidr in TRUSTED_PROXY_CIDRS):
            continue
        return str(hop_ip)
    return str(peer)


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
    else:
        forwarded_proto = request.headers.get("X-Forwarded-Proto")
        cf_visitor = request.headers.get("CF-Visitor")
        if forwarded_proto:
            scheme = forwarded_proto.split(",")[0].strip()
        elif cf_visitor and '"scheme":"https"' in cf_visitor:
            scheme = "https"
        elif request.headers.get("X-Forwarded-Ssl") == "on":
            scheme = "https"
        elif _is_trusted_peer(request):
            netloc = request.url.netloc.lower()
            if not (netloc.startswith("localhost") or netloc.startswith("127.0.0.1")):
                scheme = "https"
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
                _last_config_check = now
                try:
                    import asyncio
                    asyncio.create_task(asyncio.to_thread(_config_loader))
                except Exception:
                    pass
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


def is_https_request(request: Request) -> bool:
    """True when the client connection is HTTPS, trusting proxy headers only from trusted peers."""
    if request.url.scheme == "https" or ON_RENDER or ON_VERCEL:
        return True
    if not _is_trusted_peer(request):
        return False
    proto = request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
    if proto:
        return proto == "https"
    return '"scheme":"https"' in request.headers.get("CF-Visitor", "").replace(" ", "")


_HSTS_VALUE = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware:
    """
    Adds baseline security headers to every response (API, dashboard, errors):
    X-Content-Type-Options, Referrer-Policy, X-Frame-Options and CSP frame-ancestors.
    Adds Strict-Transport-Security only when the request arrived over HTTPS.
    Headers already set by a route are left untouched.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                defaults = {
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "X-Frame-Options": "DENY",
                    "Content-Security-Policy": "frame-ancestors 'none'",
                }
                try:
                    if is_https_request(Request(scope)):
                        defaults["Strict-Transport-Security"] = _HSTS_VALUE
                except Exception:
                    pass
                for name, value in defaults.items():
                    if name not in headers:
                        headers[name] = value
            await send(message)

        await self.app(scope, receive, send_wrapper)


class AnalyticsMetricsMiddleware:
    """
    Lightweight ASGI middleware that tracks request volume, route distribution,
    HTTP status codes, and latency in api.metrics.

    Must sit outside RequestTimeoutMiddleware and RequestBodyLimitMiddleware so
    the 504 / 413 responses they send pass through ``send_wrapper``. An
    exception that escapes before any response started is recorded as 500,
    because Starlette's ServerErrorMiddleware (outermost) will answer with 500.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.time()
        status_code = None

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            if status_code is None:
                status_code = 500
            raise
        finally:
            if status_code is None:
                # Cancelled / disconnected before a response was started.
                status_code = 499
            path = scope.get("path", "")
            method = scope.get("method", "GET")
            duration_ms = (time.time() - start_time) * 1000.0
            try:
                from api.metrics import record_request
                record_request(path, method, status_code, duration_ms)
            except Exception:
                pass


class RequestBodyLimitMiddleware:
    """
    Guards the server against oversized payloads and memory exhaustion attacks.
    Immediately rejects requests whose Content-Length or streaming body exceeds
    MAX_REQUEST_BODY_SIZE_BYTES with 413 Payload Too Large.
    """

    def __init__(self, app, max_body_size: int = MAX_REQUEST_BODY_SIZE_BYTES):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            content_length = headers.get(b"content-length")
            if content_length:
                try:
                    if int(content_length) > self.max_body_size:
                        limit_mb = self.max_body_size // (1024 * 1024)
                        response = Response(
                            content=json.dumps({
                                "status": "error",
                                "message": f"Payload Too Large: Request body exceeds {limit_mb} MB limit.",
                            }),
                            status_code=413,
                            media_type="application/json",
                        )
                        await response(scope, receive, send)
                        return
                except (ValueError, TypeError):
                    pass

            # Count stream body chunks for chunked transfers without content-length
            received_bytes = 0

            async def wrapped_receive():
                nonlocal received_bytes
                message = await receive()
                if message.get("type") == "http.request":
                    body = message.get("body", b"")
                    received_bytes += len(body)
                    if received_bytes > self.max_body_size:
                        raise HTTPException(
                            status_code=413,
                            detail=f"Payload Too Large: Request stream exceeded {self.max_body_size} bytes limit.",
                        )
                return message

            await self.app(scope, wrapped_receive, send)
            return

        await self.app(scope, receive, send)


class RequestTimeoutMiddleware:
    """
    Guards API routes against slowloris-style connection holding and hanging requests.
    Cancels non-streaming API requests that exceed REQUEST_TIMEOUT_SECONDS with 504.
    """

    STREAMING_PATHS = (
        "/api/download",
        "/api/stream/segment",
        "/api/stream/segment.ts",
        "/api/admin/cloudvids/stream",
    )

    def __init__(self, app, timeout_seconds: float = REQUEST_TIMEOUT_SECONDS):
        self.app = app
        self.timeout_seconds = float(timeout_seconds)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        # Streaming file chunks can take longer legitimately, exempt them
        if any(path.startswith(sp) for sp in self.STREAMING_PATHS):
            await self.app(scope, receive, send)
            return

        try:
            async with asyncio.timeout(self.timeout_seconds):
                await self.app(scope, receive, send)
        except (asyncio.TimeoutError, TimeoutError):
            logger.warning("[Timeout] Request to %s exceeded %.1fs timeout", path, self.timeout_seconds)
            response = Response(
                content=json.dumps({
                    "status": "error",
                    "message": f"Gateway Timeout: Request execution exceeded {int(self.timeout_seconds)}s limit.",
                }),
                status_code=504,
                media_type="application/json",
            )
            await response(scope, receive, send)


