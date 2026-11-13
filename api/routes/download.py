"""
api/routes/download.py — File download proxy.

Routes:
  GET /api/download    — proxies file bytes, supports Range headers
  GET /api/thumbnail   — proxies thumbnail images
  GET /api/stream/thumbnail — alias
"""
import hashlib
import logging
import re
import urllib.parse

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse

from api.auth import check_auth
from api.cache import cache
from api.middleware import client_ip, validate_safe_outbound_url
from api.rate_limiter import rate_limiter
from api.signing import make_signed_params, verify_signature
from downloader import UA, COOKIES_DICT, multi_connection_stream_generator, parse_surl
from api.routes.resolve import resolve_link_with_retry

logger = logging.getLogger("terabridge.routes.download")
router = APIRouter()

# ── Shared proxy client (injected from index.py at startup) ───────────
_proxy_client: httpx.AsyncClient | None = None


def set_proxy_client(client: httpx.AsyncClient):
    global _proxy_client
    _proxy_client = client


def _get_active_client() -> httpx.AsyncClient:
    global _proxy_client
    if _proxy_client is None or _proxy_client.is_closed:
        try:
            from api.index import get_proxy_client
            _proxy_client = get_proxy_client()
        except Exception:
            _proxy_client = httpx.AsyncClient(follow_redirects=True, timeout=120.0)
    return _proxy_client


def parse_byte_range(range_header: str | None, file_size: int | None) -> tuple[int, int, int] | None:
    """
    Parses an RFC 9110 / RFC 7233 Range header against known file_size.
    Returns:
        (start, end, status_code) where status_code is 200 (full content) or 206 (partial range).
        Returns None if range is unsatisfiable (must return HTTP 416).
    """
    if not file_size or file_size <= 0:
        return (0, 0, 200)

    if not range_header or not range_header.strip():
        return (0, file_size - 1, 200)

    header = range_header.strip()
    if not header.startswith("bytes="):
        # Unknown unit: RFC 9110 specifies servers MUST ignore unrecognized units and return full content
        return (0, file_size - 1, 200)

    spec = header[6:].split(",")[0].strip()

    # Suffix byte range: "-N" (last N bytes of the file)
    if spec.startswith("-"):
        try:
            suffix_len = int(spec[1:])
            if suffix_len <= 0:
                return None
            start = max(0, file_size - suffix_len)
            end = file_size - 1
            return (start, end, 206)
        except ValueError:
            return (0, file_size - 1, 200)

    # Standard range: "N-M" or "N-"
    if "-" in spec:
        parts = spec.split("-", 1)
        try:
            start = int(parts[0])
            if start < 0 or start >= file_size:
                # First byte position is beyond end of representation -> 416 Unsatisfiable
                return None
            if parts[1].strip():
                end = int(parts[1])
                if end < start:
                    # Invalid range: end before start -> 416 Unsatisfiable
                    return None
                end = min(end, file_size - 1)
            else:
                end = file_size - 1
            return (start, end, 206)
        except ValueError:
            return (0, file_size - 1, 200)

    return (0, file_size - 1, 200)


# ─── /api/download ───────────────────────────────────────────────────

@router.api_route("/api/download", methods=["GET", "OPTIONS"])
async def download_file_route(request: Request):
    ip = client_ip(request)

    # 1. Rate limiting check (evaluated before auth to prevent brute force)
    if not await rate_limiter.is_allowed_async(ip):
        return JSONResponse(
            {"status": "error", "message": "Rate limit exceeded. Try again shortly."},
            status_code=429,
            headers=rate_limiter.get_headers(ip, is_blocked=True),
        )

    # 2. Check auth failure lockout
    if not await rate_limiter.is_auth_allowed_async(ip):
        return JSONResponse(
            {"status": "error", "message": "Too many failed authentication attempts. Access temporarily locked."},
            status_code=429,
            headers=rate_limiter.get_auth_headers(ip),
        )

    surl  = request.query_params.get("surl")  or ""
    fs_id = request.query_params.get("fs_id") or ""
    sig   = request.query_params.get("sig")   or ""
    exp   = request.query_params.get("exp")   or ""

    if not surl or not fs_id:
        return JSONResponse(
            {"status": "error", "message": "Missing required parameters: 'surl' and 'fs_id'."},
            status_code=400,
        )

    if not (sig and verify_signature(surl, fs_id, "", sig, exp)) and not await check_auth(request):
        await rate_limiter.record_auth_failure_async(ip)
        return JSONResponse(
            {"status": "error", "message": "Unauthorized: Invalid signature or API key."},
            status_code=401,
            headers=rate_limiter.get_headers(ip),
        )

    link = request.query_params.get("url") or request.query_params.get("link") or f"https://1024terabox.com/s/{surl}"

    # Resolve (with cache)
    cached_res = cache.get(link, "raw:d", False) or cache.get(link, "raw:both", False) or cache.get(link, "d", False)
    if not cached_res or not _find_file(cached_res.get("files", []), fs_id):
        try:
            cached_res = await resolve_link_with_retry(link, action="d")
            if cached_res.get("errno") == 0:
                is_transcoding = any(
                    f.get("error") == "transcoding_in_progress"
                    for f in cached_res.get("files", [])
                )
                if not is_transcoding:
                    cache.put(link, "raw:d", False, cached_res)
        except Exception as exc:
            logger.exception("Failed to resolve download details for surl=%s: %s", surl, exc)
            return JSONResponse(
                {"status": "error", "message": "Failed to resolve download details from upstream service."},
                status_code=500,
            )

    if cached_res.get("errno", 0) != 0 and cached_res.get("status") != "success":
        return JSONResponse(
            {"status": "error", "message": cached_res.get("error", "Failed to resolve share link.")},
            status_code=400,
        )

    target_file = _find_file(cached_res.get("files", []), fs_id)
    if not target_file:
        return JSONResponse(
            {"status": "error", "message": "File not found in share link."},
            status_code=404,
        )

    dlink = target_file.get("dlink")
    # If dlink is still a self-referencing proxy link from response_data, resolve raw upstream
    if not dlink or "/api/download" in dlink:
        fresh_res = await resolve_link_with_retry(link, action="d")
        if fresh_res.get("errno") == 0:
            cached_res = fresh_res
            cache.put(link, "raw:d", False, cached_res)
            target_file = _find_file(cached_res.get("files", []), fs_id)
            dlink = target_file.get("dlink") if target_file else None

    if target_file and target_file.get("error"):
        return JSONResponse(
            {"status": "error", "message": f"File resolution error: {target_file['error']}"},
            status_code=400,
        )

    filename = target_file.get("filename") if target_file else "download"
    if not dlink:
        return JSONResponse(
            {"status": "error", "message": "Download link not available for this file."},
            status_code=404,
        )

    from api.config import PROXY_DOWNLOADS
    if not PROXY_DOWNLOADS:
        return RedirectResponse(url=dlink, status_code=307)

    try:
        headers = {"User-Agent": UA, "Referer": "https://dm.1024terabox.com/"}
        file_size = target_file.get("size_bytes")
        range_header = request.headers.get("Range")
        quoted_filename = urllib.parse.quote(filename)

        async def dlink_refresher() -> str | None:
            """Callback to refresh expired dlink mid-download on upstream 403/410."""
            try:
                cache.invalidate(link, "d", False)
                fresh_res = await resolve_link_with_retry(link, "d", False, None)
                if fresh_res.get("errno") == 0:
                    fresh_file = _find_file(fresh_res.get("files", []), fs_id)
                    if fresh_file and fresh_file.get("dlink"):
                        cache.put(link, "d", False, fresh_res)
                        return fresh_file.get("dlink")
            except Exception as e:
                logger.warning("Failed to refresh dlink during download: %s", e)
            return None

        # Multi-connection stream for large files (> 4 MB)
        if file_size and file_size > 4 * 1024 * 1024:
            if range_header:
                range_info = parse_byte_range(range_header, file_size)
                if range_info is None:
                    return JSONResponse(
                        {"status": "error", "message": "Requested range not satisfiable."},
                        status_code=416,
                        headers={"Content-Range": f"bytes */{file_size}"},
                    )
                start, end, status_code = range_info
            else:
                start, end, status_code = 0, file_size - 1, 200

            content_len = end - start + 1
            resp_headers = {
                "Content-Length":       str(content_len),
                "Content-Type":         "application/octet-stream",
                "Accept-Ranges":        "bytes",
                "Content-Disposition":  f"attachment; filename*=UTF-8''{quoted_filename}",
                "Access-Control-Allow-Origin":  "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
            }
            if status_code == 206:
                resp_headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"

            stream_gen = multi_connection_stream_generator(
                dlink=dlink,
                start_byte=start,
                end_byte=end,
                headers=headers,
                cookies=COOKIES_DICT,
                concurrency=4,
                chunk_size=2 * 1024 * 1024,
                dlink_refresher=dlink_refresher,
            )
            return StreamingResponse(stream_gen, status_code=status_code, headers=resp_headers)

        # Single-stream fallback for small files
        if range_header and file_size:
            range_info = parse_byte_range(range_header, file_size)
            if range_info is None:
                return JSONResponse(
                    {"status": "error", "message": "Requested range not satisfiable."},
                    status_code=416,
                    headers={"Content-Range": f"bytes */{file_size}"},
                )
            s_byte, e_byte, sc = range_info
            if sc == 206:
                headers["Range"] = f"bytes={s_byte}-{e_byte}"
        elif range_header:
            headers["Range"] = range_header

        client = _get_active_client()
        req_ctx = client.stream("GET", dlink, headers=headers, cookies=COOKIES_DICT, timeout=httpx.Timeout(120.0, connect=5.0))
        req = await req_ctx.__aenter__()

        resp_headers = {}
        for key in ("Content-Length", "Content-Type", "Content-Range", "Accept-Ranges"):
            if key in req.headers:
                resp_headers[key] = req.headers[key]
        if "Content-Type" not in resp_headers:
            resp_headers["Content-Type"] = "application/octet-stream"
        resp_headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quoted_filename}"
        resp_headers.update({
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
        })

        async def generate():
            try:
                async for chunk in req.aiter_bytes(chunk_size=524288):
                    yield chunk
            finally:
                await req_ctx.__aexit__(None, None, None)

        return StreamingResponse(generate(), status_code=req.status_code, headers=resp_headers)

    except Exception as exc:
        logger.exception("Download proxy error for surl=%s: %s", surl, exc)
        return JSONResponse(
            {"status": "error", "message": "Download proxy streaming error."},
            status_code=500,
        )


# ─── /api/thumbnail ──────────────────────────────────────────────────

@router.api_route("/api/thumbnail",        methods=["GET", "OPTIONS"])
@router.api_route("/api/stream/thumbnail", methods=["GET", "OPTIONS"])
async def stream_thumbnail(request: Request):
    ip = client_ip(request)

    # 1. Media rate limit check (evaluated before auth to prevent brute force)
    if not await rate_limiter.is_media_allowed_async(ip):
        return JSONResponse(
            {"status": "error", "message": "Rate limit exceeded for thumbnail requests. Please slow down."},
            status_code=429,
            headers=rate_limiter.get_headers(ip, max_override=rate_limiter._media_max, is_blocked=True),
        )

    # 2. Check auth failure lockout
    if not await rate_limiter.is_auth_allowed_async(ip):
        return JSONResponse(
            {"status": "error", "message": "Too many failed authentication attempts. Access temporarily locked."},
            status_code=429,
            headers=rate_limiter.get_auth_headers(ip),
        )

    url       = request.query_params.get("url")       or ""
    surl      = request.query_params.get("surl")      or ""
    fs_id     = request.query_params.get("fs_id")     or ""
    size_type = (
        request.query_params.get("size_type")
        or request.query_params.get("size")
        or "url3"
    )
    sig = request.query_params.get("sig") or ""
    exp = request.query_params.get("exp") or ""

    if not url and not (surl and fs_id):
        return JSONResponse(
            {"status": "error", "message": "Missing required: 'url' or 'surl' + 'fs_id'."},
            status_code=400,
        )

    if not url:
        # Resolve via surl+fs_id
        if not (sig and verify_signature(surl, fs_id, size_type, sig, exp)) and not await check_auth(request):
            await rate_limiter.record_auth_failure_async(ip)
            return JSONResponse(
                {"status": "error", "message": "Unauthorized: Invalid signature or API key."},
                status_code=401,
                headers=rate_limiter.get_headers(ip),
            )

        share_url = f"https://1024terabox.com/s/{surl}"
        cached_res = cache.get(share_url, "l", False)
        if not cached_res:
            try:
                cached_res = await resolve_link_with_retry(share_url, action="l")
                if cached_res.get("errno") == 0:
                    cache.put(share_url, "l", False, cached_res)
            except Exception as exc:
                return JSONResponse(
                    {"status": "error", "message": f"Failed to resolve thumbnail: {exc}"},
                    status_code=500,
                )

        if cached_res.get("errno") != 0:
            return JSONResponse(
                {"status": "error", "message": "Failed to query share content."},
                status_code=400,
            )

        matching = _find_file(cached_res.get("files", []), fs_id)
        if not matching or not matching.get("thumbnails"):
            return JSONResponse(
                {"status": "error", "message": "Thumbnail not found."},
                status_code=404,
            )

        url = matching["thumbnails"].get(size_type) or next(
            iter(matching["thumbnails"].values()), None
        )
        if not url:
            return JSONResponse(
                {"status": "error", "message": "Thumbnail not available."},
                status_code=404,
            )

    else:
        # Direct URL path
        if not (sig and verify_signature(url, "", "", sig, exp)) and not await check_auth(request):
            await rate_limiter.record_auth_failure_async(ip)
            return JSONResponse(
                {"status": "error", "message": "Unauthorized: Invalid signature or API key."},
                status_code=401,
                headers=rate_limiter.get_headers(ip),
            )
        if not validate_safe_outbound_url(url):
            return JSONResponse(
                {"status": "error", "message": "Forbidden: Invalid thumbnail host."},
                status_code=403,
            )

    # ── Multi-Tier Thumbnail Caching (Browser Cache-Control + Redis / Memory) ─
    cache_lookup_key = url if url else f"{surl}:{fs_id}:{size_type}"
    etag = f'"{hashlib.md5(cache_lookup_key.encode("utf-8")).hexdigest()}"'

    # Check browser conditional If-None-Match header for 304 Not Modified
    client_etag = request.headers.get("if-none-match")
    if client_etag and client_etag.strip() == etag:
        return Response(
            status_code=304,
            headers={
                "ETag": etag,
                "Cache-Control": "public, max-age=86400, stale-while-revalidate=604800, immutable",
                "Access-Control-Allow-Origin": "*",
            },
        )

    # Check server-side cache (Redis / In-Memory)
    cached_thumb = cache.get_thumbnail(cache_lookup_key)
    if cached_thumb is not None:
        thumb_bytes, content_type = cached_thumb
        return Response(
            content=thumb_bytes,
            media_type=content_type,
            headers={
                "Content-Length": str(len(thumb_bytes)),
                "Content-Type": content_type,
                "Cache-Control": "public, max-age=86400, stale-while-revalidate=604800, immutable",
                "ETag": etag,
                "X-Cache": "HIT",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
            },
        )

    client = _proxy_client
    try:
        r = await client.get(url, headers={"User-Agent": UA}, timeout=httpx.Timeout(25.0, connect=5.0))
        if r.status_code == 200:
            thumb_data = r.content
            ct = r.headers.get("Content-Type", "image/jpeg")
            cache.put_thumbnail(cache_lookup_key, thumb_data, ct)
            return Response(
                content=thumb_data,
                media_type=ct,
                headers={
                    "Content-Length": str(len(thumb_data)),
                    "Content-Type": ct,
                    "Cache-Control": "public, max-age=86400, stale-while-revalidate=604800, immutable",
                    "ETag": etag,
                    "X-Cache": "MISS",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                },
            )
        else:
            return JSONResponse(
                {"status": "error", "message": f"Upstream CDN returned status {r.status_code}"},
                status_code=r.status_code,
            )

    except httpx.HTTPError as exc:
        logger.debug("Upstream thumbnail fetch failed: %s", exc)
        return JSONResponse({"status": "error", "message": "Failed to fetch thumbnail from upstream CDN."}, status_code=502)
    except Exception as exc:
        logger.warning("Thumbnail proxy error: %s", exc)
        return JSONResponse({"status": "error", "message": "Thumbnail unavailable."}, status_code=500)


# ─── Helpers ─────────────────────────────────────────────────────────

def _find_file(files: list, fs_id: str) -> dict | None:
    for f in files:
        if str(f.get("original_fs_id")) == str(fs_id) or str(f.get("fs_id")) == str(fs_id):
            return f
    return None
