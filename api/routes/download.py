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
from fastapi.responses import JSONResponse, Response, StreamingResponse

from api.auth import check_auth
from api.cache import cache
from api.middleware import client_ip, validate_safe_outbound_url
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


# ─── /api/download ───────────────────────────────────────────────────

@router.api_route("/api/download", methods=["GET", "OPTIONS"])
async def download_file_route(request: Request):
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
        return JSONResponse(
            {"status": "error", "message": "Unauthorized: Invalid signature or API key."},
            status_code=401,
        )

    share_url = f"https://1024terabox.com/s/{surl}"

    # Resolve (with cache)
    cached_res = cache.get(share_url, "d", False)
    if not cached_res:
        try:
            cached_res = await resolve_link_with_retry(share_url, action="d")
            if cached_res.get("errno") == 0:
                is_transcoding = any(
                    f.get("error") == "transcoding_in_progress"
                    for f in cached_res.get("files", [])
                )
                if not is_transcoding:
                    cache.put(share_url, "d", False, cached_res)
        except Exception as exc:
            return JSONResponse(
                {"status": "error", "message": f"Failed to resolve download details: {exc}"},
                status_code=500,
            )

    if cached_res.get("errno") != 0:
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

    if target_file.get("error"):
        return JSONResponse(
            {"status": "error", "message": f"File resolution error: {target_file['error']}"},
            status_code=400,
        )

    dlink = target_file.get("dlink")
    filename = target_file.get("filename") or "download"
    if not dlink:
        return JSONResponse(
            {"status": "error", "message": "Download link not available for this file."},
            status_code=404,
        )

    try:
        headers = {"User-Agent": UA, "Referer": "https://dm.1024terabox.com/"}
        file_size = target_file.get("size_bytes")
        range_header = request.headers.get("Range")
        quoted_filename = urllib.parse.quote(filename)

        # Multi-connection stream for large files (> 4 MB)
        if file_size and file_size > 4 * 1024 * 1024:
            start, end, status_code = 0, file_size - 1, 200

            if range_header:
                m = re.match(r"bytes=(\d+)-(\d*)", range_header.strip())
                if m:
                    start = int(m.group(1))
                    if m.group(2):
                        end = min(int(m.group(2)), file_size - 1)
                    status_code = 206

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
            )
            return StreamingResponse(stream_gen, status_code=status_code, headers=resp_headers)

        # Single-stream fallback for small files
        if range_header:
            headers["Range"] = range_header

        client = _proxy_client
        req_ctx = client.stream("GET", dlink, headers=headers, cookies=COOKIES_DICT, timeout=120.0)
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
        return JSONResponse(
            {"status": "error", "message": f"Download proxy error: {exc}"},
            status_code=500,
        )


# ─── /api/thumbnail ──────────────────────────────────────────────────

@router.api_route("/api/thumbnail",        methods=["GET", "OPTIONS"])
@router.api_route("/api/stream/thumbnail", methods=["GET", "OPTIONS"])
async def stream_thumbnail(request: Request):
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
            return JSONResponse(
                {"status": "error", "message": "Unauthorized: Invalid signature or API key."},
                status_code=401,
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
            return JSONResponse(
                {"status": "error", "message": "Unauthorized: Invalid signature or API key."},
                status_code=401,
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
        r = await client.get(url, headers={"User-Agent": UA}, timeout=25.0)
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
