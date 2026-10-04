"""
api/routes/stream.py — HLS streaming proxy routes.

Routes:
  GET /api/stream/manifest       — multivariant master playlist
  GET /api/stream/playlist.m3u8  — alias for manifest
  GET /api/stream/segment        — .ts segment proxy
  GET /api/stream/segment.ts     — alias for segment
"""
import asyncio
import json
import logging
import urllib.parse

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse

from api.auth import check_auth
from api.cache import cache
from api.config import RATE_LIMIT_RPM, REDIRECT_SEGMENTS
from api.middleware import client_ip, request_base_url, validate_safe_outbound_url
from api.rate_limiter import rate_limiter
from api.redis_client import redis_client
from api.signing import make_signed_params, verify_signature
from downloader import UA, VIDEO_EXTS, parse_surl
from api.routes.resolve import resolve_link_with_retry

logger = logging.getLogger("terabridge.routes.stream")
router = APIRouter()

# ── Shared proxy client (injected from index.py at startup) ───────────
_proxy_client: httpx.AsyncClient | None = None

QUALITIES_MAP = {
    "1080p": "M3U8_AUTO_1080",
    "720p":  "M3U8_AUTO_720",
    "480p":  "M3U8_AUTO_480",
    "360p":  "M3U8_AUTO_360",
}


def set_proxy_client(client: httpx.AsyncClient):
    global _proxy_client
    _proxy_client = client


# ─── /api/stream/manifest ────────────────────────────────────────────

@router.api_route("/api/stream/manifest", methods=["GET", "OPTIONS"])
@router.api_route("/api/stream/playlist.m3u8", methods=["GET", "OPTIONS"])
async def stream_manifest(request: Request):
    surl = request.query_params.get("surl") or ""
    fs_id = request.query_params.get("fs_id") or ""
    sig   = request.query_params.get("sig")  or ""
    exp   = request.query_params.get("exp")  or ""
    link  = request.query_params.get("url")  or request.query_params.get("link") or ""

    if not surl and link:
        try:
            surl = parse_surl(link)
        except Exception:
            pass

    is_authorized = (
        (surl and fs_id and sig and verify_signature(surl, fs_id, "manifest", sig, exp))
        or await check_auth(request)
    )
    if not is_authorized:
        return JSONResponse(
            {"status": "error", "message": "Unauthorized: Invalid signature or authentication."},
            status_code=401,
        )

    ip = client_ip(request)
    if not rate_limiter.is_allowed(ip):
        return JSONResponse(
            {"status": "error", "message": "Rate limit exceeded. Try again shortly."},
            status_code=429,
        )

    if not link and surl:
        link = f"https://1024terabox.com/s/{surl}"

    wait_for_transcoding = request.query_params.get("wait") in ("true", "1", "True")
    try:
        file_index = int(request.query_params.get("index", 0))
    except ValueError:
        file_index = 0

    if not link:
        return JSONResponse(
            {"status": "error", "message": "Missing required parameter 'url', 'link' or 'surl'."},
            status_code=400,
        )

    quality = request.query_params.get("quality") or request.query_params.get("type") or ""

    try:
        # ── CASE 1: Master multivariant playlist ───────────────────────
        if not quality:
            ready_qualities = cache.get(link, f"qualities:{file_index}", False)

            if not ready_qualities:
                res = await resolve_link_with_retry(
                    link, action="s", wait_for_transcoding=wait_for_transcoding
                )
                if res.get("errno") != 0:
                    return JSONResponse(
                        {"status": "error", "message": res.get("error", "Resolution error.")},
                        status_code=400,
                    )

                files = res.get("files", [])
                matching_file = _pick_file(files, fs_id, file_index)

                if not matching_file:
                    return JSONResponse(
                        {"status": "error", "message": "No streamable video files found."},
                        status_code=404,
                    )

                filename = matching_file.get("filename", "")
                if not filename.lower().endswith(VIDEO_EXTS):
                    return JSONResponse(
                        {"status": "error", "message": "Selected file is not a streamable video."},
                        status_code=400,
                    )

                is_transcoding = any(f.get("error") == "transcoding_in_progress" for f in files)
                if is_transcoding and not any(f.get("stream_ready") for f in files):
                    return JSONResponse(
                        {
                            "status": "transcoding",
                            "message": "HLS manifest is currently transcoding. Try again shortly.",
                        },
                        status_code=202,
                    )

                ready_qualities = await _probe_qualities(matching_file)

                if not ready_qualities:
                    return JSONResponse(
                        {"status": "error", "message": "No streamable qualities are ready."},
                        status_code=404,
                    )

                ttl = 120 if is_transcoding else 86400
                _save_qualities_to_cache(link, file_index, ready_qualities, ttl)

            return _build_master_playlist(request, surl, ready_qualities)

        # ── CASE 2: Specific quality sub-playlist ──────────────────────
        qtype = QUALITIES_MAP.get(quality)
        if not qtype:
            return JSONResponse(
                {"status": "error", "message": f"Unsupported stream quality: {quality}"},
                status_code=400,
            )

        res = await resolve_link_with_retry(
            link, action="s", wait_for_transcoding=wait_for_transcoding
        )
        if res.get("errno") != 0:
            return JSONResponse(
                {"status": "error", "message": res.get("error", "Resolution error.")},
                status_code=400,
            )

        files = res.get("files", [])
        matching_file = _pick_file(files, fs_id, file_index)
        if not matching_file:
            return JSONResponse({"status": "error", "message": "File not found."}, status_code=404)

        return await _fetch_quality_playlist(request, matching_file, quality, qtype)

    except Exception as exc:
        return JSONResponse(
            {"status": "error", "message": f"Manifest proxy error: {exc}"},
            status_code=500,
        )


# ─── /api/stream/segment ─────────────────────────────────────────────

@router.api_route("/api/stream/segment",    methods=["GET", "OPTIONS"])
@router.api_route("/api/stream/segment.ts", methods=["GET", "OPTIONS"])
async def stream_segment(request: Request):
    url = request.query_params.get("url") or ""
    sig = request.query_params.get("sig") or ""
    exp = request.query_params.get("exp") or ""

    if not url:
        return JSONResponse(
            {"status": "error", "message": "Missing required parameter 'url'."},
            status_code=400,
        )

    if not (sig and verify_signature(url, "", "", sig, exp)) and not await check_auth(request):
        return JSONResponse(
            {"status": "error", "message": "Unauthorized: Invalid signature or API key."},
            status_code=401,
        )

    if not validate_safe_outbound_url(url):
        return JSONResponse(
            {"status": "error", "message": "Forbidden: Invalid stream host destination."},
            status_code=403,
        )

    if REDIRECT_SEGMENTS:
        return RedirectResponse(url=url, status_code=307)

    client = _proxy_client
    try:
        headers: dict = {"User-Agent": UA, "Referer": "https://dm.1024terabox.com/"}
        range_header = request.headers.get("Range")
        if range_header:
            headers["Range"] = range_header

        from downloader import COOKIES_DICT
        req_ctx = client.stream("GET", url, headers=headers, cookies=COOKIES_DICT, timeout=30.0)
        req = await req_ctx.__aenter__()

        resp_headers: dict = {}
        for key in ("Content-Length", "Content-Type", "Content-Range", "Accept-Ranges"):
            if key in req.headers:
                resp_headers[key] = req.headers[key]
        resp_headers.update({
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
        })

        async def generate():
            try:
                async for chunk in req.aiter_bytes(chunk_size=65536):
                    yield chunk
            finally:
                await req_ctx.__aexit__(None, None, None)

        return StreamingResponse(generate(), status_code=req.status_code, headers=resp_headers)

    except Exception as exc:
        return JSONResponse(
            {"status": "error", "message": f"Segment proxy error: {exc}"},
            status_code=500,
        )


# ─── Helpers ─────────────────────────────────────────────────────────

def _pick_file(files: list, fs_id: str, file_index: int) -> dict | None:
    if fs_id:
        for f in files:
            if str(f.get("original_fs_id")) == str(fs_id) or str(f.get("fs_id")) == str(fs_id):
                return f
    if files and file_index < len(files):
        return files[file_index]
    return None


async def _probe_qualities(matching_file: dict) -> dict:
    """Hit the Terabox streaming API for each quality tier and return ready ones."""
    import downloader as dl

    filename = matching_file.get("filename", "")
    my_file_path = dl.ROOT_PATH.rstrip("/") + "/" + filename
    encoded_path = urllib.parse.quote(my_file_path)

    async def _check(qname: str, qtype: str):
        url = (
            f"{dl.BASE_API}/api/streaming?{dl.qp()}&path={encoded_path}&type={qtype}"
            f"&bdstoken={dl.BDSTOKEN}&isplayer=1&check_blue=1&clienttype=1&resolution={qname}"
        )
        try:
            sr = await dl.get_session().get(url, timeout=15.0)
            if sr.status_code == 200 and "#EXTM3U" in sr.text:
                return qname, {"fs_id": matching_file.get("original_fs_id") or matching_file.get("fs_id")}
        except Exception as exc:
            logger.error("[Manifest] Quality %s probe failed: %s", qname, exc)
        return qname, None

    results = await asyncio.gather(*[_check(qn, qt) for qn, qt in QUALITIES_MAP.items()])
    return {qn: data for qn, data in results if data}


def _save_qualities_to_cache(link: str, file_index: int, ready: dict, ttl: int):
    key = cache.make_key(link, f"qualities:{file_index}", False)
    if redis_client:
        try:
            redis_client.set(f"cache:response:{key}", json.dumps(ready), ex=ttl)
        except Exception as exc:
            logger.warning("[Manifest] Redis cache save error: %s", exc)
    else:
        cache.put(link, f"qualities:{file_index}", False, ready)


def _build_master_playlist(request: Request, surl: str, ready_qualities: dict) -> Response:
    base_url = request_base_url(request)
    playlist = ["#EXTM3U", "#EXT-X-VERSION:3"]
    quality_meta = [
        ("1080p", "4000000", "1920x1080"),
        ("720p",  "2500000", "1280x720"),
        ("480p",  "1200000", "854x480"),
        ("360p",  "600000",  "640x360"),
    ]
    for qname, bandwidth, res_str in quality_meta:
        if qname in ready_qualities:
            q_fs_id = ready_qualities[qname]["fs_id"]
            signed = make_signed_params(request, surl, q_fs_id, "manifest", kind="manifest")
            stream_url = (
                f"{base_url}/api/stream/playlist.m3u8"
                f"?surl={surl}&fs_id={q_fs_id}&quality={qname}&{signed}"
            )
            playlist.append(f"#EXT-X-STREAM-INF:BANDWIDTH={bandwidth},RESOLUTION={res_str}")
            playlist.append(stream_url)
    return Response(content="\n".join(playlist), media_type="application/x-mpegURL")


async def _fetch_quality_playlist(
    request: Request,
    matching_file: dict,
    quality: str,
    qtype: str,
) -> Response:
    import downloader as dl

    filename = matching_file.get("filename", "")
    my_file_path = dl.ROOT_PATH.rstrip("/") + "/" + filename
    encoded_path = urllib.parse.quote(my_file_path)

    url = (
        f"{dl.BASE_API}/api/streaming?{dl.qp()}&path={encoded_path}&type={qtype}"
        f"&bdstoken={dl.BDSTOKEN}&isplayer=1&check_blue=1&clienttype=1&resolution={quality}"
    )
    sr = await dl.get_session().get(url, timeout=20.0)
    if sr.status_code != 200 or "#EXTM3U" not in sr.text:
        return JSONResponse(
            {"status": "error", "message": f"Failed to retrieve stream (status={sr.status_code})"},
            status_code=500,
        )

    base_url = request_base_url(request)
    rewritten = []
    for line in sr.text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("http://") or line.startswith("https://"):
            signed = make_signed_params(request, line, "", "", kind="segment")
            proxy_seg = f"{base_url}/api/stream/segment.ts?url={urllib.parse.quote(line)}&{signed}"
            rewritten.append(proxy_seg)
        else:
            rewritten.append(line)

    return Response(content="\n".join(rewritten), media_type="application/x-mpegURL")
