"""
api/routes/resolve.py — /api/resolve endpoint.

Handles:
  - Auth + rate-limit gating
  - Single-flight request collapsing (asyncio.Event-based, non-blocking)
  - Multi-account retry with automatic account rotation on failure
  - Background transcoder polling worker
  - Background quality pre-warming for HLS streams
  - Response formatting (proxy URLs, HMAC signing)
"""
import asyncio
import logging
import re
import threading
import urllib.parse

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from api.auth import check_auth
from api.cache import cache
from api.config import RATE_LIMIT_RPM, RATE_LIMIT_WINDOW
from api.middleware import client_ip, request_base_url
from api.rate_limiter import rate_limiter
from api.redis_client import redis_client
from api.signing import make_signed_params
from downloader import (
    VIDEO_EXTS,
    parse_surl,
    resolve_link,
)
from api.account_pool import (
    ACTIVE_ACCOUNT_KEY,
    ACCOUNTS_HASH_KEY,
    get_all_accounts,
    get_next_healthy_account,
    mark_account_unhealthy,
)

logger = logging.getLogger("terabridge.routes.resolve")
router = APIRouter()

# ── account-rotation state (shared with admin routes via account_manager) ──
_current_active_account_id: str | None = None


def set_active_account_id(account_id: str | None):
    global _current_active_account_id
    _current_active_account_id = account_id


def get_active_account_id() -> str | None:
    return _current_active_account_id


# ─── Notification webhook helper ─────────────────────────────────────
import datetime
import httpx as _httpx
from api.config import NOTIFICATION_WEBHOOK_URL


async def send_webhook_alert(message: str):
    if not NOTIFICATION_WEBHOOK_URL:
        return
    payload: dict
    if "discord.com" in NOTIFICATION_WEBHOOK_URL:
        payload = {
            "embeds": [{
                "title": "🚨 TeraBridge API Warning",
                "description": message,
                "color": 16711680,
                "timestamp": datetime.datetime.utcnow().isoformat(),
            }]
        }
    elif "slack.com" in NOTIFICATION_WEBHOOK_URL:
        payload = {"text": f"🚨 *TeraBridge API Warning:*\n{message}"}
    else:
        payload = {"event": "session_expired", "message": message}

    try:
        async with _httpx.AsyncClient() as c:
            await c.post(NOTIFICATION_WEBHOOK_URL, json=payload, timeout=10.0)
    except Exception as exc:
        logger.warning("Failed to send webhook alert: %s", exc)


# ─── Multi-account resolve with retry ────────────────────────────────

async def resolve_link_with_retry(
    link: str,
    action: str = "d",
    wait_for_transcoding: bool = False,
    quality: str | None = None,
) -> dict:
    """Resolve a share link, rotating accounts on auth/storage failures."""
    import json

    max_retries = 3
    if redis_client:
        try:
            accounts = get_all_accounts()
            healthy_count = sum(
                1 for d in accounts.values() if d.get("status", "healthy") == "healthy"
            )
            max_retries = max(3, healthy_count)
        except Exception:
            pass

    res: dict = {}

    for attempt in range(max_retries):
        active_id = _current_active_account_id
        res = await resolve_link(
            link, action=action,
            wait_for_transcoding=wait_for_transcoding,
            quality=quality,
        )

        is_account_error = False
        is_transient_rotation = False
        reason = "unknown"
        errno = res.get("errno")
        error_msg = str(res.get("error", ""))

        if errno == -1:
            is_account_error = True
            reason = f"Token resolution failed: {error_msg}"
        elif errno == -2:
            is_account_error = True
            reason = f"Share list query failed: {error_msg}"
        elif errno in (-6, -9, 111):
            is_account_error = True
            reason = f"Session expired/invalid (errno {errno})"

        if not is_account_error and res.get("errno") == 0:
            files = res.get("files", [])
            if files:
                account_fail = 0
                transient_fail = 0
                for f in files:
                    emsg = str(f.get("error", ""))
                    if "errno -6" in emsg or "errno -9" in emsg or "errno 111" in emsg:
                        account_fail += 1
                        reason = "File transfer authentication failure"
                    elif "errno -10" in emsg or "errno 12" in emsg:
                        account_fail += 1
                        reason = "Account storage limit reached"
                    elif "400810" in emsg:
                        transient_fail += 1
                        reason = "Temporary transfer rate-limit (errno 400810)"
                if account_fail == len(files):
                    is_account_error = True
                elif transient_fail == len(files):
                    is_transient_rotation = True

        if is_account_error and active_id:
            logger.warning(
                "Account '%s' hit account-level failure: %s. Marking UNHEALTHY.",
                active_id, reason,
            )
            mark_account_unhealthy(active_id, reason)
            _load_config_from_redis()
            if attempt < max_retries - 1:
                logger.info("Retrying with rotated account: %s", _current_active_account_id)
                continue
        elif is_transient_rotation and active_id:
            logger.warning(
                "Account '%s' hit transient limit: %s. Rotating…", active_id, reason,
            )
            get_next_healthy_account()
            _load_config_from_redis()
            if attempt < max_retries - 1:
                logger.info("Retrying with rotated account: %s", _current_active_account_id)
                continue

        break

    return res


# ─── Config loader (deferred import to avoid circular deps) ──────────

def _load_config_from_redis():
    """Thin wrapper — delegates to account_manager to avoid circular imports."""
    try:
        from api.account_manager import load_config_from_redis
        load_config_from_redis()
    except Exception as exc:
        logger.warning("Config reload failed: %s", exc)


# ─── Response formatter ───────────────────────────────────────────────

def format_resolved_response(request: Request | None, res: dict, link: str) -> tuple[dict, bool]:
    """Convert raw resolve_link output into the public API response shape."""
    is_transcoding = any(
        f.get("error") == "transcoding_in_progress" for f in res.get("files", [])
    )

    response_data: dict = {
        "status": "transcoding" if is_transcoding else "success",
        "title": res.get("title"),
        "share_id": res.get("share_id"),
        "uk": res.get("uk"),
        "files": [],
    }

    try:
        surl = parse_surl(link)
    except ValueError:
        surl = ""

    base = request_base_url(request) if request else ""

    for f in res.get("files", []):
        original_fs_id = f.get("original_fs_id")
        raw_thumbs = f.get("thumbnails")
        proxied_thumbs: dict = {}

        if raw_thumbs and isinstance(raw_thumbs, dict):
            for k, v in raw_thumbs.items():
                if v:
                    if original_fs_id and surl and request:
                        signed = make_signed_params(request, surl, original_fs_id, k, kind="thumbnail")
                        proxy_url = f"{base}/api/thumbnail?surl={surl}&fs_id={original_fs_id}&size_type={k}&{signed}"
                    else:
                        quoted_v = urllib.parse.quote(v)
                        signed = make_signed_params(request, v, "", "", kind="thumbnail") if request else ""
                        proxy_url = f"{base}/api/thumbnail?url={quoted_v}&{signed}"
                    proxied_thumbs[k] = proxy_url

        proxy_dlink = None
        if f.get("dlink") and original_fs_id and surl and request:
            signed = make_signed_params(request, surl, original_fs_id, "", kind="download")
            proxy_dlink = f"{base}/api/download?surl={surl}&fs_id={original_fs_id}&{signed}"
        else:
            proxy_dlink = f.get("dlink")

        proxy_stream = None
        if f.get("stream_ready") and original_fs_id and surl and request:
            signed = make_signed_params(request, surl, original_fs_id, "manifest", kind="manifest")
            proxy_stream = f"{base}/api/stream/manifest?surl={surl}&fs_id={original_fs_id}&{signed}"

        response_data["files"].append({
            "filename":        f.get("filename"),
            "size_bytes":      f.get("size_bytes"),
            "size_mb":         f.get("size_mb"),
            "fs_id":           f.get("fs_id"),
            "transfer_status": f.get("transfer_status"),
            "dlink":           proxy_dlink,
            "stream_url":      proxy_stream,
            "stream_ready":    f.get("stream_ready"),
            "error":           f.get("error"),
            "thumbnails":      proxied_thumbs or None,
            "path":            f.get("path"),
            "is_directory":    f.get("is_directory"),
        })

    return response_data, is_transcoding


# ─── Single-flight (asyncio.Event-based, non-blocking) ───────────────

_sf_events: dict[str, asyncio.Event] = {}
_sf_lock = threading.Lock()


def _acquire_resolve_lock(key: str) -> bool:
    if redis_client:
        try:
            return bool(redis_client.set(f"lock:resolve:{key}", "locked", nx=True, ex=30))
        except Exception as exc:
            logger.warning("[SingleFlight] Redis lock set error: %s", exc)

    with _sf_lock:
        if key in _sf_events:
            return False
        _sf_events[key] = asyncio.Event()
        return True


def _release_resolve_lock(key: str):
    if redis_client:
        try:
            redis_client.delete(f"lock:resolve:{key}")
        except Exception as exc:
            logger.warning("[SingleFlight] Redis lock delete error: %s", exc)

    with _sf_lock:
        ev = _sf_events.pop(key, None)
    if ev:
        ev.set()


async def _wait_for_resolution(key: str, check_cache_fn, timeout: int = 30):
    if redis_client:
        import time as _time
        start = _time.time()
        while _time.time() - start < timeout:
            cached = check_cache_fn()
            if cached is not None:
                return cached
            if not redis_client.exists(f"lock:resolve:{key}"):
                break
            await asyncio.sleep(1.0)
        return check_cache_fn()

    with _sf_lock:
        ev = _sf_events.get(key)

    if ev:
        try:
            await asyncio.wait_for(ev.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

    return check_cache_fn()


# ─── Background quality pre-warmer ───────────────────────────────────

async def _prewarm_quality_cache(link: str, res: dict):
    import downloader as dl

    try:
        for file_index, f in enumerate(res.get("files", [])):
            filename = f.get("filename", "")
            if not (filename and filename.lower().endswith(VIDEO_EXTS)):
                continue
            if cache.get(link, f"qualities:{file_index}", False):
                continue

            my_file_path = dl.ROOT_PATH.rstrip("/") + "/" + filename
            encoded_path = urllib.parse.quote(my_file_path)

            qualities_to_check = {
                "1080p": "M3U8_AUTO_1080",
                "720p":  "M3U8_AUTO_720",
                "480p":  "M3U8_AUTO_480",
                "360p":  "M3U8_AUTO_360",
            }

            async def _check(qname: str, qtype: str, _f=f):
                url = (
                    f"{dl.BASE_API}/api/streaming?{dl.qp()}&path={encoded_path}"
                    f"&type={qtype}&bdstoken={dl.BDSTOKEN}"
                )
                try:
                    sr = await dl.get_session().get(url, timeout=15.0)
                    if sr.status_code == 200 and "#EXTM3U" in sr.text:
                        return qname, {"fs_id": _f.get("original_fs_id") or _f.get("fs_id")}
                except Exception as exc:
                    logger.error("[PreWarm] Quality %s check failed: %s", qname, exc)
                return qname, None

            results = await asyncio.gather(
                *[_check(qn, qt) for qn, qt in qualities_to_check.items()]
            )
            ready = {qn: data for qn, data in results if data}

            if ready:
                import json
                key = cache.make_key(link, f"qualities:{file_index}", False)
                if redis_client:
                    try:
                        redis_client.set(f"cache:response:{key}", json.dumps(ready), ex=86400)
                    except Exception as exc:
                        logger.warning("[PreWarm] Redis save error: %s", exc)
                else:
                    cache.put(link, f"qualities:{file_index}", False, ready)
                logger.info("[PreWarm] Cached qualities for file %d: %s", file_index, list(ready.keys()))
    except Exception as exc:
        logger.error("[PreWarm] Background quality pre-warm failed: %s", exc)


# ─── Background transcoder polling worker ────────────────────────────

_transcode_jobs_lock = threading.Lock()
_active_transcode_jobs: set = set()


async def _background_transcode_poll(link: str, action: str, cache_key: str):
    lock_key = f"lock:transcode:{cache_key}"

    if redis_client:
        try:
            if not redis_client.set(lock_key, "running", nx=True, ex=300):
                return
        except Exception:
            pass
    else:
        with _transcode_jobs_lock:
            if cache_key in _active_transcode_jobs:
                return
            _active_transcode_jobs.add(cache_key)

    logger.info("[TranscoderWorker] Starting background checks for: %s", link)
    try:
        res = await resolve_link_with_retry(link, action=action, wait_for_transcoding=True)
        if res.get("errno") == 0:
            response_data, is_transcoding = format_resolved_response(None, res, link)
            if not is_transcoding:
                cache.put(link, action, False, response_data)
                cache.put(link, action, True, response_data)
                title = res.get("title", "Unknown Video")
                await send_webhook_alert(
                    f"🎉 **HLS Transcoding Complete!**\n"
                    f"Video **{title}** is ready for streaming."
                )
                logger.info("[TranscoderWorker] Transcoding complete for: %s", link)
                return
        logger.info("[TranscoderWorker] Transcoding still incomplete for: %s", link)
    except Exception as exc:
        logger.error("[TranscoderWorker] Exception: %s", exc)
    finally:
        if redis_client:
            try:
                redis_client.delete(lock_key)
            except Exception:
                pass
        else:
            with _transcode_jobs_lock:
                _active_transcode_jobs.discard(cache_key)


# ─── /api/resolve route ───────────────────────────────────────────────

@router.api_route("/api/resolve", methods=["GET", "POST"])
async def resolve(request: Request):
    if not await check_auth(request):
        return JSONResponse(
            {"status": "error", "message": "Unauthorized: Invalid or missing API key."},
            status_code=401,
        )

    ip = client_ip(request)

    if not rate_limiter.is_allowed(ip):
        return JSONResponse(
            {
                "status": "error",
                "message": (
                    f"Rate limit exceeded. Max {RATE_LIMIT_RPM} requests "
                    f"per minute. Try again shortly."
                ),
            },
            status_code=429,
            headers={
                "Retry-After":            str(RATE_LIMIT_WINDOW),
                "X-RateLimit-Limit":      str(RATE_LIMIT_RPM),
                "X-RateLimit-Remaining":  str(rate_limiter.remaining(ip)),
            },
        )

    # ── Parse request params ──────────────────────────────────────────
    link = ""
    action = "d"
    wait_for_transcoding = False

    if request.method == "POST":
        try:
            data = await request.json()
        except Exception:
            data = {}
        link = data.get("url") or data.get("link") or ""
        action = data.get("mode") or data.get("action") or "d"
        wait_for_transcoding = bool(data.get("wait"))
    else:
        link = request.query_params.get("url") or request.query_params.get("link") or ""
        action = request.query_params.get("mode") or request.query_params.get("action") or "d"
        wait_for_transcoding = request.query_params.get("wait") in ("true", "1", "True")

    if not link:
        return JSONResponse(
            {"status": "error", "message": "Missing required parameter 'url' or 'link'."},
            status_code=400,
        )

    # Strip zero-width / bidi characters
    link = re.sub(
        r"[\s\u200b\u200c\u200d\ufeff\u202a\u202b\u202c\u202d\u202e]+", "", link
    )

    act_lower = action.lower()
    if act_lower in ("s", "stream", "streaming"):
        action = "s"
    elif act_lower in ("l", "list", "info", "metadata"):
        action = "l"
    else:
        action = "d"

    # ── Cache hit ─────────────────────────────────────────────────────
    cached = cache.get(link, action, wait_for_transcoding)
    if cached is not None:
        return JSONResponse(
            cached,
            headers={
                "X-Cache":                "HIT",
                "X-RateLimit-Remaining":  str(rate_limiter.remaining(ip)),
            },
        )

    # ── Single-flight ─────────────────────────────────────────────────
    cache_key = cache.make_key(link, action, wait_for_transcoding)
    has_lock = _acquire_resolve_lock(cache_key)

    if not has_lock:
        logger.info("[SingleFlight] Waiting for concurrent resolution of: %s", link)
        cached = await _wait_for_resolution(
            cache_key,
            lambda: cache.get(link, action, wait_for_transcoding),
            timeout=30,
        )
        if cached is not None:
            return JSONResponse(
                cached,
                headers={
                    "X-Cache":               "HIT (COLLAPSED)",
                    "X-RateLimit-Remaining": str(rate_limiter.remaining(ip)),
                },
            )
        logger.info("[SingleFlight] Wait timed out, resolving independently: %s", link)
        _acquire_resolve_lock(cache_key)

    try:
        res = await resolve_link_with_retry(
            link, action=action, wait_for_transcoding=wait_for_transcoding
        )
        if res.get("errno") != 0:
            return JSONResponse(
                {"status": "error", "message": res.get("error", "Unknown resolution error.")},
                status_code=400,
            )

        response_data, is_transcoding = format_resolved_response(request, res, link)

        if is_transcoding and not wait_for_transcoding:
            asyncio.create_task(_background_transcode_poll(link, action, cache_key))

        if action == "s" and not is_transcoding:
            asyncio.create_task(_prewarm_quality_cache(link, res))

        if not is_transcoding:
            cache.put(link, action, wait_for_transcoding, response_data)

        return JSONResponse(
            response_data,
            headers={
                "X-Cache":               "MISS",
                "X-RateLimit-Remaining": str(rate_limiter.remaining(ip)),
            },
        )

    except ValueError as exc:
        return JSONResponse({"status": "error", "message": str(exc)}, status_code=400)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            {"status": "error", "message": f"Server error: {exc}"},
            status_code=500,
        )
    finally:
        _release_resolve_lock(cache_key)
