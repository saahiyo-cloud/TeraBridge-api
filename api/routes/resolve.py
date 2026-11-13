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
import json
import logging
import re
import threading
import time
import urllib.parse

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from api.auth import check_auth
from api.cache import cache
from api.config import (
    RATE_LIMIT_RPM,
    RATE_LIMIT_WINDOW,
    REQUEST_TIMEOUT_SECONDS,
    RESOLVE_TIMEOUT_SECONDS,
)
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

# ── Input validation ──────────────────────────────────────────────────
MAX_LINK_LENGTH = 2048
MIN_SURL_LENGTH = 15  # conservative floor; real ids are 22-23 chars

_MODE_ALIASES = {
    "d": "d", "download": "d",
    "s": "s", "stream": "s", "streaming": "s", "both": "s",
    "l": "l", "list": "l", "info": "l", "metadata": "l",
}


def _bad_request(message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"status": "error", "message": message}, status_code=status_code)


def _looks_like_http_url(value: str) -> bool:
    from api.middleware import _is_private_or_local_host

    parsed = urllib.parse.urlparse(value)
    return (
        parsed.scheme in ("http", "https")
        and bool(parsed.hostname)
        and not _is_private_or_local_host(parsed.hostname)
    )


def _scrub_upstream(message) -> str:
    """Drop TeraBox request ids from upstream error text before returning it."""
    return re.sub(r",?\s*request_id=[\w-]+", "", str(message))

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
    """Resolve a share link, rotating accounts or proxies on failures."""
    import json
    from api.proxy_manager import proxy_manager

    max_retries = max(3, proxy_manager.get_healthy_count())
    if redis_client:
        try:
            accounts = get_all_accounts()
            healthy_count = sum(
                1 for d in accounts.values() if d.get("status", "healthy") == "healthy"
            )
            max_retries = max(max_retries, healthy_count)
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
        is_proxy_error = False
        reason = "unknown"
        errno = res.get("errno")
        error_msg = str(res.get("error", ""))

        if errno in (400141, 400810):
            is_proxy_error = True
            reason = f"TeraBox WAF flagged proxy (errno {errno})"
        elif errno in (-1, -2):
            is_transport = (
                errno == -2
                or any(w in error_msg.lower() for w in (
                    "transport", "proxy", "402", "407", "connect", "timeout",
                    "refused", "reset", "network", "remote", "connection", "socket", "empty"
                ))
                or error_msg.strip() in ("", "Failed to resolve session tokens:", "Failed to resolve session tokens")
            )
            is_cookie_expired = any(
                w in error_msg.lower()
                for w in ("cookie may be expired", "session cookie expired", "login required", "did not return bdstoken")
            )

            if is_transport or (not is_cookie_expired and proxy_manager.get_total_count() > 0):
                is_proxy_error = True
                reason = f"Proxy transport failure: {error_msg}"
            elif is_cookie_expired:
                is_account_error = True
                reason = f"Account cookie expired: {error_msg}"
            else:
                # Do not ban accounts on ambiguous transient query failures
                is_proxy_error = True
                reason = f"Network transport failure: {error_msg}"
        elif errno in (-6, -9, 111):
            is_account_error = True
            reason = f"Session expired/invalid (errno {errno})"

        if not is_account_error and not is_proxy_error and res.get("errno") == 0:
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

        if is_proxy_error:
            logger.warning("Proxy issue detected: %s.", reason)
            if attempt < max_retries - 1 and proxy_manager.get_total_count() > 1:
                logger.info("Retrying with rotated proxy (attempt %d/%d)...", attempt + 2, max_retries)
                continue

        if is_account_error and active_id:
            logger.warning(
                "Account '%s' hit account-level failure: %s. Marking UNHEALTHY.",
                active_id, reason,
            )
            mark_account_unhealthy(active_id, reason)
            try:
                from api.metrics import record_event
                record_event("account_unhealthy", f"Account '{active_id}' marked unhealthy: {reason}", level="error")
            except Exception:
                pass
            try:
                import downloader as dl
                dl.invalidate_token_cache()
            except Exception:
                pass
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
        "errno": res.get("errno", 0),
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

        encoded_link = urllib.parse.quote(link) if link else ""
        link_param = f"&url={encoded_link}" if encoded_link else ""
        proxy_dlink = None
        if f.get("dlink") and original_fs_id and surl and request:
            signed = make_signed_params(request, surl, original_fs_id, "", kind="download")
            proxy_dlink = f"{base}/api/download?surl={surl}&fs_id={original_fs_id}{link_param}&{signed}"
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


# Time budget (seconds). The API-level resolve timeout is kept below the request
# timeout so the route answers with its own clean 504 rather than being cancelled
# by RequestTimeoutMiddleware; the lock must outlive a full resolve attempt, or a
# second request would start duplicate upstream work while the first is running.
_RESOLVE_BUDGET_SECONDS = max(5, min(RESOLVE_TIMEOUT_SECONDS, REQUEST_TIMEOUT_SECONDS - 5))
_LOCK_TTL_SECONDS = int(_RESOLVE_BUDGET_SECONDS) + 10


def _acquire_resolve_lock(key: str) -> bool:
    if redis_client:
        try:
            return bool(redis_client.set(f"lock:resolve:{key}", "locked", nx=True, ex=_LOCK_TTL_SECONDS))
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


async def _wait_for_resolution(key: str, check_cache_fn, timeout: float = 30):
    if redis_client:
        import time as _time
        start = _time.time()
        while _time.time() - start < timeout:
            # Upstash calls are blocking HTTP requests: keep them off the event loop.
            cached = await asyncio.to_thread(check_cache_fn)
            if cached is not None:
                return cached
            if not await asyncio.to_thread(redis_client.exists, f"lock:resolve:{key}"):
                break
            await asyncio.sleep(1.0)
        return await asyncio.to_thread(check_cache_fn)

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
                cache.put(link, f"raw:{action}", False, res)
                cache.put(link, f"raw:{action}", True, res)
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
    ip = client_ip(request)

    # 1. IP-level Rate Limit check (evaluated before auth to prevent brute-forcing)
    if not await rate_limiter.is_allowed_async(ip):
        return JSONResponse(
            {
                "status": "error",
                "message": (
                    f"Rate limit exceeded. Max {RATE_LIMIT_RPM} requests "
                    f"per minute. Try again shortly."
                ),
            },
            status_code=429,
            headers=rate_limiter.get_headers(ip, is_blocked=True),
        )

    # 2. Check failed auth lockout
    if not await rate_limiter.is_auth_allowed_async(ip):
        return JSONResponse(
            {
                "status": "error",
                "message": "Too many failed authentication attempts. Access temporarily locked.",
            },
            status_code=429,
            headers=rate_limiter.get_auth_headers(ip),
        )

    # 3. Check authentication
    if not await check_auth(request):
        await rate_limiter.record_auth_failure_async(ip)
        return JSONResponse(
            {"status": "error", "message": "Unauthorized: Invalid or missing API key."},
            status_code=401,
            headers=rate_limiter.get_headers(ip),
        )

    # ── Parse request params ──────────────────────────────────────────
    link = ""
    action = "d"
    wait_for_transcoding = False

    if request.method == "POST":
        raw_body = await request.body()
        data = {}
        if raw_body.strip():
            try:
                data = json.loads(raw_body)
            except (ValueError, UnicodeDecodeError):
                return _bad_request("Invalid JSON body.")
            if not isinstance(data, dict):
                return _bad_request("Request body must be a JSON object.")
        link = data.get("url") or data.get("link") or ""
        action = data.get("mode") or data.get("action") or "d"
        wait_for_transcoding = bool(data.get("wait"))
    else:
        link = request.query_params.get("url") or request.query_params.get("link") or ""
        action = request.query_params.get("mode") or request.query_params.get("action") or "d"
        wait_for_transcoding = request.query_params.get("wait") in ("true", "1", "True")

    if not link:
        return _bad_request("Missing required parameter 'url' or 'link'.")
    if not isinstance(link, str):
        return _bad_request("Parameter 'url' must be a string.")
    if len(link) > MAX_LINK_LENGTH:
        return _bad_request(
            f"Parameter 'url' is too long (max {MAX_LINK_LENGTH} characters).", status_code=413
        )

    # Strip zero-width / bidi characters
    link = re.sub(
        r"[\s\u200b\u200c\u200d\ufeff\u202a\u202b\u202c\u202d\u202e]+", "", link
    )
    if not link:
        return _bad_request("Missing required parameter 'url' or 'link'.")

    # Validate mode locally: an unknown value must not silently run a download.
    if not isinstance(action, str) or action.lower() not in _MODE_ALIASES:
        return _bad_request("Invalid mode. Use one of: download, stream, list.")
    action = _MODE_ALIASES[action.lower()]

    # Validate the share link locally so junk never reaches TeraBox.
    # http(s) URLs that are not recognisable share links are still passed on:
    # resolve_link follows third-party shorteners and re-parses the destination.
    try:
        parsed_surl = parse_surl(link)
        # parse_surl accepts any 8+ char slug; real TeraBox ids are 22-23 chars.
        if len(parsed_surl) < MIN_SURL_LENGTH:
            raise ValueError("short")
    except ValueError:
        if not _looks_like_http_url(link):
            return _bad_request(
                "Invalid share link. Provide a TeraBox share URL or short link ID."
            )

    # ── Cache hit ─────────────────────────────────────────────────────
    cached = cache.get(link, action, wait_for_transcoding)
    if cached is not None:
        resp_headers = {"X-Cache": "HIT"}
        resp_headers.update(rate_limiter.get_headers(ip))
        return JSONResponse(
            cached,
            headers=resp_headers,
        )

    # ── Single-flight ─────────────────────────────────────────────────
    started = time.monotonic()
    cache_key = cache.make_key(link, action, wait_for_transcoding)
    has_lock = _acquire_resolve_lock(cache_key)

    if not has_lock:
        logger.info("[SingleFlight] Waiting for concurrent resolution of: %s", link)
        # Wait at most as long as the leader can legitimately run.
        cached = await _wait_for_resolution(
            cache_key,
            lambda: cache.get(link, action, wait_for_transcoding),
            timeout=_RESOLVE_BUDGET_SECONDS,
        )
        if cached is not None:
            resp_headers = {"X-Cache": "HIT (COLLAPSED)"}
            resp_headers.update(rate_limiter.get_headers(ip))
            return JSONResponse(
                cached,
                headers=resp_headers,
            )
        logger.info("[SingleFlight] Wait timed out, resolving independently: %s", link)
        # Only the request that actually holds the lock may release it later.
        has_lock = _acquire_resolve_lock(cache_key)

    try:
        # Whatever the wait consumed comes out of the same budget, so the total
        # stays under the request timeout.
        remaining_budget = max(1.0, REQUEST_TIMEOUT_SECONDS - 5 - (time.monotonic() - started))
        resolve_budget = min(float(RESOLVE_TIMEOUT_SECONDS), remaining_budget)
        try:
            res = await asyncio.wait_for(
                resolve_link_with_retry(
                    link, action=action, wait_for_transcoding=wait_for_transcoding
                ),
                timeout=resolve_budget,
            )
        except asyncio.TimeoutError:
            logger.warning("[Resolve] Operation timed out after %.0fs for %s", resolve_budget, link)
            return JSONResponse(
                {
                    "status": "error",
                    "message": f"Upstream resolution timed out after {int(resolve_budget)}s. Please retry shortly.",
                },
                status_code=504,
            )

        if res.get("errno") != 0:
            return _bad_request(_scrub_upstream(res.get("error", "Unknown resolution error.")))

        response_data, is_transcoding = format_resolved_response(request, res, link)

        if is_transcoding and not wait_for_transcoding:
            asyncio.create_task(_background_transcode_poll(link, action, cache_key))

        if action == "s" and not is_transcoding:
            asyncio.create_task(_prewarm_quality_cache(link, res))

        if not is_transcoding:
            cache.put(link, f"raw:{action}", wait_for_transcoding, res)
            cache.put(link, action, wait_for_transcoding, response_data)
            try:
                from api.metrics import record_event
                record_event("resolve_success", f"Resolved: {res.get('title', 'Unknown shared file')}", level="success")
            except Exception:
                pass

        miss_headers = {"X-Cache": "MISS"}
        miss_headers.update(rate_limiter.get_headers(ip))
        return JSONResponse(
            response_data,
            headers=miss_headers,
        )

    except ValueError:
        return _bad_request("Invalid share link.")
    except Exception as exc:
        logger.exception("[Resolve] Server error handling link: %s", exc)
        return JSONResponse(
            {"status": "error", "message": "An internal server error occurred while resolving the link."},
            status_code=500,
        )
    finally:
        if has_lock:
            _release_resolve_lock(cache_key)
