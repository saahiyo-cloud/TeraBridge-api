"""
api/routes/admin.py — Admin, observability, and cron routes.

Routes:
  GET  /api/stats            — cache, rate-limiter, session health (admin only)
  GET  /api/debug_curl       — raw HTTP probe for debugging (admin only)
  GET|POST /api/admin/config — read / update account pool credentials (admin only)
  GET|POST /api/cron/validate — validate session cookies, fire webhook alerts
"""
import hmac
import json
import logging
import os
import time
import urllib.parse

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from api.auth import check_admin, get_recent_auth_errors
from api.cache import cache
from api.config import CRON_SECRET, NOTIFICATION_WEBHOOK_URL
from api.middleware import _is_allowed_stream_host, _is_private_or_local_host
from api.rate_limiter import rate_limiter
from api.redis_client import redis_client
from api.account_pool import (
    ACCOUNTS_HASH_KEY,
    ACTIVE_ACCOUNT_KEY,
    get_all_accounts,
    get_next_healthy_account,
    mark_account_unhealthy,
    safe_json_loads,
    extract_ndus,
    fetch_account_profile,
)
from downloader import (
    UA,
    COOKIE,
    BASE_API,
    qp,
    parse_cookies,
    validate_session_cookie,
    resolve_tokens_from_cookie,
)
from api.signing import make_signed_params

logger = logging.getLogger("terabridge.routes.admin")
router = APIRouter()

_start_time = time.time()  # set by index.py via set_start_time()


def set_start_time(t: float):
    global _start_time
    _start_time = t


# ─── Webhook helper (shared with resolve.py via import) ──────────────

import datetime


async def send_webhook_alert(message: str):
    if not NOTIFICATION_WEBHOOK_URL:
        return
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
        async with httpx.AsyncClient() as c:
            await c.post(NOTIFICATION_WEBHOOK_URL, json=payload, timeout=10.0)
    except Exception as exc:
        logger.warning("Webhook send failed: %s", exc)


# ─── /api/stats ───────────────────────────────────────────────────────

@router.get("/api/stats")
async def stats(request: Request):
    if not await check_admin(request):
        return JSONResponse(
            {"status": "error", "message": "Unauthorized: Admin API key required."},
            status_code=401,
        )

    uptime = int(time.time() - _start_time)
    redis_status = "connected" if redis_client else "disabled"

    session_health = {
        "status": "unknown",
        "last_checked_timestamp": None,
        "message": "No validation check run yet.",
    }
    if redis_client:
        try:
            status_data = redis_client.hgetall("terabridge:status")
            if status_data:
                session_health = {
                    "status": "healthy" if status_data.get("cookie_valid") == "true" else "unhealthy",
                    "last_checked_timestamp": status_data.get("last_checked"),
                    "message": status_data.get("message"),
                }
        except Exception:
            pass

    from api.config import FIREBASE_PROJECT_ID
    return {
        "status":              "online",
        "uptime_seconds":      uptime,
        "redis":               redis_status,
        "session_health":      session_health,
        "cache":               cache.stats(),
        "rate_limiter":        rate_limiter.stats(),
        "firebase_project_id": FIREBASE_PROJECT_ID,
        "recent_auth_errors":  get_recent_auth_errors(),
    }


# ─── /api/debug_curl ─────────────────────────────────────────────────

@router.get("/api/debug_curl")
async def debug_curl(request: Request):
    if not await check_admin(request):
        return JSONResponse(
            {"status": "error", "message": "Unauthorized: Admin API key required."},
            status_code=401,
        )

    url = request.query_params.get("url")
    if not url:
        return JSONResponse(
            {"status": "error", "message": "Missing required parameter 'url'."},
            status_code=400,
        )

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return JSONResponse(
            {"status": "error", "message": "Forbidden: Unsupported URL scheme."},
            status_code=403,
        )
    hostname = parsed.hostname or ""
    if _is_private_or_local_host(hostname):
        return JSONResponse(
            {"status": "error", "message": "Forbidden: Private or loopback destination."},
            status_code=403,
        )
    # Only send Terabox cookies to allowlisted hosts
    from downloader import COOKIES_DICT
    request_cookies = COOKIES_DICT if _is_allowed_stream_host(hostname) else None

    try:
        async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
            r = await client.get(url, headers={"User-Agent": UA}, cookies=request_cookies)
            try:
                body = r.json()
            except Exception:
                body = r.text[:2000]
        return {
            "status":      "success",
            "status_code": r.status_code,
            "headers":     dict(r.headers),
            "body":        body,
        }
    except Exception as exc:
        return JSONResponse({"status": "error", "message": str(exc)}, status_code=500)


# ─── /api/admin/config ────────────────────────────────────────────────

@router.api_route("/api/admin/config", methods=["GET", "POST", "DELETE"])
async def admin_config(request: Request):
    if not await check_admin(request):
        return JSONResponse(
            {"status": "error", "message": "Unauthorized: Admin API key required."},
            status_code=401,
        )

    if not redis_client:
        return JSONResponse(
            {
                "status": "error",
                "message": "Redis client not configured. Config cannot be updated dynamically.",
            },
            status_code=400,
        )

    if request.method == "POST":
        return await _handle_config_post(request)
    elif request.method == "DELETE":
        return await _handle_config_delete(request)

    # GET — return masked pool summary
    return await _handle_config_get()


async def _handle_config_post(request: Request):
    from api.account_manager import load_config_from_redis

    try:
        data = await request.json()
    except Exception:
        data = {}

    from api.routes.resolve import get_active_account_id
    account_id = data.get("account_id") or get_active_account_id() or "account_1"

    # Option to simply activate an existing account
    if data.get("action") == "activate":
        redis_client.set(ACTIVE_ACCOUNT_KEY, account_id)
        load_config_from_redis()
        return {
            "status": "success",
            "message": f"Account '{account_id}' set as active account.",
            "active_account_id": account_id,
        }

    # Option to re-test/verify an account's health live
    if data.get("action") == "verify":
        existing_raw = redis_client.hget(ACCOUNTS_HASH_KEY, account_id)
        if not existing_raw:
            return JSONResponse({"status": "error", "message": f"Account '{account_id}' not found."}, status_code=404)
        acc_data = safe_json_loads(existing_raw)
        cookie = acc_data.get("cookie")
        if not cookie:
            return JSONResponse({"status": "error", "message": "No cookie configured for this account."}, status_code=400)

        if "PANWEB=" not in cookie:
            cookie = f"{cookie}; PANWEB=1"
            acc_data["cookie"] = cookie

        try:
            tokens = await resolve_tokens_from_cookie(cookie)
            bds = tokens.get("bds_token") or acc_data.get("bds_token")
            js = tokens.get("js_token") or acc_data.get("js_token")
            acc_data["bds_token"] = bds
            acc_data["js_token"] = js

            prof = await fetch_account_profile(cookie, bds)
            if prof:
                acc_data.update(prof)

            acc_data["status"] = "healthy"
            acc_data["last_used"] = int(time.time())
            acc_data.pop("unhealthy_reason", None)
            acc_data.pop("unhealthy_at", None)

            redis_client.hset(ACCOUNTS_HASH_KEY, account_id, json.dumps(acc_data))
            return {
                "status": "success",
                "message": f"Account '{account_id}' verified healthy and active!",
                "account": acc_data,
            }
        except Exception as exc:
            acc_data["status"] = "unhealthy"
            acc_data["unhealthy_reason"] = f"Re-test failed: {exc}"
            acc_data["unhealthy_at"] = int(time.time())
            redis_client.hset(ACCOUNTS_HASH_KEY, account_id, json.dumps(acc_data))
            return JSONResponse({
                "status": "error",
                "message": f"Account re-test failed: {exc}"
            }, status_code=400)

    # Allow shorthand: just ndus token
    ndus_value = data.get("ndus")
    if ndus_value and not data.get("cookie"):
        data["cookie"] = f"ndus={ndus_value}; PANWEB=1"

    cookie_value = data.get("cookie")
    valid_keys = {"cookie", "js_token", "bds_token", "logid"}

    if cookie_value:
        try:
            resolved_tokens = await resolve_tokens_from_cookie(cookie_value)
            for key in ("bds_token", "js_token", "logid"):
                if resolved_tokens.get(key) and not data.get(key):
                    data[key] = resolved_tokens[key]
        except Exception as exc:
            return JSONResponse(
                {"status": "error", "message": f"Cookie validation failed: {exc}"},
                status_code=400,
            )
    else:
        updates = {k: v for k, v in data.items() if k in valid_keys and v is not None}
        if not updates:
            return JSONResponse(
                {
                    "status": "error",
                    "message": "No valid config updates. Provide at least 'ndus' or 'cookie'.",
                },
                status_code=400,
            )

    updates = {k: v for k, v in data.items() if k in valid_keys and v is not None}

    try:
        existing_raw = redis_client.hget(ACCOUNTS_HASH_KEY, account_id)
        account_data: dict = safe_json_loads(existing_raw)

        account_data.update(updates)
        account_data["status"] = "healthy"
        account_data.setdefault("last_used", int(time.time()))
        account_data.pop("unhealthy_reason", None)
        account_data.pop("unhealthy_at", None)
        # Remove stale legacy fields
        for legacy in ("sign", "timestamp"):
            account_data.pop(legacy, None)

        # Automatically fetch and attach account profile
        try:
            profile = await fetch_account_profile(account_data.get("cookie"), account_data.get("bds_token"))
            if profile:
                account_data.update(profile)
        except Exception:
            pass

        redis_client.hset(ACCOUNTS_HASH_KEY, account_id, json.dumps(account_data))

        active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
        if isinstance(active_id, bytes):
            active_id = active_id.decode("utf-8")
        if active_id == account_id or not active_id:
            redis_client.set(ACTIVE_ACCOUNT_KEY, account_id)
            load_config_from_redis()

        cache.invalidate_dashboard(account_id)

        return {
            "status":       "success",
            "message":      f"Account '{account_id}' updated successfully.",
            "updated_keys": list(updates.keys()),
        }
    except Exception as exc:
        return JSONResponse(
            {"status": "error", "message": f"Failed to update Redis pool: {exc}"},
            status_code=500,
        )


async def _handle_config_delete(request: Request):
    from api.account_manager import load_config_from_redis
    account_id = request.query_params.get("account_id")
    if not account_id:
        try:
            body = await request.json()
            account_id = body.get("account_id")
        except Exception:
            pass

    if not account_id:
        return JSONResponse({"status": "error", "message": "Missing 'account_id' to delete."}, status_code=400)

    try:
        redis_client.hdel(ACCOUNTS_HASH_KEY, account_id)
        cache.invalidate_dashboard(account_id)

        active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
        if isinstance(active_id, bytes):
            active_id = active_id.decode("utf-8")

        # If deleted active account, pick next healthy or clear
        if active_id == account_id:
            get_next_healthy_account()
            load_config_from_redis()

        return {
            "status": "success",
            "message": f"Account '{account_id}' removed from pool.",
        }
    except Exception as exc:
        return JSONResponse({"status": "error", "message": f"Failed to delete account: {exc}"}, status_code=500)


async def _handle_config_get():
    try:
        active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
        if isinstance(active_id, bytes):
            active_id = active_id.decode("utf-8")

        raw_accounts = redis_client.hgetall(ACCOUNTS_HASH_KEY) or {}
        env_cookie = os.environ.get("TERABOX_COOKIE", "")
        env_ndus = extract_ndus(env_cookie)

        def _mask(key: str, val):
            if not val:
                return None
            if key == "cookie":
                return f"{val[:15]}...{val[-15:]}" if len(val) > 30 else "set"
            return f"{val[:4]}...{val[-4:]}" if len(val) > 8 else "set"

        pool_summary: dict = {}
        has_env_account_match = False

        for acc_id, raw_val in raw_accounts.items():
            acc_data = safe_json_loads(raw_val)
            if not acc_data:
                continue
            acc_id_str = acc_id.decode("utf-8") if isinstance(acc_id, bytes) else str(acc_id)

            acc_ndus = extract_ndus(acc_data.get("cookie", ""))
            is_env = bool(env_ndus and acc_ndus and acc_ndus == env_ndus)
            if is_env:
                has_env_account_match = True

            # If profile not yet cached and account has a cookie, fetch profile once and cache it in Redis
            if not acc_data.get("username") and not acc_data.get("email") and acc_data.get("status") == "healthy" and acc_data.get("cookie"):
                try:
                    prof = await fetch_account_profile(acc_data["cookie"], acc_data.get("bds_token"))
                    if prof:
                        acc_data.update(prof)
                        redis_client.hset(ACCOUNTS_HASH_KEY, acc_id_str, json.dumps(acc_data))
                except Exception:
                    pass

            item = {
                k: _mask(k, v) if k in ("cookie", "js_token", "bds_token", "logid") else v
                for k, v in acc_data.items()
            }
            item["is_env_account"] = is_env
            item["username"] = acc_data.get("username", "")
            item["email"] = acc_data.get("email", "")
            item["uk"] = acc_data.get("uk", "")
            item["avatar_url"] = acc_data.get("avatar_url", "")
            pool_summary[acc_id_str] = item

        # If .env has credentials but no account in Redis matches it, include it as default_env
        if env_cookie and not has_env_account_match:
            pool_summary["default_env"] = {
                "is_env_account": True,
                "status": "healthy",
                "cookie": _mask("cookie", env_cookie),
                "bds_token": _mask("bds_token", os.environ.get("TERABOX_BDSTOKEN", "")),
                "js_token": _mask("js_token", os.environ.get("TERABOX_JSTOKEN", "")),
                "username": "Default .env",
                "email": "",
                "uk": "",
                "avatar_url": "",
                "last_used": 0,
            }

        return {
            "status":            "success",
            "active_account_id": active_id,
            "accounts_pool":     pool_summary,
            "env_ndus_prefix":   (env_ndus[:6] + "..." + env_ndus[-4:]) if env_ndus else None,
        }
    except Exception as exc:
        return JSONResponse(
            {"status": "error", "message": f"Failed to read Redis pool: {exc}"},
            status_code=500,
        )


# ─── /api/cron/validate ──────────────────────────────────────────────

@router.api_route("/api/cron/validate", methods=["GET", "POST"])
async def cron_validate(request: Request):
    client_secret = request.query_params.get("secret")
    if not client_secret and "application/json" in request.headers.get("content-type", ""):
        try:
            body = await request.json()
            client_secret = body.get("secret")
        except Exception:
            pass

    is_master  = await check_admin(request)
    is_cron_ok = bool(
        CRON_SECRET
        and client_secret
        and hmac.compare_digest(str(client_secret), str(CRON_SECRET))
    )
    if not (is_master or is_cron_ok):
        return JSONResponse(
            {"status": "error", "message": "Unauthorized: Invalid or missing cron secret."},
            status_code=401,
        )

    accounts_checked = 0
    accounts_invalidated: list[tuple[str, str]] = []

    if redis_client:
        try:
            raw_accounts = redis_client.hgetall(ACCOUNTS_HASH_KEY) or {}
            for acc_id, raw_val in raw_accounts.items():
                acc_id_str = acc_id.decode("utf-8") if isinstance(acc_id, bytes) else acc_id
                creds = json.loads(raw_val)
                if creds.get("status", "healthy") == "healthy":
                    cookie_val = creds.get("cookie")
                    if cookie_val:
                        accounts_checked += 1
                        is_valid, msg = await validate_session_cookie(cookie_val)
                        if not is_valid:
                            mark_account_unhealthy(acc_id_str, reason=msg)
                            accounts_invalidated.append((acc_id_str, msg))
                            await send_webhook_alert(
                                f"🚨 **TeraBox Account Expired!**\n"
                                f"Account ID: `{acc_id_str}`\n"
                                f"Reason: `{msg}`\n\n"
                                f"Please refresh its cookie at `/api/admin/config`."
                            )

            # Force-rotate if the active account was just invalidated
            active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
            if isinstance(active_id, bytes):
                active_id = active_id.decode("utf-8")
            if active_id and any(a[0] == active_id for a in accounts_invalidated):
                get_next_healthy_account()
                from api.account_manager import load_config_from_redis
                load_config_from_redis()

        except Exception as exc:
            logger.warning("Cron accounts check failed: %s", exc)
    else:
        # No Redis — fall back to env cookie
        if COOKIE:
            accounts_checked += 1
            is_valid, msg = await validate_session_cookie(COOKIE)
            if not is_valid:
                accounts_invalidated.append(("default_env", msg))
                await send_webhook_alert(
                    f"🚨 **Default Env Cookie Expired!**\nReason: `{msg}`"
                )

    if redis_client:
        try:
            redis_client.hset("terabridge:status", values={
                "last_checked":      str(int(time.time())),
                "checked_count":     str(accounts_checked),
                "invalidated_count": str(len(accounts_invalidated)),
                "status":            "healthy" if not accounts_invalidated else "degraded",
            })
        except Exception as exc:
            logger.warning("Failed to write cron status to Redis: %s", exc)

    return {
        "status":               "success",
        "checked_count":        accounts_checked,
        "invalidated_count":    len(accounts_invalidated),
        "invalidated_accounts": [a[0] for a in accounts_invalidated],
    }


# ─── Cloudvids File & Storage Management Endpoints ────────────────────

async def _get_account_credentials(account_id: str | None = None) -> tuple[dict, str, str]:
    """
    Returns (cookies_dict, bdstoken, jstoken) for a given account_id or active account.
    Auto-resolves bdstoken and jstoken from cookie if not cached.
    """
    from downloader import COOKIES_DICT, BDSTOKEN, JSTOKEN
    target_cookie = COOKIE
    target_bds = BDSTOKEN
    target_js = JSTOKEN

    if redis_client:
        try:
            if not account_id:
                active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
                account_id = active_id.decode("utf-8") if isinstance(active_id, bytes) else active_id

            if account_id:
                raw = redis_client.hget(ACCOUNTS_HASH_KEY, account_id)
                if raw:
                    data = json.loads(raw)
                    target_cookie = data.get("cookie") or target_cookie
                    target_bds = data.get("bds_token") or target_bds
                    target_js = data.get("js_token") or target_js
        except Exception as exc:
            logger.warning("[Admin] Error fetching account %s credentials: %s", account_id, exc)

    cookie_dict = parse_cookies(target_cookie) if target_cookie else COOKIES_DICT.copy()

    # If bdstoken or jstoken is missing, auto-resolve
    if target_cookie and (not target_bds or not target_js):
        try:
            resolved = await resolve_tokens_from_cookie(target_cookie)
            target_bds = resolved.get("bds_token") or target_bds
            target_js = resolved.get("js_token") or target_js
            # Save resolved tokens back to Redis if possible
            if redis_client and account_id:
                raw = redis_client.hget(ACCOUNTS_HASH_KEY, account_id)
                if raw:
                    data = json.loads(raw)
                    data["bds_token"] = target_bds
                    data["js_token"] = target_js
                    redis_client.hset(ACCOUNTS_HASH_KEY, account_id, json.dumps(data))
        except Exception as exc:
            logger.warning("[Admin] Token auto-resolution error for account %s: %s", account_id, exc)

    return cookie_dict, target_bds, target_js


@router.get("/api/admin/storage/quota")
async def get_storage_quota(request: Request):
    if not await check_admin(request):
        return JSONResponse({"status": "error", "message": "Unauthorized: Admin API key required."}, status_code=401)

    account_id = request.query_params.get("account_id") or "active"
    force_refresh = request.query_params.get("refresh") in ("1", "true") or request.query_params.get("no_cache") in ("1", "true")

    cache_key = f"quota:{account_id}"
    if not force_refresh:
        cached = cache.get_dashboard(cache_key)
        if cached:
            return cached

    cookies_dict, bds, _ = await _get_account_credentials(account_id if account_id != "active" else None)

    headers = {"User-Agent": UA, "Referer": "https://dm.1024terabox.com/"}
    try:
        async with httpx.AsyncClient(headers=headers, cookies=cookies_dict, follow_redirects=True, timeout=15.0) as client:
            url = f"{BASE_API}/api/quota?{qp()}&bdstoken={bds}"
            r = await client.get(url)
            data = r.json()
            if data.get("errno") != 0:
                return JSONResponse({"status": "error", "message": data.get("errmsg", "Failed to retrieve quota"), "errno": data.get("errno")}, status_code=400)

            total = data.get("total", 0)
            used = data.get("used", 0)
            free = max(total - used, 0)
            pct = round((used / total * 100), 2) if total > 0 else 0

            res = {
                "status": "success",
                "account_id": account_id,
                "total_bytes": total,
                "used_bytes": used,
                "free_bytes": free,
                "total_gb": round(total / (1024 ** 3), 2),
                "used_gb": round(used / (1024 ** 3), 2),
                "free_gb": round(free / (1024 ** 3), 2),
                "used_percent": pct,
            }
            cache.put_dashboard(cache_key, res, ttl_seconds=60)
            return res
    except Exception as exc:
        return JSONResponse({"status": "error", "message": f"Storage quota request failed: {exc}"}, status_code=500)


@router.get("/api/admin/cloudvids")
async def list_cloudvids(request: Request):
    if not await check_admin(request):
        return JSONResponse({"status": "error", "message": "Unauthorized: Admin API key required."}, status_code=401)

    account_id = request.query_params.get("account_id") or "active"
    dir_path = request.query_params.get("dir") or "/cloudvids"
    page = int(request.query_params.get("page") or 1)
    num = int(request.query_params.get("num") or 100)
    force_refresh = request.query_params.get("refresh") in ("1", "true") or request.query_params.get("no_cache") in ("1", "true")

    cache_key = f"cloudvids:{account_id}:{dir_path}:{page}:{num}"
    if not force_refresh:
        cached = cache.get_dashboard(cache_key)
        if cached:
            return cached

    cookies_dict, bds, _ = await _get_account_credentials(account_id if account_id != "active" else None)
    encoded_dir = urllib.parse.quote(dir_path)

    headers = {"User-Agent": UA, "Referer": "https://dm.1024terabox.com/"}
    try:
        async with httpx.AsyncClient(headers=headers, cookies=cookies_dict, follow_redirects=True, timeout=20.0) as client:
            url = (
                f"{BASE_API}/api/list?{qp()}&dir={encoded_dir}&order=time&desc=1"
                f"&showempty=0&page={page}&num={num}&bdstoken={bds}"
            )
            r = await client.get(url)
            data = r.json()
            errno = data.get("errno")

            # errno -9 means directory doesn't exist yet on this account
            if errno == -9:
                # Auto-create /cloudvids folder on this account
                try:
                    create_url = f"{BASE_API}/api/create?{qp()}&bdstoken={bds}"
                    await client.post(create_url, data={
                        "path": dir_path,
                        "isdir": "1",
                        "size": "0",
                        "block_list": "[]",
                        "method": "post"
                    })
                except Exception:
                    pass
                empty_res = {
                    "status": "success",
                    "account_id": account_id,
                    "dir": dir_path,
                    "count": 0,
                    "files": [],
                }
                cache.put_dashboard(cache_key, empty_res, ttl_seconds=60)
                return empty_res

            if errno != 0:
                return JSONResponse(
                    {"status": "error", "message": data.get("errmsg", "Failed to list directory"), "errno": errno},
                    status_code=400,
                )

            file_list = []
            for item in data.get("list", []):
                size_bytes = item.get("size", 0)
                raw_thumbs = item.get("thumbs") or {}
                # Sign thumbnail URL if available
                thumb_url = raw_thumbs.get("url3") or raw_thumbs.get("url2") or raw_thumbs.get("url1") or raw_thumbs.get("icon")
                proxied_thumb = None
                if thumb_url:
                    signed_t = make_signed_params(request, thumb_url, "", "", kind="thumbnail")
                    proxied_thumb = f"/api/thumbnail?url={urllib.parse.quote(thumb_url)}&{signed_t}"

                file_list.append({
                    "fs_id": str(item.get("fs_id")),
                    "filename": item.get("server_filename"),
                    "path": item.get("path"),
                    "size_bytes": size_bytes,
                    "size_mb": round(size_bytes / (1024 * 1024), 2),
                    "created_at": item.get("server_mtime") or item.get("server_ctime"),
                    "is_dir": bool(item.get("isdir")),
                    "thumbnail": proxied_thumb,
                    "raw_thumbs": raw_thumbs,
                })

            res = {
                "status": "success",
                "account_id": account_id,
                "dir": dir_path,
                "count": len(file_list),
                "files": file_list,
            }
            cache.put_dashboard(cache_key, res, ttl_seconds=60)
            return res
    except Exception as exc:
        return JSONResponse({"status": "error", "message": f"List directory failed: {exc}"}, status_code=500)


@router.delete("/api/admin/cloudvids")
async def delete_cloudvids(request: Request):
    if not await check_admin(request):
        return JSONResponse({"status": "error", "message": "Unauthorized: Admin API key required."}, status_code=401)

    account_id = request.query_params.get("account_id")
    try:
        body = await request.json()
    except Exception:
        body = {}

    paths = body.get("paths") or []
    if isinstance(paths, str):
        paths = [paths]

    if not paths:
        return JSONResponse({"status": "error", "message": "Missing 'paths' list in request body."}, status_code=400)

    # Sanity check: ensure only paths under /cloudvids can be deleted via this endpoint
    safe_paths = []
    for p in paths:
        clean = p.strip()
        if clean.startswith("/cloudvids"):
            safe_paths.append(clean)

    if not safe_paths:
        return JSONResponse({"status": "error", "message": "No valid paths under /cloudvids provided."}, status_code=400)

    cookies_dict, bds, js = await _get_account_credentials(account_id)

    headers = {"User-Agent": UA, "Referer": "https://dm.1024terabox.com/"}
    try:
        async with httpx.AsyncClient(headers=headers, cookies=cookies_dict, follow_redirects=True, timeout=25.0) as client:
            # clienttype=1 & app_id=250528 bypasses web captcha challenge (errno 450016 "need verify")
            url = f"{BASE_API}/api/filemanager?opera=delete&async=0&onnest=fail&bdstoken={bds}&clienttype=1&app_id=250528"
            payload = {"filelist": json.dumps(safe_paths)}
            r = await client.post(url, data=payload)
            data = r.json()

            # If mobile endpoint fails, attempt xpan endpoint as fallback
            if data.get("errno") != 0:
                xpan_url = f"{BASE_API}/rest/2.0/xpan/file?method=filemanager&opera=delete&bdstoken={bds}"
                r_xpan = await client.post(xpan_url, data=payload)
                data_xpan = r_xpan.json()
                if data_xpan.get("errno") == 0:
                    data = data_xpan

            if data.get("errno") == 0:
                cache.invalidate_dashboard(account_id)
                return {
                    "status": "success",
                    "message": f"Successfully deleted {len(safe_paths)} file(s).",
                    "deleted_paths": safe_paths,
                    "terabox_response": data.get("info", []),
                }
            else:
                return JSONResponse(
                    {
                        "status": "error",
                        "message": data.get("errmsg", "TeraBox delete operation failed"),
                        "errno": data.get("errno"),
                        "request_id": data.get("request_id"),
                    },
                    status_code=400,
                )
    except Exception as exc:
        return JSONResponse({"status": "error", "message": f"Delete request failed: {exc}"}, status_code=500)

