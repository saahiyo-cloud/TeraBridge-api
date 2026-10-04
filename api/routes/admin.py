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
)
from downloader import UA, COOKIE, validate_session_cookie, resolve_tokens_from_cookie

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

@router.api_route("/api/admin/config", methods=["GET", "POST"])
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

    # GET — return masked pool summary
    return _handle_config_get()


async def _handle_config_post(request: Request):
    from api.account_manager import load_config_from_redis

    try:
        data = await request.json()
    except Exception:
        data = {}

    from api.routes.resolve import get_active_account_id
    account_id = data.get("account_id") or get_active_account_id() or "account_1"

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
        account_data: dict = {}
        if existing_raw:
            try:
                account_data = json.loads(existing_raw)
            except Exception:
                pass

        account_data.update(updates)
        account_data["status"] = "healthy"
        account_data.setdefault("last_used", int(time.time()))
        account_data.pop("unhealthy_reason", None)
        account_data.pop("unhealthy_at", None)
        # Remove stale legacy fields
        for legacy in ("sign", "timestamp"):
            account_data.pop(legacy, None)

        redis_client.hset(ACCOUNTS_HASH_KEY, account_id, json.dumps(account_data))

        active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
        if isinstance(active_id, bytes):
            active_id = active_id.decode("utf-8")
        if active_id == account_id or not active_id:
            redis_client.set(ACTIVE_ACCOUNT_KEY, account_id)
            load_config_from_redis()

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


def _handle_config_get():
    try:
        active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
        if isinstance(active_id, bytes):
            active_id = active_id.decode("utf-8")

        raw_accounts = redis_client.hgetall(ACCOUNTS_HASH_KEY) or {}

        def _mask(key: str, val):
            if not val:
                return None
            if key == "cookie":
                return f"{val[:15]}...{val[-15:]}" if len(val) > 30 else "set"
            return f"{val[:4]}...{val[-4:]}" if len(val) > 8 else "set"

        pool_summary: dict = {}
        for acc_id, raw_val in raw_accounts.items():
            try:
                acc_data = json.loads(raw_val)
                acc_id_str = acc_id.decode("utf-8") if isinstance(acc_id, bytes) else acc_id
                pool_summary[acc_id_str] = {
                    k: _mask(k, v) if k in ("cookie", "js_token", "bds_token", "logid") else v
                    for k, v in acc_data.items()
                }
            except Exception:
                pass

        return {
            "status":            "success",
            "active_account_id": active_id,
            "accounts_pool":     pool_summary,
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
