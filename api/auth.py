"""
api/auth.py — Authentication helpers for TeraBridge API.

Handles:
  - API key extraction from headers / query params / body
  - Firebase ID token verification (RS256 JWT)
  - check_auth / check_admin guards used by route handlers
  - User-tier resolution (free / premium) with local + Redis caching
"""
import re
import time
import logging
import threading

import httpx
import jwt

from fastapi import Request

from api.config import (
    API_KEY,
    HMAC_SECRET,
    REQUIRE_API_KEY,
    FIREBASE_PROJECT_ID,
)
from api.redis_client import redis_client

logger = logging.getLogger("terabridge.auth")

# ─── Google public-key cache ─────────────────────────────────────────
GOOGLE_KEYS_URL = (
    "https://www.googleapis.com/robot/v1/metadata/x509/"
    "securetoken@system.gserviceaccount.com"
)
_google_public_keys: dict = {}
_keys_expiry: float = 0.0
_recent_auth_errors: list = []


async def get_google_public_keys() -> dict:
    global _google_public_keys, _keys_expiry
    now = time.time()
    if _google_public_keys and now <= _keys_expiry:
        return _google_public_keys
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(GOOGLE_KEYS_URL, timeout=10.0)
            if r.status_code == 200:
                _google_public_keys = r.json()
                cache_control = r.headers.get("Cache-Control", "")
                max_age = 3600
                m = re.search(r"max-age=(\d+)", cache_control)
                if m:
                    max_age = int(m.group(1))
                _keys_expiry = now + max_age
    except Exception as exc:
        logger.error("Failed to fetch Google public keys: %s", exc)
    return _google_public_keys


async def verify_firebase_token(request: Request, token: str) -> bool:
    global _recent_auth_errors
    if not token:
        return False
    try:
        request.state.firebase_token = token
        public_keys = await get_google_public_keys()
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        public_key_pem = public_keys.get(kid)
        if not public_key_pem:
            err_msg = f"Public key for kid '{kid}' not found."
            logger.error("[Auth] %s", err_msg)
            _record_auth_error(err_msg)
            return False

        from cryptography.x509 import load_pem_x509_certificate
        cert_obj = load_pem_x509_certificate(public_key_pem.encode())
        public_key_obj = cert_obj.public_key()

        decoded = jwt.decode(
            token,
            public_key_obj,
            algorithms=["RS256"],
            audience=FIREBASE_PROJECT_ID,
            issuer=f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}",
        )
        request.state.user = decoded
        return True
    except Exception as exc:
        logger.error("[Auth] Firebase JWT verification failed: %s", exc)
        _record_auth_error(str(exc))
        return False


def _record_auth_error(msg: str):
    _recent_auth_errors.append({"timestamp": time.time(), "error": msg})
    if len(_recent_auth_errors) > 10:
        _recent_auth_errors.pop(0)


def get_recent_auth_errors() -> list:
    return list(_recent_auth_errors)


# ─── API key extraction ───────────────────────────────────────────────
def _extract_api_key(request: Request, body_json=None, exclude_jwt: bool = False) -> str | None:
    client_key = request.headers.get("X-API-Key")

    if not client_key:
        auth_header = request.headers.get("Authorization") or ""
        if auth_header.startswith("Bearer "):
            bearer_token = auth_header[len("Bearer "):].strip()
            if not (exclude_jwt and bearer_token.count(".") == 2):
                client_key = bearer_token

    if not client_key:
        client_key = (
            request.query_params.get("key")
            or request.query_params.get("api_key")
        )

    if not client_key and body_json is not None:
        client_key = body_json.get("key") or body_json.get("api_key")

    return client_key


# ─── Auth guards ─────────────────────────────────────────────────────
async def check_auth(request: Request) -> bool:
    """Return True if the request carries valid credentials (Firebase JWT or API key)."""
    import hmac as _hmac

    request.state.auth_type = None

    body_json = None
    if "application/json" in request.headers.get("content-type", ""):
        try:
            body_json = await request.json()
        except Exception:
            pass

    client_key = _extract_api_key(request, body_json)

    # Firebase JWT (three-part dot-separated token)
    if client_key and client_key.count(".") == 2:
        if await verify_firebase_token(request, client_key):
            request.state.auth_type = "firebase"
            request.state.firebase_token = client_key
            await resolve_and_cache_user_tier_async(request, client_key)
            return True
        return False

    if not client_key:
        if not API_KEY:
            if REQUIRE_API_KEY:
                return False
            request.state.auth_type = "anonymous"
            return True
        return False

    if API_KEY and _hmac.compare_digest(client_key, API_KEY):
        request.state.auth_type = "admin"
        return True

    return False


async def check_admin(request: Request) -> bool:
    """Return True only for requests carrying the master API key (not Firebase JWTs)."""
    import hmac as _hmac

    if not API_KEY:
        return False

    body_json = None
    if "application/json" in request.headers.get("content-type", ""):
        try:
            body_json = await request.json()
        except Exception:
            pass

    client_key = _extract_api_key(request, body_json, exclude_jwt=True)
    if not client_key:
        return False

    return _hmac.compare_digest(client_key, API_KEY)


# ─── User-tier resolution ─────────────────────────────────────────────
_user_tier_cache: dict = {}
_user_tier_cache_lock = threading.Lock()
USER_TIER_CACHE_TTL = 300  # seconds


async def resolve_and_cache_user_tier_async(request: Request, token: str):
    """Fetch and cache the Firebase user's tier without blocking the event loop."""
    user = getattr(request.state, "user", None) or {}
    uid = user.get("user_id") or user.get("sub")
    if not uid or not FIREBASE_PROJECT_ID:
        return

    now = time.time()
    with _user_tier_cache_lock:
        if uid in _user_tier_cache:
            _, expiry = _user_tier_cache[uid]
            if now < expiry:
                return

    if redis_client:
        try:
            cached_tier = redis_client.get(f"user:tier:{uid}")
            if cached_tier:
                if isinstance(cached_tier, bytes):
                    cached_tier = cached_tier.decode("utf-8")
                with _user_tier_cache_lock:
                    _user_tier_cache[uid] = (cached_tier, now + USER_TIER_CACHE_TTL)
                return
        except Exception:
            pass

    try:
        url = (
            f"https://{FIREBASE_PROJECT_ID}-default-rtdb.asia-southeast1"
            f".firebasedatabase.app/users/{uid}/profile/tier.json?auth={token}"
        )
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(url)
        if r.status_code == 200:
            db_tier = r.json()
            resolved_tier = "free"
            if db_tier:
                tier_str = str(db_tier).lower()
                if "premium" in tier_str or "pro" in tier_str:
                    resolved_tier = "premium"
            with _user_tier_cache_lock:
                _user_tier_cache[uid] = (resolved_tier, now + USER_TIER_CACHE_TTL)
            if redis_client:
                try:
                    redis_client.set(f"user:tier:{uid}", resolved_tier, ex=USER_TIER_CACHE_TTL)
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("Async Firebase user tier fetch failed: %s", exc)


def get_user_tier(request: Request | None = None) -> str:
    """Return 'premium' or 'free' for the authenticated user on this request."""
    if not request:
        return "free"

    auth_type = getattr(request.state, "auth_type", None)
    if auth_type == "admin":
        return "premium"

    user = getattr(request.state, "user", None)
    if not user:
        return "free"

    tier = user.get("tier") or user.get("role")
    if tier:
        tier_str = str(tier).lower()
        return "premium" if ("premium" in tier_str or "pro" in tier_str) else "free"

    uid = user.get("user_id") or user.get("sub")
    if not uid:
        return "free"

    now = time.time()
    with _user_tier_cache_lock:
        if uid in _user_tier_cache:
            cached_tier, expiry = _user_tier_cache[uid]
            if now < expiry:
                return cached_tier

    if redis_client:
        try:
            cached_tier = redis_client.get(f"user:tier:{uid}")
            if cached_tier:
                if isinstance(cached_tier, bytes):
                    cached_tier = cached_tier.decode("utf-8")
                with _user_tier_cache_lock:
                    _user_tier_cache[uid] = (cached_tier, now + USER_TIER_CACHE_TTL)
                return cached_tier
        except Exception as exc:
            logger.warning("Redis user tier cache get error: %s", exc)

    return "free"
