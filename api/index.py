import sys
import os
import httpx
import time
import asyncio
import threading
import hashlib
import hmac
import json
import ipaddress
import jwt
import urllib.parse
import re
from collections import OrderedDict
import logging

# Add the project root directory to sys.path to resolve downloader module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─── Query Parameter Truncating Filter for clean access logs ──────────
class QueryParamTruncatingFilter(logging.Filter):
    def filter(self, record):
        if not record.args:
            return True
        try:
            new_args = list(record.args)
            modified = False
            
            # Case 1: Standard Uvicorn formatting with 5 arguments:
            # (client_addr, method, path_with_query, http_version, status_code)
            if len(new_args) >= 5:
                path_with_query = new_args[2]
                if isinstance(path_with_query, str) and len(path_with_query) > 150:
                    parts = path_with_query.split("?", 1)
                    if len(parts) > 1:
                        path, query = parts
                        truncated_query = query[:30] + "... [truncated]" if len(query) > 30 else query
                        new_args[2] = f"{path}?{truncated_query}"
                        modified = True
            
            # Case 2: Alternative/fallback logging format with 3 arguments:
            # (client_addr, request_line, status_code)
            elif len(new_args) >= 3:
                request_line = new_args[1]
                if isinstance(request_line, str) and len(request_line) > 150:
                    parts = request_line.split("?", 1)
                    if len(parts) > 1:
                        path, query = parts
                        truncated_query = query[:30] + "... [truncated]" if len(query) > 30 else query
                        new_args[1] = f"{path}?{truncated_query}"
                        modified = True
            
            if modified:
                record.args = tuple(new_args)
        except Exception:
            pass
        return True

logging.getLogger("uvicorn.access").addFilter(QueryParamTruncatingFilter())

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse, RedirectResponse
from fastapi.middleware.gzip import GZipMiddleware

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from downloader import resolve_link, session, parse_surl, UA, COOKIES_DICT, validate_session_cookie, resolve_tokens_from_cookie, VIDEO_EXTS
from api.redis_client import redis_client
from api.account_pool import get_next_healthy_account, mark_account_unhealthy, ACCOUNTS_HASH_KEY, ACTIVE_ACCOUNT_KEY

app = FastAPI(title="TeraBridge API", version="2.0.0")

# Gzip Compression Middleware
app.add_middleware(GZipMiddleware, minimum_size=500)

# ─── Configuration ───────────────────────────────────────────────────
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL", 60))         # Cache responses for 60s
CACHE_MAX_ENTRIES = int(os.environ.get("CACHE_MAX_ENTRIES", 256)) # LRU eviction after 256 entries
RATE_LIMIT_RPM    = int(os.environ.get("RATE_LIMIT_RPM", 30))    # 30 requests per minute per IP
RATE_LIMIT_WINDOW = 60  # seconds
API_KEY           = os.environ.get("API_KEY")                    # API Key for securing endpoints (REQUIRED in production)
HMAC_SECRET       = os.environ.get("HMAC_SECRET") or API_KEY        # HMAC secret (falls back to API_KEY if not set; required if API_KEY is set)
REQUIRE_API_KEY   = os.environ.get("REQUIRE_API_KEY", "auto").lower() not in ("0", "false", "no")
TRUSTED_PROXY_CIDRS_RAW = os.environ.get("TRUSTED_PROXIES", "").strip()
CRON_SECRET             = os.environ.get("CRON_SECRET")
NOTIFICATION_WEBHOOK_URL = os.environ.get("NOTIFICATION_WEBHOOK_URL")

# CORS Origin Allowlist
ALLOWED_ORIGINS_RAW = os.environ.get("ALLOWED_ORIGINS", "").strip()
ALLOWED_ORIGINS = frozenset(
    o.strip().rstrip("/") for o in ALLOWED_ORIGINS_RAW.split(",") if o.strip()
)

def _cors_origin_for_request(request: Request):
    origin = request.headers.get("Origin", "").rstrip("/")
    if ALLOWED_ORIGINS:
        return origin if origin in ALLOWED_ORIGINS else None
    if origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
        return origin
    if not REQUIRE_API_KEY:
        return "*"
    return None

# Global CORS & Configuration Refresh ASGI Middleware
class CustomASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        # 1. Dynamic config refresh
        if request.method != "OPTIONS":
            global _last_config_check
            now = time.time()
            if now - _last_config_check > CONFIG_CHECK_INTERVAL:
                load_config_from_redis()
                _last_config_check = now

        # 2. Options preflight bypass
        if request.method == "OPTIONS":
            allowed_origin = _cors_origin_for_request(request)
            headers = [
                (b"access-control-allow-headers", b"*"),
                (b"access-control-allow-methods", b"GET, POST, OPTIONS"),
                (b"access-control-expose-headers", b"*"),
            ]
            if allowed_origin:
                headers.append((b"access-control-allow-origin", allowed_origin.encode()))
                headers.append((b"vary", b"Origin"))

            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": headers
            })
            await send({
                "type": "http.response.body",
                "body": b"",
                "more_body": False
            })
            return

        # 3. CORS origin header injection
        allowed_origin = _cors_origin_for_request(request)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                
                # Check and append CORS headers if they are not already set
                has_origin = False
                has_headers = False
                has_methods = False
                has_expose = False
                
                for h in headers:
                    name = h[0].lower()
                    if name == b"access-control-allow-origin":
                        has_origin = True
                    elif name == b"access-control-allow-headers":
                        has_headers = True
                    elif name == b"access-control-allow-methods":
                        has_methods = True
                    elif name == b"access-control-expose-headers":
                        has_expose = True
                
                if not has_origin and allowed_origin:
                    headers.append((b"access-control-allow-origin", allowed_origin.encode()))
                    headers.append((b"vary", b"Origin"))
                if not has_headers:
                    headers.append((b"access-control-allow-headers", b"*"))
                if not has_methods:
                    headers.append((b"access-control-allow-methods", b"GET, POST, OPTIONS"))
                if not has_expose:
                    headers.append((b"access-control-expose-headers", b"*"))
                
                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, send_wrapper)

app.add_middleware(CustomASGIMiddleware)

REDIRECT_SEGMENTS = os.environ.get("REDIRECT_SEGMENTS", "False").lower() in ("true", "1")

def _parse_trusted_cidrs(raw):
    cidrs = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            cidrs.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as e:
            print(f"[TeraBridge][WARN] Ignoring invalid TRUSTED_PROXIES entry {entry!r}: {e}")
    return cidrs

TRUSTED_PROXY_CIDRS = _parse_trusted_cidrs(TRUSTED_PROXY_CIDRS_RAW)

ON_VERCEL = bool(os.environ.get("VERCEL"))
ON_RENDER = (os.environ.get("RENDER", "").lower() in ("true", "1", "yes")) or ("RENDER_SERVICE_ID" in os.environ)

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

def _is_trusted_peer(request: Request, peer=None):
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

def _client_ip(request: Request):
    cached = getattr(request.state, "_cached_client_ip", None)
    if cached is not None:
        return cached

    resolved = _resolve_client_ip(request)
    request.state._cached_client_ip = resolved
    return resolved

def _resolve_client_ip(request: Request):
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

    if ON_RENDER or (not TRUSTED_PROXY_CIDRS and any(peer in c for c in _LOOPBACK_CIDRS)):
        return xff.split(",")[0].strip()

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

def _request_base_url(request: Request):
    scheme = request.url.scheme
    if ON_RENDER or ON_VERCEL:
        scheme = "https"
    elif _is_trusted_peer(request):
        forwarded_proto = request.headers.get("X-Forwarded-Proto")
        if forwarded_proto:
            scheme = forwarded_proto.split(",")[0].strip()
    return f"{scheme}://{request.url.netloc}"

# ─── Thread-safe LRU Cache ──────────────────────────────────────────
class ResponseCache:
    def __init__(self, max_entries=256, ttl_seconds=60, redis_client=None):
        self.redis_client = redis_client
        self._store = OrderedDict()
        self._lock = asyncio.Lock()
        self._max = max_entries
        self._ttl = ttl_seconds
        self.hits = 0
        self.misses = 0

    def _make_key(self, link, action, wait):
        raw = f"{link}|{action}|{wait}"
        return hashlib.md5(raw.encode()).hexdigest()

    def get(self, link, action, wait):
        key = self._make_key(link, action, wait)
        if self.redis_client:
            try:
                redis_key = f"cache:response:{key}"
                data_str = self.redis_client.get(redis_key)
                if data_str:
                    self.hits += 1
                    try:
                        self.redis_client.incr("stats:cache_hits")
                    except Exception:
                        pass
                    return json.loads(data_str)
                else:
                    self.misses += 1
                    try:
                        self.redis_client.incr("stats:cache_misses")
                    except Exception:
                        pass
                    return None
            except Exception as e:
                print(f"[TeraBridge][WARN] Upstash Redis get error: {e}", flush=True)

        if key in self._store:
            data, ts = self._store[key]
            if time.time() - ts < self._ttl:
                self._store.move_to_end(key)
                self.hits += 1
                return data
            else:
                del self._store[key]
        self.misses += 1
        return None

    def put(self, link, action, wait, response):
        key = self._make_key(link, action, wait)
        if self.redis_client:
            try:
                redis_key = f"cache:response:{key}"
                self.redis_client.set(redis_key, json.dumps(response), ex=self._ttl)
                return
            except Exception as e:
                print(f"[TeraBridge][WARN] Upstash Redis put error: {e}", flush=True)

        if key in self._store:
            del self._store[key]
        self._store[key] = (response, time.time())
        while len(self._store) > self._max:
            self._store.popitem(last=False)

    def stats(self):
        if self.redis_client:
            try:
                redis_hits = int(self.redis_client.get("stats:cache_hits") or 0)
                redis_misses = int(self.redis_client.get("stats:cache_misses") or 0)
                total = redis_hits + redis_misses
                
                try:
                    entries_count = len(self.redis_client.keys("cache:response:*") or [])
                except Exception:
                    entries_count = "unknown"
                
                return {
                    "provider": "upstash-redis",
                    "entries": entries_count,
                    "ttl_seconds": self._ttl,
                    "hits": redis_hits,
                    "misses": redis_misses,
                    "hit_rate": f"{(redis_hits / total * 100):.1f}%" if total > 0 else "N/A",
                }
            except Exception as e:
                print(f"[TeraBridge][WARN] Upstash Redis stats error: {e}", flush=True)
        
        total = self.hits + self.misses
        return {
            "provider": "in-memory",
            "entries": len(self._store),
            "max_entries": self._max,
            "ttl_seconds": self._ttl,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{(self.hits / total * 100):.1f}%" if total > 0 else "N/A",
        }

cache = ResponseCache(max_entries=CACHE_MAX_ENTRIES, ttl_seconds=CACHE_TTL_SECONDS, redis_client=redis_client)

# ─── Sliding-Window Rate Limiter ─────────────────────────────────────
class RateLimiter:
    def __init__(self, max_requests=30, window_seconds=60, redis_client=None):
        self.redis_client = redis_client
        self._requests = {}
        self._lock = asyncio.Lock()
        self._max = max_requests
        self._window = window_seconds
        self.total_blocked = 0

    def is_allowed(self, ip):
        now = time.time()
        if self.redis_client:
            try:
                key = f"rate_limit:{ip}"
                pipeline = self.redis_client.pipeline()
                pipeline.zremrangebyscore(key, 0, now - self._window)
                pipeline.zadd(key, {str(now): now})
                pipeline.zcard(key)
                pipeline.expire(key, self._window)
                res = pipeline.exec()
                
                count = int(res[2])
                if count > self._max:
                    try:
                        self.redis_client.incr("stats:rate_limit_blocked")
                    except Exception:
                        pass
                    return False
                return True
            except Exception as e:
                print(f"[TeraBridge][WARN] Upstash Redis rate limit check error: {e}", flush=True)

        if ip not in self._requests:
            self._requests[ip] = []

        self._requests[ip] = [
            ts for ts in self._requests[ip] if now - ts < self._window
        ]

        if len(self._requests[ip]) >= self._max:
            self.total_blocked += 1
            return False

        self._requests[ip].append(now)
        return True

    def remaining(self, ip):
        now = time.time()
        if self.redis_client:
            try:
                key = f"rate_limit:{ip}"
                pipeline = self.redis_client.pipeline()
                pipeline.zremrangebyscore(key, 0, now - self._window)
                pipeline.zcard(key)
                res = pipeline.exec()
                count = int(res[1])
                return max(0, self._max - count)
            except Exception as e:
                print(f"[TeraBridge][WARN] Upstash Redis rate limit remaining error: {e}", flush=True)

        if ip not in self._requests:
            return self._max
        active = [ts for ts in self._requests[ip] if now - ts < self._window]
        return max(0, self._max - len(active))

    def stats(self):
        if self.redis_client:
            try:
                blocked = int(self.redis_client.get("stats:rate_limit_blocked") or 0)
                try:
                    active_keys = self.redis_client.keys("rate_limit:*") or []
                    active_clients = len(active_keys)
                except Exception:
                    active_clients = "unknown"
                return {
                    "provider": "upstash-redis",
                    "max_rpm": self._max,
                    "window_seconds": self._window,
                    "active_clients": active_clients,
                    "total_blocked": blocked,
                }
            except Exception as e:
                print(f"[TeraBridge][WARN] Upstash Redis rate limit stats error: {e}", flush=True)

        now = time.time()
        active_ips = sum(
            1 for ts_list in self._requests.values()
            if any(now - ts < self._window for ts in ts_list)
        )
        return {
            "provider": "in-memory",
            "max_rpm": self._max,
            "window_seconds": self._window,
            "active_clients": active_ips,
            "total_blocked": self.total_blocked,
        }

    def cleanup(self):
        if self.redis_client:
            return
        now = time.time()
        stale = [
            ip for ip, ts_list in self._requests.items()
            if not any(now - ts < self._window for ts in ts_list)
        ]
        for ip in stale:
            del self._requests[ip]

rate_limiter = RateLimiter(max_requests=RATE_LIMIT_RPM, window_seconds=RATE_LIMIT_WINDOW, redis_client=redis_client)

async def _periodic_cleanup():
    while True:
        await asyncio.sleep(300)
        rate_limiter.cleanup()

# Startup background cleanup task
@app.on_event("startup")
async def startup_event():
    logging.getLogger("uvicorn.access").addFilter(QueryParamTruncatingFilter())
    asyncio.create_task(_periodic_cleanup())

# ─── Firebase ID Token Validation Helpers ────────────────────────────
FIREBASE_PROJECT_ID = os.environ.get("VITE_FIREBASE_PROJECT_ID") or os.environ.get("FIREBASE_PROJECT_ID") or "teraplay-project"
GOOGLE_KEYS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
_google_public_keys = {}
_keys_expiry = 0
_recent_auth_errors = []

async def get_google_public_keys():
    global _google_public_keys, _keys_expiry
    now = time.time()
    if not _google_public_keys or now > _keys_expiry:
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                r = await client.get(GOOGLE_KEYS_URL, timeout=10.0)
                if r.status_code == 200:
                    _google_public_keys = r.json()
                    cache_control = r.headers.get("Cache-Control", "")
                    max_age = 3600
                    match = re.search(r'max-age=(\d+)', cache_control)
                    if match:
                        max_age = int(match.group(1))
                    _keys_expiry = now + max_age
        except Exception as e:
            print(f"[TeraBridge][ERROR] Failed to fetch Google public keys: {e}", flush=True)
    return _google_public_keys

async def verify_firebase_token(request: Request, token):
    global _recent_auth_errors
    if not token:
        return False
    try:
        request.state.firebase_token = token
        public_keys = await get_google_public_keys()
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        public_key = public_keys.get(kid)
        if not public_key:
            err_msg = f"Public key for kid '{kid}' not found."
            print(f"[Auth][ERROR] {err_msg}", flush=True)
            _recent_auth_errors.append({
                "timestamp": time.time(),
                "error": err_msg
            })
            if len(_recent_auth_errors) > 10:
                _recent_auth_errors.pop(0)
            return False
            
        from cryptography.x509 import load_pem_x509_certificate
        cert_obj = load_pem_x509_certificate(public_key.encode())
        public_key_obj = cert_obj.public_key()
        
        decoded = jwt.decode(
            token,
            public_key_obj,
            algorithms=["RS256"],
            audience=FIREBASE_PROJECT_ID,
            issuer=f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}"
        )
        request.state.user = decoded
        return True
    except Exception as e:
        import traceback
        err_msg = f"{str(e)}\n{traceback.format_exc()}"
        print(f"[Auth][ERROR] Firebase JWT verification failed: {err_msg}", flush=True)
        _recent_auth_errors.append({
            "timestamp": time.time(),
            "error": str(e),
            "traceback": traceback.format_exc()
        })
        if len(_recent_auth_errors) > 10:
            _recent_auth_errors.pop(0)
        return False

def _extract_api_key(request: Request, body_json=None, exclude_jwt=False):
    client_key = request.headers.get("X-API-Key")
    if not client_key:
        auth_header = request.headers.get("Authorization") or ""
        if auth_header.startswith("Bearer "):
            bearer_token = auth_header[len("Bearer "):].strip()
            if not (exclude_jwt and bearer_token.count(".") == 2):
                client_key = bearer_token

    if not client_key:
        client_key = request.query_params.get("key") or request.query_params.get("api_key")

    if not client_key and body_json is not None:
        client_key = body_json.get("key") or body_json.get("api_key")

    return client_key

async def check_auth(request: Request):
    request.state.auth_type = None

    body_json = None
    if "application/json" in request.headers.get("content-type", ""):
        try:
            body_json = await request.json()
        except Exception:
            pass

    client_key = _extract_api_key(request, body_json)

    if client_key and client_key.count(".") == 2:
        if await verify_firebase_token(request, client_key):
            request.state.auth_type = "firebase"
            return True
        return False

    if not client_key:
        if not API_KEY:
            if REQUIRE_API_KEY:
                return False
            request.state.auth_type = "anonymous"
            return True
        return False

    if API_KEY and hmac.compare_digest(client_key, API_KEY):
        request.state.auth_type = "admin"
        return True

    return False

async def check_admin(request: Request):
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

    return hmac.compare_digest(client_key, API_KEY)

# ─── HMAC Signature Helpers for URL Security ──────────────────────────
TIERED_SIGNATURE_TTLS = {
    "free": {
        "segment":   int(os.environ.get("SIG_TTL_SEGMENT_FREE",   30 * 60)),
        "download":  int(os.environ.get("SIG_TTL_DOWNLOAD_FREE",  2 * 3600)),
        "manifest":  int(os.environ.get("SIG_TTL_MANIFEST_FREE",  24 * 3600)),
        "thumbnail": int(os.environ.get("SIG_TTL_THUMBNAIL_FREE", 24 * 3600)),
    },
    "premium": {
        "segment":   int(os.environ.get("SIG_TTL_SEGMENT_PREMIUM",   2 * 3600)),
        "download":  int(os.environ.get("SIG_TTL_DOWNLOAD_PREMIUM",  24 * 3600)),
        "manifest":  int(os.environ.get("SIG_TTL_MANIFEST_PREMIUM",  30 * 24 * 3600)),
        "thumbnail": int(os.environ.get("SIG_TTL_THUMBNAIL_PREMIUM", 30 * 24 * 3600)),
    }
}
DEFAULT_SIGNATURE_TTL = int(os.environ.get("SIG_TTL_DEFAULT", 24 * 3600))

_user_tier_cache = {}
_user_tier_cache_lock = threading.Lock()
USER_TIER_CACHE_TTL = 300

def get_user_tier(request: Request = None):
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
        if "premium" in tier_str or "pro" in tier_str:
            return "premium"
        return "free"

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
            redis_key = f"user:tier:{uid}"
            cached_tier = redis_client.get(redis_key)
            if cached_tier:
                if isinstance(cached_tier, bytes):
                    cached_tier = cached_tier.decode('utf-8')
                with _user_tier_cache_lock:
                    _user_tier_cache[uid] = (cached_tier, now + USER_TIER_CACHE_TTL)
                return cached_tier
        except Exception as e:
            print(f"[TeraBridge][WARN] Redis user tier cache get error: {e}", flush=True)

    token = getattr(request.state, "firebase_token", None)
    if token:
        try:
            url = f"https://{FIREBASE_PROJECT_ID}-default-rtdb.asia-southeast1.firebasedatabase.app/users/{uid}/profile/tier.json?auth={token}"
            with httpx.Client() as client:
                r = client.get(url, timeout=5)
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
                        redis_key = f"user:tier:{uid}"
                        redis_client.set(redis_key, resolved_tier, ex=USER_TIER_CACHE_TTL)
                    except Exception as e:
                        print(f"[TeraBridge][WARN] Redis user tier cache set error: {e}", flush=True)

                return resolved_tier
        except Exception as e:
            print(f"[TeraBridge][WARN] Failed to fetch user tier from Firebase DB: {e}", flush=True)

    return "free"

def signature_ttl_for(kind, tier="free"):
    ttls = TIERED_SIGNATURE_TTLS.get(tier, TIERED_SIGNATURE_TTLS["free"])
    return ttls.get(kind, DEFAULT_SIGNATURE_TTL)

def generate_signature(param1, param2, param3="", exp=""):
    if not HMAC_SECRET:
        return ""
    if exp != "":
        message = f"{param1}|{param2}|{param3}|{exp}"
    else:
        message = f"{param1}|{param2}|{param3}"
    return hmac.new(HMAC_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()

def make_signed_params(request: Request, param1, param2, param3="", kind="download"):
    if not HMAC_SECRET:
        return ""
    tier = get_user_tier(request)
    exp = int(time.time()) + signature_ttl_for(kind, tier)
    sig = generate_signature(param1, param2, param3, exp)
    return f"sig={sig}&exp={exp}"

def verify_signature(param1, param2, param3, signature, exp=""):
    if not signature or not HMAC_SECRET:
        return False

    if exp:
        try:
            if int(exp) < int(time.time()):
                return False
        except (TypeError, ValueError):
            return False
        expected = generate_signature(param1, param2, param3, exp)
        if not expected:
            return False
        return hmac.compare_digest(expected, signature)

    expected_legacy = generate_signature(param1, param2, param3, "")
    if expected_legacy and hmac.compare_digest(expected_legacy, signature):
        print("[TeraBridge][WARN] Accepted legacy un-expiring signed URL "
              f"(p1={param1[:24]}...). Consider re-resolving to refresh.", flush=True)
        return True
    return False

# ─── Startup timestamp ──────────────────────────────────────────────
_start_time = time.time()

# ─── Routes ──────────────────────────────────────────────────────────
@app.get("/")
def home():
    uptime = int(time.time() - _start_time)
    return {
        "status": "online",
        "message": "TeraBridge API is running!",
        "version": "2.0.0",
        "uptime_seconds": uptime,
        "endpoints": {
            "/api/resolve": "Resolve share links. Params: url (required), mode [download|stream|list] (optional)",
            "/api/stats": "View cache, rate limiter, and server statistics",
        }
    }

@app.get("/api/stats")
async def stats(request: Request):
    if not await check_admin(request):
        return JSONResponse({"status": "error", "message": "Unauthorized: Admin API key required."}, status_code=401)
    uptime = int(time.time() - _start_time)
    redis_status = "connected" if redis_client else "disabled"
    
    session_health = {"status": "unknown", "last_checked_timestamp": None, "message": "No validation check run yet."}
    if redis_client:
        try:
            status_data = redis_client.hgetall("terabridge:status")
            if status_data:
                session_health = {
                    "status": "healthy" if status_data.get("cookie_valid") == "true" else "unhealthy",
                    "last_checked_timestamp": status_data.get("last_checked"),
                    "message": status_data.get("message")
                }
        except Exception:
            pass

    return {
        "status": "online",
        "uptime_seconds": uptime,
        "redis": redis_status,
        "session_health": session_health,
        "cache": cache.stats(),
        "rate_limiter": rate_limiter.stats(),
        "firebase_project_id": FIREBASE_PROJECT_ID,
        "recent_auth_errors": _recent_auth_errors
    }

async def resolve_link_with_retry(link, action="d", wait_for_transcoding=False, quality=None):
    global _current_active_account_id
    max_retries = 2
    res = {}
    
    for attempt in range(max_retries):
        active_id = _current_active_account_id
        res = await resolve_link(link, action=action, wait_for_transcoding=wait_for_transcoding, quality=quality)
        
        # Identify account-level errors
        is_account_error = False
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
            
        # Check files for storage full or auth errors
        if not is_account_error and res.get("errno") == 0:
            files = res.get("files", [])
            if files:
                account_failure_count = 0
                for f in files:
                    err_msg = str(f.get("error", ""))
                    if "errno -6" in err_msg or "errno -9" in err_msg or "errno 111" in err_msg:
                        account_failure_count += 1
                        reason = "File transfer authentication failure"
                    elif "errno -10" in err_msg or "errno 12" in err_msg:
                        account_failure_count += 1
                        reason = "Account storage limit reached (quota exceeded)"
                if account_failure_count == len(files):
                    is_account_error = True
                    
        if is_account_error and active_id:
            print(f"[TeraBridge] Account '{active_id}' hit account-level failure: {reason}. Marking UNHEALTHY.", flush=True)
            mark_account_unhealthy(active_id, reason)
            # Rotate config
            load_config_from_redis()
            if attempt < max_retries - 1:
                print(f"[TeraBridge] Retrying resolution using rotated account: {_current_active_account_id}", flush=True)
                continue
                
        break
        
    return res

# ─── Helper: Format resolve_link outputs to API proxy format ──────────
def _format_resolved_response(request: Request, res, link):
    is_transcoding = any(f.get("error") == "transcoding_in_progress" for f in res.get("files", []))
    
    response_data = {
        "status": "transcoding" if is_transcoding else "success",
        "title": res.get("title"),
        "share_id": res.get("share_id"),
        "uk": res.get("uk"),
        "files": []
    }

    surl = parse_surl(link)
    for f in res.get("files", []):
        original_fs_id = f.get("original_fs_id")
        raw_thumbs = f.get("thumbnails")
        proxied_thumbs = {}
        if raw_thumbs and isinstance(raw_thumbs, dict):
            for k, v in raw_thumbs.items():
                if v:
                    if original_fs_id and surl:
                        signed = make_signed_params(request, surl, original_fs_id, k, kind="thumbnail")
                        proxy_url = f"{_request_base_url(request)}/api/thumbnail?surl={surl}&fs_id={original_fs_id}&size_type={k}&{signed}"
                    else:
                        quoted_v = urllib.parse.quote(v)
                        signed = make_signed_params(request, v, "", "", kind="thumbnail")
                        proxy_url = f"{_request_base_url(request)}/api/thumbnail?url={quoted_v}&{signed}"
                    proxied_thumbs[k] = proxy_url

        dlink_url = f.get("dlink")
        if dlink_url and original_fs_id and surl:
            signed = make_signed_params(request, surl, original_fs_id, "", kind="download")
            proxy_dlink = f"{_request_base_url(request)}/api/download?surl={surl}&fs_id={original_fs_id}&{signed}"
        else:
            proxy_dlink = dlink_url

        if f.get("stream_ready") and original_fs_id and surl:
            signed = make_signed_params(request, surl, original_fs_id, "manifest", kind="manifest")
            proxy_stream = f"{_request_base_url(request)}/api/stream/manifest?surl={surl}&fs_id={original_fs_id}&{signed}"
        else:
            proxy_stream = None

        file_info = {
            "filename": f.get("filename"),
            "size_bytes": f.get("size_bytes"),
            "size_mb": f.get("size_mb"),
            "fs_id": f.get("fs_id"),
            "transfer_status": f.get("transfer_status"),
            "dlink": proxy_dlink,
            "stream_url": proxy_stream,
            "stream_ready": f.get("stream_ready"),
            "error": f.get("error"),
            "thumbnails": proxied_thumbs if proxied_thumbs else None,
            "path": f.get("path"),
            "is_directory": f.get("is_directory")
        }
        response_data["files"].append(file_info)
        
    return response_data, is_transcoding

# ─── Background Quality Pre-Warming ─────────────────────────────────
async def _prewarm_quality_cache(link, res):
    import downloader

    try:
        files = res.get("files", [])
        for file_index, f in enumerate(files):
            filename = f.get("filename", "")
            if not (filename and filename.lower().endswith(VIDEO_EXTS)):
                continue

            existing = cache.get(link, f"qualities:{file_index}", False)
            if existing:
                continue

            my_file_path = downloader.ROOT_PATH.rstrip("/") + "/" + filename
            encoded_path = urllib.parse.quote(my_file_path)

            qualities_to_check = {
                "1080p": "M3U8_AUTO_1080",
                "720p": "M3U8_AUTO_720",
                "480p": "M3U8_AUTO_480",
                "360p": "M3U8_AUTO_360"
            }

            matching_file = f
            ready_qualities = {}

            async def check_quality(qname, qtype):
                url = f"{downloader.BASE_API}/api/streaming?{downloader.qp()}&path={encoded_path}&type={qtype}&bdstoken={downloader.BDSTOKEN}"
                try:
                    sr = await downloader.session.get(url, timeout=15.0)
                    if sr.status_code == 200 and "#EXTM3U" in sr.text:
                        return qname, {
                            "fs_id": matching_file.get("original_fs_id") or matching_file.get("fs_id")
                        }
                except Exception as e:
                    print(f"[PreWarm][ERROR] Quality {qname}: {e}", flush=True)
                return qname, None

            tasks = [check_quality(qname, qtype) for qname, qtype in qualities_to_check.items()]
            quality_results = await asyncio.gather(*tasks)
            for qname, res_data in quality_results:
                if res_data:
                    ready_qualities[qname] = res_data

            if ready_qualities:
                key = cache._make_key(link, f"qualities:{file_index}", False)
                if redis_client:
                    try:
                        redis_key = f"cache:response:{key}"
                        redis_client.set(redis_key, json.dumps(ready_qualities), ex=86400)
                    except Exception as e:
                        print(f"[PreWarm][WARN] Redis cache save error: {e}", flush=True)
                else:
                    cache.put(link, f"qualities:{file_index}", False, ready_qualities)
                print(f"[PreWarm] Cached qualities for file {file_index}: {list(ready_qualities.keys())}", flush=True)
            else:
                print(f"[PreWarm] No streamable qualities found for file {file_index}", flush=True)

    except Exception as e:
        print(f"[PreWarm][ERROR] Background quality pre-warm failed: {e}", flush=True)

# ─── Single Flight (Request Collapsing) locks ────────────────────────
_single_flight_events = {}
_single_flight_lock = threading.Lock()

def acquire_resolve_lock(key):
    if redis_client:
        try:
            is_locked = redis_client.set(f"lock:resolve:{key}", "locked", nx=True, ex=30)
            return bool(is_locked)
        except Exception as e:
            print(f"[SingleFlight][WARN] Redis lock set error: {e}", flush=True)
            
    with _single_flight_lock:
        if key in _single_flight_events:
            return False
        _single_flight_events[key] = threading.Event()
        return True

def release_resolve_lock(key):
    if redis_client:
        try:
            redis_client.delete(f"lock:resolve:{key}")
        except Exception as e:
            print(f"[SingleFlight][WARN] Redis lock delete error: {e}", flush=True)
            
    with _single_flight_lock:
        if key in _single_flight_events:
            event = _single_flight_events.pop(key)
            event.set()

async def wait_for_resolution(key, check_cache_func, timeout=30):
    start = time.time()
    
    if redis_client:
        while time.time() - start < timeout:
            cached = check_cache_func()
            if cached is not None:
                return cached
            if not redis_client.exists(f"lock:resolve:{key}"):
                break
            await asyncio.sleep(1.0)
        return check_cache_func()

    event = None
    with _single_flight_lock:
        event = _single_flight_events.get(key)
        
    if event:
        await asyncio.to_thread(event.wait, timeout=timeout)
        
    return check_cache_func()

# ─── Background Transcoder Polling Worker ────────────────────────────
_transcode_jobs_lock = threading.Lock()
_active_transcode_jobs = set()

async def _background_transcode_poll(link, action, cache_key):
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

    print(f"[TranscoderWorker] Starting background transcoding checks for: {link}", flush=True)
    try:
        res = await resolve_link_with_retry(link, action=action, wait_for_transcoding=True)
        if res.get("errno") == 0:
            # Fake a request to check user tier or just pass None
            response_data, is_transcoding = _format_resolved_response(None, res, link)
            
            if not is_transcoding:
                cache.put(link, action, False, response_data)
                cache.put(link, action, True, response_data)
                
                video_title = res.get("title", "Unknown Video")
                alert_msg = f"🎉 **HLS Transcoding Complete!**\nVideo **{video_title}** has finished transcoding and is ready for streaming."
                await send_webhook_alert(alert_msg)
                print(f"[TranscoderWorker] Success: transcoding complete for: {link}", flush=True)
                return
                
        print(f"[TranscoderWorker] Finished polling, but transcoding is still incomplete for: {link}", flush=True)
    except Exception as e:
        print(f"[TranscoderWorker][ERROR] Exception during background transcode: {e}", flush=True)
    finally:
        if redis_client:
            try:
                redis_client.delete(lock_key)
            except Exception:
                pass
        else:
            with _transcode_jobs_lock:
                _active_transcode_jobs.discard(cache_key)

# ─── Main API Resolution Route ───────────────────────────────────────
@app.api_route("/api/resolve", methods=["GET", "POST"])
async def resolve(request: Request):
    if not await check_auth(request):
        return JSONResponse({"status": "error", "message": "Unauthorized: Invalid or missing API key."}, status_code=401)

    client_ip = _client_ip(request)

    if not rate_limiter.is_allowed(client_ip):
        remaining = rate_limiter.remaining(client_ip)
        return JSONResponse({
            "status": "error",
            "message": f"Rate limit exceeded. Max {RATE_LIMIT_RPM} requests per minute. Try again shortly.",
        }, status_code=429, headers={
            "Retry-After": str(RATE_LIMIT_WINDOW),
            "X-RateLimit-Limit": str(RATE_LIMIT_RPM),
            "X-RateLimit-Remaining": str(remaining)
        })

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
        return JSONResponse({
            "status": "error",
            "message": "Missing required parameter 'url' or 'link'."
        }, status_code=400)

    link = re.sub(r'[\s\u200b\u200c\u200d\ufeff\u202a\u202b\u202c\u202d\u202e]+', '', link)

    act_lower = action.lower()
    if act_lower in ("s", "stream", "streaming"):
        action = "s"
    elif act_lower in ("l", "list", "info", "metadata"):
        action = "l"
    else:
        action = "d"

    cached = cache.get(link, action, wait_for_transcoding)
    if cached is not None:
        return JSONResponse(cached, headers={
            "X-Cache": "HIT",
            "X-RateLimit-Remaining": str(rate_limiter.remaining(client_ip))
        })

    cache_key = cache._make_key(link, action, wait_for_transcoding)
    has_lock = acquire_resolve_lock(cache_key)
    
    if not has_lock:
        print(f"[SingleFlight] Waiting for concurrent resolution of: {link}", flush=True)
        cached = await wait_for_resolution(cache_key, lambda: cache.get(link, action, wait_for_transcoding), timeout=30)
        if cached is not None:
            return JSONResponse(cached, headers={
                "X-Cache": "HIT (COLLAPSED)",
                "X-RateLimit-Remaining": str(rate_limiter.remaining(client_ip))
            })
        print(f"[SingleFlight] Wait timed out, proceeding to resolve ourselves: {link}", flush=True)
        acquire_resolve_lock(cache_key)

    try:
        res = await resolve_link_with_retry(link, action=action, wait_for_transcoding=wait_for_transcoding)
        if res.get("errno") != 0:
            return JSONResponse({
                "status": "error",
                "message": res.get("error", "Unknown resolution error occurred.")
            }, status_code=400)

        response_data, is_transcoding = _format_resolved_response(request, res, link)

        if is_transcoding and not wait_for_transcoding:
            asyncio.create_task(_background_transcode_poll(link, action, cache_key))

        if action == "s" and not is_transcoding:
            asyncio.create_task(_prewarm_quality_cache(link, res))

        if not is_transcoding:
            cache.put(link, action, wait_for_transcoding, response_data)

        return JSONResponse(response_data, headers={
            "X-Cache": "MISS",
            "X-RateLimit-Remaining": str(rate_limiter.remaining(client_ip))
        })

    except ValueError as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=400)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({
            "status": "error",
            "message": f"Server encountered exception: {str(e)}"
        }, status_code=500)
    finally:
        release_resolve_lock(cache_key)

# ─── HLS Streaming Proxy routes ─────────────────────────────────────
@app.api_route("/api/stream/manifest", methods=["GET", "OPTIONS"])
@app.api_route("/api/stream/playlist.m3u8", methods=["GET", "OPTIONS"])
async def stream_manifest(request: Request):
    surl = request.query_params.get("surl") or ""
    fs_id = request.query_params.get("fs_id") or ""
    sig = request.query_params.get("sig") or ""
    exp = request.query_params.get("exp") or ""
    link = request.query_params.get("url") or request.query_params.get("link") or ""
    
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
        return JSONResponse({"status": "error", "message": "Unauthorized: Invalid signature or authentication."}, status_code=401)

    client_ip = _client_ip(request)

    if not rate_limiter.is_allowed(client_ip):
        return JSONResponse({
            "status": "error",
            "message": f"Rate limit exceeded. Try again shortly.",
        }, status_code=429)

    if not link and surl:
        link = f"https://1024terabox.com/s/{surl}"

    wait_for_transcoding = request.query_params.get("wait") in ("true", "1", "True")
    
    try:
        file_index = int(request.query_params.get("index", 0))
    except ValueError:
        file_index = 0

    if not link:
        return JSONResponse({
            "status": "error",
            "message": "Missing required parameter 'url', 'link' or 'surl'."
        }, status_code=400)

    quality = request.query_params.get("quality") or request.query_params.get("type") or ""

    qualities_to_check = {
        "1080p": "M3U8_AUTO_1080",
        "720p": "M3U8_AUTO_720",
        "480p": "M3U8_AUTO_480",
        "360p": "M3U8_AUTO_360"
    }

    try:
        if not quality:
            ready_qualities = cache.get(link, f"qualities:{file_index}", False)
            if ready_qualities:
                print(f"[Manifest] Cache HIT for available qualities: {link} -> {list(ready_qualities.keys())}", flush=True)
            else:
                print(f"[Manifest] Cache MISS for available qualities: {link}. Resolving...", flush=True)
                res = await resolve_link_with_retry(link, action="s", wait_for_transcoding=wait_for_transcoding)
                if res.get("errno") != 0:
                    return JSONResponse({"status": "error", "message": res.get("error", "Unknown resolution error occurred.")}, status_code=400)

                files = res.get("files", [])
                matching_file = None
                if fs_id and files:
                    for f in files:
                        if str(f.get("original_fs_id")) == str(fs_id) or str(f.get("fs_id")) == str(fs_id):
                            matching_file = f
                            break
                if not matching_file and files and file_index < len(files):
                    matching_file = files[file_index]

                if not matching_file:
                    return JSONResponse({"status": "error", "message": "No streamable video files found in this share link."}, status_code=404)

                filename = matching_file.get("filename")
                is_video = bool(filename and filename.lower().endswith(VIDEO_EXTS))

                if not is_video:
                    return JSONResponse({"status": "error", "message": "Selected file is not a streamable video."}, status_code=400)

                is_transcoding = any(f.get("error") == "transcoding_in_progress" for f in files)
                if is_transcoding and not any(f.get("stream_ready") for f in files):
                    return JSONResponse({
                        "status": "transcoding",
                        "message": "HLS streaming manifest is currently transcoding. Please try again shortly."
                    }, status_code=202)

                import downloader
                my_file_path = downloader.ROOT_PATH.rstrip("/") + "/" + filename
                encoded_path = urllib.parse.quote(my_file_path)

                ready_qualities = {}

                async def check_streaming_quality(qname, qtype):
                    url = (
                        f"{downloader.BASE_API}/api/streaming?{downloader.qp()}&path={encoded_path}&type={qtype}"
                        f"&bdstoken={downloader.BDSTOKEN}&isplayer=1&check_blue=1&clienttype=1&resolution={qname}"
                    )
                    try:
                        sr = await downloader.session.get(url, timeout=15.0)
                        if sr.status_code == 200 and "#EXTM3U" in sr.text:
                            return qname, {
                                "fs_id": matching_file.get("original_fs_id") or matching_file.get("fs_id")
                            }
                    except Exception as e:
                        print(f"[Manifest][ERROR] Failed to check quality {qname}: {e}", flush=True)
                    return qname, None

                tasks = [check_streaming_quality(qname, qtype) for qname, qtype in qualities_to_check.items()]
                quality_results = await asyncio.gather(*tasks)
                for qname, res_data in quality_results:
                    if res_data:
                        ready_qualities[qname] = res_data

                if not ready_qualities:
                    return JSONResponse({
                        "status": "error",
                        "message": "No streamable qualities are ready or transcoding for this video."
                    }, status_code=404)

                key = cache._make_key(link, f"qualities:{file_index}", False)
                if redis_client:
                    try:
                        redis_key = f"cache:response:{key}"
                        ttl = 86400 if not is_transcoding else 120
                        redis_client.set(redis_key, json.dumps(ready_qualities), ex=ttl)
                    except Exception as e:
                        print(f"[Manifest][WARN] Redis cache save error: {e}", flush=True)
                else:
                    cache.put(link, f"qualities:{file_index}", False, ready_qualities)

            # Build multivariant master playlist
            base_url = _request_base_url(request)
            playlist = ["#EXTM3U", "#EXT-X-VERSION:3"]
            
            qualities = [
                ("1080p", "4000000", "1920x1080"),
                ("720p",  "2500000", "1280x720"),
                ("480p",  "1200000", "854x480"),
                ("360p",  "60000",   "640x360")
            ]

            for qname, bandwidth, res_str in qualities:
                if qname in ready_qualities:
                    q_fs_id = ready_qualities[qname]["fs_id"]
                    signed = make_signed_params(request, surl, q_fs_id, "manifest", kind="manifest")
                    stream_url = (
                        f"{base_url}/api/stream/playlist.m3u8"
                        f"?surl={surl}&fs_id={q_fs_id}&quality={qname}&{signed}"
                    )
                    playlist.append(
                        f"#EXT-X-STREAM-INF:BANDWIDTH={bandwidth},"
                        f"RESOLUTION={res_str}"
                    )
                    playlist.append(stream_url)

            return Response(content="\n".join(playlist), media_type="application/x-mpegURL")

        # CASE 2: Specific quality playlist
        qtype = qualities_to_check.get(quality)
        if not qtype:
            return JSONResponse({"status": "error", "message": f"Unsupported stream quality: {quality}"}, status_code=400)

        import downloader
        res = await resolve_link_with_retry(link, action="s", wait_for_transcoding=wait_for_transcoding)
        if res.get("errno") != 0:
            return JSONResponse({"status": "error", "message": res.get("error", "Failed to resolve link.")}, status_code=400)

        files = res.get("files", [])
        matching_file = None
        if fs_id and files:
            for f in files:
                if str(f.get("original_fs_id")) == str(fs_id) or str(f.get("fs_id")) == str(fs_id):
                    matching_file = f
                    break
        if not matching_file and files and file_index < len(files):
            matching_file = files[file_index]

        if not matching_file:
            return JSONResponse({"status": "error", "message": "File not found."}, status_code=404)

        filename = matching_file.get("filename")
        my_file_path = downloader.ROOT_PATH.rstrip("/") + "/" + filename
        encoded_path = urllib.parse.quote(my_file_path)

        url = (
            f"{downloader.BASE_API}/api/streaming?{downloader.qp()}&path={encoded_path}&type={qtype}"
            f"&bdstoken={downloader.BDSTOKEN}&isplayer=1&check_blue=1&clienttype=1&resolution={quality}"
        )
        
        sr = await downloader.session.get(url, timeout=20.0)
        if sr.status_code != 200 or "#EXTM3U" not in sr.text:
            return JSONResponse({"status": "error", "message": f"Failed to retrieve stream from Terabox (status={sr.status_code})"}, status_code=500)

        m3u8_text = sr.text
        rewritten = []
        base_url = _request_base_url(request)

        for line in m3u8_text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("http://") or line.startswith("https://"):
                signed = make_signed_params(request, line, "", "", kind="segment")
                proxy_segment = f"{base_url}/api/stream/segment.ts?url={urllib.parse.quote(line)}&{signed}"
                rewritten.append(proxy_segment)
            else:
                rewritten.append(line)

        return Response(content="\n".join(rewritten), media_type="application/x-mpegURL")

    except Exception as e:
        return JSONResponse({"status": "error", "message": f"Manifest proxy error: {str(e)}"}, status_code=500)

@app.api_route("/api/stream/segment", methods=["GET", "OPTIONS"])
@app.api_route("/api/stream/segment.ts", methods=["GET", "OPTIONS"])
async def stream_segment(request: Request):
    url = request.query_params.get("url") or ""
    sig = request.query_params.get("sig") or ""
    exp = request.query_params.get("exp") or ""
    if not url:
        return Response(content="Missing segment URL", status_code=400)

    target_url = url

    if not (sig and verify_signature(target_url, "", "", sig, exp)) and not await check_auth(request):
        return Response(content="Unauthorized: Invalid signature or API key.", status_code=401)

    # SSRF Protection
    try:
        parsed = urllib.parse.urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return Response(content="Forbidden: Unsupported URL scheme.", status_code=403)
        domain = parsed.hostname.lower() if parsed.hostname else ""
        allowed_suffixes = (
            ".1024terabox.com", ".terabox.com", ".teraboxapp.com", ".terabox.app", ".baidu.com",
            ".freeterabox.com", ".nephobox.com", ".momerybox.com", ".mirrobox.com", ".gibibox.com",
            ".tibibox.com", ".4funbox.com", ".1024tera.com", ".1024nephobox.com", ".terabox.fun",
            ".terasharefile.com", ".teraboxlink.com", ".teraboxshare.com",
            ".1024terabox.com-videotran-hybcloud", ".terabox.com-videotran-hybcloud",
            ".teraboxapp.com-videotran-hybcloud", ".terabox.app-videotran-hybcloud",
            ".freeterabox.com-videotran-hybcloud", ".nephobox.com-videotran-hybcloud",
            ".momerybox.com-videotran-hybcloud", ".mirrobox.com-videotran-hybcloud",
            ".gibibox.com-videotran-hybcloud", ".teraboxshare.com-videotran-hybcloud",
            ".tibibox.com-videotran-hybcloud", ".4funbox.com-videotran-hybcloud",
            ".1024tera.com-videotran-hybcloud", ".1024nephobox.com-videotran-hybcloud",
            ".terabox.fun-videotran-hybcloud", ".terasharefile.com-videotran-hybcloud",
            ".teraboxlink.com-videotran-hybcloud",
            ".koofr.net", ".koofr.eu", "pcs.baidu.com", "d.pcs.1024terabox.com",
        )

        def _host_allowed(host, suffix):
            if suffix.startswith("."):
                return host == suffix[1:] or host.endswith(suffix)
            return host == suffix

        is_allowed = any(_host_allowed(domain, suffix) for suffix in allowed_suffixes)
        if not is_allowed:
            return Response(content="Forbidden: Invalid stream host destination.", status_code=403)
    except Exception:
        return Response(content="Invalid segment URL format", status_code=400)

    if REDIRECT_SEGMENTS:
        return RedirectResponse(url=target_url, status_code=307)

    client = httpx.AsyncClient(timeout=30.0, http2=True)
    try:
        headers = {
            "User-Agent": UA,
            "Referer": "https://dm.1024terabox.com/",
        }
        range_header = request.headers.get("Range")
        if range_header:
            headers["Range"] = range_header

        req_ctx = client.stream("GET", target_url, headers=headers, cookies=COOKIES_DICT)
        req = await req_ctx.__aenter__()
        
        resp_headers = {}
        cors_headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
        }
        
        for key in ("Content-Length", "Content-Type", "Content-Range", "Accept-Ranges"):
            if key in req.headers:
                resp_headers[key] = req.headers[key]
        
        resp_headers.update(cors_headers)
        
        async def generate():
            try:
                async for chunk in req.aiter_bytes(chunk_size=16384):
                    yield chunk
            finally:
                await req_ctx.__aexit__(None, None, None)
                await client.aclose()

        return StreamingResponse(generate(), status_code=req.status_code, headers=resp_headers)

    except Exception as e:
        await client.aclose()
        return Response(content=f"Segment proxy encountered an error: {str(e)}", status_code=500)

@app.api_route("/api/thumbnail", methods=["GET", "OPTIONS"])
@app.api_route("/api/stream/thumbnail", methods=["GET", "OPTIONS"])
async def stream_thumbnail(request: Request):
    url = request.query_params.get("url") or ""
    surl = request.query_params.get("surl") or ""
    fs_id = request.query_params.get("fs_id") or ""
    size_type = request.query_params.get("size_type") or request.query_params.get("size") or "url3"
    sig = request.query_params.get("sig") or ""
    exp = request.query_params.get("exp") or ""

    if not url and not (surl and fs_id):
        return Response(content="Missing thumbnail URL or surl/fs_id parameters", status_code=400)

    if not url:
        if not (sig and verify_signature(surl, fs_id, size_type, sig, exp)) and not await check_auth(request):
            return Response(content="Unauthorized: Invalid signature or API key.", status_code=401)
        
        share_url = f"https://1024terabox.com/s/{surl}"
        cached_res = cache.get(share_url, "l", False)
        if not cached_res:
            try:
                cached_res = await resolve_link_with_retry(share_url, action="l")
                if cached_res.get("errno") == 0:
                    cache.put(share_url, "l", False, cached_res)
            except Exception as e:
                return Response(content=f"Failed to resolve thumbnail details: {str(e)}", status_code=500)

        if cached_res.get("errno") != 0:
            return Response(content="Failed to query share content.", status_code=400)

        matching_file = None
        for f in cached_res.get("files", []):
            if str(f.get("original_fs_id")) == str(fs_id) or str(f.get("fs_id")) == str(fs_id):
                matching_file = f
                break
        
        if not matching_file or not matching_file.get("thumbnails"):
            return Response(content="Thumbnail image not found", status_code=404)

        url = matching_file["thumbnails"].get(size_type)
        if not url:
            url = next(iter(matching_file["thumbnails"].values()), None)

        if not url:
            return Response(content="Thumbnail image not available", status_code=404)

    else:
        if not (sig and verify_signature(url, "", "", sig, exp)) and not await check_auth(request):
            return Response(content="Unauthorized: Invalid signature or API key.", status_code=401)

    client = httpx.AsyncClient(timeout=30.0, http2=True)
    try:
        req_ctx = client.stream("GET", url, headers={"User-Agent": UA}, cookies=COOKIES_DICT)
        req = await req_ctx.__aenter__()

        resp_headers = {}
        for key in ("Content-Length", "Content-Type"):
            if key in req.headers:
                resp_headers[key] = req.headers[key]

        cors_headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
        }
        resp_headers.update(cors_headers)

        async def generate():
            try:
                async for chunk in req.aiter_bytes(chunk_size=8192):
                    yield chunk
            finally:
                await req_ctx.__aexit__(None, None, None)
                await client.aclose()

        return StreamingResponse(generate(), status_code=req.status_code, headers=resp_headers)

    except Exception as e:
        await client.aclose()
        return Response(content=f"Thumbnail proxy encountered an error: {str(e)}", status_code=500)

@app.api_route("/api/download", methods=["GET", "OPTIONS"])
async def download_file_route(request: Request):
    surl = request.query_params.get("surl") or ""
    fs_id = request.query_params.get("fs_id") or ""
    sig = request.query_params.get("sig") or ""
    exp = request.query_params.get("exp") or ""

    if not surl or not fs_id:
        return Response(content="Missing required parameters: surl and fs_id", status_code=400)

    if not (sig and verify_signature(surl, fs_id, "", sig, exp)) and not await check_auth(request):
        return Response(content="Unauthorized: Invalid signature or API key.", status_code=401)

    share_url = f"https://1024terabox.com/s/{surl}"
    cached_res = cache.get(share_url, "d", False)
    if not cached_res:
        try:
            cached_res = await resolve_link_with_retry(share_url, action="d")
            if cached_res.get("errno") == 0:
                is_transcoding = any(f.get("error") == "transcoding_in_progress" for f in cached_res.get("files", []))
                if not is_transcoding:
                    cache.put(share_url, "d", False, cached_res)
        except Exception as e:
            return Response(content=f"Failed to resolve download details: {str(e)}", status_code=500)

    if cached_res.get("errno") != 0:
        return Response(content=f"Failed to resolve share link: {cached_res.get('error', 'Unknown error')}", status_code=400)

    target_file = None
    for f in cached_res.get("files", []):
        if str(f.get("original_fs_id")) == str(fs_id) or str(f.get("fs_id")) == str(fs_id):
            target_file = f
            break

    if not target_file:
        return Response(content="File not found in share link", status_code=404)

    if target_file.get("error"):
        return Response(content=f"File resolution error: {target_file.get('error')}", status_code=400)

    dlink = target_file.get("dlink")
    filename = target_file.get("filename") or "download"

    if not dlink:
        return Response(content="Download link not available for this file", status_code=404)

    client = httpx.AsyncClient(follow_redirects=True, timeout=120.0, http2=True)
    try:
        headers = {
            "User-Agent": UA,
            "Referer": "https://dm.1024terabox.com/",
        }
        range_header = request.headers.get("Range")
        if range_header:
            headers["Range"] = range_header

        req_ctx = client.stream("GET", dlink, headers=headers, cookies=COOKIES_DICT)
        req = await req_ctx.__aenter__()

        resp_headers = {}
        for key in ("Content-Length", "Content-Type", "Content-Range", "Accept-Ranges"):
            if key in req.headers:
                resp_headers[key] = req.headers[key]

        if "Content-Type" not in resp_headers:
            resp_headers["Content-Type"] = "application/octet-stream"

        quoted_filename = urllib.parse.quote(filename)
        resp_headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quoted_filename}"

        resp_headers.update({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
        })

        async def generate():
            try:
                async for chunk in req.aiter_bytes(chunk_size=131072):
                    yield chunk
            finally:
                await req_ctx.__aexit__(None, None, None)
                await client.aclose()

        return StreamingResponse(generate(), status_code=req.status_code, headers=resp_headers)

    except Exception as e:
        await client.aclose()
        return Response(content=f"Download proxy encountered an error: {str(e)}", status_code=500)

@app.get("/api/debug_curl")
async def debug_curl(request: Request):
    if not await check_admin(request):
        return Response(content="Unauthorized", status_code=401)
    url = request.query_params.get("url")
    if not url:
        return Response(content="Missing url", status_code=400)
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
            req = await client.get(url, headers={"User-Agent": UA}, cookies=COOKIES_DICT)
            try:
                body = req.json()
            except Exception:
                body = req.text[:2000]
            return {
                "status_code": req.status_code,
                "headers": dict(req.headers),
                "body": body
            }
    except Exception as e:
        return Response(content=str(e), status_code=500)

# ─── Dynamic Config Sync ─────────────────────────────────────────────
_last_config_check = 0
CONFIG_CHECK_INTERVAL = 60
_current_active_account_id = None

def load_config_from_redis():
    global _current_active_account_id
    if not redis_client:
        return
    try:
        active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
        if isinstance(active_id, bytes):
            active_id = active_id.decode("utf-8")
        creds = None
        
        if active_id:
            raw_creds = redis_client.hget(ACCOUNTS_HASH_KEY, active_id)
            if raw_creds:
                try:
                    creds = json.loads(raw_creds)
                except Exception:
                    pass
                    
        if not creds or creds.get("status") != "healthy":
            active_id, creds = get_next_healthy_account()
            
        if creds:
            _current_active_account_id = active_id
            from downloader import update_credentials
            update_credentials(
                cookie=creds.get("cookie"),
                js_token=creds.get("js_token"),
                bds_token=creds.get("bds_token"),
                logid=creds.get("logid")
            )
            print(f"[TeraBridge] Successfully synchronized active pool account: {active_id}", flush=True)
    except Exception as e:
        print(f"[TeraBridge][WARN] Failed to load config from Upstash Redis pool: {e}", flush=True)

# Load initial config on startup
load_config_from_redis()

@app.api_route("/api/admin/config", methods=["GET", "POST"])
async def admin_config(request: Request):
    if not await check_admin(request):
        return JSONResponse({"status": "error", "message": "Unauthorized: Admin API key required."}, status_code=401)

    if not redis_client:
        return JSONResponse({
            "status": "error",
            "message": "Redis client is not configured. Config cannot be updated dynamically."
        }, status_code=400)

    if request.method == "POST":
        try:
            data = await request.json()
        except Exception:
            data = {}
        
        account_id = data.get("account_id") or _current_active_account_id or "account_1"
        
        # Support adding just the ndus token — auto-construct the full cookie
        ndus_value = data.get("ndus")
        if ndus_value and not data.get("cookie"):
            data["cookie"] = f"ndus={ndus_value}; PANWEB=1"
        
        cookie_value = data.get("cookie")
        
        if not cookie_value:
            # Check if there are other valid updates (for existing accounts)
            valid_keys = {"cookie", "js_token", "bds_token", "logid"}
            updates = {k: v for k, v in data.items() if k in valid_keys and v is not None}
            if not updates:
                return JSONResponse({
                    "status": "error",
                    "message": "No valid configuration updates provided. Provide at least 'ndus' or 'cookie'."
                }, status_code=400)
        else:
            # Validate session and resolve tokens in a single request to Terabox
            try:
                resolved_tokens = await resolve_tokens_from_cookie(cookie_value)
                # Merge resolved tokens (don't override if user explicitly provided them)
                for key in ("bds_token", "js_token", "logid"):
                    if resolved_tokens.get(key) and not data.get(key):
                        data[key] = resolved_tokens[key]
            except Exception as e:
                return JSONResponse({
                    "status": "error",
                    "message": f"Cookie validation or token resolution failed: {str(e)}"
                }, status_code=400)
        
        valid_keys = {"cookie", "js_token", "bds_token", "logid"}
        updates = {k: v for k, v in data.items() if k in valid_keys and v is not None}

        try:
            existing_raw = redis_client.hget(ACCOUNTS_HASH_KEY, account_id)
            account_data = {}
            if existing_raw:
                try:
                    account_data = json.loads(existing_raw)
                except Exception:
                    pass
            
            account_data.update(updates)
            account_data["status"] = "healthy"
            account_data["last_used"] = account_data.get("last_used") or int(time.time())
            if "unhealthy_reason" in account_data:
                del account_data["unhealthy_reason"]
            if "unhealthy_at" in account_data:
                del account_data["unhealthy_at"]
            # Clean up legacy fields that are no longer used
            for legacy_key in ("sign", "timestamp"):
                account_data.pop(legacy_key, None)

            redis_client.hset(ACCOUNTS_HASH_KEY, account_id, json.dumps(account_data))
            
            active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
            if isinstance(active_id, bytes):
                active_id = active_id.decode("utf-8")
            if active_id == account_id or not active_id:
                redis_client.set(ACTIVE_ACCOUNT_KEY, account_id)
                load_config_from_redis()
                
            return {
                "status": "success",
                "message": f"Account '{account_id}' updated successfully in Redis pool.",
                "updated_keys": list(updates.keys()),
                "auto_resolved": [k for k in ("bds_token", "js_token", "logid") if k in updates and k not in (data.get("_user_provided_keys") or [])]
            }
        except Exception as e:
            return JSONResponse({
                "status": "error",
                "message": f"Failed to update config in Redis pool: {str(e)}"
            }, status_code=500)

    else:
        try:
            active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
            if isinstance(active_id, bytes):
                active_id = active_id.decode("utf-8")
            raw_accounts = redis_client.hgetall(ACCOUNTS_HASH_KEY) or {}
            
            def mask_val(key, val):
                if not val:
                    return None
                if key == "cookie":
                    if len(val) > 30:
                        return f"{val[:15]}...{val[-15:]}"
                    return "set"
                if len(val) > 8:
                    return f"{val[:4]}...{val[-4:]}"
                return "set"

            pool_summary = {}
            for acc_id, raw_val in raw_accounts.items():
                try:
                    acc_data = json.loads(raw_val)
                    masked = {k: mask_val(k, v) if k in ("cookie", "js_token", "bds_token", "logid") else v for k, v in acc_data.items()}
                    pool_summary[acc_id.decode("utf-8") if isinstance(acc_id, bytes) else acc_id] = masked
                except Exception:
                    pass

            return {
                "status": "success",
                "active_account_id": active_id,
                "accounts_pool": pool_summary
            }
        except Exception as e:
            return JSONResponse({
                "status": "error",
                "message": f"Failed to read accounts from Redis pool: {str(e)}"
            }, status_code=500)

# ─── Cron Session Validation & Webhook Alerts ───────────────────────
async def send_webhook_alert(message):
    if not NOTIFICATION_WEBHOOK_URL:
        return
    import datetime
    import httpx
    
    payload = {}
    if "discord.com" in NOTIFICATION_WEBHOOK_URL:
        payload = {
            "embeds": [{
                "title": "🚨 TeraBridge API Warning",
                "description": message,
                "color": 16711680,
                "timestamp": datetime.datetime.utcnow().isoformat()
            }]
        }
    elif "slack.com" in NOTIFICATION_WEBHOOK_URL:
        payload = {
            "text": f"🚨 *TeraBridge API Warning:*\n{message}"
        }
    else:
        payload = {
            "event": "session_expired",
            "message": message
        }

    try:
        async with httpx.AsyncClient() as client:
            await client.post(NOTIFICATION_WEBHOOK_URL, json=payload, timeout=10.0)
    except Exception as e:
        print(f"[TeraBridge][WARN] Failed to send webhook alert: {e}", flush=True)

@app.api_route("/api/cron/validate", methods=["GET", "POST"])
async def cron_validate(request: Request):
    client_secret = request.query_params.get("secret")
    if not client_secret and "application/json" in request.headers.get("content-type", ""):
        try:
            body = await request.json()
            client_secret = body.get("secret")
        except Exception:
            pass

    is_master = await check_admin(request)
    is_cron_ok = bool(
        CRON_SECRET
        and client_secret
        and hmac.compare_digest(str(client_secret), str(CRON_SECRET))
    )
    if not (is_master or is_cron_ok):
        return JSONResponse({"status": "error", "message": "Unauthorized: Invalid or missing cron secret or admin key."}, status_code=401)

    accounts_checked = 0
    accounts_invalidated = []
    
    if redis_client:
        try:
            raw_accounts = redis_client.hgetall(ACCOUNTS_HASH_KEY) or {}
            for acc_id, raw_val in raw_accounts.items():
                acc_id_str = acc_id.decode("utf-8") if isinstance(acc_id, bytes) else acc_id
                creds = json.loads(raw_val)
                
                # We only check healthy accounts (no need to repeatedly check already unhealthy ones)
                if creds.get("status", "healthy") == "healthy":
                    cookie_val = creds.get("cookie")
                    if cookie_val:
                        accounts_checked += 1
                        is_valid, msg = await validate_session_cookie(cookie_val)
                        if not is_valid:
                            mark_account_unhealthy(acc_id_str, reason=msg)
                            accounts_invalidated.append((acc_id_str, msg))
                            
                            # Alert on Slack/Discord webhook
                            alert_msg = (
                                f"🚨 **TeraBox Account Expired!**\n"
                                f"Account ID: `{acc_id_str}`\n"
                                f"Reason: `{msg}`\n\n"
                                f"Please refresh its cookie and update it at `/api/admin/config` immediately."
                            )
                            await send_webhook_alert(alert_msg)
                            
            # If the current active account got invalidated, force rotate immediately
            active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
            if isinstance(active_id, bytes):
                active_id = active_id.decode("utf-8")
            if active_id and any(item[0] == active_id for item in accounts_invalidated):
                get_next_healthy_account()
                load_config_from_redis()
                
        except Exception as e:
            print(f"[TeraBridge][WARN] Failed to run cron accounts check: {e}", flush=True)
            
    else:
        # Fallback to local default cookie if Redis is not configured
        from downloader import COOKIE
        if COOKIE:
            accounts_checked += 1
            is_valid, msg = await validate_session_cookie(COOKIE)
            if not is_valid:
                accounts_invalidated.append(("default_env", msg))
                alert_msg = f"🚨 **Default Env Cookie Expired!**\nReason: `{msg}`"
                await send_webhook_alert(alert_msg)

    # Write summary status to Redis status hash
    status_data = {
        "last_checked": str(int(time.time())),
        "checked_count": str(accounts_checked),
        "invalidated_count": str(len(accounts_invalidated)),
        "status": "healthy" if len(accounts_invalidated) == 0 else "degraded"
    }
    
    if redis_client:
        try:
            redis_client.hset("terabridge:status", values=status_data)
        except Exception as e:
            print(f"[TeraBridge][WARN] Failed to write status to Redis in cron: {e}", flush=True)

    return {
        "status": "success",
        "checked_count": accounts_checked,
        "invalidated_count": len(accounts_invalidated),
        "invalidated_accounts": [acc[0] for acc in accounts_invalidated]
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 5000))
    print(f"[TeraBridge] Cache TTL: {CACHE_TTL_SECONDS}s | Rate limit: {RATE_LIMIT_RPM} req/min")
    if not API_KEY and not REQUIRE_API_KEY:
        print("[TeraBridge][WARNING] API_KEY is not set and REQUIRE_API_KEY is disabled — "
              "all endpoints are currently OPEN (no authentication). Do not expose this "
              "instance to the public internet.", flush=True)
    print(f"[TeraBridge] Starting Uvicorn async server on 0.0.0.0:{port}")
    uvicorn.run("api.index:app", host="0.0.0.0", port=port, reload=False, workers=1)
