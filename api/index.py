import sys
import os
import time
import threading
import hashlib
import hmac
import json
import ipaddress
from collections import OrderedDict
from flask import Flask, request, jsonify, Response
import urllib.parse
import re

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Add the project root directory to sys.path to resolve downloader module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from downloader import resolve_link, session, parse_surl, UA, COOKIES_DICT, validate_session_cookie
from api.redis_client import redis_client
from api.account_pool import get_next_healthy_account, mark_account_unhealthy, ACCOUNTS_HASH_KEY, ACTIVE_ACCOUNT_KEY

app = Flask(__name__)

# ─── Global CORS Setup ───────────────────────────────────────────────
@app.before_request
def handle_options_preflight():
    if request.method == "OPTIONS":
        resp = Response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Expose-Headers"] = "*"
        return resp

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Expose-Headers"] = "*"
    return response

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
REDIRECT_SEGMENTS = os.environ.get("REDIRECT_SEGMENTS", "True").lower() in ("true", "1")


def _parse_trusted_cidrs(raw):
    """Parse a comma-separated CIDR list. Empty entries are ignored."""
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

# Platform auto-detection. Both Vercel and Render set their own env vars on
# every service instance; when present we trust their respective proxy headers
# without requiring TRUSTED_PROXIES to be configured.
ON_VERCEL = bool(os.environ.get("VERCEL"))
ON_RENDER = (os.environ.get("RENDER", "").lower() in ("true", "1", "yes")) or ("RENDER_SERVICE_ID" in os.environ)

# Loopback addresses are always trusted by default — they correspond to a local
# reverse proxy (nginx, caddy, Render's sidecar, Docker port-mapping) running
# on the same host.  This removes the need to manually configure
# TRUSTED_PROXIES=127.0.0.1/32 in the most common container / PaaS setups.
_LOOPBACK_CIDRS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)

def _peer_ip():
    """Return the immediate TCP peer as an ipaddress.IPv4Address / IPv6Address, or None."""
    addr = request.remote_addr
    if not addr:
        return None
    try:
        # Strip a zone id if the WSGI server passed an IPv6 zone (e.g. "fe80::1%eth0")
        return ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return None

def _is_trusted_peer(peer=None):
    """True if the immediate TCP peer is in a trusted proxy set.

    Trusted means one of:
      - Vercel edge  (VERCEL env detected)
      - Render proxy  (RENDER env detected)
      - Loopback address  (127.x.x.x or ::1) — local reverse proxy / sidecar
      - Explicit TRUSTED_PROXY_CIDRS entry
    """
    if ON_VERCEL or ON_RENDER:
        return True
    if peer is None:
        peer = _peer_ip()
    if peer is None:
        return False
    if any(peer in cidr for cidr in _LOOPBACK_CIDRS):
        return True
    if TRUSTED_PROXY_CIDRS and any(peer in cidr for cidr in TRUSTED_PROXY_CIDRS):
        return True
    return False

def _client_ip():
    """
    Resolve the *real* client IP, taking reverse proxies into account.

    Priority order:
      1. Vercel  →  x-vercel-forwarded-for (set by the edge, single hop).
      2. Render / loopback proxy  →  leftmost X-Forwarded-For entry.  The
         platform proxy (or local nginx/caddy) sanitizes the header, so the
         first value is the real client.
      3. Explicit TRUSTED_PROXY_CIDRS  →  walk the XFF chain right-to-left
         and return the first IP that is *not* in the trusted set.
      4. Direct connection  →  request.remote_addr.  XFF is ignored so a
         client cannot spoof their way around the per-IP rate limiter.
    """
    # ── Case 1: Vercel ──────────────────────────────────────────────
    if ON_VERCEL:
        v = request.headers.get("X-Vercel-Forwarded-For")
        if v:
            return v.split(",")[0].strip()
        return request.remote_addr or "unknown"

    peer = _peer_ip()
    if peer is None:
        return request.remote_addr or "unknown"

    # ── Case 4: direct connection ───────────────────────────────────
    if not _is_trusted_peer(peer):
        return str(peer)

    xff = request.headers.get("X-Forwarded-For", "")
    if not xff:
        return str(peer)

    # ── Case 2: platform-managed proxy or loopback ──────────────────
    # When the proxy is a platform sidecar / reverse-proxy on the same host
    # (Render, Docker, local dev) or no explicit CIDRs were configured, the
    # proxy already sanitized the XFF header. Take the leftmost entry.
    if ON_RENDER or (not TRUSTED_PROXY_CIDRS and any(peer in c for c in _LOOPBACK_CIDRS)):
        return xff.split(",")[0].strip()

    # ── Case 3: explicit CIDR list — walk right-to-left ────────────
    chain = [h.strip() for h in xff.split(",") if h.strip()]
    candidate = str(peer)
    for hop in reversed(chain):
        try:
            hop_ip = ipaddress.ip_address(hop.split("%")[0])
        except ValueError:
            return hop  # malformed entry — best effort, return as-is
        if any(hop_ip in cidr for cidr in TRUSTED_PROXY_CIDRS):
            continue  # still inside the trusted prefix, keep walking
        return str(hop_ip)
    return candidate

def _request_base_url():
    """Return the public base URL (scheme + host) for building proxy URLs.

    Behind a reverse proxy (Render, Vercel, nginx) Flask sees http even when
    the client connected over https.  We trust X-Forwarded-Proto from any
    recognised platform proxy or trusted peer.
    """
    scheme = request.scheme
    if ON_RENDER or ON_VERCEL:
        scheme = "https"
    elif _is_trusted_peer():
        forwarded_proto = request.headers.get("X-Forwarded-Proto")
        if forwarded_proto:
            scheme = forwarded_proto.split(",")[0].strip()
    return f"{scheme}://{request.host}"

# ─── Thread-safe LRU Cache ──────────────────────────────────────────
class ResponseCache:
    """Thread-safe cache that uses Upstash Redis (if configured) or falls back to in-memory LRU."""

    def __init__(self, max_entries=256, ttl_seconds=60, redis_client=None):
        self.redis_client = redis_client
        self._store = OrderedDict()   # key -> (response_dict, timestamp)
        self._lock = threading.Lock()
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

        with self._lock:
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

        with self._lock:
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
        
        with self._lock:
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
    """Per-IP sliding window rate limiter that utilizes Upstash Redis (if configured)."""

    def __init__(self, max_requests=30, window_seconds=60, redis_client=None):
        self.redis_client = redis_client
        self._requests = {}   # ip -> list of timestamps
        self._lock = threading.Lock()
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

        with self._lock:
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

        with self._lock:
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
        with self._lock:
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
        """Periodically remove stale IPs to prevent memory growth (only for in-memory)."""
        if self.redis_client:
            return
        now = time.time()
        with self._lock:
            stale = [
                ip for ip, ts_list in self._requests.items()
                if not any(now - ts < self._window for ts in ts_list)
            ]
            for ip in stale:
                del self._requests[ip]

rate_limiter = RateLimiter(max_requests=RATE_LIMIT_RPM, window_seconds=RATE_LIMIT_WINDOW, redis_client=redis_client)

# Background cleanup every 5 minutes to prevent stale IP accumulation
def _periodic_cleanup():
    while True:
        time.sleep(300)
        rate_limiter.cleanup()

_cleanup_thread = threading.Thread(target=_periodic_cleanup, daemon=True)
_cleanup_thread.start()

# ─── API Key Verification Helper ────────────────────────────────────
def check_auth():
    """
    Verify the request carries a valid API key.

    Accepted transports (in priority order):
      1. X-API-Key header
      2. Authorization: Bearer <key>
      3. ?key=...  or  ?api_key=...  query parameter
      4. JSON body {"key": ...} or {"api_key": ...}

    Behavior is controlled by REQUIRE_API_KEY:
      - True  (or unset, when API_KEY is configured): every protected endpoint
              must carry a valid key. No key configured at all also fails closed.
      - False (or unset, when API_KEY is *not* configured): endpoints are open.
              This is the legacy "auto" mode and is meant for local dev only.
              A loud warning is logged at startup when it kicks in.
    """
    # Fail-closed when API_KEY is not configured (unless explicitly disabled).
    if not API_KEY:
        if REQUIRE_API_KEY:
            # Operator asked for strict auth but didn't set a key: reject.
            return False
        # Auto/disabled mode with no key: open access (dev only).
        return True

    # 1. Custom header
    client_key = request.headers.get("X-API-Key")

    # 2. Standard Authorization: Bearer
    if not client_key:
        auth_header = request.headers.get("Authorization") or ""
        if auth_header.startswith("Bearer "):
            client_key = auth_header[len("Bearer "):].strip()

    # 3. Query parameter (fallback for media players / browser <video> tags)
    if not client_key:
        client_key = request.args.get("key") or request.args.get("api_key")

    # 4. JSON body
    if not client_key and request.is_json:
        try:
            client_key = request.json.get("key") or request.json.get("api_key")
        except Exception:
            pass

    if not client_key:
        return False

    # Constant-time comparison; both values must be the same length for a hit.
    return hmac.compare_digest(client_key, API_KEY)


# ─── HMAC Signature Helpers for URL Security ──────────────────────────
def generate_signature(param1, param2, param3=""):
    """
    HMAC-SHA256 signature over `param1|param2|param3` using HMAC_SECRET.

    HMAC_SECRET defaults to API_KEY when unset. If neither is configured,
    signing is disabled and an empty string is returned, which causes
    verify_signature to fail closed.
    """
    if not HMAC_SECRET:
        return ""
    message = f"{param1}|{param2}|{param3}"
    return hmac.new(HMAC_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify_signature(param1, param2, param3, signature):
    """
    Constant-time HMAC verification. Returns False on any missing input
    or when HMAC signing is not configured.
    """
    if not signature or not HMAC_SECRET:
        return False
    expected = generate_signature(param1, param2, param3)
    if not expected:
        return False
    return hmac.compare_digest(expected, signature)




# ─── Startup timestamp ──────────────────────────────────────────────
_start_time = time.time()

# ─── Routes ──────────────────────────────────────────────────────────

@app.route("/")
def home():
    uptime = int(time.time() - _start_time)
    return jsonify({
        "status": "online",
        "message": "TeraBridge API is running!",
        "version": "2.0.0",
        "uptime_seconds": uptime,
        "endpoints": {
            "/api/resolve": "Resolve share links. Params: url (required), mode [download|stream|list] (optional)",
            "/api/stats": "View cache, rate limiter, and server statistics",
        }
    })

@app.route("/api/stats")
def stats():
    """Observability endpoint for cache and rate limiter metrics."""
    if not check_auth():
        return jsonify({"status": "error", "message": "Unauthorized: Invalid or missing API key."}), 401
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

    return jsonify({
        "status": "online",
        "uptime_seconds": uptime,
        "redis": redis_status,
        "session_health": session_health,
        "cache": cache.stats(),
        "rate_limiter": rate_limiter.stats(),
    })

# ─── Helper: Format resolve_link outputs to API proxy format ──────────
def _format_resolved_response(res, link):
    """Format resolve_link dictionary to the API's proxy-rewritten output dictionary."""
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
                        sig = generate_signature(surl, original_fs_id, k)
                        proxy_url = f"{_request_base_url()}/api/thumbnail?surl={surl}&fs_id={original_fs_id}&size_type={k}&sig={sig}"
                    else:
                        quoted_v = urllib.parse.quote(v)
                        proxy_url = f"{_request_base_url()}/api/thumbnail?url={quoted_v}"
                        if API_KEY:
                            proxy_url += f"&key={API_KEY}"
                    proxied_thumbs[k] = proxy_url

        # Shortened download proxy link
        dlink_url = f.get("dlink")
        if dlink_url and original_fs_id and surl:
            sig = generate_signature(surl, original_fs_id, "")
            proxy_dlink = f"{_request_base_url()}/api/download?surl={surl}&fs_id={original_fs_id}&sig={sig}"
        else:
            proxy_dlink = dlink_url

        file_info = {
            "filename": f.get("filename"),
            "size_bytes": f.get("size_bytes"),
            "size_mb": f.get("size_mb"),
            "fs_id": f.get("fs_id"),
            "transfer_status": f.get("transfer_status"),
            "dlink": proxy_dlink,
            "stream_ready": f.get("stream_ready"),
            "error": f.get("error"),
            "thumbnails": proxied_thumbs if proxied_thumbs else None,
            "path": f.get("path"),
            "is_directory": f.get("is_directory")
        }
        # Only include HLS stream content if it is successfully parsed
        if f.get("stream_ready"):
            file_info["stream_m3u8"] = f.get("stream_m3u8")
        response_data["files"].append(file_info)
        
    return response_data, is_transcoding


# ─── Single Flight (Request Collapsing) locks ────────────────────────
_single_flight_events = {}
_single_flight_lock = threading.Lock()

def acquire_resolve_lock(key):
    """
    Tries to acquire a resolution lock for the given cache key.
    Returns True if acquired (caller must resolve and release), False otherwise (caller should wait).
    """
    if redis_client:
        try:
            # Set lock with 30 second expiration
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
    """Releases the resolution lock for the given cache key."""
    if redis_client:
        try:
            redis_client.delete(f"lock:resolve:{key}")
        except Exception as e:
            print(f"[SingleFlight][WARN] Redis lock delete error: {e}", flush=True)
            
    with _single_flight_lock:
        if key in _single_flight_events:
            event = _single_flight_events.pop(key)
            event.set()

def wait_for_resolution(key, check_cache_func, timeout=30):
    """Waits for another thread/process to complete resolution, checking the cache periodically."""
    start = time.time()
    
    if redis_client:
        while time.time() - start < timeout:
            cached = check_cache_func()
            if cached is not None:
                return cached
            # If lock is gone and cache is still empty, break to resolve ourselves
            if not redis_client.exists(f"lock:resolve:{key}"):
                break
            time.sleep(1.0)
        return check_cache_func()

    # In-memory event fallback
    event = None
    with _single_flight_lock:
        event = _single_flight_events.get(key)
        
    if event:
        event.wait(timeout=timeout)
        
    return check_cache_func()


# ─── Background Transcoder Polling Worker ────────────────────────────
_transcode_jobs_lock = threading.Lock()
_active_transcode_jobs = set()

def _background_transcode_poll(link, action, cache_key):
    """Background polling worker for HLS video transcoding."""
    lock_key = f"lock:transcode:{cache_key}"
    
    # Distributed lock check
    if redis_client:
        try:
            if not redis_client.set(lock_key, "running", nx=True, ex=300): # 5 min limit
                return # Already running
        except Exception:
            pass
    else:
        with _transcode_jobs_lock:
            if cache_key in _active_transcode_jobs:
                return
            _active_transcode_jobs.add(cache_key)

    print(f"[TranscoderWorker] Starting background transcoding checks for: {link}", flush=True)
    try:
        # Calls downloader.resolve_link with wait_for_transcoding=True,
        # which polls up to 12 times (120s total)
        res = resolve_link(link, action=action, wait_for_transcoding=True)
        if res.get("errno") == 0:
            # Check if transcoding is complete
            response_data, is_transcoding = _format_resolved_response(res, link)
            
            if not is_transcoding:
                # Update both wait=True and wait=False caches
                cache.put(link, action, False, response_data)
                cache.put(link, action, True, response_data)
                
                # Send Webhook Alert
                video_title = res.get("title", "Unknown Video")
                alert_msg = f"🎉 **HLS Transcoding Complete!**\nVideo **{video_title}** has finished transcoding and is ready for streaming."
                send_webhook_alert(alert_msg)
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


@app.route("/api/resolve", methods=["GET", "POST"])
def resolve():
    if not check_auth():
        return jsonify({"status": "error", "message": "Unauthorized: Invalid or missing API key."}), 401

    # ── Rate Limiting ──
    client_ip = _client_ip()

    if not rate_limiter.is_allowed(client_ip):
        remaining = rate_limiter.remaining(client_ip)
        resp = jsonify({
            "status": "error",
            "message": f"Rate limit exceeded. Max {RATE_LIMIT_RPM} requests per minute. Try again shortly.",
        })
        resp.status_code = 429
        resp.headers["Retry-After"] = str(RATE_LIMIT_WINDOW)
        resp.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_RPM)
        resp.headers["X-RateLimit-Remaining"] = str(remaining)
        return resp

    # ── Parse Parameters ──
    link = ""
    action = "d"  # default is download
    wait_for_transcoding = False

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        link = data.get("url") or data.get("link") or ""
        action = data.get("mode") or data.get("action") or "d"
        wait_for_transcoding = bool(data.get("wait"))
    else:
        link = request.args.get("url") or request.args.get("link") or ""
        action = request.args.get("mode") or request.args.get("action") or "d"
        wait_for_transcoding = request.args.get("wait") in ("true", "1", "True")

    if not link:
        return jsonify({
            "status": "error",
            "message": "Missing required parameter 'url' or 'link'."
        }), 400

    # Sanitize link (strip whitespaces, zero-width spaces, directional formatting markers)
    link = re.sub(r'[\s\u200b\u200c\u200d\ufeff\u202a\u202b\u202c\u202d\u202e]+', '', link)

    # Ensure action code matches downloader expected format ('d', 's', or 'l')
    act_lower = action.lower()
    if act_lower in ("s", "stream", "streaming"):
        action = "s"
    elif act_lower in ("l", "list", "info", "metadata"):
        action = "l"
    else:
        action = "d"

    # ── Check Cache ──
    cached = cache.get(link, action, wait_for_transcoding)
    if cached is not None:
        resp = jsonify(cached)
        resp.headers["X-Cache"] = "HIT"
        resp.headers["X-RateLimit-Remaining"] = str(rate_limiter.remaining(client_ip))
        return resp

    # ── Single Flight / Request Collapsing Lock ──
    cache_key = cache._make_key(link, action, wait_for_transcoding)
    has_lock = acquire_resolve_lock(cache_key)
    
    if not has_lock:
        # Wait for concurrent resolution to finish and populate cache
        print(f"[SingleFlight] Waiting for concurrent resolution of: {link}", flush=True)
        cached = wait_for_resolution(cache_key, lambda: cache.get(link, action, wait_for_transcoding), timeout=30)
        if cached is not None:
            resp = jsonify(cached)
            resp.headers["X-Cache"] = "HIT (COLLAPSED)"
            resp.headers["X-RateLimit-Remaining"] = str(rate_limiter.remaining(client_ip))
            return resp
        # If wait timeout or failed, fall through to resolve ourselves
        print(f"[SingleFlight] Wait timed out, proceeding to resolve ourselves: {link}", flush=True)
        # Re-attempt lock acquisition just in case
        acquire_resolve_lock(cache_key)

    # ── Call resolve_link ──
    try:
        res = resolve_link(link, action=action, wait_for_transcoding=wait_for_transcoding)
        if res.get("errno") != 0:
            return jsonify({
                "status": "error",
                "message": res.get("error", "Unknown resolution error occurred.")
            }), 400

        # Formulate proxy-ready response payload and detect transcoding status
        response_data, is_transcoding = _format_resolved_response(res, link)

        # Trigger background transcoding check if transcoding is detected & wait_for_transcoding is false
        if is_transcoding and not wait_for_transcoding:
            import threading
            threading.Thread(target=_background_transcode_poll, args=(link, action, cache_key), daemon=True).start()

        # ── Store in Cache (don't cache transcoding-in-progress responses) ──
        if not is_transcoding:
            cache.put(link, action, wait_for_transcoding, response_data)

        resp = jsonify(response_data)
        resp.headers["X-Cache"] = "MISS"
        resp.headers["X-RateLimit-Remaining"] = str(rate_limiter.remaining(client_ip))
        return resp

    except ValueError as e:
        # Bad input from the client (e.g. parse_surl couldn't find a valid id).
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        import traceback
        import sys
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        return jsonify({
            "status": "error",
            "message": f"Server encountered exception: {str(e)}"
        }), 500
    finally:
        # Always release Single Flight lock
        release_resolve_lock(cache_key)


# ─── HLS Streaming Proxy routes ─────────────────────────────────────

@app.route("/api/stream/manifest", methods=["GET", "OPTIONS"])
@app.route("/api/stream/playlist.m3u8", methods=["GET", "OPTIONS"])
def stream_manifest():
    if request.method == "OPTIONS":
        resp = Response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return resp

    if not check_auth():
        return jsonify({"status": "error", "message": "Unauthorized: Invalid or missing API key."}), 401

    # ── Rate Limiting ──
    client_ip = _client_ip()

    if not rate_limiter.is_allowed(client_ip):
        resp = jsonify({
            "status": "error",
            "message": f"Rate limit exceeded. Try again shortly.",
        })
        return resp, 429

    link = request.args.get("url") or request.args.get("link") or ""
    wait_for_transcoding = request.args.get("wait") in ("true", "1", "True")
    
    try:
        file_index = int(request.args.get("index", 0))
    except ValueError:
        file_index = 0

    if not link:
        return jsonify({
            "status": "error",
            "message": "Missing required parameter 'url' or 'link'."
        }), 400

    try:
        res = resolve_link(link, action="s", wait_for_transcoding=wait_for_transcoding)
        if res.get("errno") != 0:
            return jsonify({
                "status": "error",
                "message": res.get("error", "Unknown resolution error occurred.")
            }), 400

        files = res.get("files", [])
        streamable_files = [f for f in files if f.get("stream_ready")]

        if not streamable_files:
            is_transcoding = any(f.get("error") == "transcoding_in_progress" for f in files)
            if is_transcoding:
                return jsonify({
                    "status": "transcoding",
                    "message": "HLS streaming manifest is currently transcoding. Please try again shortly."
                }), 202
            return jsonify({
                "status": "error",
                "message": "No streamable video files found in this share link."
            }), 404

        if file_index < 0 or file_index >= len(streamable_files):
            file_index = 0

        target_file = streamable_files[file_index]
        raw_m3u8 = target_file.get("stream_m3u8", "")

        if not raw_m3u8:
            return jsonify({
                "status": "error",
                "message": "Stream manifest content is empty."
            }), 500

        # Rewrite segment URLs to use local proxy
        proxied_lines = []
        for line in raw_m3u8.splitlines():
            line_stripped = line.strip()
            if line_stripped and not line_stripped.startswith("#"):
                quoted_url = urllib.parse.quote(line_stripped)
                sig = generate_signature(line_stripped, "", "")
                proxy_url = f"{_request_base_url()}/api/stream/segment?url={quoted_url}&sig={sig}"
                proxied_lines.append(proxy_url)
            else:
                proxied_lines.append(line)

        proxied_m3u8 = "\n".join(proxied_lines)

        response = Response(proxied_m3u8, content_type="application/vnd.apple.mpegurl")
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Manifest proxy error: {str(e)}"
        }), 500


@app.route("/api/stream/segment", methods=["GET", "OPTIONS"])
def stream_segment():
    if request.method == "OPTIONS":
        resp = Response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return resp

    url = request.args.get("url") or ""
    sig = request.args.get("sig") or ""
    if not url:
        return "Missing segment URL", 400

    target_url = url

    # Authorize either via master key OR via valid signature
    if not check_auth() and not verify_signature(target_url, "", "", sig):
        return "Unauthorized: Invalid signature or API key.", 401

    # SSRF Protection
    try:
        parsed = urllib.parse.urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return "Forbidden: Unsupported URL scheme.", 403
        domain = parsed.netloc.lower()
        # Trusted CDN roots that TeraBox hands out for HLS manifest/segment URIs.
        # An entry that starts with "." is a domain-suffix match; an entry
        # without a leading dot is matched exactly (e.g. "pcs.baidu.com").
        allowed_suffixes = (
            # Core/Official
            ".1024terabox.com",
            ".terabox.com",
            ".teraboxapp.com",
            ".terabox.app",
            ".baidu.com",
            
            # Common Mirrors/Rebrands
            ".freeterabox.com",
            ".nephobox.com",
            ".momerybox.com",
            ".mirrobox.com",
            ".gibibox.com",
            ".tibibox.com",
            ".4funbox.com",
            ".1024tera.com",
            ".1024nephobox.com",
            ".terabox.fun",
            ".terasharefile.com",
            ".teraboxlink.com",

            # HLS Videotran CDN variants
            ".1024terabox.com-videotran-hybcloud",
            ".terabox.com-videotran-hybcloud",
            ".teraboxapp.com-videotran-hybcloud",
            ".terabox.app-videotran-hybcloud",
            ".freeterabox.com-videotran-hybcloud",
            ".nephobox.com-videotran-hybcloud",
            ".momerybox.com-videotran-hybcloud",
            ".mirrobox.com-videotran-hybcloud",
            ".gibibox.com-videotran-hybcloud",
            ".tibibox.com-videotran-hybcloud",
            ".4funbox.com-videotran-hybcloud",
            ".1024tera.com-videotran-hybcloud",
            ".1024nephobox.com-videotran-hybcloud",
            ".terabox.fun-videotran-hybcloud",
            ".terasharefile.com-videotran-hybcloud",
            ".teraboxlink.com-videotran-hybcloud",
            
            # Other CDNs/Redirects
            ".koofr.net",        # TeraBox HLS segment / manifest CDN
            ".koofr.eu",
            "pcs.baidu.com",
            "d.pcs.1024terabox.com",
        )

        def _host_allowed(host, suffix):
            if suffix.startswith("."):
                return host == suffix[1:] or host.endswith(suffix)
            return host == suffix

        is_allowed = any(_host_allowed(domain, suffix) for suffix in allowed_suffixes)
        if not is_allowed:
            return "Forbidden: Invalid stream host destination.", 403
    except Exception:
        return "Invalid segment URL format", 400

    if REDIRECT_SEGMENTS:
        return Response("", status=307, headers={"Location": target_url})

    try:
        headers = {
            "User-Agent": UA,
            "Referer": "https://dm.1024terabox.com/",
        }
        range_header = request.headers.get("Range")
        if range_header:
            headers["Range"] = range_header

        req = session.get(
            target_url,
            headers=headers,
            cookies=COOKIES_DICT,
            stream=True,
            timeout=30
        )
        
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
        
        def generate():
            try:
                for chunk in req.iter_content(chunk_size=16384):
                    if chunk:
                        yield chunk
            finally:
                req.close()

        return Response(generate(), status=req.status_code, headers=resp_headers)

    except Exception as e:
        return f"Segment proxy encountered an error: {str(e)}", 500


@app.route("/api/thumbnail", methods=["GET", "OPTIONS"])
@app.route("/api/stream/thumbnail", methods=["GET", "OPTIONS"])
def stream_thumbnail():
    if request.method == "OPTIONS":
        resp = Response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return resp

    url = request.args.get("url") or ""
    surl = request.args.get("surl") or ""
    fs_id = request.args.get("fs_id") or ""
    size_type = request.args.get("size_type") or request.args.get("size") or "url3"
    sig = request.args.get("sig") or ""

    if not url and not (surl and fs_id):
        return "Missing thumbnail URL or surl/fs_id parameters", 400

    # Authorize either via master key OR via valid signature
    if not url:
        if not check_auth() and not verify_signature(surl, fs_id, size_type, sig):
            return "Unauthorized: Invalid signature or API key.", 401
    else:
        if not check_auth():
            return "Unauthorized: Invalid API key.", 401

    target_url = ""
    if url:
        target_url = url
    else:
        # Resolve from surl and fs_id
        share_url = f"https://1024terabox.com/s/{surl}"
        cached_res = cache.get(share_url, "d", False) or cache.get(share_url, "l", False)
        if not cached_res:
            try:
                cached_res = resolve_link(share_url, action="l")
            except Exception as e:
                return f"Failed to resolve share link metadata: {str(e)}", 500
        
        target_file = None
        for f in cached_res.get("files", []):
            if str(f.get("original_fs_id")) == str(fs_id) or str(f.get("fs_id")) == str(fs_id):
                target_file = f
                break
        
        if not target_file:
            return "File not found in share link", 404
        
        thumbs = target_file.get("thumbnails")
        if not thumbs or not isinstance(thumbs, dict):
            return "No thumbnails available for this file", 404
        
        target_url = thumbs.get(size_type) or thumbs.get("url3") or thumbs.get("original") or list(thumbs.values())[0]
        if not target_url:
            return "No matching thumbnail URL found", 404

    # SSRF Protection
    try:
        parsed = urllib.parse.urlparse(target_url)
        domain = parsed.netloc.lower()
        allowed_suffixes = (
            # Core/Official
            ".1024terabox.com",
            ".terabox.com",
            ".teraboxapp.com",
            ".terabox.app",
            ".baidu.com",
            
            # Mirrors/Rebrands
            ".freeterabox.com",
            ".nephobox.com",
            ".momerybox.com",
            ".mirrobox.com",
            ".gibibox.com",
            ".tibibox.com",
            ".4funbox.com",
            ".1024tera.com",
            ".1024nephobox.com",
            ".terabox.fun",
            ".terasharefile.com",
            ".teraboxlink.com",

            # Other CDN and storage servers
            "pcs.baidu.com",
            "d.pcs.1024terabox.com",
            "dm-data.terabox.com"
        )
        is_allowed = any(domain == suffix or domain.endswith(suffix) for suffix in allowed_suffixes)
        if not is_allowed:
            return "Forbidden: Invalid stream host destination.", 403
    except Exception:
        return "Invalid thumbnail URL format", 400

    try:
        req = session.get(
            target_url,
            headers={"User-Agent": UA, "Referer": "https://dm.1024terabox.com/"},
            cookies=COOKIES_DICT,
            stream=True,
            timeout=30
        )
        
        resp_headers = {}
        cors_headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
        }
        
        for key in ("Content-Length", "Content-Type"):
            if key in req.headers:
                resp_headers[key] = req.headers[key]
        
        if "Content-Type" not in resp_headers:
            resp_headers["Content-Type"] = "image/jpeg"
            
        resp_headers.update(cors_headers)
        
        def generate():
            try:
                for chunk in req.iter_content(chunk_size=16384):
                    if chunk:
                        yield chunk
            finally:
                req.close()

        return Response(generate(), status=req.status_code, headers=resp_headers)

    except Exception as e:
        return f"Thumbnail proxy encountered an error: {str(e)}", 500


@app.route("/api/download", methods=["GET", "OPTIONS"])
def download_file_route():
    if request.method == "OPTIONS":
        resp = Response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return resp

    surl = request.args.get("surl") or ""
    fs_id = request.args.get("fs_id") or ""
    sig = request.args.get("sig") or ""

    if not surl or not fs_id:
        return "Missing required parameters: surl and fs_id", 400

    # Authorize either via master key OR via valid signature
    if not check_auth() and not verify_signature(surl, fs_id, "", sig):
        return "Unauthorized: Invalid signature or API key.", 401

    share_url = f"https://1024terabox.com/s/{surl}"
    cached_res = cache.get(share_url, "d", False)
    if not cached_res:
        try:
            cached_res = resolve_link(share_url, action="d")
            if cached_res.get("errno") == 0:
                is_transcoding = any(f.get("error") == "transcoding_in_progress" for f in cached_res.get("files", []))
                if not is_transcoding:
                    cache.put(share_url, "d", False, cached_res)
        except Exception as e:
            return f"Failed to resolve download details: {str(e)}", 500

    if cached_res.get("errno") != 0:
        return f"Failed to resolve share link: {cached_res.get('error', 'Unknown error')}", 400

    target_file = None
    for f in cached_res.get("files", []):
        if str(f.get("original_fs_id")) == str(fs_id) or str(f.get("fs_id")) == str(fs_id):
            target_file = f
            break

    if not target_file:
        return "File not found in share link", 404

    if target_file.get("error"):
        return f"File resolution error: {target_file.get('error')}", 400

    dlink = target_file.get("dlink")
    filename = target_file.get("filename") or "download"

    if not dlink:
        return "Download link not available for this file", 404

    try:
        headers = {
            "User-Agent": UA,
            "Referer": "https://dm.1024terabox.com/",
        }
        cookies = COOKIES_DICT

        range_header = request.headers.get("Range")
        if range_header:
            headers["Range"] = range_header

        req = session.get(
            dlink,
            headers=headers,
            cookies=cookies,
            stream=True,
            allow_redirects=True,
            timeout=120
        )

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

        def generate():
            try:
                for chunk in req.iter_content(chunk_size=131072):
                    if chunk:
                        yield chunk
            finally:
                req.close()

        return Response(generate(), status=req.status_code, headers=resp_headers)

    except Exception as e:
        return f"Download proxy encountered an error: {str(e)}", 500


# ─── Dynamic Config Sync ─────────────────────────────────────────────
_last_config_check = 0
CONFIG_CHECK_INTERVAL = 60 # seconds
_current_active_account_id = None

def load_config_from_redis():
    """Load latest configuration/cookies from Upstash Redis managed account pool."""
    global _current_active_account_id
    if not redis_client:
        return
    try:
        active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
        creds = None
        
        if active_id:
            raw_creds = redis_client.hget(ACCOUNTS_HASH_KEY, active_id)
            if raw_creds:
                try:
                    creds = json.loads(raw_creds)
                except Exception:
                    pass
                    
        # If no active account is set or the current one is not healthy, rotate
        if not creds or creds.get("status") != "healthy":
            active_id, creds = get_next_healthy_account()
            
        if creds:
            _current_active_account_id = active_id
            from downloader import update_credentials
            update_credentials(
                cookie=creds.get("cookie"),
                js_token=creds.get("js_token"),
                bds_token=creds.get("bds_token"),
                sign=creds.get("sign"),
                timestamp=creds.get("timestamp"),
                logid=creds.get("logid")
            )
            print(f"[TeraBridge] Successfully synchronized active pool account: {active_id}", flush=True)
    except Exception as e:
        print(f"[TeraBridge][WARN] Failed to load config from Upstash Redis pool: {e}", flush=True)

@app.before_request
def check_config_refresh():
    if request.method == "OPTIONS":
        return
    global _last_config_check
    now = time.time()
    if now - _last_config_check > CONFIG_CHECK_INTERVAL:
        load_config_from_redis()
        _last_config_check = now

# Load initial config from Redis on import / startup
load_config_from_redis()


# ─── Admin Config Routes ─────────────────────────────────────────────

@app.route("/api/admin/config", methods=["GET", "POST", "OPTIONS"])
def admin_config():
    if request.method == "OPTIONS":
        resp = Response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return resp

    if not check_auth():
        return jsonify({"status": "error", "message": "Unauthorized: Invalid or missing API key."}), 401

    if not redis_client:
        return jsonify({
            "status": "error",
            "message": "Redis client is not configured. Config cannot be updated dynamically."
        }), 400

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        
        # Get account_id from request or default to active account or account_1
        account_id = data.get("account_id") or _current_active_account_id or "account_1"
        
        valid_keys = {"cookie", "js_token", "bds_token", "sign", "timestamp", "logid"}
        updates = {k: v for k, v in data.items() if k in valid_keys and v is not None}
        
        if not updates:
            return jsonify({
                "status": "error",
                "message": "No valid configuration updates provided."
            }), 400

        try:
            # Load existing account from Redis if it exists
            existing_raw = redis_client.hget(ACCOUNTS_HASH_KEY, account_id)
            account_data = {}
            if existing_raw:
                try:
                    account_data = json.loads(existing_raw)
                except Exception:
                    pass
            
            # Merge updates and reset status to healthy
            account_data.update(updates)
            account_data["status"] = "healthy"
            account_data["last_used"] = account_data.get("last_used") or int(time.time())
            if "unhealthy_reason" in account_data:
                del account_data["unhealthy_reason"]
            if "unhealthy_at" in account_data:
                del account_data["unhealthy_at"]

            # Save back to Redis pool
            redis_client.hset(ACCOUNTS_HASH_KEY, account_id, json.dumps(account_data))
            
            # Immediately update memory state if this is the active account
            active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
            if active_id == account_id or not active_id:
                redis_client.set(ACTIVE_ACCOUNT_KEY, account_id)
                load_config_from_redis()
                
            return jsonify({
                "status": "success",
                "message": f"Account '{account_id}' updated successfully in Redis pool.",
                "updated_keys": list(updates.keys())
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Failed to update config in Redis pool: {str(e)}"
            }), 500

    else:
        # GET request: fetch all accounts from pool and mask sensitive values
        try:
            active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
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
                    masked = {k: mask_val(k, v) if k in ("cookie", "js_token", "bds_token", "sign", "timestamp", "logid") else v for k, v in acc_data.items()}
                    pool_summary[acc_id] = masked
                except Exception:
                    pass

            return jsonify({
                "status": "success",
                "active_account_id": active_id,
                "accounts_pool": pool_summary
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Failed to read accounts from Redis pool: {str(e)}"
            }), 500


# ─── Cron Session Validation & Webhook Alerts ───────────────────────

def send_webhook_alert(message):
    """Send an embed alert message to Discord or text alert to Slack."""
    if not NOTIFICATION_WEBHOOK_URL:
        return
    import datetime
    import requests
    
    payload = {}
    if "discord.com" in NOTIFICATION_WEBHOOK_URL:
        payload = {
            "embeds": [{
                "title": "🚨 TeraBridge API Warning",
                "description": message,
                "color": 16711680, # Red
                "timestamp": datetime.datetime.utcnow().isoformat()
            }]
        }
    elif "slack.com" in NOTIFICATION_WEBHOOK_URL:
        payload = {
            "text": f"🚨 *TeraBridge API Warning:*\n{message}"
        }
    else:
        # Generic webhook structure
        payload = {
            "event": "session_expired",
            "message": message
        }

    try:
        requests.post(NOTIFICATION_WEBHOOK_URL, json=payload, timeout=10)
    except Exception as e:
        print(f"[TeraBridge][WARN] Failed to send webhook alert: {e}", flush=True)


@app.route("/api/cron/validate", methods=["GET", "POST", "OPTIONS"])
def cron_validate():
    if request.method == "OPTIONS":
        resp = Response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return resp

    # Validate secret parameter to prevent spam
    client_secret = request.args.get("secret") or (request.get_json(silent=True) or {}).get("secret")
    if CRON_SECRET and client_secret != CRON_SECRET:
        return jsonify({"status": "error", "message": "Unauthorized: Invalid or missing cron secret."}), 401

    # Load active cookie from Redis pool or fall back to environment variable
    active_cookie = None
    active_id = None
    if redis_client:
        try:
            active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
            if active_id:
                raw_creds = redis_client.hget(ACCOUNTS_HASH_KEY, active_id)
                if raw_creds:
                    creds = json.loads(raw_creds)
                    active_cookie = creds.get("cookie")
        except Exception as e:
            print(f"[TeraBridge][WARN] Failed to fetch cookie from Redis in cron: {e}", flush=True)
    
    if not active_id:
        active_id = "default_env"
        from downloader import COOKIE
        active_cookie = COOKIE
 
    if not active_cookie:
        return jsonify({"status": "error", "message": "No active cookie found to validate."}), 400
 
    # Call validate_session_cookie helper
    is_valid, msg = validate_session_cookie(active_cookie)
    
    # Update state in Redis
    status_data = {
        "cookie_valid": "true" if is_valid else "false",
        "last_checked": str(int(time.time())),
        "message": msg
    }
    
    if redis_client:
        try:
            redis_client.hset("terabridge:status", values=status_data)
        except Exception as e:
            print(f"[TeraBridge][WARN] Failed to write status to Redis in cron: {e}", flush=True)

    if not is_valid:
        # Trigger webhook alert
        alert_msg = (
            f"Your TeraBox cookies have expired or are invalid!\n"
            f"**Error/Reason:** `{msg}`\n\n"
            f"Please refresh your cookies and update them at the dynamic configuration endpoint `/api/admin/config` immediately."
        )
        send_webhook_alert(alert_msg)
        return jsonify({
            "status": "unhealthy",
            "message": "Session cookies are expired or invalid. Webhook notification triggered.",
            "error": msg
        }), 200

    return jsonify({
        "status": "healthy",
        "message": "Session cookies are valid."
    }), 200


# ─── Server Entry Point ─────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    is_windows = sys.platform == "win32"

    print(f"[TeraBridge] Cache TTL: {CACHE_TTL_SECONDS}s | Rate limit: {RATE_LIMIT_RPM} req/min")

    if not API_KEY and not REQUIRE_API_KEY:
        print("[TeraBridge][WARNING] API_KEY is not set and REQUIRE_API_KEY is disabled — "
              "all endpoints are currently OPEN (no authentication). Do not expose this "
              "instance to the public internet.", flush=True)

    if is_windows:
        # On Windows, Waitress's asyncore has a 2s select() timeout that causes
        # high latency. Use Flask's built-in threaded mode instead.
        print(f"[TeraBridge] Starting Flask threaded server on 0.0.0.0:{port} (Windows)")
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
    else:
        # On Linux/macOS, use Waitress for true production performance
        try:
            from waitress import serve
            print(f"[TeraBridge] Starting Waitress production server on 0.0.0.0:{port}")
            print(f"[TeraBridge] Threads: 8")
            serve(app, host="0.0.0.0", port=port, threads=8)
        except ImportError:
            print(f"[TeraBridge] Waitress not found, using Flask threaded mode on port {port}")
            print(f"[TeraBridge] TIP: pip install waitress  (for better production performance)")
            app.run(host="0.0.0.0", port=port, debug=False, threaded=True)

