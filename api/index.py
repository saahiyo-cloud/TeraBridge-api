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

from downloader import resolve_link, session, parse_surl, UA, COOKIES_DICT

app = Flask(__name__)

# ─── Global CORS Setup ───────────────────────────────────────────────
@app.before_request
def handle_options_preflight():
    if request.method == "OPTIONS":
        resp = Response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return resp

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

# ─── Configuration ───────────────────────────────────────────────────
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL", 60))         # Cache responses for 60s
CACHE_MAX_ENTRIES = int(os.environ.get("CACHE_MAX_ENTRIES", 256)) # LRU eviction after 256 entries
RATE_LIMIT_RPM    = int(os.environ.get("RATE_LIMIT_RPM", 30))    # 30 requests per minute per IP
RATE_LIMIT_WINDOW = 60  # seconds
API_KEY           = os.environ.get("API_KEY")                    # API Key for securing endpoints (REQUIRED in production)
HMAC_SECRET       = os.environ.get("HMAC_SECRET") or API_KEY        # HMAC secret (falls back to API_KEY if not set; required if API_KEY is set)
REQUIRE_API_KEY   = os.environ.get("REQUIRE_API_KEY", "auto").lower() not in ("0", "false", "no")
# When REQUIRE_API_KEY is true (or auto + no API_KEY set), all protected endpoints reject requests with no/wrong key.
# When REQUIRE_API_KEY is false, endpoints stay open (useful for local dev only).

# ─── Trusted proxy configuration (for client-IP resolution) ─────────
# Comma-separated CIDR list of reverse proxies whose X-Forwarded-For chains we trust.
# Examples: TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8   (add your LB's CIDR)
# Vercel is auto-trusted when the VERCEL=1 env var is set (the platform injects
# x-vercel-forwarded-for itself, which we use as the single source of truth there).
TRUSTED_PROXY_CIDRS_RAW = os.environ.get("TRUSTED_PROXIES", "").strip()

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
# Vercel runs behind its own edge; the platform sets VERCEL=1 and forwards a
# single client IP via x-vercel-forwarded-for. Trust that header in that case.
ON_VERCEL = bool(os.environ.get("VERCEL"))

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

def _is_trusted_peer():
    """True if the immediate TCP peer is in TRUSTED_PROXY_CIDRS (or we're on Vercel)."""
    if ON_VERCEL:
        return True
    if not TRUSTED_PROXY_CIDRS:
        return False
    peer = _peer_ip()
    if peer is None:
        return False
    return any(peer in cidr for cidr in TRUSTED_PROXY_CIDRS)

def _client_ip():
    """
    Resolve the *real* client IP, taking reverse proxies into account.

    - On Vercel: trust x-vercel-forwarded-for (single hop, set by the platform).
    - Behind a configured trusted proxy: take the *rightmost* untrusted entry in
      X-Forwarded-For (i.e. the value added by the closest trusted hop). Walking
      right-to-left stops at the first IP that's NOT in the trusted set.
    - Direct connection (no trusted proxy): return request.remote_addr unchanged.
      In this mode X-Forwarded-For is ignored entirely so a client cannot spoof
      their way around the per-IP rate limiter.
    """
    if ON_VERCEL:
        v = request.headers.get("X-Vercel-Forwarded-For")
        if v:
            return v.split(",")[0].strip()

    peer = _peer_ip()
    if peer is None:
        return request.remote_addr or "unknown"

    if not _is_trusted_peer():
        # Direct connection — never trust X-Forwarded-For from an untrusted source.
        return str(peer)

    xff = request.headers.get("X-Forwarded-For", "")
    if not xff:
        return str(peer)

    # Walk right-to-left. The hop just inside the trusted boundary is the client.
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

# ─── Thread-safe LRU Cache ──────────────────────────────────────────
class ResponseCache:
    """Thread-safe in-memory LRU cache with TTL expiry."""

    def __init__(self, max_entries=256, ttl_seconds=60):
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
        with self._lock:
            if key in self._store:
                del self._store[key]
            self._store[key] = (response, time.time())
            # LRU eviction
            while len(self._store) > self._max:
                self._store.popitem(last=False)

    def stats(self):
        with self._lock:
            total = self.hits + self.misses
            return {
                "entries": len(self._store),
                "max_entries": self._max,
                "ttl_seconds": self._ttl,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": f"{(self.hits / total * 100):.1f}%" if total > 0 else "N/A",
            }

cache = ResponseCache(max_entries=CACHE_MAX_ENTRIES, ttl_seconds=CACHE_TTL_SECONDS)

# ─── Sliding-Window Rate Limiter ─────────────────────────────────────
class RateLimiter:
    """Per-IP sliding window rate limiter."""

    def __init__(self, max_requests=30, window_seconds=60):
        self._requests = {}   # ip -> list of timestamps
        self._lock = threading.Lock()
        self._max = max_requests
        self._window = window_seconds
        self.total_blocked = 0

    def is_allowed(self, ip):
        now = time.time()
        with self._lock:
            if ip not in self._requests:
                self._requests[ip] = []

            # Trim timestamps outside the window
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
        with self._lock:
            if ip not in self._requests:
                return self._max
            active = [ts for ts in self._requests[ip] if now - ts < self._window]
            return max(0, self._max - len(active))

    def stats(self):
        now = time.time()
        with self._lock:
            active_ips = sum(
                1 for ts_list in self._requests.values()
                if any(now - ts < self._window for ts in ts_list)
            )
            return {
                "max_rpm": self._max,
                "window_seconds": self._window,
                "active_clients": active_ips,
                "total_blocked": self.total_blocked,
            }

    def cleanup(self):
        """Periodically remove stale IPs to prevent memory growth."""
        now = time.time()
        with self._lock:
            stale = [
                ip for ip, ts_list in self._requests.items()
                if not any(now - ts < self._window for ts in ts_list)
            ]
            for ip in stale:
                del self._requests[ip]

rate_limiter = RateLimiter(max_requests=RATE_LIMIT_RPM, window_seconds=RATE_LIMIT_WINDOW)

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
    return jsonify({
        "status": "online",
        "uptime_seconds": uptime,
        "cache": cache.stats(),
        "rate_limiter": rate_limiter.stats(),
    })

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

    # ── Call resolve_link ──
    try:
        res = resolve_link(link, action=action, wait_for_transcoding=wait_for_transcoding)
        if res.get("errno") != 0:
            return jsonify({
                "status": "error",
                "message": res.get("error", "Unknown resolution error occurred.")
            }), 400

        # Check if any video has transcoding in progress
        is_transcoding = any(f.get("error") == "transcoding_in_progress" for f in res.get("files", []))

        response_data = {
            "status": "transcoding" if is_transcoding else "success",
            "title": res.get("title"),
            "share_id": res.get("share_id"),
            "uk": res.get("uk"),
            "files": []
        }

        surl = parse_surl(link)
        print(f"[DEBUG] link={link} parsed surl={surl}", flush=True)
        for f in res.get("files", []):
            original_fs_id = f.get("original_fs_id")
            print(f"[DEBUG] file={f.get('filename')} original_fs_id={original_fs_id} fs_id={f.get('fs_id')}", flush=True)
            raw_thumbs = f.get("thumbnails")
            proxied_thumbs = {}
            if raw_thumbs and isinstance(raw_thumbs, dict):
                for k, v in raw_thumbs.items():
                    if v:
                        if original_fs_id and surl:
                            sig = generate_signature(surl, original_fs_id, k)
                            proxy_url = f"{request.scheme}://{request.host}/api/thumbnail?surl={surl}&fs_id={original_fs_id}&size_type={k}&sig={sig}"
                        else:
                            quoted_v = urllib.parse.quote(v)
                            proxy_url = f"{request.scheme}://{request.host}/api/thumbnail?url={quoted_v}"
                            if API_KEY:
                                proxy_url += f"&key={API_KEY}"
                        proxied_thumbs[k] = proxy_url

            # Shortened download proxy link
            dlink_url = f.get("dlink")
            if dlink_url and original_fs_id and surl:
                sig = generate_signature(surl, original_fs_id, "")
                proxy_dlink = f"{request.scheme}://{request.host}/api/download?surl={surl}&fs_id={original_fs_id}&sig={sig}"
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
        traceback.print_exc(file=sys.stdout)
        return jsonify({
            "status": "error",
            "message": f"Server encountered exception: {str(e)}"
        }), 500


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
                proxy_url = f"{request.scheme}://{request.host}/api/stream/segment?url={quoted_url}&sig={sig}"
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

    target_url = urllib.parse.unquote(url)

    # Authorize either via master key OR via valid signature
    if not check_auth() and not verify_signature(target_url, "", "", sig):
        return "Unauthorized: Invalid signature or API key.", 401

    # SSRF Protection
    try:
        parsed = urllib.parse.urlparse(target_url)
        domain = parsed.netloc.lower()
        allowed_suffixes = (
            ".1024terabox.com",
            ".baidu.com",
            ".terabox.com",
            ".teraboxapp.com",
            "pcs.baidu.com",
            "d.pcs.1024terabox.com"
        )
        is_allowed = any(domain == suffix or domain.endswith(suffix) for suffix in allowed_suffixes)
        if not is_allowed:
            return "Forbidden: Invalid stream host destination.", 403
    except Exception:
        return "Invalid segment URL format", 400
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
        target_url = urllib.parse.unquote(url)
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
            ".1024terabox.com",
            ".baidu.com",
            ".terabox.com",
            ".teraboxapp.com",
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

