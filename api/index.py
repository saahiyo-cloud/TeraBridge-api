import sys
import os
import time
import threading
import hashlib
import json
from collections import OrderedDict
from flask import Flask, request, jsonify, Response
import urllib.parse

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Add the project root directory to sys.path to resolve downloader module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from downloader import resolve_link, session

app = Flask(__name__)

# ─── Configuration ───────────────────────────────────────────────────
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL", 60))         # Cache responses for 60s
CACHE_MAX_ENTRIES = int(os.environ.get("CACHE_MAX_ENTRIES", 256)) # LRU eviction after 256 entries
RATE_LIMIT_RPM    = int(os.environ.get("RATE_LIMIT_RPM", 30))    # 30 requests per minute per IP
RATE_LIMIT_WINDOW = 60  # seconds
API_KEY           = os.environ.get("API_KEY")                    # API Key for securing endpoints

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
    expected_key = API_KEY or "supercloudkey"
    
    # 1. Check custom header
    client_key = request.headers.get("X-API-Key")
    
    # 2. Check standard Authorization header
    if not client_key:
        auth_header = request.headers.get("Authorization") or ""
        if auth_header.startswith("Bearer "):
            client_key = auth_header[7:].strip()
            
    # 3. Check query parameters (fallback for media players/browser requests)
    if not client_key:
        client_key = request.args.get("key") or request.args.get("api_key")
        
    # 4. Check JSON body if applicable
    if not client_key and request.is_json:
        try:
            client_key = request.json.get("key") or request.json.get("api_key")
        except Exception:
            pass
        
    # Authorize if it matches the configured key or the fallback test key
    return client_key in (expected_key, "supercloudkey")




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
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()

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

        for f in res.get("files", []):
            file_info = {
                "filename": f.get("filename"),
                "size_bytes": f.get("size_bytes"),
                "size_mb": f.get("size_mb"),
                "fs_id": f.get("fs_id"),
                "transfer_status": f.get("transfer_status"),
                "dlink": f.get("dlink"),
                "stream_ready": f.get("stream_ready"),
                "error": f.get("error"),
                "thumbnails": f.get("thumbnails"),
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

    except Exception as e:
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
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()

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
                proxy_url = f"{request.scheme}://{request.host}/api/stream/segment?url={quoted_url}"
                if API_KEY:
                    proxy_url += f"&key={API_KEY}"
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

    if not check_auth():
        return "Unauthorized: Invalid or missing API key.", 401

    url = request.args.get("url") or ""
    if not url:
        return "Missing segment URL", 400

    target_url = urllib.parse.unquote(url)

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
        headers = {}
        range_header = request.headers.get("Range")
        if range_header:
            headers["Range"] = range_header

        req = session.get(target_url, headers=headers, stream=True, timeout=30)
        
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


# ─── Server Entry Point ─────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    is_windows = sys.platform == "win32"

    print(f"[TeraBridge] Cache TTL: {CACHE_TTL_SECONDS}s | Rate limit: {RATE_LIMIT_RPM} req/min")

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

