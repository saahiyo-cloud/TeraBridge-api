# TeraBridge API

A lightweight, modular Python API and CLI utility for retrieving direct download links and playable HLS `.m3u8` streaming manifests from Terabox shared folders. Built on **FastAPI** with fully asynchronous I/O (`httpx` + `asyncio`), it is designed for high concurrency and can be deployed to **Render** (free plan), **Docker**, or **Vercel**.

---

## Features

- **Async-First Architecture:** Built on FastAPI and Uvicorn's ASGI event loop, a single instance handles thousands of concurrent connections without spawning OS threads.
- **Dynamic Token Resolution:** Automatically resolves session-specific `bdstoken` and `jsToken` dynamically from your cookies to bypass standard verification blocks.
- **Save Location Targeting:** Copies shared files automatically to a `/cloudvids` folder inside the account storage for clear organization.
- **HLS Transcoding Handling:** Automatically handles transcoding ready delays (`errno: 130`). For serverless executions, it flags this state cleanly in the JSON response, enabling clients to poll/retry.
- **Render Deployable:** One-click deploy on Render's free plan via `render.yaml` Blueprint, with auto-generated secrets and free-plan tuning built in.
- **Vercel Deployable:** Designed out-of-the-box for quick deployment using the Vercel Python runtime.
- **Response Caching:** In-memory LRU cache (or Upstash Redis) with configurable TTL (default 60s) reduces redundant Terabox API calls for repeated links.
- **Rate Limiting:** Per-IP sliding window rate limiter (default 30 req/min) protects Terabox session tokens from exhaustion.
- **Non-blocking HTTP Client:** Uses `httpx.AsyncClient` with connection pooling, automatic retry on 5xx errors, and HTTP/2 multiplexing.
- **Single-Flight Request Collapsing:** Duplicate concurrent requests for the same link are collapsed into a single upstream call, dramatically reducing Terabox API load under burst traffic.
- **HMAC-Signed Proxy URLs:** All download, stream, and thumbnail proxy URLs are signed with time-limited HMAC tokens for security.
- **Multi-Account Pool:** Supports rotating between multiple Terabox accounts via Redis, with automatic health checks and failover.

---

## Deployment

Deploy this API directly to your platform of choice with a single click:

[![Deploy to Vercel](https://img.shields.io/badge/Deploy_to-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fsaahiyo-cloud%2FTeraBridge-api&env=API_KEY,UPSTASH_REDIS_REST_URL,UPSTASH_REDIS_REST_TOKEN,CRON_SECRET) [![Deploy to Render](https://img.shields.io/badge/Deploy_to-Render-4613B1?style=for-the-badge&logo=render&logoColor=white)](https://render.com/deploy?repo=https://github.com/saahiyo-cloud/TeraBridge-api)

---

## Project Structure

```
terabridge-api/
├── api/
│   ├── index.py              # FastAPI application (routes, middleware, auth, caching)
│   ├── redis_client.py       # Upstash Redis connection helper
│   └── account_pool.py       # Multi-account rotation and health management
├── downloader.py             # Core async library & CLI interface (httpx + asyncio)
├── load_test.py              # Concurrent load testing script
├── gunicorn.conf.py          # Gunicorn config (UvicornWorker for Docker)
├── Dockerfile                # Multi-stage Docker build
├── docker-compose.yml        # Docker Compose for local development
├── render.yaml               # Render.com Blueprint (free plan defaults)
├── requirements.txt          # Python dependencies
├── vercel.json               # Vercel deployment rewrites config
└── README.md                 # This documentation
```

---

## 1. Local CLI Usage

Run the core script as a Command Line Interface (CLI):

```bash
# 1. Run direct download mode
python downloader.py "<terabox_share_link>"

# 2. Run streaming manifest resolver mode
python downloader.py --stream "<terabox_share_link>"

# 3. List files without downloading
python downloader.py --list "<terabox_share_link>"
```

*Note: If no link is provided as an argument, the CLI will prompt for one interactively.*

---

## 2. Local API Server


### Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server (port 5000)
python api/index.py
```

This launches an **Uvicorn** ASGI server on `http://0.0.0.0:5000`. The async event loop handles all concurrent requests without OS thread overhead, regardless of the host platform.

> **⚡ Windows Tip:** Always use `http://127.0.0.1:5000` instead of `http://localhost:5000` when testing locally. Windows DNS reverse lookup on `localhost` adds ~2 seconds to every request.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `5000` | Server port |
| `CACHE_TTL` | `60` | Cache time-to-live in seconds |
| `CACHE_MAX_ENTRIES` | `256` | Maximum cached responses (LRU eviction) |
| `RATE_LIMIT_RPM` | `30` | Max requests per minute per IP |
| `API_KEY` | `None` | **Required in production.** Enforces authentication on all protected endpoints. |
| `HMAC_SECRET` | `API_KEY` | Secret for signing proxy URLs (download, stream, thumbnail). Defaults to `API_KEY`. |
| `REQUIRE_API_KEY` | `auto` | Set to `0`/`false` to allow open access (dev only). `auto` = require when `API_KEY` is set. |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated list of proxy IPs/CIDRs. Only needed for non-loopback proxies. |
| `RENDER` | *(unset)* | Set to `true` on Render.com to auto-trust Render's load balancer. |
| `VERCEL` | *(auto)* | Set automatically by Vercel — no manual config needed. |
| `REDIRECT_SEGMENTS` | `false` | Set to `true` to 307-redirect segments to CDN instead of proxying. Cuts egress ~90% and avoids timeouts. |
| `CRON_SECRET` | *(unset)* | Secret token to protect cron/keep-alive endpoints. |
| `UPSTASH_REDIS_REST_URL` | *(unset)* | Upstash Redis REST URL for persistent caching, rate limiting, and account pool. |
| `UPSTASH_REDIS_REST_TOKEN` | *(unset)* | Upstash Redis REST token. |
| `NOTIFICATION_WEBHOOK_URL` | *(unset)* | Discord/Slack webhook URL for session expiry alerts. |
| `ALLOWED_ORIGINS` | *(empty)* | Comma-separated CORS origin allowlist. Empty = permissive for dev. |

```bash
# Example: custom configuration with API Key
API_KEY=my_secret_key CACHE_TTL=120 PORT=8080 python api/index.py
```

### Authentication

If `API_KEY` is defined in the environment, the server protects `/api/stats`, `/api/resolve`, and `/api/stream/manifest` endpoints. Clients must authenticate using one of the following methods:

1. **HTTP Custom Header**:
   ```http
   X-API-Key: my_secret_key
   ```
2. **Authorization Bearer Token** (also accepts Firebase ID tokens):
   ```http
   Authorization: Bearer my_secret_key
   ```
3. **Query Parameter** (recommended fallback for VLC/PotPlayer streams):
   ```
   ?key=my_secret_key   or   ?api_key=my_secret_key
   ```

Rewritten segment, download, and thumbnail proxy URLs generated by `/api/resolve` and `/api/stream/manifest` use HMAC-signed tokens (`sig` + `exp` parameters) for authentication, so clients don't need to re-send the API key for every sub-request.


### Endpoints

#### **GET /** — Health Check
Returns server status, version, and uptime.

#### **GET /api/stats** — Observability *(admin only)*
Returns cache hit/miss statistics, rate limiter state, session health, and recent auth errors.

**Example Response:**
```json
{
  "status": "online",
  "uptime_seconds": 3600,
  "redis": "connected",
  "session_health": {
    "status": "healthy",
    "last_checked_timestamp": "1720350000",
    "message": "Session cookies are valid."
  },
  "cache": {
    "provider": "upstash-redis",
    "entries": 12,
    "ttl_seconds": 60,
    "hits": 847,
    "misses": 53,
    "hit_rate": "94.1%"
  },
  "rate_limiter": {
    "provider": "upstash-redis",
    "max_rpm": 30,
    "window_seconds": 60,
    "active_clients": 5,
    "total_blocked": 3
  }
}
```

#### **GET | POST /api/resolve** — Resolve Share Links

**Parameters:**
- `url` (Required): The full Terabox share URL.
- `mode` (Optional): `download` (default), `stream`, or `list`.
- `wait` (Optional): Set to `true` or `1` to block and retry if transcoding is in progress. Recommended `false` for serverless to avoid timeouts.

**Example Request:**
```
GET http://127.0.0.1:5000/api/resolve?url=https://terasharelink.com/s/1LBCiS-QC7WtAR4OolsC2pQ&mode=download
```

**Example JSON Response:**
```json
{
  "status": "success",
  "title": "/2026-06-10 18-20/VID_20231007175038.mp4",
  "share_id": 4289361191,
  "uk": 4399686012242,
  "files": [
    {
      "filename": "VID_20231007175038.mp4",
      "size_bytes": 7514979,
      "size_mb": 7.17,
      "fs_id": "937887385083215",
      "transfer_status": "success",
      "dlink": "http://127.0.0.1:5000/api/download?surl=...&fs_id=...&sig=...&exp=...",
      "stream_url": "http://127.0.0.1:5000/api/stream/manifest?surl=...&fs_id=...&sig=...&exp=...",
      "stream_ready": true,
      "thumbnails": {
        "url1": "http://127.0.0.1:5000/api/thumbnail?surl=...&fs_id=...&size_type=url1&sig=...&exp=...",
        "url3": "http://127.0.0.1:5000/api/thumbnail?surl=...&fs_id=...&size_type=url3&sig=...&exp=..."
      },
      "error": null
    }
  ]
}
```

**Response Headers:**
| Header | Description |
|---|---|
| `X-Cache` | `HIT`, `MISS`, or `HIT (COLLAPSED)` — indicates cache status or single-flight collapsing |
| `X-RateLimit-Remaining` | Number of requests remaining in the current window |
| `Retry-After` | Seconds to wait (only on 429 responses) |

#### **GET /api/stream/manifest** (or `/api/stream/playlist.m3u8`) — HLS Stream Proxy

Resolves and rewrites the HLS manifest playlist for media players. All media chunk URLs inside the manifest are rewritten to route through the local segment proxy, allowing you to stream videos directly in players like VLC, PotPlayer, or Safari without authentication or IP blocks.

**Parameters:**
- `surl` / `url` (Required): The share URL slug or full URL.
- `fs_id` (Optional): Target a specific file by its fs_id.
- `quality` (Optional): Request a specific quality (`1080p`, `720p`, `480p`, `360p`). Omit for the multivariant master playlist.
- `index` (Optional): The file index inside the folder if multiple streamable files are present (default `0`).
- `wait` (Optional): Set to `true` or `1` to block and wait/retry if transcoding is in progress.

**Example VLC Stream URL:**
```
http://127.0.0.1:5000/api/stream/manifest?surl=1uCJPUU_1xRe10pU_bzEd0Q&fs_id=12345&sig=...&exp=...
```

#### **GET /api/stream/segment** — Segment Proxy

*Internal proxy route.* Streams segment binary files (`.ts` chunks) from Terabox CDNs using the active backend session headers and cookies. Features built-in SSRF protection limiting outbound requests to authorized Terabox and Baidu PCS domains.

#### **GET /api/download** — File Download Proxy

Proxies the actual file download through the server, injecting the correct cookies and user-agent. Supports `Range` headers for resumable downloads. URLs are signed with HMAC tokens.

#### **GET /api/thumbnail** — Thumbnail Proxy

Proxies thumbnail images for files. Can be accessed via `surl` + `fs_id` + `size_type` or a direct `url` parameter. HMAC-signed.

#### **POST /api/admin/config** — Dynamic Config *(admin only)*

Update Terabox credentials (cookie, js_token, bds_token, etc.) at runtime via the Redis account pool without redeploying.

#### **GET | POST /api/cron/validate** — Session Health Check

Validates the active Terabox session cookie. If expired, triggers a webhook alert to your configured Discord/Slack webhook. Authenticate with `CRON_SECRET` or admin API key.

---


## 3. Load Testing

A built-in load testing script is included for benchmarking:

```bash
# Light load: 20 concurrent, 100 requests
python load_test.py --api-key YOUR_KEY -c 20 -n 100

# Heavy load: 50 concurrent, 200 requests
python load_test.py --api-key YOUR_KEY -c 50 -n 200

# Duration-based sustained load (60 seconds)
python load_test.py --api-key YOUR_KEY -c 30 -d 60

# Test specific scenarios only
python load_test.py --api-key YOUR_KEY --scenarios health list

# Against a deployed URL
python load_test.py --base-url https://your-app.vercel.app --api-key YOUR_KEY -c 10 -n 50

# Custom share link
python load_test.py --api-key YOUR_KEY --link "https://1024terabox.com/s/YOUR_LINK" -c 20 -n 100
```

Results include latency percentiles (min/avg/median/p90/p95/p99/max), throughput (req/s), error rates, and are saved to `load_test_results.json`.

---

## 4. Vercel Deployment

Deploy the API globally to Vercel in seconds:

1. Install the Vercel CLI: `npm i -g vercel`
2. Navigate into the folder: `cd terabridge-api`
3. Run: `vercel`

> **Note:** On Vercel (serverless), the API runs as a FastAPI ASGI application. Caching and rate limiting still function within a single invocation context but won't persist across cold starts unless backed by Upstash Redis.

### Platform Notes — Vercel
- The `VERCEL` env var is injected automatically. Client IP resolution trusts
  Vercel's `x-vercel-forwarded-for` header without any extra configuration.
- Set `API_KEY` in the Vercel project settings (Settings → Environment Variables).
- Cold starts clear the in-memory cache and rate limiter; this is expected
  for serverless and does not affect correctness. Use Upstash Redis for persistence.

---

## 5. Render.com Deployment (Free Plan)

The repo includes a [`render.yaml`](render.yaml) Blueprint with free-plan defaults pre-configured — one-click deploy with no manual setup.

### Quick Deploy (Blueprint)

1. Push the repo to GitHub.
2. Go to **Render Dashboard → New + → Blueprint** and connect the repo.
3. Render reads `render.yaml` and creates the Web Service automatically.
4. After the first deploy, open the service → **Environment** tab and fill in the TeraBox credentials:
   | Variable | Description |
   |---|---|
   | `TERABOX_COOKIE` | Full raw cookie string from browser DevTools |
   | `TERABOX_JSTOKEN` | JS token value |
   | `TERABOX_BDSTOKEN` | BDS token value |
   | `TERABOX_SIGN` | Sign value |
   | `TERABOX_TIMESTAMP` | Timestamp value |
   | `TERABOX_LOGID` | Log ID value |

   > `API_KEY` is auto-generated by the Blueprint on first deploy. Copy it from the **Environment** tab for authenticating requests.

### Manual Deploy (without Blueprint)

If you prefer to create the service by hand:

1. Push the repo to GitHub.
2. **Render Dashboard → New + → Web Service** → connect the repo.
3. Set the start command: `uvicorn api.index:app --host 0.0.0.0 --port $PORT`
4. Add environment variables:
   | Variable | Value |
   |---|---|
   | `API_KEY` | Your secret key |
   | `RENDER` | `true` |
   | `REDIRECT_SEGMENTS` | `true` |
   | `TERABOX_*` | *(your credential values)* |

> **Why set `RENDER=true`?** Render runs the app behind its own reverse proxy.
> When `RENDER` is set, the API trusts the `X-Forwarded-For` header that Render's
> load balancer injects, so the per-IP rate limiter correctly identifies each
> client. Without it, all requests appear to come from the same proxy IP and the
> rate limiter is effectively global.

### Free-Plan Considerations

- **Spin-down:** Free instances sleep after **15 min** of inactivity. First request after sleep takes ~30–60 s. To keep the instance warm, set up a free cron ping (e.g. [cron-job.org](https://cron-job.org) or [UptimeRobot](https://uptimerobot.com)) hitting `/` every 10 minutes.
- **Request timeout:** Free plan caps single requests at **100 s**. The Blueprint sets `REDIRECT_SEGMENTS=true` by default, which makes `/api/stream/segment` return a **307 redirect** to the CDN instead of proxying bytes through the container — avoiding the timeout and cutting egress ~90%.
- **Memory:** 512 MB. The async architecture (Uvicorn + httpx) is significantly more memory-efficient than thread-per-request models since concurrent connections share the event loop instead of each consuming ~8 MB for an OS thread.

### Platform Notes — Render.com
- Loopback addresses (`127.0.0.0/8`, `::1`) are trusted automatically, so even
  without `RENDER=true` the rate limiter will usually work when Render's proxy
  is on the same host. Setting `RENDER=true` is the recommended way to make
  this explicit and future-proof.
- Render sets `PORT` automatically; the code reads it.
- If you front Render with an additional CDN or external load balancer, add its
  CIDR to `TRUSTED_PROXIES` and disable automatic loopback trust by setting
  `TRUSTED_PROXIES` explicitly.

---

## 6. Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or build and run manually
docker build -t terabridge-api .
docker run -p 8000:8000 --env-file .env terabridge-api
```

The Docker image uses **Gunicorn** with `uvicorn.workers.UvicornWorker` for production-grade multi-process serving. Worker count scales automatically based on CPU cores (configurable via `GUNICORN_WORKERS`).

---

## Performance Architecture

```
                    ┌──────────────┐
  Client Request ──>│ Rate Limiter │──> 429 if exceeded
                    └──────┬───────┘
                           │ allowed
                    ┌──────▼───────┐
                    │  LRU Cache   │──> X-Cache: HIT (instant)
                    └──────┬───────┘
                           │ cache miss
                    ┌──────▼────────┐
                    │ Single Flight │──> Collapse duplicate requests
                    └──────┬────────┘
                           │ unique request
                    ┌──────▼───────┐
                    │  resolve()   │──> Terabox API (async httpx)
                    └──────┬───────┘
                           │ store in cache
                    ┌──────▼───────┐
                    │   Response   │──> X-Cache: MISS
                    └──────────────┘
```

| Layer | Purpose | Impact |
|---|---|---|
| **Uvicorn ASGI Server** | Non-blocking event loop (single thread) | Thousands of concurrent connections |
| **Rate Limiter** | 30 req/min per IP (in-memory or Redis) | Protects Terabox session |
| **LRU Cache** | 60s TTL, 256 entries (in-memory or Redis) | Instant repeat responses |
| **Single Flight** | Request collapsing via locks | Deduplicates burst traffic |
| **Async HTTP Client** | `httpx.AsyncClient` with connection pooling | Non-blocking upstream calls |
| **Background Tasks** | `asyncio.create_task()` for transcode polling & quality pre-warm | Zero thread overhead |
