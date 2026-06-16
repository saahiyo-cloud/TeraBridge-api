# TeraBridge API

This repository contains a lightweight, modular Python CLI utility and a Flask API designed for retrieving direct download links and playable HLS `.m3u8` streaming manifests from Terabox shared folders. It is configured to run locally or deploy to **Render** (free plan), **Docker**, or **Vercel**.

---

## Features

- **Dynamic Token Resolution:** Automatically resolves session-specific `bdstoken` and `jsToken` dynamically from your cookies to bypass standard verification blocks.
- **Save Location Targeting:** Copies shared files automatically to a `/cloudvids` folder inside the account storage for clear organization.
- **HLS Transcoding Handling:** Automatically handles transcoding ready delays (`errno: 130`). For serverless executions, it flags this state cleanly in the JSON response, enabling clients to poll/retry.
- **Render Deployable:** One-click deploy on Render's free plan via `render.yaml` Blueprint, with auto-generated secrets and free-plan tuning built in.
- **Vercel Deployable:** Designed out-of-the-box for quick deployment using the Vercel Python runtime.
- **Response Caching:** In-memory LRU cache with configurable TTL (default 60s) reduces redundant Terabox API calls for repeated links.
- **Rate Limiting:** Per-IP sliding window rate limiter (default 30 req/min) protects Terabox session tokens from exhaustion.
- **Connection Pooling & Retry:** HTTP connection pooling (10 connections, 20 max pool) with automatic retry on 5xx errors and exponential backoff.
- **Production Server:** Uses [Waitress](https://docs.pylonsproject.org/projects/waitress/) multi-threaded WSGI server for local/production runs (8 threads), replacing Flask's single-threaded dev server.

---

## Deployment

Deploy this API directly to your platform of choice with a single click:

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fsaahiyo-cloud%2FTeraBridge-api&env=API_KEY,UPSTASH_REDIS_REST_URL,UPSTASH_REDIS_REST_TOKEN,CRON_SECRET) [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/saahiyo-cloud/TeraBridge-api)

---

## Project Structure

```
terabridge-api/
├── api/
│   └── index.py          # Flask API with caching, rate limiting, Waitress
├── downloader.py         # Core library & CLI interface (connection pooling + retry)
├── load_test.py          # Concurrent load testing script
├── README.md             # This documentation
├── render.yaml           # Render.com Blueprint (free plan defaults)
├── requirements.txt      # Python dependencies
└── vercel.json           # Vercel deployment rewrites config
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

The server auto-detects your platform:
- **Linux/macOS:** Uses [Waitress](https://docs.pylonsproject.org/projects/waitress/) (8-thread WSGI server) for production performance
- **Windows:** Uses Flask's built-in threaded mode (avoids Waitress's `asyncore` 2s polling delay)

> **⚡ Windows Tip:** Always use `http://127.0.0.1:5000` instead of `http://localhost:5000` when testing locally. Windows DNS reverse lookup on `localhost` adds ~2 seconds to every request.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `5000` | Server port |
| `CACHE_TTL` | `60` | Cache time-to-live in seconds |
| `CACHE_MAX_ENTRIES` | `256` | Maximum cached responses (LRU eviction) |
| `RATE_LIMIT_RPM` | `30` | Max requests per minute per IP |
| `API_KEY` | `None` | **Required in production.** Enforces authentication on all protected endpoints. |
| `HMAC_SECRET` | `API_KEY` | Secret for signing shortened proxy URLs. Defaults to `API_KEY`. |
| `REQUIRE_API_KEY` | `auto` | Set to `0`/`false` to allow open access (dev only). `auto` = require when `API_KEY` is set. |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated list of proxy IPs/CIDRs. Only needed for non-loopback proxies. |
| `RENDER` | *(unset)* | Set to `true` on Render.com to auto-trust Render's load balancer. |
| `VERCEL` | *(auto)* | Set automatically by Vercel — no manual config needed. |
| `REDIRECT_SEGMENTS` | `false` | Set to `true` to 307-redirect segments to CDN instead of proxying. Cuts egress ~90% and avoids timeouts. |
| `CRON_SECRET` | *(unset)* | Secret token to protect cron/keep-alive endpoints. |

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
2. **Authorization Bearer Token**:
   ```http
   Authorization: Bearer my_secret_key
   ```
3. **Query Parameter** (recommended fallback for VLC/PotPlayer streams):
   ```
   ?key=my_secret_key   or   ?api_key=my_secret_key
   ```

Note: Rewritten segment URLs generated by `/api/stream/manifest` automatically inherit and propagate the `key` parameter to authenticate segment proxy requests.


### Endpoints

#### **GET /** — Health Check
Returns server status, version, and uptime.

#### **GET /api/stats** — Observability
Returns cache hit/miss statistics, rate limiter state, and active client counts.

**Example Response:**
```json
{
  "status": "online",
  "uptime_seconds": 3600,
  "cache": {
    "entries": 12,
    "max_entries": 256,
    "ttl_seconds": 60,
    "hits": 847,
    "misses": 53,
    "hit_rate": "94.1%"
  },
  "rate_limiter": {
    "max_rpm": 30,
    "window_seconds": 60,
    "active_clients": 5,
    "total_blocked": 3
  }
}
```

#### **GET /api/resolve** — Resolve Share Links

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
      "dlink": "https://dm-d.terabox.com/file/a8050382588a965fcdf39e10ef48b6ee?fid=...",
      "stream_ready": false,
      "error": null
    }
  ]
}
```

**Response Headers:**
| Header | Description |
|---|---|
| `X-Cache` | `HIT` or `MISS` — indicates whether the response was served from cache |
| `X-RateLimit-Remaining` | Number of requests remaining in the current window |
| `Retry-After` | Seconds to wait (only on 429 responses) |

#### **GET /api/stream/manifest** (or `/api/stream/playlist.m3u8`) — HLS Stream Proxy

Resolves and rewrites the HLS manifest playlist for media players. All media chunk URLs inside the manifest are rewritten to route through the local segment proxy, allowing you to stream videos directly in players like VLC, PotPlayer, or Safari without authentication or IP blocks.

**Parameters:**
- `url` (Required): The full Terabox share URL.
- `index` (Optional): The file index inside the folder if multiple streamable files are present (default `0`).
- `wait` (Optional): Set to `true` or `1` to block and wait/retry if transcoding is in progress.

**Example VLC Stream URL:**
```
http://127.0.0.1:5000/api/stream/manifest?url=https://1024terabox.com/s/1uCJPUU_1xRe10pU_bzEd0Q
```

#### **GET /api/stream/segment** — Segment Proxy

*Internal proxy route.* Streams segment binary files (`.ts` chunks) from Terabox CDNs using the active backend session headers and cookies. Features built-in SSRF protection limiting outbound requests to authorized Terabox and Baidu PCS domains.

---


## 3. Load Testing

A built-in load testing script is included for benchmarking:

```bash
# Light load: 20 concurrent, 100 requests
python load_test.py -c 20 -n 100

# Heavy load: 50 concurrent, 200 requests
python load_test.py -c 50 -n 200

# Duration-based sustained load (60 seconds)
python load_test.py -c 30 -d 60

# Test specific scenarios only
python load_test.py --scenarios health list

# Against a deployed URL
python load_test.py --base-url https://your-app.vercel.app -c 10 -n 50
```

Results include latency percentiles (min/avg/median/p90/p95/p99/max), throughput (req/s), error rates, and are saved to `load_test_results.json`.

---

## 4. Vercel Deployment

Deploy the API globally to Vercel in seconds:

1. Install the Vercel CLI: `npm i -g vercel`
2. Navigate into the folder: `cd terabridge-api`
3. Run: `vercel`

> **Note:** On Vercel (serverless), the API uses Flask directly (Waitress is not used). Caching and rate limiting still function within a single invocation context but won't persist across cold starts.

### Platform notes — Vercel
- The `VERCEL` env var is injected automatically. Client IP resolution trusts
  Vercel's `x-vercel-forwarded-for` header without any extra configuration.
- Set `API_KEY` in the Vercel project settings (Settings → Environment Variables).
- Cold starts clear the in-memory cache and rate limiter; this is expected
  for serverless and does not affect correctness.

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
3. Set the start command: `python api/index.py`
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

- **Spin-down:** Free instances sleep after **15 min** of inactivity. First request after sleep takes ~30–60 s. To keep the instance warm, set up a free cron ping (e.g. [cron-job.org](https://cron-job.org) or [UptimeRobot](https://uptimerobot.com)) hitting `/api/stats` every 10 minutes.
- **Request timeout:** Free plan caps single requests at **100 s**. The Blueprint sets `REDIRECT_SEGMENTS=true` by default, which makes `/api/stream/segment` return a **307 redirect** to the CDN instead of proxying bytes through the container — avoiding the timeout and cutting egress ~90%.
- **Memory:** 512 MB. Native Python (Waitress) is lighter than Docker on the free tier; the Blueprint uses the Python runtime, not the Dockerfile.

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
                    ┌──────▼───────┐
                    │  resolve()   │──> Terabox API (pooled + retry)
                    └──────┬───────┘
                           │ store in cache
                    ┌──────▼───────┐
                    │   Response   │──> X-Cache: MISS
                    └──────────────┘
```

| Layer | Purpose | Impact |
|---|---|---|
| **Threaded Server** | Waitress (Linux) / Flask threaded (Windows) | Concurrent request handling |
| **Rate Limiter** | 30 req/min per IP | Protects Terabox session |
| **LRU Cache** | 60s TTL, 256 entries | Instant repeat responses |
| **Connection Pool** | 10 conn, 20 max, 3 retries | Handles Terabox 5xx errors |
