# TeraBridge API

This repository contains a lightweight, modular Python CLI utility and a Flask API designed for retrieving direct download links and playable HLS `.m3u8` streaming manifests from Terabox shared folders. It is configured to run locally or as a Serverless Function on **Vercel**.

---

## Features

- **Dynamic Token Resolution:** Automatically resolves session-specific `bdstoken` and `jsToken` dynamically from your cookies to bypass standard verification blocks.
- **Save Location Targeting:** Copies shared files automatically to a `/cloudvids` folder inside the account storage for clear organization.
- **HLS Transcoding Handling:** Automatically handles transcoding ready delays (`errno: 130`). For serverless executions, it flags this state cleanly in the JSON response, enabling clients to poll/retry.
- **Vercel Deployable:** Designed out-of-the-box for quick deployment using the Vercel Python runtime.
- **Response Caching:** In-memory LRU cache with configurable TTL (default 60s) reduces redundant Terabox API calls for repeated links.
- **Rate Limiting:** Per-IP sliding window rate limiter (default 30 req/min) protects Terabox session tokens from exhaustion.
- **Connection Pooling & Retry:** HTTP connection pooling (10 connections, 20 max pool) with automatic retry on 5xx errors and exponential backoff.
- **Production Server:** Uses [Waitress](https://docs.pylonsproject.org/projects/waitress/) multi-threaded WSGI server for local/production runs (8 threads), replacing Flask's single-threaded dev server.

---

## Project Structure

```
terabridge-api/
├── api/
│   └── index.py          # Flask API with caching, rate limiting, Waitress
├── downloader.py         # Core library & CLI interface (connection pooling + retry)
├── load_test.py          # Concurrent load testing script
├── README.md             # This documentation
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

```bash
# Example: custom configuration
CACHE_TTL=120 RATE_LIMIT_RPM=60 PORT=8080 python api/index.py
```

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
