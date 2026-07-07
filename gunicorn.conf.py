"""
Gunicorn configuration — tuned for the TeraBridge streaming proxy.

This app is synchronous and built on:
  - requests.Session connection pooling
  - threading.Thread / threading.Event (single-flight locks, background workers)
  - concurrent.futures.ThreadPoolExecutor (quality probing, file resolution)

Therefore we use the `gthread` worker class. Do NOT switch to gevent or
eventlet — their monkeypatching breaks requests pooling, threading.Event,
and the ThreadPoolExecutor that quality probing relies on.

All values are overridable via environment variables so the same image can
be deployed with different sizing on different hosts.
"""
import multiprocessing
import os


def _int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# ── Concurrency ──────────────────────────────────────────────────────
# workers × threads = total concurrent requests the container can serve.
# Default workers = min(2 × cores + 1, 4) — capped so small machines don't
# oversubscribe, and because the real bottleneck is outbound TeraBox API
# latency, not local CPU. Threads per worker handle concurrent streaming
# proxies (each holds a thread for the transfer duration).
_default_workers = min((multiprocessing.cpu_count() * 2) + 1, 4)
workers = _int_env("GUNICORN_WORKERS", _default_workers)

# Uvicorn worker class for running ASGI applications under Gunicorn
worker_class = "uvicorn.workers.UvicornWorker"

# ── Timeouts ─────────────────────────────────────────────────────────
# 300s covers full-file downloads on slow links and the 120s transcode-
# polling worker. The graceful timeout lets in-flight requests finish
# during rolling deploys / docker restart.
timeout = _int_env("GUNICORN_TIMEOUT", 300)
graceful_timeout = _int_env("GUNICORN_GRACEFUL_TIMEOUT", 120)
keepalive = 15

# ── Binding ──────────────────────────────────────────────────────────
bind = "0.0.0.0:" + os.environ.get("PORT", "8000")

# ── Reliability ──────────────────────────────────────────────────────
# Auto-restart workers that die, and cap the backlog so requests fail
# fast instead of piling up when saturated.
preload_app = True
max_requests = _int_env("GUNICORN_MAX_REQUESTS", 1000)
max_requests_jitter = 50
backlog = 2048

# ── Logging ──────────────────────────────────────────────────────────
accesslog = "-"          # stdout
errorlog = "-"           # stderr
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")
# Short, parseable access log format.
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sµs'
