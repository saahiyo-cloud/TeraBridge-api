"""
api/metrics.py — High-performance Analytics & Observability Engine for TeraBridge.

Tracks:
- Request volume, route distributions, and HTTP status codes (2xx, 4xx, 5xx).
- Latency percentiles and rolling average response times.
- System operational events (proxy quarantines, account rotations, errors).
- Cache hit ratios and rate limiter statistics.
- Syncs counters and events with Redis (with in-memory fallbacks).
"""
from __future__ import annotations

import collections
import json
import logging
import threading
import time
from typing import Any

from api.redis_client import redis_client

logger = logging.getLogger("terabridge.metrics")

REDIS_EVENTS_KEY = "terabridge:events"
REDIS_METRICS_HASH = "terabridge:metrics_counters"
MAX_EVENTS_LOG = 60
MAX_LATENCY_SAMPLES = 200

# ── In-Memory Ring Buffers & Counters ─────────────────────────────────
_start_time = time.time()
_local_counters: dict[str, int] = collections.defaultdict(int)
_max_seen_counters: dict[str, int] = collections.defaultdict(int)
_latency_samples: collections.deque[float] = collections.deque(maxlen=MAX_LATENCY_SAMPLES)
_local_events: collections.deque[dict[str, Any]] = collections.deque(maxlen=MAX_EVENTS_LOG)

_pending_lock = threading.Lock()
_pending_increments: dict[str, int] = collections.defaultdict(int)
_last_flush_time: float = 0.0


def set_metrics_start_time(st: float) -> None:
    global _start_time
    _start_time = st


def _exec_pipeline(pipe: Any) -> None:
    """
    Safely execute a pipeline across upstash-redis, redis-py, or mock clients.
    upstash-redis Pipeline uses .exec(), while redis-py uses .execute().
    """
    if hasattr(pipe, "exec") and callable(pipe.exec):
        pipe.exec()
    elif hasattr(pipe, "execute") and callable(pipe.execute):
        pipe.execute()


def flush_pending_metrics() -> None:
    """Flush buffered metrics counter increments to Redis in an atomic batch."""
    global _last_flush_time
    if not redis_client:
        return

    with _pending_lock:
        if not _pending_increments:
            return
        to_flush = dict(_pending_increments)
        _pending_increments.clear()
        _last_flush_time = time.time()

    try:
        pipe = redis_client.pipeline() if hasattr(redis_client, "pipeline") else None
        if pipe:
            for k, amount in to_flush.items():
                if amount > 0:
                    pipe.hincrby(REDIS_METRICS_HASH, k, amount)
            _exec_pipeline(pipe)
        else:
            for k, amount in to_flush.items():
                if amount > 0:
                    redis_client.hincrby(REDIS_METRICS_HASH, k, amount)
    except Exception as exc:
        logger.debug("Failed to flush pending metrics to Redis: %s", exc)
        # Restore unflushed increments so counts are never dropped
        with _pending_lock:
            for k, amount in to_flush.items():
                _pending_increments[k] += amount


def record_request(path: str, method: str, status_code: int, duration_ms: float) -> None:
    """Record an incoming HTTP request for traffic analytics."""
    if method == "OPTIONS":
        return

    # Normalize route category
    route_key = "other"
    if path.startswith("/api/resolve"):
        route_key = "resolve"
    elif path.startswith("/api/stream"):
        route_key = "stream"
    elif path.startswith("/api/download"):
        route_key = "download"
    elif path.startswith("/api/thumbnail"):
        route_key = "thumbnail"
    elif path.startswith("/api/admin") or path in ("/admin", "/dashboard", "/api/stats"):
        route_key = "admin"

    status_group = f"{status_code // 100}xx"
    _latency_samples.append(duration_ms)

    # Increment local memory counters
    _local_counters["total"] += 1
    _local_counters[f"route:{route_key}"] += 1
    _local_counters[f"status:{status_group}"] += 1

    # Keep track of local high-water marks for instant monotonicity
    _max_seen_counters["total"] = max(_max_seen_counters["total"], _local_counters["total"])
    _max_seen_counters[f"route:{route_key}"] = max(_max_seen_counters[f"route:{route_key}"], _local_counters[f"route:{route_key}"])
    _max_seen_counters[f"status:{status_group}"] = max(_max_seen_counters[f"status:{status_group}"], _local_counters[f"status:{status_group}"])

    # Buffer increments for batched Redis sync
    if redis_client:
        should_flush = False
        with _pending_lock:
            _pending_increments["total"] += 1
            _pending_increments[f"route:{route_key}"] += 1
            _pending_increments[f"status:{status_group}"] += 1
            if _pending_increments["total"] >= 5 or (time.time() - _last_flush_time) >= 2.0:
                should_flush = True

        if should_flush:
            flush_pending_metrics()


def record_event(
    event_type: str,
    message: str,
    level: str = "info",
    details: dict[str, Any] | None = None,
) -> None:
    """Record an operational or system incident event into the feed."""
    event = {
        "id": f"{int(time.time() * 1000)}",
        "timestamp": int(time.time()),
        "type": event_type,  # 'proxy_quarantine', 'proxy_recover', 'account_rotate', 'resolve', 'system'
        "level": level,       # 'info', 'success', 'warning', 'error'
        "message": message,
        "details": details or {},
    }

    _local_events.appendleft(event)

    if redis_client:
        try:
            redis_client.lpush(REDIS_EVENTS_KEY, json.dumps(event))
            redis_client.ltrim(REDIS_EVENTS_KEY, 0, MAX_EVENTS_LOG - 1)
        except Exception as exc:
            logger.debug("Failed to push event to Redis: %s", exc)


def get_recent_events(limit: int = 30) -> list[dict[str, Any]]:
    """Return the most recent operational events."""
    if redis_client:
        try:
            raw_list = redis_client.lrange(REDIS_EVENTS_KEY, 0, limit - 1)
            if raw_list:
                events = []
                for item in raw_list:
                    if isinstance(item, bytes):
                        item = item.decode("utf-8")
                    events.append(json.loads(item))
                return events
        except Exception as exc:
            logger.debug("Failed to fetch events from Redis: %s", exc)

    return list(_local_events)[:limit]


def get_analytics_summary() -> dict[str, Any]:
    """Compile a comprehensive telemetry, traffic, and health monitoring report."""
    now = time.time()
    uptime = int(now - _start_time)

    # 1. Flush any pending local increments first so Redis has all latest counts
    flush_pending_metrics()

    # 2. Build cumulative traffic counters using Redis with high-water mark protection
    traffic_counters = dict(_local_counters)

    # Seed with process-level high water marks
    for k, v in _max_seen_counters.items():
        traffic_counters[k] = max(traffic_counters.get(k, 0), v)

    if redis_client:
        try:
            raw_hash = redis_client.hgetall(REDIS_METRICS_HASH)
            if raw_hash:
                for k, v in raw_hash.items():
                    k_str = k.decode("utf-8") if isinstance(k, bytes) else str(k)
                    try:
                        v_int = int(v)
                        traffic_counters[k_str] = max(traffic_counters.get(k_str, 0), v_int)
                        _max_seen_counters[k_str] = max(_max_seen_counters.get(k_str, 0), v_int)
                    except (ValueError, TypeError):
                        pass
        except Exception as exc:
            logger.debug("Failed to read metrics hash from Redis: %s", exc)

    # Monotonic high-water mark lock: Ensure counters never drop under any worker race
    for k, v in traffic_counters.items():
        _max_seen_counters[k] = max(_max_seen_counters.get(k, 0), v)
        traffic_counters[k] = _max_seen_counters[k]

    total_reqs = traffic_counters.get("total", 0)
    routes_split = {
        "resolve": traffic_counters.get("route:resolve", 0),
        "stream": traffic_counters.get("route:stream", 0),
        "download": traffic_counters.get("route:download", 0),
        "thumbnail": traffic_counters.get("route:thumbnail", 0),
        "admin": traffic_counters.get("route:admin", 0),
        "other": traffic_counters.get("route:other", 0),
    }

    status_split = {
        "2xx": traffic_counters.get("status:2xx", 0),
        "3xx": traffic_counters.get("status:3xx", 0),
        "4xx": traffic_counters.get("status:4xx", 0),
        "5xx": traffic_counters.get("status:5xx", 0),
    }

    success_rate = 100.0
    non_2xx = status_split["4xx"] + status_split["5xx"]
    if total_reqs > 0:
        success_rate = round((status_split["2xx"] / total_reqs) * 100, 1)

    # Latency Stats
    avg_latency_ms = 0.0
    if _latency_samples:
        avg_latency_ms = round(sum(_latency_samples) / len(_latency_samples), 1)

    # 2. Redis Latency Ping
    redis_info = {"status": "disabled", "latency_ms": None}
    if redis_client:
        try:
            t0 = time.time()
            redis_client.ping()
            redis_info = {
                "status": "connected",
                "latency_ms": round((time.time() - t0) * 1000, 2),
            }
        except Exception as exc:
            redis_info = {"status": "error", "error": str(exc), "latency_ms": None}

    # 3. Proxy Pool Summary
    proxy_summary = {"total": 0, "healthy": 0, "cooldown": 0, "proxies": []}
    try:
        from api.proxy_manager import proxy_manager
        proxy_summary = proxy_manager.get_summary()
    except Exception:
        pass

    # 4. Accounts & Aggregated Storage Summary
    accounts_summary = {"total": 0, "healthy": 0, "active_id": None}
    storage_summary = {"total_gb": 0.0, "used_gb": 0.0, "free_gb": 0.0, "used_percent": 0.0}
    try:
        from api.account_pool import get_all_accounts, ACTIVE_ACCOUNT_KEY
        if redis_client:
            active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
            if isinstance(active_id, bytes):
                active_id = active_id.decode("utf-8")
            accounts_summary["active_id"] = active_id
            
            all_accs = get_all_accounts()
            accounts_summary["total"] = len(all_accs)
            accounts_summary["healthy"] = sum(1 for a in all_accs.values() if a.get("status") == "healthy")

        from api.cache import cache
        quota_data = cache.get_dashboard("quota:active")
        if quota_data and isinstance(quota_data, dict):
            storage_summary = {
                "total_gb": quota_data.get("total_gb", 0.0),
                "used_gb": quota_data.get("used_gb", 0.0),
                "free_gb": quota_data.get("free_gb", 0.0),
                "used_percent": quota_data.get("used_percent", 0.0),
            }
    except Exception:
        pass

    # 5. Cache & Rate Limiter Stats
    from api.cache import cache
    from api.rate_limiter import rate_limiter

    return {
        "status": "online",
        "timestamp": int(now),
        "system": {
            "uptime_seconds": uptime,
            "start_time": int(_start_time),
            "redis": redis_info,
            "platform": "InstaCloud Edge Container",
            "runtime": "Python 3.12 (ASGI FastApi)",
        },
        "traffic": {
            "total_requests": total_reqs,
            "routes": routes_split,
            "status_codes": status_split,
            "success_rate_percent": success_rate,
            "avg_latency_ms": avg_latency_ms,
        },
        "cache": cache.stats(),
        "rate_limiter": rate_limiter.stats(),
        "proxies": proxy_summary,
        "accounts": accounts_summary,
        "storage": storage_summary,
        "events": get_recent_events(25),
    }

