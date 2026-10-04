"""
api/rate_limiter.py — Per-IP sliding-window rate limiter with optional Redis backend.

Exports a single ``rate_limiter`` instance consumed by route handlers.
"""
import logging
import time

from api.config import RATE_LIMIT_RPM, RATE_LIMIT_WINDOW
from api.redis_client import redis_client

logger = logging.getLogger("terabridge.rate_limiter")


class RateLimiter:
    """
    Sliding-window rate limiter.

    Uses Upstash Redis (sorted-set per IP) when available, otherwise falls
    back to an in-process dict of timestamps.
    """

    def __init__(
        self,
        max_requests: int = 30,
        window_seconds: int = 60,
        redis=None,
    ):
        self._redis = redis
        self._requests: dict[str, list[float]] = {}
        self._max = max_requests
        self._window = window_seconds
        self.total_blocked = 0

    # ── Admission check ────────────────────────────────────────────────
    def is_allowed(self, ip: str) -> bool:
        now = time.time()

        if self._redis:
            try:
                key = f"rate_limit:{ip}"
                pipeline = self._redis.pipeline()
                pipeline.zremrangebyscore(key, 0, now - self._window)
                pipeline.zadd(key, {str(now): now})
                pipeline.zcard(key)
                pipeline.expire(key, self._window)
                res = pipeline.exec()
                count = int(res[2])
                if count > self._max:
                    try:
                        self._redis.incr("stats:rate_limit_blocked")
                    except Exception:
                        pass
                    return False
                return True
            except Exception as exc:
                logger.warning("Redis rate limit check error: %s", exc)

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

    # ── Remaining quota ────────────────────────────────────────────────
    def remaining(self, ip: str) -> int:
        now = time.time()

        if self._redis:
            try:
                key = f"rate_limit:{ip}"
                pipeline = self._redis.pipeline()
                pipeline.zremrangebyscore(key, 0, now - self._window)
                pipeline.zcard(key)
                res = pipeline.exec()
                count = int(res[1])
                return max(0, self._max - count)
            except Exception as exc:
                logger.warning("Redis rate limit remaining error: %s", exc)

        if ip not in self._requests:
            return self._max
        active = [ts for ts in self._requests[ip] if now - ts < self._window]
        return max(0, self._max - len(active))

    # ── Observability ──────────────────────────────────────────────────
    def stats(self) -> dict:
        if self._redis:
            try:
                blocked = int(self._redis.get("stats:rate_limit_blocked") or 0)
                try:
                    active_clients = len(self._redis.keys("rate_limit:*") or [])
                except Exception:
                    active_clients = "unknown"
                return {
                    "provider":       "upstash-redis",
                    "max_rpm":        self._max,
                    "window_seconds": self._window,
                    "active_clients": active_clients,
                    "total_blocked":  blocked,
                }
            except Exception as exc:
                logger.warning("Redis rate limit stats error: %s", exc)

        now = time.time()
        active_ips = sum(
            1
            for ts_list in self._requests.values()
            if any(now - ts < self._window for ts in ts_list)
        )
        return {
            "provider":       "in-memory",
            "max_rpm":        self._max,
            "window_seconds": self._window,
            "active_clients": active_ips,
            "total_blocked":  self.total_blocked,
        }

    # ── Housekeeping ───────────────────────────────────────────────────
    def cleanup(self):
        """Evict stale in-memory entries (no-op when Redis is active)."""
        if self._redis:
            return
        now = time.time()
        stale = [
            ip
            for ip, ts_list in self._requests.items()
            if not any(now - ts < self._window for ts in ts_list)
        ]
        for ip in stale:
            del self._requests[ip]


# ── Singleton instance consumed by the rest of the app ────────────────
rate_limiter = RateLimiter(
    max_requests=RATE_LIMIT_RPM,
    window_seconds=RATE_LIMIT_WINDOW,
    redis=redis_client,
)
