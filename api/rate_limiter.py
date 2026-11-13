"""
api/rate_limiter.py — Per-IP sliding-window rate limiter with optional Redis backend.

Features:
  - Atomic sliding-window rate limiting (Redis sorted sets or in-process deque).
  - Non-counting rejections: blocked requests do NOT consume quota or self-extend lockout.
  - Multi-worker aware: with Redis, one shared counter per client. Without Redis (or while it
    errors), each worker keeps its own counters and the limit is divided by the worker count
    (GUNICORN_WORKERS / WEB_CONCURRENCY, exported by gunicorn.conf.py), so the global limit
    holds approximately but a client pinned to one worker sees limit/workers.
  - Dedicated authentication failure tracking & brute-force lockout.
  - Standard RFC / IETF-style rate limit headers (X-RateLimit-Limit, Remaining, Reset, Retry-After).
  - Tiered allowance for media segments and proxy downloads.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any

from api.config import (
    AUTH_LOCKOUT_SECONDS,
    AUTH_RATE_LIMIT_RPM,
    RATE_LIMIT_MEDIA_RPM,
    RATE_LIMIT_RPM,
    RATE_LIMIT_WINDOW,
)
from api.redis_client import redis_client

logger = logging.getLogger("terabridge.rate_limiter")


class RateLimiter:
    """
    Sliding-window rate limiter with Redis backend and in-memory fallback.
    """

    def __init__(
        self,
        max_requests: int = 30,
        window_seconds: int = 60,
        auth_max_failures: int = 10,
        auth_lockout_seconds: int = 60,
        media_max_requests: int = 180,
        redis: Any = None,
    ):
        self._redis = redis
        self._max = max_requests
        self._window = window_seconds
        self._auth_max = auth_max_failures
        self._auth_lockout = auth_lockout_seconds
        self._media_max = media_max_requests
        self.total_blocked = 0

        # In-memory request timestamp store: {ip: [ts1, ts2, ...]}
        self._requests: dict[str, list[float]] = {}
        # In-memory media request timestamp store: {ip: [ts1, ts2, ...]}
        self._media_requests: dict[str, list[float]] = {}
        # In-memory auth failure timestamp store: {ip: [ts1, ts2, ...]}
        self._auth_failures: dict[str, list[float]] = {}

        # Worker count detection for in-memory partitioning
        self._worker_count = self._detect_worker_count()
        if not self._redis and self._worker_count > 1:
            worker_max = max(1, self._max // self._worker_count)
            logger.warning(
                "Redis is not configured in a multi-worker setup (%d workers). "
                "Partitioning in-memory rate limit from %d RPM to %d RPM per worker "
                "to maintain target global limit.",
                self._worker_count,
                self._max,
                worker_max,
            )

    @staticmethod
    def _detect_worker_count() -> int:
        raw = os.environ.get("GUNICORN_WORKERS") or os.environ.get("WEB_CONCURRENCY")
        if raw:
            try:
                val = int(raw.strip())
                if val > 0:
                    return val
            except (ValueError, TypeError):
                pass
        return 1

    def _get_effective_max(self, max_override: int | None = None) -> int:
        base_max = max_override if max_override is not None else self._max
        # Only reached on the in-memory path (no Redis, or Redis erroring), where each
        # worker keeps its own counters: split the budget so the sum stays <= limit.
        if self._worker_count > 1:
            return max(1, base_max // self._worker_count)
        return base_max

    def _get_effective_auth_max(self) -> int:
        if self._worker_count > 1:
            return max(1, self._auth_max // self._worker_count)
        return self._auth_max

    # ── Admission check (General API requests) ─────────────────────────

    async def is_allowed_async(self, ip: str, max_override: int | None = None) -> bool:
        """
        Non-blocking async rate-limit check using AsyncRedis or in-memory fallback.
        Rejected requests DO NOT increment or extend the window.
        """
        from api.redis_client import async_redis_client

        limit = max_override if max_override is not None else self._max

        if async_redis_client:
            try:
                now = time.time()
                key = f"rate_limit:{ip}"
                pipe = async_redis_client.pipeline()
                pipe.zremrangebyscore(key, 0, now - self._window)
                pipe.zcard(key)
                res = await pipe.exec()
                count = int(res[1])

                if count >= limit:
                    try:
                        await async_redis_client.incr("stats:rate_limit_blocked")
                    except Exception:
                        pass
                    return False

                # Admitted: record uniquely and maintain TTL
                member_id = f"{now}:{uuid.uuid4().hex[:6]}"
                pipe2 = async_redis_client.pipeline()
                pipe2.zadd(key, {member_id: now})
                pipe2.expire(key, self._window)
                await pipe2.exec()
                return True
            except Exception as exc:
                logger.warning("Async Redis rate limit check error: %s", exc)

        return self.is_allowed(ip, max_override=max_override)

    def is_allowed(self, ip: str, max_override: int | None = None) -> bool:
        """
        Synchronous rate-limit check.
        Rejected requests DO NOT increment or extend the window.
        """
        now = time.time()
        limit = max_override if max_override is not None else self._max

        if self._redis:
            try:
                key = f"rate_limit:{ip}"
                pipeline = self._redis.pipeline()
                pipeline.zremrangebyscore(key, 0, now - self._window)
                pipeline.zcard(key)
                res = pipeline.exec()
                count = int(res[1])

                if count >= limit:
                    try:
                        self._redis.incr("stats:rate_limit_blocked")
                    except Exception:
                        pass
                    return False

                member_id = f"{now}:{uuid.uuid4().hex[:6]}"
                pipeline2 = self._redis.pipeline()
                pipeline2.zadd(key, {member_id: now})
                pipeline2.expire(key, self._window)
                pipeline2.exec()
                return True
            except Exception as exc:
                logger.warning("Redis rate limit check error: %s", exc)

        effective_max = self._get_effective_max(max_override)
        if ip not in self._requests:
            self._requests[ip] = []

        self._requests[ip] = [
            ts for ts in self._requests[ip] if now - ts < self._window
        ]

        if len(self._requests[ip]) >= effective_max:
            self.total_blocked += 1
            return False

        self._requests[ip].append(now)
        return True

    # ── Media Admission check (HLS Segments, Downloads, Thumbnails) ───

    async def is_media_allowed_async(self, ip: str) -> bool:
        """
        Async rate-limit check for high-frequency media streaming segments and downloads.
        Allows up to RATE_LIMIT_MEDIA_RPM per IP.
        """
        from api.redis_client import async_redis_client

        limit = self._media_max
        if async_redis_client:
            try:
                now = time.time()
                key = f"rate_limit:media:{ip}"
                pipe = async_redis_client.pipeline()
                pipe.zremrangebyscore(key, 0, now - self._window)
                pipe.zcard(key)
                res = await pipe.exec()
                count = int(res[1])

                if count >= limit:
                    return False

                member_id = f"{now}:{uuid.uuid4().hex[:6]}"
                pipe2 = async_redis_client.pipeline()
                pipe2.zadd(key, {member_id: now})
                pipe2.expire(key, self._window)
                await pipe2.exec()
                return True
            except Exception as exc:
                logger.warning("Async Redis media rate limit error: %s", exc)

        now = time.time()
        effective_max = (
            max(1, limit // self._worker_count) if self._worker_count > 1 else limit
        )

        if ip not in self._media_requests:
            self._media_requests[ip] = []

        self._media_requests[ip] = [
            ts for ts in self._media_requests[ip] if now - ts < self._window
        ]

        if len(self._media_requests[ip]) >= effective_max:
            return False

        self._media_requests[ip].append(now)
        return True

    # ── Authentication Failure Tracking & Brute-Force Safeguard ────────

    async def is_auth_allowed_async(self, ip: str) -> bool:
        """Return False if this IP has exceeded failed auth attempts (lockout active)."""
        from api.redis_client import async_redis_client

        if async_redis_client:
            try:
                val = await async_redis_client.get(f"auth_fail:{ip}")
                if val:
                    try:
                        count = int(val)
                        if count >= self._auth_max:
                            return False
                    except (ValueError, TypeError):
                        pass
                return True
            except Exception as exc:
                logger.warning("Async Redis auth check error: %s", exc)

        return self.is_auth_allowed(ip)

    def is_auth_allowed(self, ip: str) -> bool:
        """Synchronous check for auth failure lockout."""
        if self._redis:
            try:
                val = self._redis.get(f"auth_fail:{ip}")
                if val:
                    try:
                        count = int(val)
                        if count >= self._auth_max:
                            return False
                    except (ValueError, TypeError):
                        pass
                return True
            except Exception as exc:
                logger.warning("Redis auth check error: %s", exc)

        effective_auth_max = self._get_effective_auth_max()
        now = time.time()
        active = [
            ts for ts in self._auth_failures.get(ip, [])
            if now - ts < self._auth_lockout
        ]
        self._auth_failures[ip] = active
        return len(active) < effective_auth_max

    async def record_auth_failure_async(self, ip: str) -> None:
        """Record a failed auth attempt asynchronously."""
        from api.redis_client import async_redis_client

        if async_redis_client:
            try:
                key = f"auth_fail:{ip}"
                count = await async_redis_client.incr(key)
                if count == 1:
                    await async_redis_client.expire(key, self._auth_lockout)
                return
            except Exception as exc:
                logger.warning("Async Redis record auth failure error: %s", exc)

        self.record_auth_failure(ip)

    def record_auth_failure(self, ip: str) -> None:
        """Record a failed auth attempt synchronously."""
        if self._redis:
            try:
                key = f"auth_fail:{ip}"
                count = self._redis.incr(key)
                if count == 1:
                    self._redis.expire(key, self._auth_lockout)
                return
            except Exception as exc:
                logger.warning("Redis record auth failure error: %s", exc)

        now = time.time()
        if ip not in self._auth_failures:
            self._auth_failures[ip] = []
        self._auth_failures[ip] = [
            ts for ts in self._auth_failures[ip] if now - ts < self._auth_lockout
        ]
        self._auth_failures[ip].append(now)

    # ── Remaining quota & Header generation ────────────────────────────

    def remaining(self, ip: str, max_override: int | None = None) -> int:
        now = time.time()
        limit = max_override if max_override is not None else self._max

        if self._redis:
            try:
                key = f"rate_limit:{ip}"
                pipeline = self._redis.pipeline()
                pipeline.zremrangebyscore(key, 0, now - self._window)
                pipeline.zcard(key)
                res = pipeline.exec()
                count = int(res[1])
                return max(0, limit - count)
            except Exception as exc:
                logger.warning("Redis rate limit remaining error: %s", exc)

        effective_max = self._get_effective_max(max_override)
        if ip not in self._requests:
            return effective_max
        active = [ts for ts in self._requests[ip] if now - ts < self._window]
        return max(0, effective_max - len(active))

    def get_headers(
        self,
        ip: str,
        max_override: int | None = None,
        is_blocked: bool = False,
    ) -> dict[str, str]:
        """
        Generate standard RFC rate limiting headers:
        - X-RateLimit-Limit
        - X-RateLimit-Remaining
        - X-RateLimit-Reset (epoch timestamp)
        - Retry-After (included if quota exceeded)
        """
        limit = max_override if max_override is not None else self._max
        rem = 0 if is_blocked else self.remaining(ip, max_override=limit)
        now = int(time.time())
        reset_time = now + self._window

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(rem),
            "X-RateLimit-Reset": str(reset_time),
        }
        if rem == 0 or is_blocked:
            headers["Retry-After"] = str(self._window)
        return headers

    def get_auth_headers(self, ip: str) -> dict[str, str]:
        """Generate headers specifically for authentication failure lockouts."""
        now = int(time.time())
        return {
            "X-RateLimit-Limit": str(self._auth_max),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(now + self._auth_lockout),
            "Retry-After": str(self._auth_lockout),
        }

    # ── Observability ──────────────────────────────────────────────────

    def stats(self) -> dict:
        if self._redis:
            try:
                blocked = int(self._redis.get("stats:rate_limit_blocked") or 0)
                try:
                    from api.cache import _scan_keys
                    active_clients = len(_scan_keys(self._redis, "rate_limit:*"))
                except Exception:
                    active_clients = "unknown"
                return {
                    "provider": "upstash-redis",
                    "max_rpm": self._max,
                    "window_seconds": self._window,
                    "auth_max_failures": self._auth_max,
                    "auth_lockout_seconds": self._auth_lockout,
                    "media_max_rpm": self._media_max,
                    "active_clients": active_clients,
                    "total_blocked": blocked,
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
            "provider": "in-memory",
            "max_rpm": self._max,
            "effective_worker_rpm": self._get_effective_max(),
            "worker_count": self._worker_count,
            "window_seconds": self._window,
            "auth_max_failures": self._auth_max,
            "auth_lockout_seconds": self._auth_lockout,
            "media_max_rpm": self._media_max,
            "active_clients": active_ips,
            "total_blocked": self.total_blocked,
        }

    # ── Housekeeping ───────────────────────────────────────────────────

    def cleanup(self):
        """Evict stale in-memory entries (no-op when Redis is active)."""
        if self._redis:
            return
        now = time.time()

        for store in (self._requests, self._media_requests):
            stale = [
                ip
                for ip, ts_list in store.items()
                if not any(now - ts < self._window for ts in ts_list)
            ]
            for ip in stale:
                del store[ip]

        stale_auth = [
            ip
            for ip, ts_list in self._auth_failures.items()
            if not any(now - ts < self._auth_lockout for ts in ts_list)
        ]
        for ip in stale_auth:
            del self._auth_failures[ip]


# ── Singleton instance consumed by the rest of the app ────────────────
rate_limiter = RateLimiter(
    max_requests=RATE_LIMIT_RPM,
    window_seconds=RATE_LIMIT_WINDOW,
    auth_max_failures=AUTH_RATE_LIMIT_RPM,
    auth_lockout_seconds=AUTH_LOCKOUT_SECONDS,
    media_max_requests=RATE_LIMIT_MEDIA_RPM,
    redis=redis_client,
)
