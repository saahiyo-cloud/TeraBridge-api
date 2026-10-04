"""
api/cache.py — Thread-safe LRU response cache with optional Upstash Redis backend.

Exports a single ``cache`` instance consumed by route handlers.
"""
import hashlib
import json
import logging
import time
from collections import OrderedDict

from api.config import CACHE_MAX_ENTRIES, CACHE_TTL_SECONDS
from api.redis_client import redis_client

logger = logging.getLogger("terabridge.cache")


class ResponseCache:
    """
    In-memory LRU cache with an optional Redis backend.

    When a Redis client is provided every operation is delegated to Redis;
    the in-memory store is used as a fallback.
    """

    def __init__(
        self,
        max_entries: int = 256,
        ttl_seconds: int = 60,
        redis=None,
    ):
        self._redis = redis
        self._store: OrderedDict = OrderedDict()
        self._max = max_entries
        self._ttl = ttl_seconds
        self.hits = 0
        self.misses = 0

    # ── Key construction ───────────────────────────────────────────────
    def make_key(self, link: str, action: str, wait: bool) -> str:
        raw = f"{link}|{action}|{wait}"
        return hashlib.md5(raw.encode()).hexdigest()

    # Keep the private alias so existing callers in routes don't break
    def _make_key(self, link: str, action: str, wait: bool) -> str:
        return self.make_key(link, action, wait)

    # ── Get ────────────────────────────────────────────────────────────
    def get(self, link: str, action: str, wait: bool):
        key = self.make_key(link, action, wait)

        if self._redis:
            try:
                data_str = self._redis.get(f"cache:response:{key}")
                if data_str:
                    self.hits += 1
                    self._incr_stat("stats:cache_hits")
                    return json.loads(data_str)
                self.misses += 1
                self._incr_stat("stats:cache_misses")
                return None
            except Exception as exc:
                logger.warning("Redis cache get error: %s", exc)

        if key in self._store:
            data, ts = self._store[key]
            if time.time() - ts < self._ttl:
                self._store.move_to_end(key)
                self.hits += 1
                return data
            del self._store[key]

        self.misses += 1
        return None

    # ── Put ────────────────────────────────────────────────────────────
    def put(self, link: str, action: str, wait: bool, response):
        key = self.make_key(link, action, wait)

        if self._redis:
            try:
                self._redis.set(f"cache:response:{key}", json.dumps(response), ex=self._ttl)
                return
            except Exception as exc:
                logger.warning("Redis cache put error: %s", exc)

        if key in self._store:
            del self._store[key]
        self._store[key] = (response, time.time())
        while len(self._store) > self._max:
            self._store.popitem(last=False)

    # ── Stats ──────────────────────────────────────────────────────────
    def stats(self) -> dict:
        if self._redis:
            try:
                redis_hits   = int(self._redis.get("stats:cache_hits")   or 0)
                redis_misses = int(self._redis.get("stats:cache_misses") or 0)
                total = redis_hits + redis_misses
                try:
                    entries_count = len(self._redis.keys("cache:response:*") or [])
                except Exception:
                    entries_count = "unknown"
                return {
                    "provider":    "upstash-redis",
                    "entries":     entries_count,
                    "ttl_seconds": self._ttl,
                    "hits":        redis_hits,
                    "misses":      redis_misses,
                    "hit_rate":    f"{redis_hits / total * 100:.1f}%" if total > 0 else "N/A",
                }
            except Exception as exc:
                logger.warning("Redis cache stats error: %s", exc)

        total = self.hits + self.misses
        return {
            "provider":    "in-memory",
            "entries":     len(self._store),
            "max_entries": self._max,
            "ttl_seconds": self._ttl,
            "hits":        self.hits,
            "misses":      self.misses,
            "hit_rate":    f"{self.hits / total * 100:.1f}%" if total > 0 else "N/A",
        }

    # ── Internal ───────────────────────────────────────────────────────
    def _incr_stat(self, key: str):
        try:
            self._redis.incr(key)
        except Exception:
            pass


# ── Singleton instance consumed by the rest of the app ────────────────
cache = ResponseCache(
    max_entries=CACHE_MAX_ENTRIES,
    ttl_seconds=CACHE_TTL_SECONDS,
    redis=redis_client,
)
