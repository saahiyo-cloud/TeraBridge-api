"""
api/cache.py — Multi-tier LRU cache with optional Upstash Redis backend.

Provides:
  1. Resolved Link & Response Caching (configurable TTL, default 5m)
  2. Thumbnail Image Caching (24h TTL, Redis Base64 + in-memory LRU)
  3. Dashboard Data Caching (Storage Quota & /cloudvids file lists, 60s TTL)

Exports a single ``cache`` instance consumed by route handlers.
"""
import base64
import hashlib
import json
import logging
import time
from collections import OrderedDict

from api.config import (
    CACHE_DASHBOARD_TTL,
    CACHE_MAX_ENTRIES,
    CACHE_THUMBNAIL_TTL,
    CACHE_TTL_SECONDS,
)
from api.redis_client import redis_client

logger = logging.getLogger("terabridge.cache")


class ResponseCache:
    """
    Multi-tier cache supporting response links, thumbnail media, and dashboard data.
    Delegates to Upstash Redis when available, falling back seamlessly to thread-safe in-memory stores.
    """

    def __init__(
        self,
        max_entries: int = 512,
        ttl_seconds: int = 300,
        redis=None,
    ):
        self._redis = redis
        self._store: OrderedDict = OrderedDict()
        self._max = max_entries
        self._ttl = ttl_seconds

        # In-memory stores for thumbnails and dashboard metrics
        self._thumb_store: OrderedDict = OrderedDict()
        self._dash_store: OrderedDict = OrderedDict()

        self.hits = 0
        self.misses = 0
        self.thumb_hits = 0
        self.thumb_misses = 0
        self.dash_hits = 0
        self.dash_misses = 0

    # ── Key construction ───────────────────────────────────────────────
    def make_key(self, link: str, action: str, wait: bool) -> str:
        raw = f"{link}|{action}|{wait}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _make_key(self, link: str, action: str, wait: bool) -> str:
        return self.make_key(link, action, wait)

    # ── Resolved Link Cache ────────────────────────────────────────────
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

    def delete(self, link: str, action: str, wait: bool):
        key = self.make_key(link, action, wait)
        if self._redis:
            try:
                self._redis.delete(f"cache:response:{key}")
            except Exception as exc:
                logger.warning("Redis cache delete error: %s", exc)
        self._store.pop(key, None)

    # ── Thumbnail Media Cache (24h TTL) ────────────────────────────────
    def get_thumbnail(self, lookup_key: str) -> tuple[bytes, str] | None:
        """Returns (image_bytes, content_type) or None if cached item not found."""
        thumb_hash = hashlib.md5(lookup_key.encode("utf-8")).hexdigest()

        if self._redis:
            try:
                raw_json = self._redis.get(f"cache:thumb:{thumb_hash}")
                if raw_json:
                    payload = json.loads(raw_json)
                    data = base64.b64decode(payload["b64"])
                    self.thumb_hits += 1
                    self._incr_stat("stats:thumb_hits")
                    return data, payload.get("ct", "image/jpeg")
                self.thumb_misses += 1
                self._incr_stat("stats:thumb_misses")
                return None
            except Exception as exc:
                logger.debug("Redis thumbnail get error: %s", exc)

        if thumb_hash in self._thumb_store:
            data, ct, ts, ttl = self._thumb_store[thumb_hash]
            if time.time() - ts < ttl:
                self._thumb_store.move_to_end(thumb_hash)
                self.thumb_hits += 1
                return data, ct
            del self._thumb_store[thumb_hash]

        self.thumb_misses += 1
        return None

    def put_thumbnail(self, lookup_key: str, data: bytes, content_type: str = "image/jpeg", ttl_seconds: int = CACHE_THUMBNAIL_TTL):
        """Caches thumbnail bytes in Redis / memory."""
        thumb_hash = hashlib.md5(lookup_key.encode("utf-8")).hexdigest()

        if self._redis:
            try:
                payload = {
                    "ct": content_type,
                    "b64": base64.b64encode(data).decode("ascii"),
                }
                self._redis.set(f"cache:thumb:{thumb_hash}", json.dumps(payload), ex=ttl_seconds)
                return
            except Exception as exc:
                logger.debug("Redis thumbnail put error: %s", exc)

        if thumb_hash in self._thumb_store:
            del self._thumb_store[thumb_hash]
        self._thumb_store[thumb_hash] = (data, content_type, time.time(), ttl_seconds)
        while len(self._thumb_store) > 500:
            self._thumb_store.popitem(last=False)

    # ── Dashboard Data Cache (Quota & Cloudvids Lists) ─────────────────
    def get_dashboard(self, key: str) -> dict | None:
        """Retrieves cached dashboard metrics (quota, file list)."""
        dash_key = f"cache:dash:{key}"
        if self._redis:
            try:
                raw = self._redis.get(dash_key)
                if raw:
                    self.dash_hits += 1
                    self._incr_stat("stats:dash_hits")
                    return json.loads(raw)
                self.dash_misses += 1
                self._incr_stat("stats:dash_misses")
                return None
            except Exception as exc:
                logger.debug("Redis dashboard get error: %s", exc)

        if key in self._dash_store:
            data, ts, ttl = self._dash_store[key]
            if time.time() - ts < ttl:
                self._dash_store.move_to_end(key)
                self.dash_hits += 1
                return data
            del self._dash_store[key]

        self.dash_misses += 1
        return None

    def put_dashboard(self, key: str, data: dict, ttl_seconds: int = CACHE_DASHBOARD_TTL):
        """Caches dashboard metrics for snappy UI interactions."""
        dash_key = f"cache:dash:{key}"
        if self._redis:
            try:
                self._redis.set(dash_key, json.dumps(data), ex=ttl_seconds)
                return
            except Exception as exc:
                logger.debug("Redis dashboard put error: %s", exc)

        if key in self._dash_store:
            del self._dash_store[key]
        self._dash_store[key] = (data, time.time(), ttl_seconds)
        while len(self._dash_store) > 100:
            self._dash_store.popitem(last=False)

    def invalidate_dashboard(self, account_id: str | None = None):
        """Purges cached dashboard quota & file listings for an account or all accounts."""
        if self._redis:
            try:
                pattern = f"cache:dash:*{account_id}*" if account_id else "cache:dash:*"
                keys = self._redis.keys(pattern) or []
                if keys:
                    self._redis.delete(*keys)
            except Exception as exc:
                logger.debug("Redis dashboard invalidation error: %s", exc)

        # In-memory purge
        to_del = [k for k in self._dash_store if not account_id or account_id in k]
        for k in to_del:
            self._dash_store.pop(k, None)

    # ── Stats ──────────────────────────────────────────────────────────
    def stats(self) -> dict:
        total_links = self.hits + self.misses
        total_thumb = self.thumb_hits + self.thumb_misses
        total_dash  = self.dash_hits + self.dash_misses

        if self._redis:
            try:
                r_hits   = int(self._redis.get("stats:cache_hits")   or 0)
                r_misses = int(self._redis.get("stats:cache_misses") or 0)
                r_total  = r_hits + r_misses

                t_hits   = int(self._redis.get("stats:thumb_hits")   or 0)
                t_misses = int(self._redis.get("stats:thumb_misses") or 0)
                t_total  = t_hits + t_misses

                d_hits   = int(self._redis.get("stats:dash_hits")   or 0)
                d_misses = int(self._redis.get("stats:dash_misses") or 0)
                d_total  = d_hits + d_misses

                try:
                    entries_count = len(self._redis.keys("cache:response:*") or [])
                    thumb_count   = len(self._redis.keys("cache:thumb:*") or [])
                except Exception:
                    entries_count = "unknown"
                    thumb_count   = "unknown"

                return {
                    "provider": "upstash-redis",
                    "links": {
                        "entries":     entries_count,
                        "ttl_seconds": self._ttl,
                        "hits":        r_hits,
                        "misses":      r_misses,
                        "hit_rate":    f"{r_hits / r_total * 100:.1f}%" if r_total > 0 else "N/A",
                    },
                    "thumbnails": {
                        "entries":     thumb_count,
                        "ttl_seconds": CACHE_THUMBNAIL_TTL,
                        "hits":        t_hits,
                        "misses":      t_misses,
                        "hit_rate":    f"{t_hits / t_total * 100:.1f}%" if t_total > 0 else "N/A",
                    },
                    "dashboard": {
                        "ttl_seconds": CACHE_DASHBOARD_TTL,
                        "hits":        d_hits,
                        "misses":      d_misses,
                        "hit_rate":    f"{d_hits / d_total * 100:.1f}%" if d_total > 0 else "N/A",
                    },
                }
            except Exception as exc:
                logger.warning("Redis cache stats error: %s", exc)

        return {
            "provider": "in-memory",
            "links": {
                "entries":     len(self._store),
                "max_entries": self._max,
                "ttl_seconds": self._ttl,
                "hits":        self.hits,
                "misses":      self.misses,
                "hit_rate":    f"{self.hits / total_links * 100:.1f}%" if total_links > 0 else "N/A",
            },
            "thumbnails": {
                "entries":     len(self._thumb_store),
                "ttl_seconds": CACHE_THUMBNAIL_TTL,
                "hits":        self.thumb_hits,
                "misses":      self.thumb_misses,
                "hit_rate":    f"{self.thumb_hits / total_thumb * 100:.1f}%" if total_thumb > 0 else "N/A",
            },
            "dashboard": {
                "entries":     len(self._dash_store),
                "ttl_seconds": CACHE_DASHBOARD_TTL,
                "hits":        self.dash_hits,
                "misses":      self.dash_misses,
                "hit_rate":    f"{self.dash_hits / total_dash * 100:.1f}%" if total_dash > 0 else "N/A",
            },
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
