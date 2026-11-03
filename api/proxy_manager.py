"""
api/proxy_manager.py — Smart multi-proxy pool manager for TeraBridge.

Features:
- Multi-proxy pool support (Webshare, BrightData, residential, datacenter, etc.).
- Normalization of proxies (e.g. 'IP:PORT:USER:PASS', 'http://USER:PASS@IP:PORT').
- Round-robin load balancing across healthy proxies.
- Auto-quarantine & Cooldown: when a proxy triggers TeraBox WAF 'need verify' (400141),
  transfer rate-limits (400810), payment/auth errors (402, 407), or connection timeouts,
  it is quarantined for a cooldown period (default: 300s) and automatically re-tested later.
- ContextVars-based per-request binding: ensures all chained calls within a single
  resolve task (refresh tokens, shorturlinfo, list, transfer) share the exact same
  proxy and session cookies without race conditions under concurrency.
- Redis persistence: pool configuration and health state synced with Redis.
- Fallback resilience: if all proxies are quarantined, best-effort selection uses
  the proxy closest to recovery.
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import re
import sys
import time
import urllib.parse
from contextlib import asynccontextmanager
from typing import Any

import httpx

logger = logging.getLogger("terabridge.proxy_manager")
if not logger.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

REDIS_PROXY_POOL_KEY = "terabridge:proxy_pool"
REDIS_SINGLE_PROXY_KEY = "terabridge:outbound_proxy"
DEFAULT_COOLDOWN_SECONDS = 300.0  # 5 minutes


# ─── URL Normalization & Masking ──────────────────────────────────────

def normalize_proxy(raw: str | None) -> str | None:
    """
    Normalize various proxy string formats to standard HTTP/SOCKS URL.

    Supported formats:
      - 'IP:PORT:USER:PASS' -> 'http://USER:PASS@IP:PORT'
      - 'IP:PORT'           -> 'http://IP:PORT'
      - 'http://USER:PASS@IP:PORT' (unchanged)
      - 'https://...', 'socks5://...'
    """
    if not raw:
        return None

    cleaned = raw.strip()
    # Remove outer quotes or commas if pasted with punctuation
    cleaned = cleaned.strip("\"' \t\r\n,;")
    if not cleaned:
        return None

    # Already has a recognized URL scheme
    if re.match(r"^(https?|socks5h?|socks4a?)://", cleaned, re.IGNORECASE):
        try:
            parsed = urllib.parse.urlsplit(cleaned)
            if parsed.hostname and parsed.port:
                return cleaned
        except Exception:
            return None

    # Format: IP:PORT:USER:PASS (common proxy provider export format, e.g. Webshare)
    parts = cleaned.split(":")
    if len(parts) == 4:
        host, port_str, user, password = parts
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                # URL encode username and password in case of special characters
                safe_user = urllib.parse.quote(user, safe="")
                safe_pass = urllib.parse.quote(password, safe="")
                return f"http://{safe_user}:{safe_pass}@{host}:{port}"
        except ValueError:
            pass

    # Format: IP:PORT
    if len(parts) == 2:
        host, port_str = parts
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                return f"http://{host}:{port}"
        except ValueError:
            pass

    return None


def mask_proxy(url: str | None) -> str | None:
    """Return proxy URL with password masked for safe logging and UI display."""
    if not url:
        return None
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.username:
            netloc = f"{parsed.username}:***@{parsed.hostname}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
        return url
    except Exception:
        return url


# ─── Proxy Entry Model ────────────────────────────────────────────────

class ProxyEntry:
    def __init__(
        self,
        url: str,
        raw: str | None = None,
        status: str = "healthy",
        cooldown_until: float = 0.0,
        last_used: float = 0.0,
        success_count: int = 0,
        failure_count: int = 0,
        consecutive_failures: int = 0,
        last_error: str | None = None,
        added_at: float | None = None,
    ):
        self.url = url
        self.raw = raw or url
        self.status = status  # 'healthy' | 'cooldown' | 'disabled'
        self.cooldown_until = float(cooldown_until or 0.0)
        self.last_used = float(last_used or 0.0)
        self.success_count = int(success_count or 0)
        self.failure_count = int(failure_count or 0)
        self.consecutive_failures = int(consecutive_failures or 0)
        self.last_error = last_error
        self.added_at = float(added_at or time.time())

    def is_cooling_down(self) -> bool:
        if self.status != "cooldown":
            return False
        if time.time() >= self.cooldown_until:
            # Cooldown expired: promote back to healthy (probation)
            self.status = "healthy"
            return False
        return True

    def cooldown_remaining(self) -> int:
        if not self.is_cooling_down():
            return 0
        return max(0, int(self.cooldown_until - time.time()))

    def to_dict(self) -> dict[str, Any]:
        cooling = self.is_cooling_down()
        return {
            "url": mask_proxy(self.url),
            "raw_url": self.url,
            "status": "cooldown" if cooling else self.status,
            "cooldown_remaining": self.cooldown_remaining(),
            "cooldown_until": int(self.cooldown_until) if self.cooldown_until else 0,
            "last_used": int(self.last_used) if self.last_used else None,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "added_at": int(self.added_at),
        }

    def serialize_for_redis(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "raw": self.raw,
            "status": self.status,
            "cooldown_until": self.cooldown_until,
            "last_used": self.last_used,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "added_at": self.added_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProxyEntry:
        return cls(
            url=data.get("url", ""),
            raw=data.get("raw"),
            status=data.get("status", "healthy"),
            cooldown_until=data.get("cooldown_until", 0.0),
            last_used=data.get("last_used", 0.0),
            success_count=data.get("success_count", 0),
            failure_count=data.get("failure_count", 0),
            consecutive_failures=data.get("consecutive_failures", 0),
            last_error=data.get("last_error"),
            added_at=data.get("added_at"),
        )


# ─── Context Variables ────────────────────────────────────────────────

_current_proxy_client: contextvars.ContextVar[httpx.AsyncClient | None] = contextvars.ContextVar(
    "current_proxy_client", default=None
)
_current_proxy_url: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_proxy_url", default=None
)
_current_proxy_entry: contextvars.ContextVar[ProxyEntry | None] = contextvars.ContextVar(
    "current_proxy_entry", default=None
)


class ProxyContext:
    def __init__(
        self,
        proxy_url: str | None,
        entry: ProxyEntry | None,
        client: httpx.AsyncClient | None,
    ):
        self.proxy_url = proxy_url
        self.entry = entry
        self.client = client


# ─── Proxy Pool Manager ───────────────────────────────────────────────

class ProxyPoolManager:
    def __init__(self, persist_to_redis: bool = True):
        self._entries: list[ProxyEntry] = []
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._client_loops: dict[str, asyncio.AbstractEventLoop] = {}
        self._rr_index: int = 0
        self._lock = asyncio.Lock()
        self._initialized = False
        self._persist_to_redis = persist_to_redis

    def get_total_count(self) -> int:
        return len(self._entries)

    def get_healthy_count(self) -> int:
        return sum(1 for e in self._entries if not e.is_cooling_down())

    def get_summary(self) -> dict[str, Any]:
        healthy = 0
        cooldown = 0
        proxies_data = []
        for e in self._entries:
            d = e.to_dict()
            if d["status"] == "cooldown":
                cooldown += 1
            elif d["status"] == "healthy":
                healthy += 1
            proxies_data.append(d)

        return {
            "total": len(self._entries),
            "healthy": healthy,
            "cooldown": cooldown,
            "proxies": proxies_data,
        }

    # ── Proxy Pool Mutation ──────────────────────────────────────────

    def parse_proxy_inputs(self, proxy_inputs: list[str] | str | None) -> list[str]:
        """Parse arbitrary user inputs (lines, comma-separated, or list) into normalized URLs."""
        if not proxy_inputs:
            return []

        raw_list: list[str] = []
        if isinstance(proxy_inputs, str):
            # Split by newlines, carriage returns, or commas
            lines = re.split(r"[\r\n,]+", proxy_inputs)
            raw_list.extend(lines)
        elif isinstance(proxy_inputs, (list, tuple, set)):
            for item in proxy_inputs:
                if isinstance(item, str):
                    raw_list.extend(re.split(r"[\r\n,]+", item))

        normalized_urls: list[str] = []
        seen = set()
        for item in raw_list:
            norm = normalize_proxy(item)
            if norm and norm not in seen:
                seen.add(norm)
                normalized_urls.append(norm)

        return normalized_urls

    def set_proxies(self, proxy_inputs: list[str] | str | None) -> int:
        """Replace the entire proxy pool with the given inputs."""
        new_urls = self.parse_proxy_inputs(proxy_inputs)
        existing_map = {e.url: e for e in self._entries}

        new_entries: list[ProxyEntry] = []
        for url in new_urls:
            if url in existing_map:
                new_entries.append(existing_map[url])
            else:
                new_entries.append(ProxyEntry(url=url))

        # Close clients for removed proxies
        new_url_set = set(new_urls)
        for url, client in list(self._clients.items()):
            if url not in new_url_set:
                try:
                    if not client.is_closed:
                        asyncio.create_task(client.aclose())
                except Exception:
                    pass
                self._clients.pop(url, None)
                self._client_loops.pop(url, None)

        self._entries = new_entries
        self._rr_index = 0
        self.save_to_redis()
        logger.info("Proxy pool updated: %d active proxies", len(self._entries))
        return len(self._entries)

    def add_proxies(self, proxy_inputs: list[str] | str | None) -> int:
        """Add new proxies to the pool without clearing existing ones."""
        new_urls = self.parse_proxy_inputs(proxy_inputs)
        existing_urls = {e.url for e in self._entries}
        added = 0
        for url in new_urls:
            if url not in existing_urls:
                self._entries.append(ProxyEntry(url=url))
                existing_urls.add(url)
                added += 1

        if added > 0:
            self.save_to_redis()
            logger.info("Added %d new proxies to pool (total: %d)", added, len(self._entries))
        return added

    def clear_proxies(self) -> None:
        """Clear all proxies from the pool."""
        for client in self._clients.values():
            try:
                if not client.is_closed:
                    asyncio.create_task(client.aclose())
            except Exception:
                pass
        self._clients.clear()
        self._client_loops.clear()
        self._entries.clear()
        self._rr_index = 0
        self.save_to_redis()
        logger.info("Proxy pool cleared")

    # ── Proxy Selection & Context ─────────────────────────────────────

    def get_next_proxy(self) -> ProxyEntry | None:
        """
        Select the next eligible proxy using round-robin.

        If all proxies are cooling down, returns the proxy closest to cooldown
        expiration as a best-effort fallback.
        """
        if not self._entries:
            return None

        # Check and update cooldown states
        eligible = [e for e in self._entries if not e.is_cooling_down()]

        if eligible:
            entry = eligible[self._rr_index % len(eligible)]
            self._rr_index += 1
            entry.last_used = time.time()
            return entry

        # All proxies in cooldown: pick the one that recovers soonest
        entry = min(self._entries, key=lambda e: e.cooldown_until)
        entry.last_used = time.time()
        logger.warning(
            "All %d proxies in cooldown. Best-effort selection: %s (quarantine remaining: %ds)",
            len(self._entries),
            mask_proxy(entry.url),
            entry.cooldown_remaining(),
        )
        return entry

    def get_entry_by_url(self, url: str | None) -> ProxyEntry | None:
        if not url:
            return None
        norm = normalize_proxy(url)
        for e in self._entries:
            if e.url == norm or e.url == url:
                return e
        return None

    def get_client_for_proxy(self, proxy_url: str | None) -> httpx.AsyncClient | None:
        """Return or create an httpx.AsyncClient configured for the given proxy URL."""
        if not proxy_url:
            return None

        current_loop = None
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        client = self._clients.get(proxy_url)
        loop = self._client_loops.get(proxy_url)

        if client is None or client.is_closed or (current_loop is not None and loop != current_loop):
            # Deferred import from downloader to prevent circular startup import
            from downloader import HEADERS, COOKIES_DICT
            limits = httpx.Limits(max_keepalive_connections=20, max_connections=50, keepalive_expiry=60.0)
            client = httpx.AsyncClient(
                headers=HEADERS,
                cookies=COOKIES_DICT,
                limits=limits,
                timeout=httpx.Timeout(connect=25.0, read=30.0, write=20.0, pool=10.0),
                proxy=proxy_url,
                http2=False,  # HTTP/1.1 is more robust with authenticated proxies
            )
            self._clients[proxy_url] = client
            if current_loop:
                self._client_loops[proxy_url] = current_loop
        else:
            # Ensure cookies are in sync
            try:
                from downloader import COOKIES_DICT
                for k, v in COOKIES_DICT.items():
                    client.cookies.set(k, v)
            except Exception:
                pass

        return client

    def sync_cookies(self, cookies: dict[str, str]) -> None:
        """Update cookies on all active proxy clients."""
        for client in self._clients.values():
            try:
                if not client.is_closed:
                    for k, v in cookies.items():
                        client.cookies.set(k, v)
            except Exception:
                pass

    @asynccontextmanager
    async def acquire_context(self, proxy_override: str | None = None):
        """
        Context manager that binds a selected proxy to the current asyncio Task.

        Any call to downloader.get_session() inside this context block will
        route through the selected proxy.
        """
        entry: ProxyEntry | None = None
        if proxy_override:
            entry = self.get_entry_by_url(proxy_override)
            proxy_url = entry.url if entry else normalize_proxy(proxy_override)
        else:
            entry = self.get_next_proxy()
            proxy_url = entry.url if entry else None

        client = self.get_client_for_proxy(proxy_url) if proxy_url else None

        token_client = _current_proxy_client.set(client)
        token_url = _current_proxy_url.set(proxy_url)
        token_entry = _current_proxy_entry.set(entry)

        ctx = ProxyContext(proxy_url=proxy_url, entry=entry, client=client)
        try:
            yield ctx
        finally:
            _current_proxy_client.reset(token_client)
            _current_proxy_url.reset(token_url)
            _current_proxy_entry.reset(token_entry)

    def get_current_session(self) -> httpx.AsyncClient | None:
        """Return the current context-bound proxy client, or None."""
        return _current_proxy_client.get()

    def get_current_proxy_url(self) -> str | None:
        """Return the current context-bound proxy URL, or None."""
        return _current_proxy_url.get()

    # ── Feedback & Quarantine ─────────────────────────────────────────

    def mark_success(self, proxy_url: str | None) -> None:
        """Record a successful request through this proxy."""
        if not proxy_url:
            return
        entry = self.get_entry_by_url(proxy_url)
        if entry:
            entry.success_count += 1
            entry.consecutive_failures = 0
            entry.status = "healthy"
            entry.last_error = None

    def mark_failure(
        self,
        proxy_url: str | None,
        reason: str,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
    ) -> None:
        """Quarantine a proxy after a failure or rate-limit with smart transient handling."""
        if not proxy_url:
            return
        entry = self.get_entry_by_url(proxy_url)
        if entry:
            entry.failure_count += 1
            entry.consecutive_failures += 1
            entry.last_error = reason

            reason_lower = reason.lower()
            is_hard_waf_or_auth = any(
                w in reason_lower
                for w in ("400141", "400810", "402", "407", "waf", "captcha", "forbidden", "unauthorized")
            )

            # For transient network timeouts, allow 1 retry before hard-quarantining
            if not is_hard_waf_or_auth and entry.consecutive_failures < 2:
                # Soft cooldown: brief 15s pause so next immediate request picks another proxy
                entry.cooldown_until = time.time() + min(15.0, cooldown_seconds)
                logger.info(
                    "Proxy %s transient hiccup (1/2). Soft backoff 15s: %s",
                    mask_proxy(proxy_url),
                    reason,
                )
                self.save_to_redis()
                return

            # Hard quarantine
            entry.status = "cooldown"
            entry.cooldown_until = time.time() + cooldown_seconds
            logger.warning(
                "Quarantining proxy %s for %ds. Reason: %s",
                mask_proxy(proxy_url),
                int(cooldown_seconds),
                reason,
            )
            try:
                from api.metrics import record_event
                record_event("proxy_quarantine", f"Proxy {mask_proxy(proxy_url)} quarantined for {int(cooldown_seconds)}s: {reason}", level="warning")
            except Exception:
                pass
            # Sync to Redis asynchronously or in memory
            self.save_to_redis()

    # ── Redis Persistence ─────────────────────────────────────────────

    def load_from_redis(self) -> None:
        """Load proxy pool state from Redis, with fallback to env vars."""
        if not self._persist_to_redis:
            return
        import os
        from api.redis_client import redis_client

        if redis_client:
            try:
                raw_data = redis_client.get(REDIS_PROXY_POOL_KEY)
                if isinstance(raw_data, bytes):
                    raw_data = raw_data.decode("utf-8")
                if raw_data:
                    entries_list = json.loads(raw_data)
                    loaded: list[ProxyEntry] = []
                    for item in entries_list:
                        if isinstance(item, dict) and item.get("url"):
                            loaded.append(ProxyEntry.from_dict(item))
                        elif isinstance(item, str):
                            norm = normalize_proxy(item)
                            if norm:
                                loaded.append(ProxyEntry(url=norm, raw=item))
                    if loaded:
                        self._entries = loaded
                        logger.info("Loaded %d proxies from Redis pool", len(self._entries))
                        return
            except Exception as exc:
                logger.warning("Failed to load proxy pool from Redis: %s", exc)

            # Check if legacy single proxy is stored in Redis
            try:
                single = redis_client.get(REDIS_SINGLE_PROXY_KEY)
                if isinstance(single, bytes):
                    single = single.decode("utf-8")
                if single:
                    norm = normalize_proxy(single)
                    if norm:
                        self._entries = [ProxyEntry(url=norm, raw=single)]
                        logger.info("Imported single proxy from Redis: %s", mask_proxy(norm))
                        return
            except Exception:
                pass

        # Fallback to environment variables
        env_proxies = os.environ.get("TERABOX_OUTBOUND_PROXIES")
        if env_proxies:
            self.set_proxies(env_proxies)
        else:
            single_env = (
                os.environ.get("TERABOX_OUTBOUND_PROXY")
                or os.environ.get("OUTBOUND_PROXY")
                or os.environ.get("HTTPS_PROXY")
                or os.environ.get("HTTP_PROXY")
            )
            if single_env:
                norm = normalize_proxy(single_env)
                if norm:
                    self._entries = [ProxyEntry(url=norm, raw=single_env)]
                    logger.info("Configured default proxy from env: %s", mask_proxy(norm))

    def save_to_redis(self) -> None:
        """Persist current proxy pool state to Redis."""
        if not self._persist_to_redis:
            return
        from api.redis_client import redis_client
        if not redis_client:
            return
        try:
            payload = json.dumps([e.serialize_for_redis() for e in self._entries])
            redis_client.set(REDIS_PROXY_POOL_KEY, payload)
            # Also keep single proxy key in sync for backwards compatibility
            if self._entries:
                redis_client.set(REDIS_SINGLE_PROXY_KEY, self._entries[0].url)
            else:
                redis_client.delete(REDIS_SINGLE_PROXY_KEY)
        except Exception as exc:
            logger.warning("Failed to persist proxy pool to Redis: %s", exc)

    async def close_all(self) -> None:
        """Close all cached HTTP clients on shutdown."""
        for client in self._clients.values():
            try:
                if not client.is_closed:
                    await client.aclose()
            except Exception:
                pass
        self._clients.clear()
        self._client_loops.clear()


# Global Singleton Instance
proxy_manager = ProxyPoolManager()
