"""
Tests for the production-readiness fixes: shared rate limiting behind Cloudflare,
header-only API keys, local input validation, and security headers.

Runs in-process (no network, Redis replaced by an in-process fake).
"""
import asyncio
import os
import time
import unittest
from unittest.mock import AsyncMock, patch

os.environ.setdefault("API_KEY", "supercloudkey")
# Never touch a real Redis from these tests (must be set before api.* is imported).
os.environ["UPSTASH_REDIS_REST_URL"] = ""
os.environ["UPSTASH_REDIS_REST_TOKEN"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from api.config import API_KEY  # noqa: E402
from api.index import app  # noqa: E402
from api.rate_limiter import RateLimiter  # noqa: E402
import api.rate_limiter as rl_module  # noqa: E402

PEER = ("10.0.0.5", 50000)  # private peer => trusted proxy
GOOD_LINK = "https://1024terabox.com/s/1WmWHnGmI-7I41MIPI7XgMg"


class FakeRedis:
    """Minimal sorted-set/str Redis double supporting the calls the limiter makes (sync + async)."""

    def __init__(self):
        self.z: dict[str, dict[str, float]] = {}
        self.kv: dict[str, int] = {}

    class _Pipe:
        def __init__(self, parent):
            self.p, self.ops = parent, []

        def zremrangebyscore(self, k, lo, hi):
            self.ops.append(("zrem", k, lo, hi))

        def zcard(self, k):
            self.ops.append(("zcard", k))

        def zadd(self, k, m):
            self.ops.append(("zadd", k, m))

        def expire(self, k, s):
            self.ops.append(("expire", k))

        def exec(self):
            out = []
            for op in self.ops:
                if op[0] == "zrem":
                    d = self.p.z.setdefault(op[1], {})
                    for m in [m for m, s in d.items() if op[2] <= s <= op[3]]:
                        del d[m]
                    out.append(0)
                elif op[0] == "zcard":
                    out.append(len(self.p.z.get(op[1], {})))
                elif op[0] == "zadd":
                    self.p.z.setdefault(op[1], {}).update(op[2])
                    out.append(1)
                else:
                    out.append(1)
            return out

    def pipeline(self):
        return FakeRedis._Pipe(self)

    def incr(self, k):
        self.kv[k] = self.kv.get(k, 0) + 1
        return self.kv[k]

    def get(self, k):
        return self.kv.get(k)

    def expire(self, k, s):
        return 1


class FakeAsyncRedis(FakeRedis):
    class _APipe(FakeRedis._Pipe):
        async def exec(self):
            return FakeRedis._Pipe.exec(self)

    def pipeline(self):
        return FakeAsyncRedis._APipe(self)

    async def incr(self, k):
        return FakeRedis.incr(self, k)

    async def get(self, k):
        return FakeRedis.get(self, k)

    async def expire(self, k, s):
        return 1


def _cf_headers(edge_ip: str, client: str = "203.0.113.9") -> dict:
    """Headers Cloudflare + a platform proxy would produce; only the edge node varies."""
    return {
        "X-Forwarded-For": f"{client}, {edge_ip}",
        "CF-Connecting-IP": client,
        "X-API-Key": API_KEY,
    }


EDGES = ["172.69.10.1", "162.158.5.7", "104.23.200.4", "108.162.200.9", "172.70.1.1"]


class TestClientIpBehindCloudflare(unittest.TestCase):
    def _req(self, headers):
        from starlette.requests import Request

        scope = {
            "type": "http", "method": "GET", "path": "/", "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "client": PEER, "server": ("x", 80), "scheme": "http",
        }
        return Request(scope)

    def test_same_client_same_ip_across_edge_nodes(self):
        from api.middleware import client_ip

        ips = {client_ip(self._req(_cf_headers(e))) for e in EDGES}
        self.assertEqual(ips, {"203.0.113.9"})

    def test_xff_only_skips_cloudflare_edge(self):
        from api.middleware import client_ip

        ips = {
            client_ip(self._req({"X-Forwarded-For": f"203.0.113.9, {e}"})) for e in EDGES
        }
        self.assertEqual(ips, {"203.0.113.9"})

    def test_peer_rewritten_to_edge_by_uvicorn_proxy_headers(self):
        """uvicorn --proxy-headers replaces the peer with the last XFF hop (the edge)."""
        from api.middleware import client_ip

        ips = set()
        for e in EDGES:
            req = self._req(_cf_headers(e))
            req.scope["client"] = (e, 0)
            ips.add(client_ip(req))
        self.assertEqual(ips, {"203.0.113.9"})

    def test_forged_cf_header_ignored_without_cloudflare_hop(self):
        from api.middleware import client_ip

        got = client_ip(self._req({"X-Forwarded-For": "198.51.100.7", "CF-Connecting-IP": "1.2.3.4"}))
        self.assertEqual(got, "198.51.100.7")


class TestSharedRateLimit(unittest.TestCase):
    def test_limit_shared_across_workers_with_redis(self):
        shared = FakeAsyncRedis()
        workers = [RateLimiter(max_requests=30, window_seconds=60) for _ in range(4)]
        for w in workers:
            w._worker_count = 4

        async def run():
            results = []
            with patch("api.redis_client.async_redis_client", shared):
                for i in range(40):
                    results.append(await workers[i % 4].is_allowed_async("203.0.113.9"))
            return results

        results = asyncio.run(run())
        self.assertEqual(sum(results), 30)
        self.assertFalse(any(results[30:]))

    def test_in_memory_fallback_divides_budget_even_if_redis_configured_but_down(self):
        w = RateLimiter(max_requests=30, window_seconds=60, redis=object())
        w._worker_count = 3
        self.assertEqual(w._get_effective_max(), 10)

    def test_api_returns_429_with_headers_and_recovers(self):
        fake = FakeAsyncRedis()
        clock = [1_000_000.0]
        # Peer = edge node, as after uvicorn's proxy-headers rewrite.
        clients = [TestClient(app, client=(e, 0)) for e in EDGES]
        # A bogus mode returns 400 locally (no upstream) but still consumes quota.
        url = "/api/resolve?url=" + GOOD_LINK + "&mode=bogus"
        with patch("api.redis_client.async_redis_client", fake), \
                patch.object(rl_module.time, "time", lambda: clock[0]), \
                patch.object(rl_module.rate_limiter, "_redis", None):
            codes = []
            for i in range(31):
                client = clients[i % len(EDGES)]
                r = client.get(url, headers=_cf_headers(EDGES[i % len(EDGES)]))
                codes.append(r.status_code)
                clock[0] += 0.5
            self.assertEqual(codes[:30], [400] * 30)
            self.assertEqual(codes[30], 429)
            self.assertIn("Retry-After", r.headers)
            self.assertEqual(r.headers["X-RateLimit-Limit"], "30")
            self.assertEqual(r.headers["X-RateLimit-Remaining"], "0")
            self.assertIn("X-RateLimit-Reset", r.headers)
            self.assertEqual(r.json()["status"], "error")
            # Window passes -> recovered
            clock[0] += 61
            r2 = clients[0].get(url, headers=_cf_headers(EDGES[0]))
            self.assertEqual(r2.status_code, 400)


class TestHeaderOnlyAuth(unittest.TestCase):
    def setUp(self):
        self.c = TestClient(app, client=("10.0.0.6", 1))
        self.q = "&mode=bogus"  # would 400 if authenticated, 401 otherwise

    def test_query_and_body_keys_rejected(self):
        for qs in (f"key={API_KEY}", f"api_key={API_KEY}"):
            r = self.c.get(f"/api/resolve?url={GOOD_LINK}{self.q}&{qs}")
            self.assertEqual(r.status_code, 401, qs)
        r = self.c.post("/api/resolve", json={"url": GOOD_LINK, "mode": "bogus", "key": API_KEY})
        self.assertEqual(r.status_code, 401)
        r = self.c.get(f"/api/stats?key={API_KEY}")
        self.assertEqual(r.status_code, 401)

    def test_header_and_bearer_still_work(self):
        r = self.c.get(f"/api/resolve?url={GOOD_LINK}{self.q}", headers={"X-API-Key": API_KEY})
        self.assertEqual(r.status_code, 400)
        r = self.c.get(f"/api/resolve?url={GOOD_LINK}{self.q}", headers={"Authorization": f"Bearer {API_KEY}"})
        self.assertEqual(r.status_code, 400)

    def test_cookie_not_accepted_on_public_api(self):
        self.c.cookies.set("terabridge_admin_key", API_KEY)
        r = self.c.get(f"/api/resolve?url={GOOD_LINK}{self.q}")
        self.assertEqual(r.status_code, 401)

    def test_dashboard_login_flow(self):
        c = TestClient(app, client=("10.0.0.7", 1))
        # key in URL no longer unlocks
        self.assertIn("Unlock Dashboard", c.get(f"/admin?key={API_KEY}").text)
        bad = c.post("/admin/login", data={"key": "wrong"}, follow_redirects=False)
        self.assertEqual(bad.status_code, 401)
        ok = c.post("/admin/login", data={"key": API_KEY}, follow_redirects=False)
        self.assertEqual(ok.status_code, 303)
        sc = ok.headers["set-cookie"].lower()
        self.assertIn("httponly", sc)
        self.assertIn("samesite=strict", sc)
        self.assertNotIn(API_KEY, ok.headers["location"])
        page = c.get("/admin")
        self.assertNotIn("Unlock Dashboard", page.text)
        # the cookie also authorises the admin API (what the dashboard JS relies on)
        self.assertEqual(c.get("/api/stats").status_code, 200)

    def test_signed_url_flow_independent_of_api_key(self):
        from api.signing import generate_signature

        url = "https://evil.example.com/t.jpg"
        exp = str(int(time.time()) + 600)
        sig = generate_signature(url, "", "", exp)
        c = TestClient(app, client=("10.0.0.8", 1))
        q = f"/api/thumbnail?url={url}"
        # valid signature passes auth (then fails the host allow-list: 403, not 401)
        self.assertEqual(c.get(f"{q}&sig={sig}&exp={exp}").status_code, 403)
        self.assertEqual(c.get(f"{q}&sig=bad&exp={exp}").status_code, 401)
        self.assertEqual(c.get(f"{q}&key={API_KEY}").status_code, 401)


class TestInputValidation(unittest.TestCase):
    def setUp(self):
        self.c = TestClient(app, client=("10.0.0.9", 1))
        self.h = {"X-API-Key": API_KEY}
        self.p = patch("api.routes.resolve.resolve_link", new=AsyncMock(side_effect=AssertionError("upstream called")))
        self.mock = self.p.start()
        self.addCleanup(self.p.stop)
        self.addCleanup(lambda: self.assertEqual(self.mock.call_count, 0))

    def _assert_clean(self, r, code):
        self.assertEqual(r.status_code, code)
        body = r.json()
        self.assertEqual(body["status"], "error")
        self.assertIn("message", body)
        self.assertNotIn("parse_surl", body["message"])
        self.assertNotIn("request_id", body["message"])

    def test_bogus_mode(self):
        self._assert_clean(self.c.get(f"/api/resolve?url={GOOD_LINK}&mode=bogus", headers=self.h), 400)

    def test_junk_links(self):
        for junk in ("notalink", "%20", "abc$%^&", "short"):
            self._assert_clean(self.c.get(f"/api/resolve?url={junk}&mode=list", headers=self.h), 400)

    def test_oversized_url(self):
        self._assert_clean(self.c.get("/api/resolve?url=" + "a" * 3000, headers=self.h), 413)
        r = self.c.post("/api/resolve", json={"url": "a" * 3000}, headers=self.h)
        self._assert_clean(r, 413)

    def test_invalid_json(self):
        r = self.c.post("/api/resolve", content=b"{not json", headers={**self.h, "Content-Type": "application/json"})
        self._assert_clean(r, 400)
        self.assertIn("Invalid JSON", r.json()["message"])
        r = self.c.post("/api/resolve", content=b"[1,2]", headers={**self.h, "Content-Type": "application/json"})
        self._assert_clean(r, 400)

    def test_valid_request_reaches_resolver(self):
        self.mock.side_effect = None
        self.mock.return_value = {"errno": -3, "error": "x"}
        self.c.get(f"/api/resolve?url={GOOD_LINK}&mode=list", headers=self.h)
        self.assertEqual(self.mock.call_count, 1)
        self.mock.reset_mock()  # keep cleanup assertion satisfied


class TestSecurityHeaders(unittest.TestCase):
    NEEDED = ("x-content-type-options", "referrer-policy", "x-frame-options")

    def test_headers_on_api_dashboard_and_errors(self):
        c = TestClient(app, client=("10.0.0.10", 1))
        for path in ("/", "/admin", "/api/resolve", "/nope"):
            r = c.get(path)
            for h in self.NEEDED:
                self.assertIn(h, r.headers, f"{h} on {path}")
            self.assertEqual(r.headers["x-content-type-options"], "nosniff")
            self.assertNotIn("strict-transport-security", r.headers)

    def test_hsts_only_when_https_via_trusted_proxy(self):
        c = TestClient(app, client=("10.0.0.10", 1))
        self.assertIn("strict-transport-security", c.get("/", headers={"X-Forwarded-Proto": "https"}).headers)
        # untrusted peer cannot claim https
        c2 = TestClient(app, client=("198.51.100.20", 1))
        self.assertNotIn("strict-transport-security", c2.get("/", headers={"X-Forwarded-Proto": "https"}).headers)

    def test_healthz_trimmed(self):
        c = TestClient(app, client=("10.0.0.10", 1))
        self.assertEqual(set(c.get("/healthz").json()), {"status", "service"})
        self.assertEqual(set(c.get("/api/health").json()), {"status", "service"})


if __name__ == "__main__":
    unittest.main()
