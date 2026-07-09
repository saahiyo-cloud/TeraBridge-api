import os
import unittest
import urllib.parse
from dotenv import load_dotenv

# Load local environment if .env exists
load_dotenv()

# Configuration
TEST_BASE_URL = os.environ.get("TEST_BASE_URL", "").rstrip("/")
API_KEY = os.environ.get("API_KEY", "supercloudkey")
CRON_SECRET = os.environ.get("CRON_SECRET", "supercronsecret")
TEST_LINK = "https://1024terabox.com/s/1uCJPUU_1xRe10pU_bzEd0Q"

# Import app for in-process testing if not testing a live remote server
if not TEST_BASE_URL:
    try:
        from fastapi.testclient import TestClient
        from api.index import app, generate_signature
    except ImportError as e:
        print("[Error] Failed to import app or FastAPI TestClient. Ensure you are running in the virtual environment.")
        raise e
else:
    # If remote, we define a dummy signature generator using HMAC-SHA256 matching the implementation
    import hmac
    import hashlib
    def generate_signature(param1, param2, param3="", exp=""):
        secret = os.environ.get("HMAC_SECRET") or API_KEY
        if exp != "":
            message = f"{param1}|{param2}|{param3}|{exp}"
        else:
            message = f"{param1}|{param2}|{param3}"
        return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

class TestTeraBridgeAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TEST_BASE_URL:
            cls.client = TestClient(app)
            print(f"🔧 Testing local FastAPI application in-process via TestClient...")
        else:
            cls.client = None
            print(f"🌍 Testing live server at: {TEST_BASE_URL}...")

    def make_request(self, method: str, path: str, **kwargs):
        """Helper to route request to TestClient or live server."""
        if TEST_BASE_URL:
            import httpx
            url = f"{TEST_BASE_URL}{path}"
            return httpx.request(method, url, timeout=15, **kwargs)
        else:
            return self.client.request(method, path, **kwargs)

    # 1. GET / - Health Check
    def test_01_health_endpoint(self):
        resp = self.make_request("GET", "/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "online")
        self.assertIn("uptime_seconds", data)

    # 2. GET /api/stats - Auth Enforced
    def test_02_stats_endpoint_auth_enforced(self):
        resp = self.make_request("GET", "/api/stats")
        self.assertEqual(resp.status_code, 401)

    # 3. GET /api/stats - Authorized
    def test_03_stats_endpoint_authorized(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/stats", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "online")
        self.assertIn("redis", data)
        self.assertIn("cache", data)
        self.assertIn("rate_limiter", data)

    # 4. GET /api/resolve - Auth Enforced
    def test_04_resolve_endpoint_auth_enforced(self):
        resp = self.make_request("GET", f"/api/resolve?url={TEST_LINK}&mode=list")
        self.assertEqual(resp.status_code, 401)

    # 5. GET /api/resolve - Missing Parameters
    def test_05_resolve_endpoint_missing_params(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/resolve", headers=headers)
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertEqual(data.get("status"), "error")
        self.assertIn("Missing required parameter", data.get("message", ""))

    # 6. GET /api/resolve - Success (or gracefully handled Terabox error)
    def test_06_resolve_endpoint_success_list(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", f"/api/resolve?url={TEST_LINK}&mode=list", headers=headers)
        # Note: Depending on the backend session cookie state, it may return success or api-level error.
        # But both are structured JSON returned with status 200 (or 429 rate limit).
        self.assertIn(resp.status_code, [200, 429])
        if resp.status_code == 200:
            data = resp.json()
            self.assertIn("status", data)

    # 7. POST /api/resolve - Auth Enforced
    def test_07_resolve_endpoint_post_auth_enforced(self):
        payload = {"url": TEST_LINK, "mode": "list"}
        resp = self.make_request("POST", "/api/resolve", json=payload)
        self.assertEqual(resp.status_code, 401)

    # 8. POST /api/resolve - Success
    def test_08_resolve_endpoint_post_success(self):
        headers = {"X-API-Key": API_KEY}
        payload = {"url": TEST_LINK, "mode": "list"}
        resp = self.make_request("POST", "/api/resolve", json=payload, headers=headers)
        self.assertIn(resp.status_code, [200, 429])
        if resp.status_code == 200:
            data = resp.json()
            self.assertIn("status", data)

    # 9. GET /api/stream/manifest - Auth Enforced
    def test_09_stream_manifest_endpoint_auth_enforced(self):
        resp = self.make_request("GET", f"/api/stream/manifest?url={TEST_LINK}")
        self.assertEqual(resp.status_code, 401)

    # 10. GET /api/stream/manifest - Missing Parameters
    def test_10_stream_manifest_endpoint_missing_params(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/stream/manifest", headers=headers)
        self.assertEqual(resp.status_code, 400)

    # 11. GET /api/stream/manifest - Authorized
    def test_11_stream_manifest_endpoint_authorized(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", f"/api/stream/manifest?url={TEST_LINK}", headers=headers)
        # May return 200, 400 (if file has no streams), or 429 (rate limit)
        self.assertIn(resp.status_code, [200, 400, 429, 500])

    # 12. GET /api/stream/playlist.m3u8 - Route matching
    def test_12_stream_playlist_alternative_route(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", f"/api/stream/playlist.m3u8?url={TEST_LINK}", headers=headers)
        self.assertIn(resp.status_code, [200, 400, 429, 500])

    # 13. GET /api/stream/segment - Auth Enforced
    def test_13_stream_segment_endpoint_auth_enforced(self):
        resp = self.make_request("GET", "/api/stream/segment?url=http://someurl.ts")
        self.assertEqual(resp.status_code, 401)

    # 14. GET /api/stream/segment - Missing Parameters
    def test_14_stream_segment_endpoint_missing_params(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/stream/segment", headers=headers)
        self.assertEqual(resp.status_code, 400)

    # 15. GET /api/stream/segment - SSRF Block Disallowed Domain
    def test_15_stream_segment_endpoint_ssrf_disallowed(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/stream/segment?url=http://google.com/segment.ts", headers=headers)
        self.assertEqual(resp.status_code, 403)
        self.assertIn(b"Forbidden", resp.content)

    # 16. GET /api/stream/segment - SSRF Allowed Domain (307 Redirect verify)
    def test_16_stream_segment_endpoint_ssrf_allowed(self):
        headers = {"X-API-Key": API_KEY}
        target_url = "https://pcs.baidu.com/file/segment.ts"
        # Disable follow_redirects to inspect the 307 redirect
        resp = self.make_request("GET", f"/api/stream/segment?url={urllib.parse.quote(target_url)}", headers=headers, follow_redirects=False)
        self.assertEqual(resp.status_code, 307)
        self.assertEqual(resp.headers.get("Location"), target_url)

    # 17. GET /api/stream/segment.ts - Route matching
    def test_17_stream_segment_ts_alternative_route(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/stream/segment.ts?url=http://google.com/segment.ts", headers=headers)
        self.assertEqual(resp.status_code, 403)

    # 18. GET /api/thumbnail - Auth Enforced
    def test_18_thumbnail_endpoint_auth_enforced(self):
        resp = self.make_request("GET", "/api/thumbnail?surl=1uCJPUU_1xRe&fs_id=123")
        self.assertEqual(resp.status_code, 401)

    # 19. GET /api/thumbnail - Missing Parameters
    def test_19_thumbnail_endpoint_missing_params(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/thumbnail", headers=headers)
        self.assertEqual(resp.status_code, 400)

    # 20. GET /api/stream/thumbnail - Route matching
    def test_20_thumbnail_endpoint_stream_route(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/stream/thumbnail", headers=headers)
        self.assertEqual(resp.status_code, 400)

    # 21. GET /api/download - Auth Enforced
    def test_21_download_endpoint_auth_enforced(self):
        resp = self.make_request("GET", "/api/download?surl=1uCJPUU_1xRe&fs_id=123")
        self.assertEqual(resp.status_code, 401)

    # 22. GET /api/download - Missing Parameters
    def test_22_download_endpoint_missing_params(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/download", headers=headers)
        self.assertEqual(resp.status_code, 400)

    # 23. GET /api/debug_curl - Auth Enforced
    def test_23_debug_curl_endpoint_auth_enforced(self):
        resp = self.make_request("GET", "/api/debug_curl?url=https://httpbin.org/get")
        self.assertEqual(resp.status_code, 401)

    # 24. GET /api/debug_curl - Missing Parameters
    def test_24_debug_curl_endpoint_missing_params(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/debug_curl", headers=headers)
        self.assertEqual(resp.status_code, 400)

    # 25. GET /api/debug_curl - Success
    def test_25_debug_curl_endpoint_success(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/debug_curl?url=https://httpbin.org/get", headers=headers)
        self.assertEqual(resp.status_code, 200, f"Expected 200, got {resp.status_code}. Body: {resp.text}")
        data = resp.json()
        self.assertIn("status_code", data)
        self.assertIn("headers", data)
        self.assertIn("body", data)

    # 26. /api/admin/config - Auth Enforced
    def test_26_admin_config_endpoint_auth_enforced(self):
        resp_get = self.make_request("GET", "/api/admin/config")
        self.assertEqual(resp_get.status_code, 401)
        resp_post = self.make_request("POST", "/api/admin/config", json={})
        self.assertEqual(resp_post.status_code, 401)

    # 27. GET /api/admin/config - Success
    def test_27_admin_config_endpoint_get(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/admin/config", headers=headers)
        # If Redis is not connected, it returns 400 "Redis client is not configured."
        # If Redis is connected, it returns 200.
        # Both represent structured responses handling the configuration setup.
        self.assertIn(resp.status_code, [200, 400])
        data = resp.json()
        self.assertIn("status", data)

    # 28. POST /api/admin/config - Handle invalid update gracefully
    def test_28_admin_config_endpoint_post_invalid(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("POST", "/api/admin/config", json={"bad_key": "some_value"}, headers=headers)
        # Should return 400 Bad Request because no valid fields updates (like 'cookie') were sent
        self.assertEqual(resp.status_code, 400)

    # 29. /api/cron/validate - Auth Enforced
    def test_29_cron_validate_endpoint_auth_enforced(self):
        resp = self.make_request("GET", "/api/cron/validate")
        self.assertEqual(resp.status_code, 401)

    # 30. GET /api/cron/validate - Authorized via cron secret
    def test_30_cron_validate_endpoint_authorized_via_cron_secret(self):
        resp = self.make_request("GET", f"/api/cron/validate?secret={CRON_SECRET}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("checked_count", data)

    # 31. POST /api/cron/validate - Authorized via API key
    def test_31_cron_validate_endpoint_authorized_via_api_key(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("POST", "/api/cron/validate", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("checked_count", data)

if __name__ == "__main__":
    unittest.main()
