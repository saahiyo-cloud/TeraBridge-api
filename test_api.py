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
TEST_LINK = os.environ.get("TEST_LINK", "https://terabox.com/s/1sample-video-test-doc")

# Import app for in-process testing if not testing a live remote server
if not TEST_BASE_URL:
    try:
        from fastapi.testclient import TestClient
        from api.index import app
        from api.signing import generate_signature
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
            # Prevent local unit test suites from overwriting production Redis proxy pool and event logs
            from api.proxy_manager import proxy_manager
            proxy_manager._persist_to_redis = False
            try:
                from api import metrics
                metrics.redis_client = None
            except Exception:
                pass
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
        # But both are structured JSON returned with status 200, 400 (expired share), or 429 rate limit.
        self.assertIn(resp.status_code, [200, 400, 429])
        if resp.status_code in (200, 400):
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
        self.assertIn(resp.status_code, [200, 400, 429])
        if resp.status_code in (200, 400):
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

    # 32. SSRF Protection - /api/thumbnail rejects private and untrusted hosts
    def test_32_ssrf_thumbnail_rejected_for_untrusted_host(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/thumbnail?url=http://169.254.169.254/latest/meta-data", headers=headers)
        self.assertEqual(resp.status_code, 403)
        resp2 = self.make_request("GET", "/api/thumbnail?url=https://attacker-controlled-site.com/avatar.jpg", headers=headers)
        self.assertEqual(resp2.status_code, 403)

    # 33. SSRF Protection - /api/debug_curl rejects loopback & private networks
    def test_33_ssrf_debug_curl_rejected_for_private_ip(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/debug_curl?url=http://127.0.0.1:6379/info", headers=headers)
        self.assertEqual(resp.status_code, 403)
        resp2 = self.make_request("GET", "/api/debug_curl?url=http://169.254.169.254/latest/meta-data", headers=headers)
        self.assertEqual(resp2.status_code, 403)

    # 34. SSRF Protection - /api/stream/segment rejects loopback & metadata IPs
    def test_34_ssrf_segment_rejected_for_metadata(self):
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/stream/segment?url=http://169.254.169.254/secret.ts", headers=headers)
        self.assertEqual(resp.status_code, 403)

    # 35. Admin Dashboard - /admin and /dashboard serve HTML
    def test_35_dashboard_html_served(self):
        resp = self.make_request("GET", "/admin")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers.get("content-type", ""))
        self.assertIn("TeraBridge", resp.text)
        self.assertIn("Cloudvids", resp.text)

    # 36. /api/admin/storage/quota - Auth Enforced & Structure
    def test_36_storage_quota_endpoint(self):
        # 401 without auth
        resp_unauth = self.make_request("GET", "/api/admin/storage/quota")
        self.assertEqual(resp_unauth.status_code, 401)
        # 200 with auth
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/admin/storage/quota", headers=headers)
        self.assertIn(resp.status_code, [200, 400])
        if resp.status_code == 200:
            data = resp.json()
            self.assertEqual(data.get("status"), "success")
            self.assertIn("total_bytes", data)
            self.assertIn("used_bytes", data)

    # 37. /api/admin/cloudvids (GET) - Auth Enforced & List
    def test_37_cloudvids_list_endpoint(self):
        # 401 without auth
        resp_unauth = self.make_request("GET", "/api/admin/cloudvids")
        self.assertEqual(resp_unauth.status_code, 401)
        # 200 with auth
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/admin/cloudvids", headers=headers)
        self.assertIn(resp.status_code, [200, 400])
        if resp.status_code == 200:
            data = resp.json()
            self.assertEqual(data.get("status"), "success")
            self.assertIn("files", data)

    # 38. /api/admin/cloudvids (DELETE) - Auth & Validation
    def test_38_cloudvids_delete_validation(self):
        # 401 without auth
        resp_unauth = self.make_request("DELETE", "/api/admin/cloudvids", json={"paths": ["/cloudvids/test.mp4"]})
        self.assertEqual(resp_unauth.status_code, 401)
        # 400 when missing paths
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("DELETE", "/api/admin/cloudvids", json={}, headers=headers)
        self.assertEqual(resp.status_code, 400)
        # 400 when path outside /cloudvids is given
        resp_outside = self.make_request("DELETE", "/api/admin/cloudvids", json={"paths": ["/root/malicious.mp4"]}, headers=headers)
        self.assertEqual(resp_outside.status_code, 400)

    # 39. Smart Multi-Proxy Normalization & Round-Robin Rotation
    def test_39_proxy_normalization_and_rotation(self):
        from api.proxy_manager import normalize_proxy, mask_proxy, ProxyPoolManager
        
        # Test Webshare IP:PORT:USER:PASS format
        norm1 = normalize_proxy("64.137.96.74:6641:aiepavhe:6vonlhzxrt8y")
        self.assertEqual(norm1, "http://aiepavhe:6vonlhzxrt8y@64.137.96.74:6641")
        
        # Test standard URL format
        norm2 = normalize_proxy("http://user:pass@198.23.243.226:6361")
        self.assertEqual(norm2, "http://user:pass@198.23.243.226:6361")
        
        # Test mask
        masked = mask_proxy(norm1)
        self.assertEqual(masked, "http://aiepavhe:***@64.137.96.74:6641")
        
        # Test pool rotation
        pool = ProxyPoolManager(persist_to_redis=False)
        pool.set_proxies([
            "64.137.96.74:6641:aiepavhe:6vonlhzxrt8y",
            "198.23.243.226:6361:aiepavhe:6vonlhzxrt8y",
            "38.154.185.97:6370:aiepavhe:6vonlhzxrt8y",
        ])
        self.assertEqual(pool.get_total_count(), 3)
        self.assertEqual(pool.get_healthy_count(), 3)
        
        p1 = pool.get_next_proxy()
        p2 = pool.get_next_proxy()
        p3 = pool.get_next_proxy()
        p4 = pool.get_next_proxy()
        
        self.assertEqual(p1.url, "http://aiepavhe:6vonlhzxrt8y@64.137.96.74:6641")
        self.assertEqual(p2.url, "http://aiepavhe:6vonlhzxrt8y@198.23.243.226:6361")
        self.assertEqual(p3.url, "http://aiepavhe:6vonlhzxrt8y@38.154.185.97:6370")
        self.assertEqual(p4.url, p1.url)  # Round-robin wrapped around

    # 40. /api/admin/config Proxy Pool Endpoints
    def test_40_proxy_pool_admin_endpoints(self):
        headers = {"X-API-Key": API_KEY}
        
        # Set pool via POST
        proxies_payload = {
            "outbound_proxies": "64.137.96.74:6641:aiepavhe:6vonlhzxrt8y\n198.23.243.226:6361:aiepavhe:6vonlhzxrt8y"
        }
        resp = self.make_request("POST", "/api/admin/config", json=proxies_payload, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("proxy_pool", data)
        self.assertEqual(data["proxy_pool"]["total"], 2)
        
        # Verify via GET
        resp_get = self.make_request("GET", "/api/admin/config", headers=headers)
        self.assertEqual(resp_get.status_code, 200)
        get_data = resp_get.json()
        self.assertIn("proxy_pool", get_data)
        self.assertEqual(get_data["proxy_pool"]["total"], 2)
        self.assertEqual(get_data["proxy_pool"]["healthy"], 2)
        
        # Clear pool
        resp_clear = self.make_request("POST", "/api/admin/config", json={"action": "clear_proxies"}, headers=headers)
        self.assertEqual(resp_clear.status_code, 200)
        clear_data = resp_clear.json()
        self.assertEqual(clear_data["proxy_pool"]["total"], 0)

    # 41. Proxy Auto-Quarantine Cooldown Logic
    def test_41_proxy_quarantine_cooldown(self):
        from api.proxy_manager import ProxyPoolManager
        import time
        
        pool = ProxyPoolManager(persist_to_redis=False)
        pool.set_proxies(["http://user:pass@1.2.3.4:8080", "http://user:pass@5.6.7.8:8080"])
        
        # Quarantine the first proxy
        pool.mark_failure("http://user:pass@1.2.3.4:8080", reason="TeraBox WAF verify 400141", cooldown_seconds=60)
        
        self.assertEqual(pool.get_total_count(), 2)
        self.assertEqual(pool.get_healthy_count(), 1)
        
        # Next selections should ONLY pick the healthy proxy
        next_p = pool.get_next_proxy()
        self.assertEqual(next_p.url, "http://user:pass@5.6.7.8:8080")
        
        # Mark success restores health
        pool.mark_success("http://user:pass@1.2.3.4:8080")
        self.assertEqual(pool.get_healthy_count(), 2)


    # 42. Analytics & Monitoring API Endpoints
    def test_42_analytics_and_observability_endpoints(self):
        # 401 without auth
        resp_unauth = self.make_request("GET", "/api/admin/analytics")
        self.assertEqual(resp_unauth.status_code, 401)
        
        # 200 with auth
        headers = {"X-API-Key": API_KEY}
        resp = self.make_request("GET", "/api/admin/analytics", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "online")
        self.assertIn("system", data)
        self.assertIn("traffic", data)
        self.assertIn("cache", data)
        self.assertIn("proxies", data)
        self.assertIn("accounts", data)
        self.assertIn("events", data)
        
        # Verify /api/stats includes traffic telemetry
        resp_stats = self.make_request("GET", "/api/stats", headers=headers)
        self.assertEqual(resp_stats.status_code, 200)
        stats_data = resp_stats.json()
        self.assertIn("traffic", stats_data)

    # 43. GET /healthz and /api/health - Liveness & Readiness Probes
    def test_43_healthz_probes(self):
        resp1 = self.make_request("GET", "/healthz")
        self.assertEqual(resp1.status_code, 200)
        d1 = resp1.json()
        self.assertEqual(d1.get("status"), "healthy")
        self.assertEqual(d1.get("service"), "terabridge-api")
        self.assertIn("proxies", d1)
        self.assertIn("redis", d1)

        resp2 = self.make_request("GET", "/api/health")
        self.assertEqual(resp2.status_code, 200)
        d2 = resp2.json()
        self.assertEqual(d2.get("status"), "healthy")

    # 44. Strict HMAC Verification - Reject Legacy Un-expiring Signatures
    def test_44_legacy_unexpiring_signatures_rejected(self):
        from api.signing import verify_signature, generate_signature
        # Legacy signature with empty exp
        legacy_sig = generate_signature("surl_test", "12345", "", "")
        # Must be rejected when ALLOW_LEGACY_SIGNATURES is false (default)
        self.assertFalse(verify_signature("surl_test", "12345", "", legacy_sig, exp=""))

    # 45. Stream Route Helpers - Negative Bounds Protection
    def test_45_pick_file_negative_bounds(self):
        from api.routes.stream import _pick_file
        files = [{"fs_id": "1", "filename": "video.mp4"}]
        # Positive in-bounds
        self.assertIsNotNone(_pick_file(files, "", 0))
        # Negative index must not access backwards from list
        self.assertIsNone(_pick_file(files, "", -1))
        # Out-of-bounds positive
        self.assertIsNone(_pick_file(files, "", 5))

    # 46. Range Header Parsing RFC Compliance
    def test_46_range_header_parsing_rfc_compliance(self):
        from api.routes.download import parse_byte_range
        total_size = 1000

        # Normal ranges
        res = parse_byte_range("bytes=0-499", total_size)
        self.assertEqual(res, (0, 499, 206))

        res = parse_byte_range("bytes=500-", total_size)
        self.assertEqual(res, (500, 999, 206))

        # Suffix range (RFC 9110: last 200 bytes)
        res = parse_byte_range("bytes=-200", total_size)
        self.assertEqual(res, (800, 999, 206))

        # Clamping end to file_size - 1
        res = parse_byte_range("bytes=0-50000", total_size)
        self.assertEqual(res, (0, 999, 206))

        # Unsatisfiable ranges -> return None (HTTP 416)
        res_oob = parse_byte_range("bytes=1500-", total_size)
        self.assertIsNone(res_oob)

        res_inv = parse_byte_range("bytes=500-200", total_size)
        self.assertIsNone(res_inv)

        res_zero_sfx = parse_byte_range("bytes=-0", total_size)
        self.assertIsNone(res_zero_sfx)

    # 47. Cloudvids Storage Janitor Endpoint
    def test_47_cloudvids_cleanup_endpoint(self):
        # Auth check
        resp_unauth = self.make_request("POST", "/api/admin/cloudvids/cleanup")
        self.assertEqual(resp_unauth.status_code, 401)

        # Authorized check
        headers = {"X-API-Key": API_KEY}
        resp_auth = self.make_request("POST", "/api/admin/cloudvids/cleanup", headers=headers, json={"max_age_hours": 48})
        self.assertIn(resp_auth.status_code, (200, 400))
        data = resp_auth.json()
        self.assertIn("status", data)

    # 48. Safe JSON Loads Resilience
    def test_48_safe_json_loads_resilience(self):
        from api.account_pool import safe_json_loads
        # Trailing comma fix
        parsed = safe_json_loads('{"key": "value",}')
        self.assertEqual(parsed.get("key"), "value")

        # Malformed raw text returns empty dict without throwing
        self.assertEqual(safe_json_loads("not json at all"), {})
        self.assertEqual(safe_json_loads(None), {})
        self.assertEqual(safe_json_loads(b"bad bytes"), {})


if __name__ == "__main__":
    unittest.main()
