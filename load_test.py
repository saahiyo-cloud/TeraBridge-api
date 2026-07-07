"""
TeraBridge API — High-Load Test Suite
======================================
Simulates concurrent users hitting the API endpoints and reports
latency percentiles, throughput, error rates, and failure details.

Usage:
    python load_test.py                          # test against localhost:5000 (default)
    python load_test.py --base-url https://your-vercel-deployment.vercel.app
    python load_test.py --concurrency 50 --requests 200
    python load_test.py --duration 60            # run for 60 seconds instead of fixed request count
"""

import argparse
import json
import statistics
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
except ImportError:
    print("'requests' is required.  pip install requests")
    sys.exit(1)

# Fix Windows console encoding for emoji output
if sys.platform == "win32" and sys.version_info >= (3, 7):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ── Test Configuration ───────────────────────────────────────────────

DEFAULT_BASE_URL = "http://127.0.0.1:5000"
TEST_LINK = "https://1024terabox.com/s/1uCJPUU_1xRe10pU_bzEd0Q"

def _update_test_link(new_link):
    global TEST_LINK
    TEST_LINK = new_link

# ── Data Structures ──────────────────────────────────────────────────

@dataclass
class RequestResult:
    endpoint: str
    status_code: int
    latency_ms: float
    success: bool
    error: Optional[str] = None
    response_size: int = 0

@dataclass
class TestMetrics:
    endpoint: str
    total_requests: int = 0
    successful: int = 0
    failed: int = 0
    latencies: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    status_codes: dict = field(default_factory=dict)
    total_bytes: int = 0

    def record(self, result: RequestResult):
        self.total_requests += 1
        self.latencies.append(result.latency_ms)
        self.status_codes[result.status_code] = self.status_codes.get(result.status_code, 0) + 1
        self.total_bytes += result.response_size
        if result.success:
            self.successful += 1
        else:
            self.failed += 1
            if result.error:
                self.errors.append(result.error[:120])

    def summary(self, wall_time_s: float) -> dict:
        if not self.latencies:
            return {"endpoint": self.endpoint, "total": 0, "message": "No requests recorded"}
        sorted_lat = sorted(self.latencies)
        return {
            "endpoint": self.endpoint,
            "total_requests": self.total_requests,
            "successful": self.successful,
            "failed": self.failed,
            "error_rate": f"{(self.failed / self.total_requests) * 100:.1f}%",
            "throughput_rps": round(self.total_requests / wall_time_s, 2) if wall_time_s > 0 else 0,
            "latency_ms": {
                "min": round(sorted_lat[0], 1),
                "avg": round(statistics.mean(sorted_lat), 1),
                "median": round(statistics.median(sorted_lat), 1),
                "p90": round(sorted_lat[int(len(sorted_lat) * 0.90)], 1),
                "p95": round(sorted_lat[int(len(sorted_lat) * 0.95)], 1),
                "p99": round(sorted_lat[min(int(len(sorted_lat) * 0.99), len(sorted_lat) - 1)], 1),
                "max": round(sorted_lat[-1], 1),
            },
            "total_data_mb": round(self.total_bytes / 1024 / 1024, 2),
            "status_codes": dict(sorted(self.status_codes.items())),
            "sample_errors": self.errors[:5],
        }

# ── HTTP Helpers ─────────────────────────────────────────────────────

API_KEY_HEADER = None

def make_request(session: requests.Session, method: str, url: str, **kwargs) -> RequestResult:
    if API_KEY_HEADER:
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        kwargs["headers"]["X-API-Key"] = API_KEY_HEADER
    endpoint = url.split("?")[0].split("/")[-1] or "/"
    start = time.perf_counter()
    try:
        resp = session.request(method, url, timeout=30, **kwargs)
        latency = (time.perf_counter() - start) * 1000
        body = resp.text
        is_success = resp.status_code == 200
        error_msg = None
        if not is_success:
            try:
                error_msg = resp.json().get("message", body[:200])
            except Exception:
                error_msg = body[:200]
        return RequestResult(
            endpoint=endpoint,
            status_code=resp.status_code,
            latency_ms=latency,
            success=is_success,
            error=error_msg,
            response_size=len(body.encode("utf-8", errors="replace")),
        )
    except requests.exceptions.Timeout:
        latency = (time.perf_counter() - start) * 1000
        return RequestResult(endpoint=endpoint, status_code=0, latency_ms=latency, success=False, error="TIMEOUT")
    except requests.exceptions.ConnectionError as e:
        latency = (time.perf_counter() - start) * 1000
        return RequestResult(endpoint=endpoint, status_code=0, latency_ms=latency, success=False, error=f"CONNECTION_ERROR: {e}")
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return RequestResult(endpoint=endpoint, status_code=0, latency_ms=latency, success=False, error=str(e)[:200])

# ── Test Scenarios ───────────────────────────────────────────────────

def test_health(session, base_url) -> RequestResult:
    """GET / — health/status check"""
    return make_request(session, "GET", f"{base_url}/")

def test_list(session, base_url) -> RequestResult:
    """GET /api/resolve?mode=list — list files from a share link"""
    url = f"{base_url}/api/resolve?url={TEST_LINK}&mode=list"
    return make_request(session, "GET", url)

def test_download_resolve(session, base_url) -> RequestResult:
    """GET /api/resolve?mode=download — resolve download link"""
    url = f"{base_url}/api/resolve?url={TEST_LINK}&mode=download"
    return make_request(session, "GET", url)

def test_stream_resolve(session, base_url) -> RequestResult:
    """GET /api/resolve?mode=stream — resolve HLS stream"""
    url = f"{base_url}/api/resolve?url={TEST_LINK}&mode=stream"
    return make_request(session, "GET", url)

def test_post_resolve(session, base_url) -> RequestResult:
    """POST /api/resolve — JSON body resolution"""
    url = f"{base_url}/api/resolve"
    payload = {"url": TEST_LINK, "mode": "list"}
    return make_request(session, "POST", url, json=payload)

def test_bad_request(session, base_url) -> RequestResult:
    """GET /api/resolve (no url) — should return 400"""
    result = make_request(session, "GET", f"{base_url}/api/resolve")
    # Invert success logic: we EXPECT 400
    result.success = result.status_code == 400
    return result

SCENARIOS = {
    "health":           test_health,
    "list":             test_list,
    "download":         test_download_resolve,
    "stream":           test_stream_resolve,
    "post_list":        test_post_resolve,
    "bad_request":      test_bad_request,
}

# ── Load Runner ──────────────────────────────────────────────────────

def print_progress(current, total, prefix="Progress"):
    bar_len = 40
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    pct = current / total * 100
    print(f"\r  {prefix} [{bar}] {pct:.0f}% ({current}/{total})", end="", flush=True)

def run_fixed_count_test(base_url, scenarios, concurrency, num_requests):
    """Fire a fixed number of requests across scenarios with N concurrent workers."""
    metrics = {name: TestMetrics(endpoint=name) for name in scenarios}
    lock = threading.Lock()
    completed = [0]

    # Build task list: distribute requests evenly across chosen scenarios
    tasks = []
    per_scenario = max(1, num_requests // len(scenarios))
    for name in scenarios:
        for _ in range(per_scenario):
            tasks.append(name)
    # Fill remainder
    while len(tasks) < num_requests:
        tasks.append(list(scenarios.keys())[len(tasks) % len(scenarios)])

    total = len(tasks)
    print(f"\n🚀 Launching {total} requests across {len(scenarios)} scenarios "
          f"with {concurrency} concurrent workers...\n")

    wall_start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        def worker(scenario_name):
            s = requests.Session()
            result = SCENARIOS[scenario_name](s, base_url)
            with lock:
                metrics[scenario_name].record(result)
                completed[0] += 1
                print_progress(completed[0], total)
            return result

        futures = [pool.submit(worker, t) for t in tasks]
        for f in as_completed(futures):
            f.result()  # propagate exceptions

    wall_time = time.perf_counter() - wall_start
    print()  # newline after progress bar
    return metrics, wall_time

def run_duration_test(base_url, scenarios, concurrency, duration_s):
    """Keep firing requests for a fixed duration."""
    metrics = {name: TestMetrics(endpoint=name) for name in scenarios}
    lock = threading.Lock()
    stop_event = threading.Event()
    completed = [0]

    scenario_names = list(scenarios.keys())

    print(f"\n🚀 Running sustained load for {duration_s}s across {len(scenarios)} scenarios "
          f"with {concurrency} concurrent workers...\n")

    wall_start = time.perf_counter()

    def worker(idx):
        s = requests.Session()
        round_robin = 0
        while not stop_event.is_set():
            name = scenario_names[round_robin % len(scenario_names)]
            round_robin += 1
            result = SCENARIOS[name](s, base_url)
            with lock:
                metrics[name].record(result)
                completed[0] += 1
            elapsed = time.perf_counter() - wall_start
            remaining = max(0, duration_s - elapsed)
            pct = min(100, elapsed / duration_s * 100)
            bar_len = 40
            filled = int(bar_len * pct / 100)
            bar = "█" * filled + "░" * (bar_len - filled)
            print(f"\r  Time [{bar}] {pct:.0f}%  |  {completed[0]} requests  |  {remaining:.0f}s left  ", end="", flush=True)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(worker, i) for i in range(concurrency)]

        time.sleep(duration_s)
        stop_event.set()

        for f in futures:
            f.result()

    wall_time = time.perf_counter() - wall_start
    print()
    return metrics, wall_time

# ── Reporting ────────────────────────────────────────────────────────

def print_report(all_metrics: dict, wall_time: float):
    total_req = sum(m.total_requests for m in all_metrics.values())
    total_ok  = sum(m.successful for m in all_metrics.values())
    total_fail = sum(m.failed for m in all_metrics.values())

    print("\n" + "=" * 72)
    print("  📊  LOAD TEST RESULTS")
    print("=" * 72)
    print(f"  Wall-clock time : {wall_time:.2f}s")
    print(f"  Total requests  : {total_req}")
    print(f"  Total success   : {total_ok}  ✅")
    print(f"  Total failed    : {total_fail}  {'❌' if total_fail else ''}")
    print(f"  Overall RPS     : {total_req / wall_time:.2f}")
    print("=" * 72)

    for name, m in all_metrics.items():
        s = m.summary(wall_time)
        if s.get("total_requests", 0) == 0:
            continue
        print(f"\n── {name.upper()} {'─' * (58 - len(name))}")
        print(f"  Requests  : {s['total_requests']}  (✅ {s['successful']}  ❌ {s['failed']}  error rate: {s['error_rate']})")
        print(f"  Throughput: {s['throughput_rps']} req/s")
        print(f"  Data xfer : {s['total_data_mb']} MB")
        lat = s["latency_ms"]
        print(f"  Latency   : min={lat['min']}ms  avg={lat['avg']}ms  med={lat['median']}ms  "
              f"p90={lat['p90']}ms  p95={lat['p95']}ms  p99={lat['p99']}ms  max={lat['max']}ms")
        if s["status_codes"]:
            codes_str = "  ".join(f"{code}:{cnt}" for code, cnt in s["status_codes"].items())
            print(f"  HTTP codes: {codes_str}")
        if s["sample_errors"]:
            print(f"  Errors (sample):")
            for e in s["sample_errors"]:
                print(f"    • {e}")

    print("\n" + "=" * 72)

    # Also dump JSON summary to file
    json_report = {
        "wall_time_s": round(wall_time, 2),
        "total_requests": total_req,
        "total_success": total_ok,
        "total_failed": total_fail,
        "overall_rps": round(total_req / wall_time, 2),
        "scenarios": {name: m.summary(wall_time) for name, m in all_metrics.items()},
    }
    report_file = "load_test_results.json"
    with open(report_file, "w") as f:
        json.dump(json_report, f, indent=2)
    print(f"\n📄 Full JSON report saved to: {report_file}")

# ── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="TeraBridge API Load Tester")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="API base URL (default: %(default)s)")
    parser.add_argument("-c", "--concurrency", type=int, default=20, help="Number of concurrent workers (default: 20)")
    parser.add_argument("-n", "--requests", type=int, default=100, help="Total number of requests (fixed-count mode)")
    parser.add_argument("-d", "--duration", type=int, default=0, help="Duration in seconds (overrides --requests if >0)")
    parser.add_argument("--scenarios", nargs="+", choices=list(SCENARIOS.keys()) + ["all"], default=["all"],
                        help="Which test scenarios to run (default: all)")
    parser.add_argument("--link", default=TEST_LINK, help="Terabox share link to test with")
    parser.add_argument("--api-key", default="", help="API key to use in requests")
    args = parser.parse_args()

    # Update module-level test link if user provided a custom one
    if args.link != TEST_LINK:
        _update_test_link(args.link)

    if args.api_key:
        global API_KEY_HEADER
        API_KEY_HEADER = args.api_key

    chosen = SCENARIOS if "all" in args.scenarios else {k: SCENARIOS[k] for k in args.scenarios}

    # Pre-flight: check if the server is reachable
    print(f"\n🔍 Pre-flight check: {args.base_url} ...")
    try:
        r = requests.get(f"{args.base_url}/", timeout=10)
        print(f"   ✅ Server responded: {r.status_code}")
    except Exception as e:
        print(f"   ❌ Cannot reach server: {e}")
        print("   Make sure the API server is running first!")
        print(f"   Start it with: python api/index.py")
        sys.exit(1)

    if args.duration > 0:
        metrics, wall_time = run_duration_test(args.base_url, chosen, args.concurrency, args.duration)
    else:
        metrics, wall_time = run_fixed_count_test(args.base_url, chosen, args.concurrency, args.requests)

    print_report(metrics, wall_time)

if __name__ == "__main__":
    main()
