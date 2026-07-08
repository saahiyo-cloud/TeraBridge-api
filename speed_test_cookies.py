import os
import sys
import json
import time
import asyncio
import httpx
import urllib.parse
from dotenv import load_dotenv

# Fix console encoding for emoji output on Windows
if sys.platform == "win32" and sys.version_info >= (3, 7):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

load_dotenv()

from api.account_pool import get_all_accounts
import downloader

# Terabox Link from User
TARGET_LINK = "https://1024terabox.com/s/1LNr3tyl5pI5KUM8BecGtyQ"

# Optimized PC Client User-Agent
OPTIMIZED_UA = "netdisk;2.2.51.6;netdisk;PC;PC-Windows;10.0.16299;netdisk"

# Max bytes to download per speed test (1 MB is enough for testing and prevents rate-limit delays)
MAX_BENCHMARK_BYTES = 1 * 1024 * 1024 

# Accounts to benchmark (testing a subset prevents excessive rates limits)
ACCOUNTS_TO_TEST = ["account_1", "account_3"]

async def test_download_speed(account_name, dlink, cookies_dict, size_bytes, method_name, ua_val, num_connections=1):
    limit_bytes = min(size_bytes, MAX_BENCHMARK_BYTES)
    
    if num_connections == 1:
        print(f"\n⚡ Starting Single-Connection Download Speed Test for {account_name} ...")
        print(f"   Downloading first {limit_bytes / 1024 / 1024:.2f} MB of the file...")
        
        temp_filename = f"speed_test_{account_name}_temp.bin"
        chunk_size = 256 * 1024  # 256 KB chunks
        start_time = time.perf_counter()
        ttfb = None
        downloaded = 0
        
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
                async with client.stream(
                    "GET",
                    dlink,
                    headers={
                        "User-Agent": ua_val,
                        "Referer": "https://www.1024terabox.com/",
                        "Range": f"bytes=0-{limit_bytes-1}"
                    },
                    cookies=cookies_dict,
                ) as resp:
                    ttfb = (time.perf_counter() - start_time) * 1000
                    
                    if resp.status_code not in (200, 206):
                        body = await resp.aread()
                        print(f"   ❌ HTTP {resp.status_code} Error: {body[:300].decode('utf-8', errors='ignore')}")
                        return None
                    
                    content_length = int(resp.headers.get("Content-Length", limit_bytes))
                    
                    with open(temp_filename, "wb") as f:
                        async for chunk in resp.aiter_bytes(chunk_size):
                            if chunk:
                                f.write(chunk)
                                downloaded += len(chunk)
                                pct = downloaded / content_length * 100 if content_length else 0
                                bar = "█" * int(pct / 4) + "░" * (25 - int(pct / 4))
                                elapsed = time.perf_counter() - start_time
                                speed_mbps = (downloaded * 8) / (elapsed * 1024 * 1024) if elapsed > 0 else 0
                                speed_mbs = (downloaded) / (elapsed * 1024 * 1024) if elapsed > 0 else 0
                                print(f"\r   [{bar}] {pct:.1f}% | {downloaded/1024/1024:.1f}/{content_length/1024/1024:.1f} MB | Speed: {speed_mbs:.2f} MB/s ({speed_mbps:.2f} Mbps)", end="", flush=True)
                                if downloaded >= limit_bytes:
                                    break
                    print()
            
            total_time = time.perf_counter() - start_time
            avg_speed_mbs = (downloaded / 1024 / 1024) / total_time if total_time > 0 else 0
            avg_speed_mbps = avg_speed_mbs * 8
            print(f"   ✅ Done! Time: {total_time:.2f}s | TTFB: {ttfb:.1f}ms | Avg Speed: {avg_speed_mbs:.2f} MB/s ({avg_speed_mbps:.2f} Mbps)")
            
            if os.path.exists(temp_filename):
                os.remove(temp_filename)
                
            return {
                "account": account_name,
                "method": method_name,
                "ttfb_ms": ttfb,
                "duration_s": total_time,
                "avg_speed_mbs": avg_speed_mbs,
                "avg_speed_mbps": avg_speed_mbps,
                "size_mb": downloaded / 1024 / 1024
            }
        except Exception as e:
            print(f"   ❌ Download test failed: {e}")
            if os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except:
                    pass
            return None
    else:
        print(f"\n⚡ Starting Parallel Download Speed Test ({num_connections} conns) for {account_name} ...")
        print(f"   Downloading first {limit_bytes / 1024 / 1024:.2f} MB of the file in parallel...")
        
        start_time = time.perf_counter()
        chunk_size = limit_bytes // num_connections
        ranges = []
        for i in range(num_connections):
            start = i * chunk_size
            end = (i + 1) * chunk_size - 1 if i < num_connections - 1 else limit_bytes - 1
            ranges.append((start, end))
            
        headers = {
            "User-Agent": ua_val,
            "Referer": "https://www.1024terabox.com/",
        }
        
        try:
            ttfb_start = time.perf_counter()
            async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
                # Measure TTFB by requesting first byte
                tiny_headers = headers.copy()
                tiny_headers["Range"] = "bytes=0-0"
                await client.get(dlink, headers=tiny_headers, cookies=cookies_dict)
                ttfb = (time.perf_counter() - ttfb_start) * 1000
                
                # Start parallel downloads
                tasks = []
                for idx, (start, end) in enumerate(ranges):
                    tasks.append(download_chunk(client, dlink, start, end, headers, cookies_dict, idx))
                    
                results = await asyncio.gather(*tasks)
                
            results.sort(key=lambda x: x[0])
            file_data = b"".join(r[1] for r in results)
            
            total_time = time.perf_counter() - start_time
            downloaded = len(file_data)
            
            if downloaded < limit_bytes * 0.9:
                print(f"   ❌ Parallel download failed to download complete range ({downloaded}/{limit_bytes} bytes fetched)")
                return None
                
            avg_speed_mbs = (downloaded / 1024 / 1024) / total_time if total_time > 0 else 0
            avg_speed_mbps = avg_speed_mbs * 8
            
            print(f"   ✅ Done! Time: {total_time:.2f}s | TTFB: {ttfb:.1f}ms | Avg Speed: {avg_speed_mbs:.2f} MB/s ({avg_speed_mbps:.2f} Mbps)")
            
            return {
                "account": account_name,
                "method": method_name,
                "ttfb_ms": ttfb,
                "duration_s": total_time,
                "avg_speed_mbs": avg_speed_mbs,
                "avg_speed_mbps": avg_speed_mbps,
                "size_mb": downloaded / 1024 / 1024
            }
        except Exception as e:
            print(f"   ❌ Parallel download test failed: {e}")
            return None

async def download_chunk(client, dlink, start, end, headers, cookies, chunk_idx):
    headers = headers.copy()
    headers["Range"] = f"bytes={start}-{end}"
    try:
        resp = await client.get(dlink, headers=headers, cookies=cookies)
        if resp.status_code == 206:
            return chunk_idx, resp.content
        else:
            return chunk_idx, b""
    except Exception:
        return chunk_idx, b""

async def main():
    print("=========================================================")
    print(" 🚀 TeraBridge - Multi-Cookie Speed Test Challenge")
    print("=========================================================")
    print(f"Target Link: {TARGET_LINK}")
    
    accounts = get_all_accounts()
    if not accounts:
        print("❌ No accounts loaded from Redis pool.")
        return
        
    print(f"Found {len(accounts)} accounts in Redis pool: {list(accounts.keys())}")
    print(f"Benchmarking subset: {ACCOUNTS_TO_TEST}\n")
    
    results = []
    
    for name in ACCOUNTS_TO_TEST:
        if name not in accounts:
            print(f"⚠️ Account {name} not found in pool. Skipping.")
            continue
            
        data = accounts[name]
        print(f"\n--- [Testing {name}] ---")
        cookie_val = data.get("cookie")
        if not cookie_val:
            print("❌ No cookie for this account. Skipping.")
            continue
            
        downloader.update_credentials(
            cookie=cookie_val,
            js_token=data.get("js_token"),
            bds_token=data.get("bds_token"),
            logid=data.get("logid")
        )
        
        print(f"🔍 Resolving share link with {name} cookies...")
        try:
            res = await downloader.resolve_link(TARGET_LINK, action="d")
        except Exception as e:
            print(f"❌ Error during resolution: {e}")
            continue
            
        errno = res.get("errno")
        if errno != 0:
            print(f"❌ Resolution failed: {res.get('error')} (errno={errno})")
            continue
            
        files = res.get("files", [])
        if not files:
            print("⚠️ No files found in this share link.")
            continue
            
        target_file = files[0]
        dlink = target_file.get("dlink")
        if not dlink:
            print("❌ No direct download link ('dlink') found.")
            continue
            
        size_bytes = target_file.get("size_bytes", 0)
        cookies_dict = downloader.parse_cookies(cookie_val)
        
        # Test 1: Single Connection (Chrome Browser UA)
        res_single = await test_download_speed(
            name, dlink, cookies_dict, size_bytes, 
            method_name="Single (Chrome UA)", 
            ua_val=downloader.UA, num_connections=1
        )
        if res_single:
            results.append(res_single)
            
        # Test 2: Parallel Connections (4 Connections, Chrome Browser UA)
        res_parallel_4 = await test_download_speed(
            name, dlink, cookies_dict, size_bytes,
            method_name="Parallel-4 (Chrome UA)",
            ua_val=downloader.UA, num_connections=4
        )
        if res_parallel_4:
            results.append(res_parallel_4)
            
        # Test 3: Parallel Connections (16 Connections, Spoofed Baidu Netdisk PC UA)
        res_parallel_16_opt = await test_download_speed(
            name, dlink, cookies_dict, size_bytes,
            method_name="Parallel-16 (Optimized UA)",
            ua_val=OPTIMIZED_UA, num_connections=16
        )
        if res_parallel_16_opt:
            results.append(res_parallel_16_opt)
            
    # Final Report
    print("\n=============================================================================")
    print(" 🏁 FINAL CHALLENGE REPORT: DOWNLOAD SPEED COMPARISON (58.7 MB FILE)")
    print("=============================================================================")
    if not results:
        print("❌ No successful downloads recorded.")
        return
        
    # Sort results by average speed in descending order
    results_sorted = sorted(results, key=lambda x: x["avg_speed_mbs"], reverse=True)
    
    print(f"{'Rank':<5} | {'Account':<12} | {'Method':<30} | {'Avg Speed':<15} | {'TTFB':<10} | {'Duration':<10}")
    print("-" * 92)
    for rank, r in enumerate(results_sorted, 1):
        rank_str = f"#{rank}"
        if rank == 1:
            rank_str = "🏆 #1"
        print(f"{rank_str:<5} | {r['account']:<12} | {r['method']:<30} | {r['avg_speed_mbs']:.2f} MB/s | {r['ttfb_ms']:.1f} ms | {r['duration_s']:.2f}s")
    print("=============================================================================")

if __name__ == "__main__":
    asyncio.run(main())
