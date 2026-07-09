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

# Max bytes to download per speed test (Set to None to download the full file)
MAX_BENCHMARK_BYTES = None

# Accounts to benchmark (testing a subset prevents excessive rates limits)
ACCOUNTS_TO_TEST = ["account_5", "account_3"]

async def test_download_speed(account_name, dlink, cookies_dict, size_bytes, method_name, ua_val):
    limit_bytes = size_bytes if MAX_BENCHMARK_BYTES is None else min(size_bytes, MAX_BENCHMARK_BYTES)
    
    print(f"\n⚡ Starting {method_name} Speed Test for {account_name} ...")
    print(f"   Downloading first {limit_bytes / 1024 / 1024:.2f} MB of the file...")
    
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
                
                async for chunk in resp.aiter_bytes(chunk_size):
                    if chunk:
                        downloaded += len(chunk)
                        pct = downloaded / content_length * 100 if content_length else 0
                        bar = "█" * int(pct / 4) + "░" * (25 - int(pct / 4))
                        elapsed = time.perf_counter() - start_time
                        speed_mbps = (downloaded * 8) / (elapsed * 1024 * 1024) if elapsed > 0 else 0
                        speed_mbs = (downloaded) / (elapsed * 1024 * 1024) if elapsed > 0 else 0
                        print(f"\r   [{bar}] {pct:.1f}% | {downloaded/1024/1024:.1f}/{content_length/1024/1024:.1f} MB | Speed: {speed_mbs:.2f} MB/s ({speed_mbps:.2f} Mbps)", end="", flush=True)
                        if downloaded >= limit_bytes:
                            await resp.aclose()
                            break
                print()
        
        total_time = time.perf_counter() - start_time
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
        print(f"   ❌ Download test failed: {e}")
        return None

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
        mirrors = target_file.get("mirrors", [])
        if mirrors:
            print(f"   ℹ️ Detected {len(mirrors)} CDN mirrors from location resolver.")
        
        # Test 1: Single Connection (Chrome UA)
        res_single_chrome = await test_download_speed(
            name, dlink, cookies_dict, size_bytes, 
            method_name="Single (Chrome UA)", 
            ua_val=downloader.UA
        )
        if res_single_chrome:
            results.append(res_single_chrome)
            
        # Test 2: Single Connection (Premium UA)
        res_single_premium = await test_download_speed(
            name, dlink, cookies_dict, size_bytes, 
            method_name="Single (Premium UA)", 
            ua_val=OPTIMIZED_UA
        )
        if res_single_premium:
            results.append(res_single_premium)
            
    # Final Report
    file_size_mb = size_bytes / 1024 / 1024 if 'size_bytes' in locals() and size_bytes else 58.7
    print("\n=============================================================================")
    print(f" 🏁 FINAL CHALLENGE REPORT: DOWNLOAD SPEED COMPARISON ({file_size_mb:.1f} MB FILE)")
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
