import requests
import json
import urllib.parse
import sys
import re
import os
import zipfile
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Set stdout encoding to UTF-8 to prevent UnicodeEncodeError on Windows
if sys.version_info >= (3, 7):
    sys.stdout.reconfigure(encoding='utf-8')

BASE_PUBLIC = "https://www.terabox.com"
BASE_API    = "https://dm.1024terabox.com"

# Fallback values
JSTOKEN   = "5D29BC1A0FACF3CEB3FD732DA7D673A0FD8AED8B4523E154A3C81F3703E40D5447EFC35BD4572A1A6364FD87651714FD6421FCD4C698998BEFFA5A318A8A07B2"
BDSTOKEN  = "dc0d479a8da1268439f4ef3c78000af2"
SIGN      = "BLhPnIgjr3XPA0yBJBbzPiJoxt2HPLGx4xzdkuc4DpwkO4p00xrA6Q%3D%3D"
TIMESTAMP = "1781211335"
LOGID     = "91617900647418900040"

COOKIE = """_rdt_em=:b17c33bd6253cafc883745af7918eb45e3717efdde86a03f83f945b85d4d9808,df1ec41fbe939c7b84823032dd1f04949ff322250ff9ac91f8bbc363b71ff623,834c0a73e7d7be5ba10b3f6ab11b04f825ff1446065767bdc02bb6712da35edd,d121e9ec48b17b8294b872f61c97c16b8626d6bf8febce1b4267d33032cd3a2c,b4350fa6f48f4b07ea79abee4048f9d07d551ebeed400483bb9d911b14a51c61;lang=en;_pin_unauth=dWlkPVlUQTFOV1psT1RVdE5qTmlaUzAwWkRnMkxUazBaamN0TmpZelpHTTFOREV4TVdKaA;_ga_06ZNKL8C2E=GS2.1.s1781213850$o17$g1$t1781214169$j55$l0$h0;_pin_unauth=dWlkPVlUQTFOV1psT1RVdE5qTmlaUzAwWkRnMkxUazBaamN0TmpZelpHTTFOREV4TVdKaA;ndut_fmv=942571a759023b2c571d3d169ee140e2fc4fc2227a396b2b9d05b1d72eb720c517b62dcb0ab32d19475d30bdfd69ae474a2edca92ab62c0387cec953df9009e1f13817779e4dbe9fd56cc780181e2bf2319e9c5ca51fbe5edd1ee709dc10465d61d927486277f2bf5f95918088fd256e;_clck=f0pnw7%5E2%5Eg6s%5E1%5E2259;__stripe_mid=e01538ac-0ccb-4207-929c-7ef916c420f0931005;_uetvid=a47c3cb0f3cf11f08052a53985709b40;_rdt_uuid=1773049017666.9d2ce3a3-fd09-41d1-924a-2ef90c057fc4;_gcl_au=1.1.1459874536.1780893979;ndus=YdPTAX9peHuiF8hccqWybi55eQ8PxkBA39HlfmXM;_ga=GA1.1.1483605655.1773049018;g_state={"i_l":0,"i_ll":1781213848710,"i_b":"8iSpL4UKbEOvEIBtVhvblqGTAEts3eZW8k/WfLlzTV4","i_e":{"enable_itp_optimization":0},"i_et":1780487529583};__bid_n=19a30b1f4c94af60024207;_fbp=fb.1.1773049006257.468883359856284849;_ga_HSVH9T016H=GS2.1.s1781090137$o12$g0$t1781090137$j60$l0$h0;browserid=YM32BhDtSVqSsQqaNVA1oWSOT4Mm8NlbpsnHlqfhJMrZH4BunnQIf23Q4KQ=;csrfToken=8jUF4NSScroYM4p0Md5GIF0y;ndut_fmt=A49B592E36D80FE90A38028052D05942A5A7BBC26131C80C648343FDAFD95019;PANWEB=1"""
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
ROOT_PATH = "/cloudvids"

def parse_cookies(cookie_str):
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

COOKIES_DICT = parse_cookies(COOKIE)

HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.8",
    "Referer": f"{BASE_API}/main?category=all&path=%2F",
    "X-Requested-With": "XMLHttpRequest",
}

def qp():
    return f"app_id=250528&web=1&channel=dubox&clienttype=0&jsToken={JSTOKEN}&dp-logid={LOGID}"

def _create_session():
    """Create a requests session with connection pooling and automatic retry."""
    s = requests.Session()
    s.headers.update(HEADERS)
    s.cookies.update(COOKIES_DICT)

    # Retry strategy: 3 retries with exponential backoff on server errors
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    # Connection pooling: keep up to 10 connections, max 20 in the pool
    adapter = HTTPAdapter(
        pool_connections=10,
        pool_maxsize=20,
        max_retries=retry_strategy,
    )
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

session = _create_session()

def parse_surl(url):
    """Extract and clean the shorturl key from a Terabox share link."""
    if "surl=" in url:
        surl = url.split("surl=")[1].split("&")[0]
    elif "/s/" in url:
        surl = url.split("/s/")[1].split("?")[0]
    else:
        surl = url
    
    surl = surl.split("/")[-1]
    
    while len(surl) > 22 and surl.startswith("1"):
        surl = surl[1:]
        
    return surl

def show(label, r):
    print(f"\n── {label} ──")
    print(f"  Status: {r.status_code}")
    try:
        d = r.json()
        print(f"  {json.dumps(d, indent=2)[:800]}")
        return d
    except:
        print(f"  {r.text[:400]}")
        return {}

def resolve_link(link, action="d", wait_for_transcoding=False):
    """
    Exposes the core resolution logic.
    Returns a dict with metadata, transfer status, direct links, or streaming playlists.
    """
    global BDSTOKEN, JSTOKEN
    
    # 1. Fetch current session tokens dynamically if needed
    try:
        r_main = session.get(f"{BASE_API}/main", headers=HEADERS)
        m1 = re.findall(r'bdstoken["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', r_main.text, re.IGNORECASE)
        if m1:
            BDSTOKEN = m1[0]
        else:
            m2 = re.search(r'bdstoken\s*=\s*["\']([a-f0-9]{32})["\']', r_main.text)
            if m2:
                BDSTOKEN = m2.group(1)

        m3 = re.findall(r'jstoken["\']?\s*[:=]\s*["\'](.*?)["\']', r_main.text, re.IGNORECASE)
        if m3:
            decoded_js = urllib.parse.unquote(m3[0])
            arg_match = re.search(r'fn\s*\(\s*["\']([a-f0-9]{128})["\']\s*\)', decoded_js, re.IGNORECASE)
            if arg_match:
                JSTOKEN = arg_match.group(1)
    except Exception as e:
        return {"errno": -1, "error": f"Failed to resolve session tokens: {e}"}

    surl = parse_surl(link)
    list_url = (
        f"{BASE_PUBLIC}/share/list"
        f"?app_id=250528&shorturl={surl}&root=1&order=name&desc=0&showempty=0&web=1&page=1&num=100"
    )
    try:
        r = session.get(list_url)
        share_data = r.json()
    except Exception as e:
        return {"errno": -2, "error": f"Failed to query share list: {e}"}

    if share_data.get("errno") != 0:
        return {"errno": share_data.get("errno"), "error": "Share link is invalid or expired."}

    title = share_data.get("title", "Untitled Shared Content")
    share_id = share_data.get("share_id")
    uk = share_data.get("uk")
    files_list = share_data.get("list", [])

    # Pre-fetch list of existing files in ROOT_PATH to prevent duplication
    existing_files = {}
    if action != "l":
        encoded_dir = urllib.parse.quote(ROOT_PATH)
        try:
            r_list = session.get(
                f"{BASE_API}/api/list?{qp()}&dir={encoded_dir}&order=time&desc=1&showempty=0&page=1&num=100&bdstoken={BDSTOKEN}"
            )
            list_res = r_list.json()
            if list_res.get("errno") == 0:
                for entry in list_res.get("list", []):
                    name = entry.get("server_filename")
                    existing_files[name] = {
                        "fs_id": str(entry.get("fs_id", "")),
                        "path": entry.get("path", ""),
                        "size": int(entry.get("size", 0))
                    }
        except Exception:
            pass

    results = []
    
    for item in files_list:
        filename = item.get("server_filename")
        fs_id = item.get("fs_id")
        size_bytes = int(item.get("size", 0))
        size_mb = size_bytes / 1024 / 1024
        
        file_res = {
            "filename": filename,
            "size_bytes": size_bytes,
            "size_mb": round(size_mb, 2),
            "original_fs_id": fs_id,
            "fs_id": fs_id if action == "l" else None,
            "transfer_status": "not_transferred" if action == "l" else "skipped_existing",
            "dlink": None,
            "stream_ready": False,
            "stream_m3u8": None,
            "error": None
        }

        if action == "l":
            results.append(file_res)
            continue

        # Check if the file already exists with same name and size
        my_fs_id = ""
        my_file_path = ""
        if filename in existing_files and existing_files[filename]["size"] == size_bytes:
            my_fs_id = existing_files[filename]["fs_id"]
            my_file_path = existing_files[filename]["path"]
            # File exists, skip transfer step
        else:
            # Step A: Transfer
            transfer_payload = {
                "fsidlist":  f"[{fs_id}]",
                "path":      ROOT_PATH,
                "shareid":   str(share_id),
                "from":      str(uk),
                "ondup":     "newcopy",
                "bdstoken":  BDSTOKEN,
            }
            try:
                tr = session.post(
                    f"{BASE_API}/share/transfer?{qp()}&bdstoken={BDSTOKEN}",
                    data=transfer_payload
                )
                transfer_res = tr.json()
            except Exception as e:
                file_res["error"] = f"Transfer API request failed: {e}"
                file_res["transfer_status"] = "failed"
                results.append(file_res)
                continue

            if transfer_res.get("errno") not in (0, 4):
                file_res["error"] = f"Transfer failed with Terabox errno {transfer_res.get('errno')}"
                file_res["transfer_status"] = "failed"
                results.append(file_res)
                continue

            file_res["transfer_status"] = "success"

            # Step B: Resolve my fs_id
            try:
                extra_list = transfer_res.get("extra", {}).get("list", [])
                if extra_list:
                    my_fs_id = str(extra_list[0].get("to_fs_id", ""))
                    dest_path = extra_list[0].get("to", "")
                    if my_fs_id:
                        if dest_path:
                            filename = dest_path.split("/")[-1]
                            my_file_path = dest_path
            except Exception:
                pass

            if not my_fs_id:
                # Fallback search
                try:
                    r_list = session.get(
                        f"{BASE_API}/api/list?{qp()}&dir={encoded_dir}&order=time&desc=1&showempty=0&page=1&num=20&bdstoken={BDSTOKEN}"
                    )
                    list_res = r_list.json()
                    for entry in list_res.get("list", []):
                        entry_name = entry.get("server_filename", "")
                        if filename in entry_name or entry_name in filename:
                            my_fs_id = str(entry.get("fs_id", ""))
                            filename = entry_name
                            my_file_path = entry.get("path", "")
                            break
                except Exception:
                    pass

        if not my_fs_id:
            file_res["error"] = "Could not resolve transferred file ID in account."
            results.append(file_res)
            continue

        file_res["fs_id"] = my_fs_id
        file_res["filename"] = filename
        
        # --- ACTION HLS STREAMING ---
        if action == "s":
            if not my_file_path:
                my_file_path = ROOT_PATH.rstrip("/") + "/" + filename
            encoded_path = urllib.parse.quote(my_file_path)
            stream_url = f"{BASE_API}/api/streaming?{qp()}&path={encoded_path}&type=M3U8_AUTO_720&bdstoken={BDSTOKEN}"
            
            # If wait_for_transcoding is True, retry up to 6 times. Otherwise try once.
            max_retries = 6 if wait_for_transcoding else 1
            retry_delay = 10
            
            for attempt in range(1, max_retries + 1):
                try:
                    sr = session.get(stream_url)
                    if sr.status_code == 200 and "#EXTM3U" in sr.text:
                        file_res["stream_ready"] = True
                        file_res["stream_m3u8"] = sr.text
                        break
                    
                    err_code = None
                    try:
                        res_json = sr.json()
                        err_code = res_json.get("errno")
                    except Exception:
                        pass
                    
                    if err_code == 130:
                        file_res["error"] = "transcoding_in_progress"
                        if wait_for_transcoding:
                            time.sleep(retry_delay)
                        else:
                            break
                    else:
                        file_res["error"] = f"Streaming API failed: {sr.text[:200]}"
                        break
                except Exception as e:
                    file_res["error"] = f"Streaming request exception: {e}"
                    break
        
        # --- ACTION DOWNLOAD ---
        elif action == "d":
            # Direct link resolution via filemetas (which is robust and works without sign/timestamp)
            metas_url = f"{BASE_API}/api/filemetas?{qp()}&fsids=[\"{my_fs_id}\"]&dlink=1&thumb=0&bdstoken={BDSTOKEN}"
            try:
                mr = session.get(metas_url)
                metas_res = mr.json()
                dlink = ""
                for entry in metas_res.get("list", metas_res.get("info", [])):
                    dlink = entry.get("dlink", "")
                    if dlink:
                        break
                if dlink:
                    file_res["dlink"] = dlink
                else:
                    file_res["error"] = "Failed to resolve direct download link (dlink) from filemetas."
            except Exception as e:
                file_res["error"] = f"filemetas query failed: {e}"

        results.append(file_res)

    return {
        "errno": 0,
        "title": title,
        "share_id": share_id,
        "uk": uk,
        "files": results
    }

def download_file(dlink, filename):
    print("✅ Direct download link retrieved successfully!")
    print(f"   Link: {dlink[:100]}...")

    # Stream the download
    print(f"Downloading to local file: {filename} ...")
    dr = session.get(
        dlink,
        headers={
            "User-Agent": UA,
            "Referer": BASE_API + "/",
        },
        cookies=COOKIES_DICT,
        stream=True,
        allow_redirects=True,
        timeout=120
    )

    content_type = dr.headers.get("Content-Type", "")
    content_length = int(dr.headers.get("Content-Length", 0))
    print(f"  HTTP Response: {dr.status_code} | Type: {content_type} | Size: {content_length/1024/1024:.2f} MB")

    if dr.status_code not in (200, 206) or content_length < 1000:
        print(f"❌ Bad download stream response: {dr.text[:300]}")
        return False

    is_zip = "zip" in content_type.lower()
    temp_filename = filename + ".zip" if is_zip else filename

    # Write chunks to file
    with open(temp_filename, "wb") as f:
        downloaded = 0
        for chunk in dr.iter_content(1024 * 1024):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)
                pct = downloaded / content_length * 100 if content_length else 0
                bar = "█" * int(pct / 2) + "░" * (50 - int(pct / 2))
                print(f"\r  [{bar}] {pct:.1f}%  {downloaded/1024/1024:.1f}/{content_length/1024/1024:.1f} MB", end="", flush=True)
        print()

    if is_zip:
        print("📦 Extracting ZIP archive...")
        try:
            with zipfile.ZipFile(temp_filename, "r") as zf:
                for info in zf.infolist():
                    zf.extract(info, ".")
                    print(f"   Saved: {info.filename}")
            os.remove(temp_filename)
            print(f"✅ Extraction completed successfully!")
            return True
        except Exception as e:
            print(f"⚠️ Error extracting ZIP: {e}")
            print(f"ZIP file kept at: {temp_filename}")
            return False
    else:
        print(f"✅ Successfully saved: {filename}")
        return True

def main():
    global BDSTOKEN, JSTOKEN

    print("=" * 60)
    print("        TERABOX AUTOMATIC DIRECT DOWNLOADER & STREAMER")
    print("=" * 60)

    # Check for --stream or --list in command arguments
    stream_only = False
    list_only = False
    if "--stream" in sys.argv:
        stream_only = True
        sys.argv.remove("--stream")
    if "--list" in sys.argv:
        list_only = True
        sys.argv.remove("--list")

    # 1. Get link
    if len(sys.argv) > 1:
        link = sys.argv[1]
    else:
        link = input("Enter Terabox link (or press Enter for default): ").strip()
        if not link:
            link = "https://terasharefile.com/s/11HTXTPgKapRLE3cTXSFMJQ"
            print(f"Using default link: {link}")

    # 3. Choose Action (Download vs HLS Stream vs List)
    action = "d"
    if stream_only:
        action = "s"
    elif list_only:
        action = "l"
    else:
        choice = input("\nChoose action: [D]ownload file(s), [S]tream M3U8 playlist(s), or [L]ist files? (D/S/L): ").strip().lower()
        if choice == "s":
            action = "s"
        elif choice == "l":
            action = "l"

    print("Resolving Terabox link details...")
    # Call resolve_link with wait_for_transcoding=True since this is a CLI run
    res = resolve_link(link, action=action, wait_for_transcoding=True)

    if res.get("errno") != 0:
        print(f"❌ Error: {res.get('error')}")
        sys.exit(1)

    print(f"✅ Share Title: {res.get('title')}")
    print(f"   Share ID   : {res.get('share_id')}")
    print(f"   Sharer UK  : {res.get('uk')}")
    print(f"   Files found: {len(res.get('files', []))}")

    if action == "l":
        print("\n── Shared Files List ──")
        for i, file in enumerate(res.get("files", []), start=1):
            filename = file.get("filename")
            size_mb = file.get("size_mb")
            fs_id = file.get("original_fs_id")
            print(f"  {i}. {filename} ({size_mb} MB) - ID: {fs_id}")
        return

    for file in res.get("files", []):
        filename = file.get("filename")
        size_mb = file.get("size_mb")
        print(f"\nPROCESSING: {filename} ({size_mb} MB)")
        
        if file.get("transfer_status") == "skipped_existing":
            print(f"ℹ️ File already exists in {ROOT_PATH}. Skipping transfer!")
        
        if file.get("error") and file.get("error") != "transcoding_in_progress":
            print(f"❌ Error: {file.get('error')}")
            continue

        if action == "s":
            if file.get("stream_ready"):
                m3u8_filename = os.path.splitext(filename)[0] + ".m3u8"
                with open(m3u8_filename, "w", encoding="utf-8") as f:
                    f.write(file.get("stream_m3u8"))
                print(f"✅ Saved M3U8 streaming playlist to: {m3u8_filename}")
                print(f"   You can open {m3u8_filename} directly in VLC or PotPlayer to stream the video!")
            else:
                choice = input("\nStreaming playlist generation failed (transcoding). Would you like to [D]ownload the raw file instead or [E]xit/Skip? (D/E): ").strip().lower()
                if choice == "d":
                    download_res = resolve_link(link, action="d")
                    download_file_info = next((f for f in download_res.get("files", []) if f["original_fs_id"] == file["original_fs_id"]), None)
                    if download_file_info and download_file_info.get("dlink"):
                        download_file(download_file_info["dlink"], filename)
                continue

        elif action == "d":
            dlink = file.get("dlink")
            if dlink:
                download_file(dlink, filename)

if __name__ == "__main__":
    main()
