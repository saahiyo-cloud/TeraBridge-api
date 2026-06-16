import requests
import json
import urllib.parse
import sys
import re
import os
import zipfile
import time
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Set stdout encoding to UTF-8 to prevent UnicodeEncodeError on Windows
if sys.version_info >= (3, 7):
    sys.stdout.reconfigure(encoding='utf-8')

BASE_PUBLIC = "https://www.terabox.com"
BASE_API    = "https://dm.1024terabox.com"

# Environment variables with hardcoded fallbacks
JSTOKEN   = os.environ.get("TERABOX_JSTOKEN", "5D29BC1A0FACF3CEB3FD732DA7D673A0FD8AED8B4523E154A3C81F3703E40D5447EFC35BD4572A1A6364FD87651714FD6421FCD4C698998BEFFA5A318A8A07B2")
BDSTOKEN  = os.environ.get("TERABOX_BDSTOKEN", "dc0d479a8da1268439f4ef3c78000af2")
SIGN      = os.environ.get("TERABOX_SIGN", "BLhPnIgjr3XPA0yBJBbzPiJoxt2HPLGx4xzdkuc4DpwkO4p00xrA6Q%3D%3D")
TIMESTAMP = os.environ.get("TERABOX_TIMESTAMP", "1781211335")
LOGID     = os.environ.get("TERABOX_LOGID", "91617900647418900040")

COOKIE = os.environ.get(
    "TERABOX_COOKIE",
    "ndus=YdPTAX9peHuiF8hccqWybi55eQ8PxkBA39HlfmXM; PANWEB=1"
)

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

def update_credentials(cookie=None, js_token=None, bds_token=None, sign=None, timestamp=None, logid=None):
    """Dynamically update Terabox global cookies and tokens in the session."""
    global COOKIE, COOKIES_DICT, JSTOKEN, BDSTOKEN, SIGN, TIMESTAMP, LOGID, session
    if cookie:
        COOKIE = cookie
        COOKIES_DICT.clear()
        COOKIES_DICT.update(parse_cookies(cookie))
        # Clear existing cookies in session and update with new ones
        session.cookies.clear()
        session.cookies.update(COOKIES_DICT)
    if js_token:
        JSTOKEN = js_token
    if bds_token:
        BDSTOKEN = bds_token
    if sign:
        SIGN = sign
    if timestamp:
        TIMESTAMP = timestamp
    if logid:
        LOGID = logid

def validate_session_cookie(cookie_str):
    """Verify if a TeraBox cookie is valid by making a test request and checking for a bdstoken."""
    temp_session = requests.Session()
    temp_session.headers.update(HEADERS)
    temp_cookies = parse_cookies(cookie_str)
    temp_session.cookies.update(temp_cookies)
    
    try:
        r = temp_session.get(f"{BASE_API}/main", timeout=15)
        if r.status_code != 200:
            return False, f"HTTP status {r.status_code}"
        
        # Look for bdstoken in the response HTML to verify successful session
        m = re.findall(r'bdstoken["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', r.text, re.IGNORECASE)
        if m:
            return True, "Valid"
        return False, "bdstoken not found (session likely expired or invalid)"
    except Exception as e:
        return False, f"Request failed: {str(e)}"

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

_SURL_MIN_LEN = 8     # empirical floor; real Terabox surls are 22-23 chars
_LEADING_ONE_MAX_STRIPS = 4  # never strip more than this many leading '1' chars
_VALID_SURL = re.compile(r"^[A-Za-z0-9_-]+$")


def parse_surl(url):
    """
    Extract and clean the shorturl key (`surl`) from a Terabox share link.

    Recognized shapes:
      - https://terabox.com/s/1ABCDEFG...        (path form)
      - https://1024terabox.com/s/1ABCDEFG...
      - https://terabox.com/share/list?surl=1ABCDEFG...   (query form)
      - https://terabox.com/s/1ABCDEFG?fid=...
      - 1ABCDEFG...                                (bare surl)

    Cleaning rules:
      1. The result must match [A-Za-z0-9_-]+. Anything else (including the
         original URL when no marker is found) raises ValueError.
      2. If the result is longer than 22 chars and starts with a leading run
         of `1`s, strip up to _LEADING_ONE_MAX_STRIPS leading '1's. This matches
         observed Terabox behavior where the URL-path form prepends a '1' to
         a base62-ish identifier (so `/s/1ABC...` and `?surl=ABC...` resolve
         to the same share). The strip is bounded so a malicious or malformed
         input like '1111...1' cannot shrink to a single character.
      3. After cleaning, the result must be at least _SURL_MIN_LEN chars.

    Returns the cleaned surl string. Raises ValueError on invalid input.
    """
    if not isinstance(url, str) or not url:
        raise ValueError("parse_surl: empty or non-string input")

    surl = None

    # Query form: ?surl=...  (must check before path form so we don't get fooled
    # by a URL that has both `?surl=` and `/s/` in it)
    if "surl=" in url:
        after = url.split("surl=", 1)[1]
        surl = after.split("&", 1)[0]
    elif "/s/" in url:
        after = url.split("/s/", 1)[1]
        surl = after.split("?", 1)[0].split("#", 1)[0]
    else:
        # No `/s/` or `?surl=` marker found.
        # Heuristic: a real Terabox share link is always an http(s) URL with a
        # recognized marker. A bare identifier is one of:
        #   - just letters/digits/underscore/hyphen (no slashes, no scheme, no dots)
        #   - *not* starting with "http"
        # Anything else (a URL without a marker, a path with multiple slashes,
        # anything containing a dot in the path) is rejected.
        stripped = url.strip()
        if "://" in stripped or "/" in stripped or "." in stripped:
            raise ValueError(f"parse_surl: no surl marker found in {url!r}")
        if stripped.startswith("http"):
            raise ValueError(f"parse_surl: malformed input {url!r}")
        if _VALID_SURL.match(stripped) and len(stripped) >= _SURL_MIN_LEN:
            surl = stripped

    if not surl:
        raise ValueError(f"parse_surl: no surl found in {url!r}")

    # Drop any trailing path component that may have leaked in.
    surl = surl.rstrip("/").split("/")[-1]

    if not _VALID_SURL.match(surl):
        raise ValueError(f"parse_surl: extracted value {surl!r} contains invalid characters")

    # Leading-'1' strip. Mirrors Terabox's convention of prepending a '1' to
    # the path-form identifier (so /s/1ABC... and ?surl=ABC... resolve to the
    # same share). Strip at most _LEADING_ONE_MAX_STRIPS leading '1' chars and
    # only when the result is *still* at least _SURL_MIN_LEN chars long. The
    # cap on iteration count prevents a pathological input like '1111...1'
    # from collapsing to a single character.
    if len(surl) > 22 and surl.startswith("1"):
        for _ in range(_LEADING_ONE_MAX_STRIPS):
            if not surl.startswith("1") or len(surl) - 1 < _SURL_MIN_LEN or len(surl) <= 22:
                break
            surl = surl[1:]

    if len(surl) < _SURL_MIN_LEN:
        raise ValueError(
            f"parse_surl: cleaned surl {surl!r} is shorter than the {_SURL_MIN_LEN}-char minimum"
        )

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

def _process_single_file_metadata(item, share_id, uk, existing_files, action, wait_for_transcoding, bdstoken_val, quality=None):
    """
    Processes a single file from the shared link (transfer + streaming checks).
    This function is run in a ThreadPoolExecutor.
    """
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
        "error": None,
        "thumbnails": item.get("thumbs"),
        "path": item.get("path"),
        "is_directory": str(item.get("isdir")) == "1"
    }

    if file_res["is_directory"]:
        file_res["error"] = "File is a directory"
        return file_res

    if action == "l":
        return file_res

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
            "bdstoken":  bdstoken_val,
        }
        try:
            tr = session.post(
                f"{BASE_API}/share/transfer?{qp()}&bdstoken={bdstoken_val}",
                data=transfer_payload
            )
            transfer_res = tr.json()
        except Exception as e:
            file_res["error"] = f"Transfer API request failed: {e}"
            file_res["transfer_status"] = "failed"
            return file_res

        if transfer_res.get("errno") not in (0, 4):
            file_res["error"] = f"Transfer failed with Terabox errno {transfer_res.get('errno')}"
            file_res["transfer_status"] = "failed"
            return file_res

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
            encoded_dir = urllib.parse.quote(ROOT_PATH)
            try:
                r_list = session.get(
                    f"{BASE_API}/api/list?{qp()}&dir={encoded_dir}&order=time&desc=1&showempty=0&page=1&num=20&bdstoken={bdstoken_val}"
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
        return file_res

    file_res["fs_id"] = my_fs_id
    file_res["filename"] = filename
    
    # --- ACTION HLS STREAMING ---
    is_video = False
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        is_video = ext in ('.mp4', '.mkv', '.webm', '.avi', '.mov', '.flv', '.wmv', '.m4v', '.3gp', '.mpg', '.mpeg', '.ts', '.m3u8')

    if action == "s" and is_video:
        if not my_file_path:
            my_file_path = ROOT_PATH.rstrip("/") + "/" + filename
        encoded_path = urllib.parse.quote(my_file_path)
        
        # Try multiple stream quality types — highest first
        if quality:
            stream_types = [quality]
        else:
            stream_types = ["M3U8_AUTO_1080", "M3U8_AUTO_720", "M3U8_AUTO_480", "M3U8_AUTO_360"]
        
        def _try_stream(stype):
            """Try a single streaming request. Returns (success, errno, response_text)."""
            url = f"{BASE_API}/api/streaming?{qp()}&path={encoded_path}&type={stype}&bdstoken={bdstoken_val}"
            try:
                sr = session.get(url, timeout=20)
                if sr.status_code == 200 and "#EXTM3U" in sr.text:
                    return True, 0, sr.text
                err_code = None
                try:
                    res_json = sr.json()
                    err_code = res_json.get("errno")
                except Exception:
                    pass
                return False, err_code, sr.text[:200]
            except Exception as e:
                return False, -1, str(e)
        
        # PASS 1: Quick scan — try each resolution once to find any that's ready
        best_m3u8 = None
        all_transcoding = True
        fatal_error = None
        
        for stype in stream_types:
            ok, errno, text = _try_stream(stype)
            if ok:
                best_m3u8 = (stype, text)
                all_transcoding = False
                break
            elif errno == 130:
                # Transcoding in progress — try next (lower) resolution
                continue
            elif errno in (31066,):
                # File format not supported for streaming at all
                fatal_error = f"File format not supported for streaming (errno {errno})"
                all_transcoding = False
                break
            elif errno in (31341, 31023):
                fatal_error = f"File path error or not found (errno {errno})"
                all_transcoding = False
                break
            else:
                # Unknown error on this type, try next
                all_transcoding = False
                file_res["error"] = f"Streaming API errno {errno}: {text}"
                continue
        
        if best_m3u8:
            file_res["stream_ready"] = True
            file_res["stream_m3u8"] = best_m3u8[1]
            file_res["error"] = None
        elif fatal_error:
            file_res["error"] = fatal_error
        elif all_transcoding and wait_for_transcoding:
            # PASS 2: All resolutions are still transcoding — wait and retry
            max_retries = 12
            retry_delay = 10
            print(f"  ⏳ All resolutions still transcoding, waiting (up to {max_retries * retry_delay}s)...")
            for attempt in range(1, max_retries + 1):
                time.sleep(retry_delay)
                # Retry all types each round (highest first)
                for stype in stream_types:
                    ok, errno, text = _try_stream(stype)
                    if ok:
                        file_res["stream_ready"] = True
                        file_res["stream_m3u8"] = text
                        file_res["error"] = None
                        break
                if file_res["stream_ready"]:
                    break
            if not file_res["stream_ready"]:
                file_res["error"] = "transcoding_in_progress"
        elif all_transcoding:
            file_res["error"] = "transcoding_in_progress"

    return file_res

def resolve_link(link, action="d", wait_for_transcoding=False, quality=None):
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

    try:
        surl = parse_surl(link)
    except ValueError as e:
        return {"errno": -3, "error": f"Invalid share link: {e}"}
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
        return {
            "errno": share_data.get("errno"),
            "error": f"Share link is invalid or expired (errno={share_data.get('errno')}, msg={share_data.get('errmsg', 'none')}, request_id={share_data.get('request_id', 'none')})."
        }

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

    # Run the file metadata/transfer checks in parallel using ThreadPoolExecutor
    max_workers = min(10, len(files_list)) if files_list else 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures_list = [
            executor.submit(
                _process_single_file_metadata,
                item,
                share_id,
                uk,
                existing_files,
                action,
                wait_for_transcoding,
                BDSTOKEN,
                quality
            ) for item in files_list
        ]
        results = [f.result() for f in futures_list]

    # Batch resolve direct download links (dlink) via filemetas
    # We only query filemetas for successful files (valid fs_id, no error) and when action is not list-only
    if action != "l":
        fs_ids_to_resolve = [r["fs_id"] for r in results if r.get("fs_id") and not r.get("error")]
        
        if fs_ids_to_resolve:
            # We chunk the fs_ids list in groups of 100 as Terabox filemetas API might have limits
            chunk_size = 100
            fs_id_chunks = [fs_ids_to_resolve[i:i + chunk_size] for i in range(0, len(fs_ids_to_resolve), chunk_size)]
            
            dlink_map = {}
            for chunk in fs_id_chunks:
                fsids_str = json.dumps(chunk)
                encoded_fsids = urllib.parse.quote(fsids_str)
                
                metas_url = f"{BASE_API}/api/filemetas?{qp()}&fsids={encoded_fsids}&dlink=1&thumb=0&bdstoken={BDSTOKEN}"
                try:
                    mr = session.get(metas_url, timeout=20)
                    metas_res = mr.json()
                    
                    entries = metas_res.get("list", metas_res.get("info", []))
                    for entry in entries:
                        entry_fs_id = str(entry.get("fs_id", ""))
                        entry_dlink = entry.get("dlink", "")
                        if entry_fs_id and entry_dlink:
                            dlink_map[entry_fs_id] = entry_dlink
                except Exception as e:
                    print(f"[ParallelResolve][ERROR] Batch filemetas request failed: {e}", flush=True)

            # Map the resolved direct links back to results
            for r in results:
                if r.get("fs_id") and not r.get("error"):
                    my_fs_id = r["fs_id"]
                    if my_fs_id in dlink_map:
                        r["dlink"] = dlink_map[my_fs_id]
                    elif action == "d":
                        r["error"] = "Failed to resolve direct download link (dlink) from batch filemetas."

    return {
        "errno": 0,
        "title": title,
        "share_id": share_id,
        "uk": uk,
        "files": results
    }

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
