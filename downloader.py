import httpx
import asyncio
import json
import logging
import urllib.parse
import sys
import re
import os
import zipfile
import time
import hashlib
import shutil

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Set stdout encoding to UTF-8 to prevent UnicodeEncodeError on Windows
if sys.version_info >= (3, 7):
    sys.stdout.reconfigure(encoding='utf-8')

# ─── Logger setup ────────────────────────────────────────────────────
logger = logging.getLogger("terabridge.downloader")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

BASE_PUBLIC = "https://www.terabox.com"
BASE_API    = "https://dm.1024terabox.com"

# Credentials must be supplied via the environment or account pool.  TeraBox
# binds tokens to a session, so source-code fallbacks are both unsafe and stale.
JSTOKEN  = os.environ.get("TERABOX_JSTOKEN", "")
BDSTOKEN = os.environ.get("TERABOX_BDSTOKEN", "")
LOGID    = os.environ.get("TERABOX_LOGID", "")
COOKIE   = os.environ.get("TERABOX_COOKIE", "")

UA = "dubox;P2SP;2.2.91.249;dubox;4.2.0.1;I2404;android-android;16;JSbridge1.0.10;jointbridge;1.1.39;"
ROOT_PATH = "/cloudvids"
VIDEO_EXTS = ('.mp4', '.mkv', '.webm', '.avi', '.mov', '.flv', '.wmv', '.m4v', '.3gp', '.mpg', '.mpeg', '.ts', '.m3u8')

def parse_cookies(cookie_str):
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

def update_credentials(cookie=None, js_token=None, bds_token=None, logid=None):
    """Dynamically update Terabox global cookies and tokens in the session."""
    global COOKIE, COOKIES_DICT, JSTOKEN, BDSTOKEN, LOGID
    if cookie:
        COOKIE = cookie
        COOKIES_DICT.clear()
        COOKIES_DICT.update(parse_cookies(cookie))
        # Clear existing cookies in session and update with new ones
        client = get_session()
        client.cookies.clear()
        for k, v in COOKIES_DICT.items():
            client.cookies.set(k, v)
    if js_token:
        JSTOKEN = js_token
    if bds_token:
        BDSTOKEN = bds_token
    if logid:
        LOGID = logid

async def validate_session_cookie(cookie_str):
    """Verify if a TeraBox cookie is valid by making a test request and checking for a bdstoken."""
    temp_cookies = parse_cookies(cookie_str)
    
    try:
        async with httpx.AsyncClient(headers=HEADERS, cookies=temp_cookies, timeout=15.0) as temp_client:
            r = await temp_client.get(f"{BASE_API}/main")
            if r.status_code != 200:
                return False, f"HTTP status {r.status_code}"
            
            # Look for bdstoken in the response HTML to verify successful session
            m = re.findall(r'bdstoken["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', r.text, re.IGNORECASE)
            if m:
                return True, "Valid"
            return False, "bdstoken not found (session likely expired or invalid)"
    except Exception as e:
        return False, f"Request failed: {str(e)}"

async def resolve_tokens_from_cookie(cookie_str):
    """
    Given a TeraBox cookie string, hit the /main page and auto-scrape
    bds_token, js_token, and logid from the response.
    Returns a dict with the resolved tokens, or raises an exception on failure.
    """
    temp_cookies = parse_cookies(cookie_str)
    resolved = {}
    
    try:
        async with httpx.AsyncClient(headers=HEADERS, cookies=temp_cookies, timeout=15.0) as temp_client:
            r = await temp_client.get(f"{BASE_API}/main")
            if r.status_code != 200:
                raise Exception(f"TeraBox returned HTTP {r.status_code}")
            
            # Scrape bdstoken
            m1 = re.findall(r'bdstoken["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', r.text, re.IGNORECASE)
            if m1:
                resolved["bds_token"] = m1[0]
            else:
                m2 = re.search(r'bdstoken\s*=\s*["\']([a-f0-9]{32})["\']', r.text)
                if m2:
                    resolved["bds_token"] = m2.group(1)
            
            # Scrape jstoken
            m3 = re.findall(r'jstoken["\']?\s*[:=]\s*["\'](.*?)["\']', r.text, re.IGNORECASE)
            if m3:
                decoded_js = urllib.parse.unquote(m3[0])
                arg_match = re.search(r'fn\s*\(\s*["\']([a-f0-9]{128})["\']\s*\)', decoded_js, re.IGNORECASE)
                if arg_match:
                    resolved["js_token"] = arg_match.group(1)
            
            # Extract logid from response cookies if available
            for cookie_name, cookie_val in r.cookies.items():
                if cookie_name.lower() == "logid":
                    resolved["logid"] = cookie_val
                    break
            
            if not resolved.get("bds_token"):
                raise Exception("bdstoken not found — cookie is likely expired or invalid")
            
            logger.info("Auto-resolved tokens: %s", list(resolved.keys()))
            return resolved
    except Exception as e:
        raise Exception(f"Failed to resolve tokens from cookie: {str(e)}")

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


def _new_logid():
    """Create a request id tied to the current account session."""
    seed = f"{int(time.time() * 1000)}{COOKIES_DICT.get('ndus', '')[:8]}"
    return hashlib.md5(seed.encode()).hexdigest().upper()


async def refresh_account_tokens():
    """Refresh account tokens from the authenticated main page.

    Returns a (bdstoken, jstoken, logid) tuple so callers can use them as
    local variables instead of relying on shared globals. This eliminates the
    need to serialize concurrent requests through a global lock.
    """
    global JSTOKEN, BDSTOKEN, LOGID

    browser_headers = {
        **HEADERS,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Referer": f"{BASE_API}/",
    }
    response = await get_session().get(f"{BASE_API}/main", headers=browser_headers, timeout=20.0)
    response.raise_for_status()
    html = response.text

    bds_match = re.search(r'["\']bdstoken["\']?\s*[:=]\s*["\']([^"\']+)', html, re.IGNORECASE)
    if not bds_match:
        raise RuntimeError("TeraBox did not return bdstoken; the account cookie may be expired")
    bdstoken = bds_match.group(1)

    jstoken = JSTOKEN  # keep existing if not found
    js_match = re.search(r'jsToken\s*=\s*["\']([^"\']+)', html, re.IGNORECASE)
    if js_match:
        decoded = urllib.parse.unquote(urllib.parse.unquote(js_match.group(1)))
        token_match = re.search(r'fn\(["\']([A-Fa-f0-9]{32,})["\']\)', decoded)
        jstoken = token_match.group(1) if token_match else decoded

    logid = _new_logid()

    # Also update globals so other callers (e.g. qp()) stay in sync
    BDSTOKEN = bdstoken
    JSTOKEN = jstoken
    LOGID = logid

    return bdstoken, jstoken, logid


async def resolve_share_session(surl, link):
    """Get the share token required by ``/share/transfer``.

    ``randsk`` must be supplied both as ``sekey`` and the ``TSID`` cookie.
    Listing a share can work without it, while copying the share usually does
    not, which is why the previous flow failed at transfer time.
    """
    share_url = link if "://" in link else f"https://{link}"
    parsed = urllib.parse.urlparse(share_url)
    bases = [f"{parsed.scheme or 'https'}://{parsed.netloc}", BASE_PUBLIC, BASE_API]
    try:
        warmup = await get_session().get(
            share_url,
            headers={**HEADERS, "Referer": f"{parsed.scheme or 'https'}://{parsed.netloc}/"},
            follow_redirects=True,
            timeout=20.0,
        )
        final_base = f"{warmup.url.scheme}://{warmup.url.host}"
        bases.insert(0, final_base)
    except httpx.HTTPError:
        pass
    seen = set()
    for base in bases:
        if not base or base in seen:
            continue
        seen.add(base)
        for shorturl in (surl, f"1{surl}" if not surl.startswith("1") else surl[1:]):
            params = {
                "app_id": "250528", "shorturl": shorturl, "root": "1",
                "web": "1", "channel": "dubox", "clienttype": "0", "jsToken": JSTOKEN,
            }
            try:
                response = await get_session().get(
                    f"{base}/api/shorturlinfo",
                    params=params,
                    headers={**HEADERS, "Referer": f"{base}/"},
                    follow_redirects=True,
                    timeout=20.0,
                )
                data = response.json()
            except (httpx.HTTPError, ValueError):
                continue
            if data.get("errno") == 0:
                randsk = urllib.parse.unquote(data.get("randsk", ""))
                if randsk:
                    for domain in (parsed.hostname, urllib.parse.urlparse(BASE_API).hostname):
                        if domain:
                            get_session().cookies.set("TSID", randsk, domain=domain, path="/")
                return data
    return {}


async def wait_for_transfer(task_id, bdstoken_val):
    """Wait until TeraBox confirms an asynchronous share copy completed."""
    for _ in range(60):
        response = await get_session().get(
            f"{BASE_API}/share/taskquery",
            params={
                "taskid": str(task_id), "app_id": "250528", "web": "1",
                "channel": "dubox", "clienttype": "0", "jsToken": JSTOKEN,
                "bdstoken": bdstoken_val,
            },
            timeout=15.0,
        )
        result = response.json()
        status = result.get("status")
        if status in (2, "success") or (status == -1 and result.get("errno") == 0):
            return {"errno": 0}
        if status in (3, "failed") or result.get("errno", 0) not in (0,):
            return result
        await asyncio.sleep(2)
    return {"errno": -1, "errmsg": "Timed out waiting for TeraBox transfer"}


async def transfer_shared_file(fs_id, share_id, uk, share_session, bdstoken_val):
    """Copy one shared file using the share-session-aware transfer contract."""
    sekey = urllib.parse.unquote(share_session.get("randsk", ""))
    profiles = [
        ("12", "terabox;1.40.0.132;PC;PC-Windows;10.0.26100;WindowsTeraBox"),
        ("0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        ("5", "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"),
    ]
    last_result = {"errno": -1, "errmsg": "No transfer response"}
    for clienttype, user_agent in profiles:
        params = {
            "app_id": "250528", "web": "1" if clienttype == "0" else "0",
            "channel": "dubox", "clienttype": clienttype, "jsToken": JSTOKEN,
            "shareid": str(share_id), "from": str(uk), "sekey": sekey,
            "ondup": "newcopy", "async": "2", "bdstoken": bdstoken_val,
            "logid": _new_logid(),
        }
        try:
            response = await get_session().post(
                f"{BASE_API}/share/transfer",
                params=params,
                data={"fsidlist": json.dumps([fs_id]), "path": ROOT_PATH},
                headers={
                    **HEADERS, "User-Agent": user_agent, "Referer": f"{BASE_API}/",
                    "Origin": BASE_API, "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=30.0,
            )
            last_result = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            last_result = {"errno": -1, "errmsg": str(exc)}

        if last_result.get("errno") in (0, 4, 12):
            task_id = last_result.get("task_id")
            if task_id and last_result.get("errno") == 0:
                task_result = await wait_for_transfer(task_id, bdstoken_val)
                if task_result.get("errno") != 0:
                    return task_result
            return last_result
        if last_result.get("errno") not in (400810, 400141, -6):
            return last_result
        await asyncio.sleep(0.75)
        await refresh_account_tokens()
        bdstoken_val = BDSTOKEN
    return last_result

def _create_session():
    """Create an httpx.AsyncClient with connection pooling."""
    pool_conn = int(os.environ.get("HTTP_POOL_CONNECTIONS", 50))
    pool_max = int(os.environ.get("HTTP_POOL_MAXSIZE", 100))
    limits = httpx.Limits(max_keepalive_connections=pool_conn, max_connections=pool_max)
    
    s = httpx.AsyncClient(
        headers=HEADERS,
        cookies=COOKIES_DICT,
        limits=limits,
        timeout=httpx.Timeout(30.0),
        http2=True
    )
    return s

_session = None


def get_session():
    """Return the live shared client, recreating it after app shutdown/tests."""
    global _session
    if _session is None or _session.is_closed:
        _session = _create_session()
    return _session


async def close_session():
    """Close the current client without leaving a permanently closed global."""
    global _session
    if _session is not None and not _session.is_closed:
        await _session.aclose()

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

async def _process_single_file_metadata(item, share_id, uk, share_session, existing_files, action, wait_for_transcoding, bdstoken_val, quality=None):
    """
    Processes a single file from the shared link (transfer + streaming checks).
    This function is run asynchronously.
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
        try:
            transfer_res = await transfer_shared_file(
                fs_id, share_id, uk, share_session, bdstoken_val
            )
        except Exception as e:
            file_res["error"] = f"Transfer API request failed: {e}"
            file_res["transfer_status"] = "failed"
            return file_res

        if transfer_res.get("errno") == 2:
            # Target directory ROOT_PATH likely does not exist. Auto-create it and retry.
            create_url = f"{BASE_API}/api/create?{qp()}&bdstoken={bdstoken_val}"
            create_payload = {
                "path": ROOT_PATH,
                "isdir": "1",
                "size": "0",
                "block_list": "[]",
                "method": "post"
            }
            try:
                cr = await get_session().post(create_url, data=create_payload)
                cr_res = cr.json()
                if cr_res.get("errno") in (0, -8): # 0 = created, -8 = already exists
                    # Retry transfer
                    transfer_res = await transfer_shared_file(
                        fs_id, share_id, uk, share_session, BDSTOKEN
                    )
            except Exception as e:
                logger.warning("Failed to auto-create directory: %s", e)

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
                r_list = await get_session().get(
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
    file_res["path"] = my_file_path
    
    # --- ACTION HLS STREAMING ---
    is_video = bool(filename and filename.lower().endswith(VIDEO_EXTS))

    if action == "s" and is_video:
        if not my_file_path:
            my_file_path = ROOT_PATH.rstrip("/") + "/" + filename
        encoded_path = urllib.parse.quote(my_file_path)
        
        # Try multiple stream quality types — highest first
        if quality:
            stream_types = [quality]
        else:
            stream_types = ["M3U8_AUTO_1080", "M3U8_AUTO_720", "M3U8_AUTO_480", "M3U8_AUTO_360"]
        
        async def _try_stream(stype):
            """Try a single streaming request. Returns (success, errno, response_text)."""
            res_val = "1080p" if "1080" in stype else ("720p" if "720" in stype else ("480p" if "480" in stype else "360p"))
            url = (
                f"{BASE_API}/api/streaming?{qp()}&path={encoded_path}&type={stype}"
                f"&bdstoken={bdstoken_val}&isplayer=1&check_blue=1&clienttype=1&resolution={res_val}"
            )
            try:
                sr = await get_session().get(url, timeout=20.0)
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
            ok, errno, text = await _try_stream(stype)
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
            logger.info("All resolutions still transcoding, waiting (up to %ds)...", max_retries * retry_delay)
            for attempt in range(1, max_retries + 1):
                await asyncio.sleep(retry_delay)
                # Retry all types each round (highest first)
                for stype in stream_types:
                    ok, errno, text = await _try_stream(stype)
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

_resolve_lock = asyncio.Lock()


async def resolve_link(link, action="d", wait_for_transcoding=False, quality=None):
    """Dispatch resolution without a global lock.

    Tokens are refreshed locally inside each call, so concurrent requests for
    different links are fully parallel. The single-flight / request-collapsing
    logic in index.py deduplicates requests for the *same* link.
    """
    return await _resolve_link(link, action, wait_for_transcoding, quality)


async def _resolve_link(link, action="d", wait_for_transcoding=False, quality=None):
    """
    Exposes the core resolution logic.
    Returns a dict with metadata, transfer status, direct links, or streaming playlists.
    """
    # Refresh tokens for this request — returns local copies so concurrent
    # calls don't stomp each other's globals mid-request.
    try:
        bdstoken, jstoken, _ = await refresh_account_tokens()
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
        r = await get_session().get(list_url)
        share_data = r.json()
    except Exception as e:
        return {"errno": -2, "error": f"Failed to query share list: {e}"}

    if share_data.get("errno") != 0:
        return {
            "errno": share_data.get("errno"),
            "error": f"Share link is invalid or expired (errno={share_data.get('errno')}, msg={share_data.get('errmsg', 'none')}, request_id={share_data.get('request_id', 'none')})."
        }

    share_session = await resolve_share_session(surl, link)

    title = share_data.get("title", "Untitled Shared Content")
    share_id = share_data.get("share_id")
    uk = share_data.get("uk")
    files_list = share_data.get("list", [])

    # Pre-fetch list of existing files in ROOT_PATH to prevent duplication
    existing_files = {}
    if action != "l":
        encoded_dir = urllib.parse.quote(ROOT_PATH)
        try:
            r_list = await get_session().get(
                f"{BASE_API}/api/list?{qp()}&dir={encoded_dir}&order=time&desc=1&showempty=0&page=1&num=1000&bdstoken={bdstoken}"
            )
            list_res = r_list.json()
            if list_res.get("errno") == 0:
                for entry in list_res.get("list", []):
                    name = entry.get("server_filename")
                    existing_files[name] = {
                        "fs_id": str(entry.get("fs_id", "")),
                        "path": entry.get("path", ""),
                        "size": int(entry.get("size", 0)),
                        "time": int(entry.get("server_mtime") or entry.get("ctime") or 0)
                    }
        except Exception as e:
            logger.warning("Failed to list existing account files: %s", e)

    # Transfer requests mutate the same account/session. Serialising them
    # avoids triggering TeraBox verification when a shared folder is large.
    results = []
    for item in files_list:
        results.append(await _process_single_file_metadata(
            item,
            share_id,
            uk,
            share_session,
            existing_files,
            action,
            wait_for_transcoding,
            bdstoken,
            quality
        ))

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
                
                metas_url = f"{BASE_API}/api/filemetas?{qp()}&fsids={encoded_fsids}&dlink=1&thumb=0&bdstoken={bdstoken}"
                try:
                    mr = await get_session().get(metas_url, timeout=20.0)
                    metas_res = mr.json()
                    
                    entries = metas_res.get("list", metas_res.get("info", []))
                    for entry in entries:
                        entry_fs_id = str(entry.get("fs_id", ""))
                        entry_dlink = entry.get("dlink", "")
                        if entry_fs_id and entry_dlink:
                            dlink_map[entry_fs_id] = entry_dlink
                except Exception as e:
                    logger.error("Batch filemetas request failed: %s", e)

            # Map the resolved direct links back to results
            for r in results:
                if r.get("fs_id") and not r.get("error"):
                    my_fs_id = r["fs_id"]
                    if my_fs_id in dlink_map:
                        r["dlink"] = dlink_map[my_fs_id]
                    elif action == "d":
                        r["error"] = "Failed to resolve direct download link (dlink) from batch filemetas."

            # --- OPTIMIZE VIA LOCATEDOWNLOAD ---
            # Resolve premium geographically-located CDN mirror links
            async def upgrade_with_locate(r):
                path = r.get("path")
                if not path or r.get("is_directory") or r.get("error"):
                    return
                
                encoded_path = urllib.parse.quote(path)
                locate_url = (
                    f"{BASE_API}/rest/2.0/pcs/file"
                    f"?ant=1&app_id=250528&channel=0&check_blue=1&clienttype=17"
                    f"&method=locatedownload&path={encoded_path}&vip=2"
                )
                try:
                    # Request located mirrors with the same session cookies
                    mr = await get_session().post(locate_url, content=" =", timeout=15.0)
                    if mr.status_code == 200:
                        urls = mr.json().get("urls", [])
                        if urls:
                            best_url = urls[0].get("url")
                            if best_url:
                                r["dlink"] = best_url
                                # Keep reference to all mirrors for advanced tools if needed
                                r["mirrors"] = [u.get("url") for u in urls]
                except Exception:
                    pass
            
            locate_tasks = [upgrade_with_locate(r) for r in results if r.get("path")]
            if locate_tasks:
                await asyncio.gather(*locate_tasks)

    return {
        "errno": 0,
        "title": title,
        "share_id": share_id,
        "uk": uk,
        "files": results
    }

async def download_file(dlink, filename):
    print("✅ Direct download link retrieved successfully!")
    print(f"   Link: {dlink[:100]}...")

    # Stream the download
    print(f"Downloading to local file: {filename} ...")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as dl_client:
            async with dl_client.stream(
                "GET",
                dlink,
                headers={
                    "User-Agent": UA,
                    "Referer": BASE_API + "/",
                },
                cookies=COOKIES_DICT,
            ) as dr:
                content_type = dr.headers.get("Content-Type", "")
                content_length = int(dr.headers.get("Content-Length", 0))
                print(f"  HTTP Response: {dr.status_code} | Type: {content_type} | Size: {content_length/1024/1024:.2f} MB")

                if dr.status_code not in (200, 206) or content_length < 1000:
                    print(f"❌ Bad download stream response: {(await dr.aread())[:300].decode('utf-8', errors='ignore')}")
                    return False

                is_zip = "zip" in content_type.lower()
                safe_filename = os.path.basename(filename)
                if not safe_filename or safe_filename in (".", ".."):
                    safe_filename = "downloaded_file"
                temp_filename = safe_filename + ".zip" if is_zip else safe_filename

                # Write chunks to file
                with open(temp_filename, "wb") as f:
                    downloaded = 0
                    term_cols = shutil.get_terminal_size((80, 20)).columns
                    bar_len = min(25, max(10, term_cols - 45))
                    tot_mb = content_length / (1024 * 1024) if content_length else 0.0

                    async for chunk in dr.aiter_bytes(1024 * 1024):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            pct = downloaded / content_length * 100 if content_length else 0
                            filled = int(pct / 100 * bar_len)
                            bar = "█" * filled + "░" * (bar_len - filled)
                            dl_mb = downloaded / (1024 * 1024)
                            status_line = f"\r  [{bar}] {pct:5.1f}%  {dl_mb:.1f}/{tot_mb:.1f} MB"
                            sys.stdout.write(status_line.ljust(term_cols - 1)[:term_cols - 1])
                            sys.stdout.flush()

                    # Finalize progress bar on its own line
                    sys.stdout.write(f"\r  [{'█' * bar_len}] 100.0%  {tot_mb:.1f}/{tot_mb:.1f} MB\n")
                    sys.stdout.flush()

                if is_zip:
                    print("📦 Extracting ZIP archive...")
                    try:
                        def extract_zip():
                            dest_dir = os.path.abspath(".")
                            with zipfile.ZipFile(temp_filename, "r") as zf:
                                for member in zf.infolist():
                                    target_path = os.path.abspath(os.path.join(dest_dir, member.filename))
                                    if not target_path.startswith(dest_dir + os.sep) and target_path != dest_dir:
                                        raise RuntimeError(f"Zip traversal detected: {member.filename}")
                                    zf.extract(member, dest_dir)
                            os.remove(temp_filename)
                        await asyncio.to_thread(extract_zip)
                        print(f"✅ Extraction completed successfully!")
                        return True
                    except Exception as e:
                        print(f"⚠️ Error extracting ZIP: {e}")
                        print(f"ZIP file kept at: {temp_filename}")
                        return False
                else:
                    print(f"✅ Successfully saved: {safe_filename}")
                    return True
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return False

async def main():
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
    res = await resolve_link(link, action=action, wait_for_transcoding=True)

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
                safe_stream_filename = os.path.basename(filename) or "stream_video"
                m3u8_filename = os.path.splitext(safe_stream_filename)[0] + ".m3u8"
                with open(m3u8_filename, "w", encoding="utf-8") as f:
                    f.write(file.get("stream_m3u8"))
                print(f"✅ Saved M3U8 streaming playlist to: {m3u8_filename}")
                print(f"   You can open {m3u8_filename} directly in VLC or PotPlayer to stream the video!")
            else:
                choice = input("\nStreaming playlist generation failed (transcoding). Would you like to [D]ownload the raw file instead or [E]xit/Skip? (D/E): ").strip().lower()
                if choice == "d":
                    download_res = await resolve_link(link, action="d")
                    download_file_info = next((f for f in download_res.get("files", []) if f["original_fs_id"] == file["original_fs_id"]), None)
                    if download_file_info and download_file_info.get("dlink"):
                        await download_file(download_file_info["dlink"], filename)
                continue

        elif action == "d":
            dlink = file.get("dlink")
            if dlink:
                await download_file(dlink, filename)

if __name__ == "__main__":
    async def run_cli():
        try:
            await main()
        finally:
            await close_session()

    try:
        asyncio.run(run_cli())
    except KeyboardInterrupt:
        print("\nExiting...")
