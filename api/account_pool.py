import json
import logging
import time
import re
import httpx
from api.redis_client import redis_client

logger = logging.getLogger("terabridge.account_pool")

ACCOUNTS_HASH_KEY = "terabridge:accounts"
ACTIVE_ACCOUNT_KEY = "terabridge:active_account_id"

def safe_json_loads(val):
    """Safely parse JSON from Redis strings, bytes, or dicts, stripping trailing commas if needed."""
    if not val:
        return {}
    if isinstance(val, dict):
        return val
    if isinstance(val, bytes):
        val = val.decode("utf-8", errors="ignore")
    if not isinstance(val, str):
        return {}
    try:
        return json.loads(val)
    except Exception:
        cleaned = re.sub(r',\s*([}\]])', r'\1', val)
        try:
            return json.loads(cleaned)
        except Exception:
            return {}

def extract_ndus(cookie_str: str) -> str:
    """Extract the ndus token value from a cookie string."""
    for part in (cookie_str or "").split(";"):
        p = part.strip()
        if p.startswith("ndus="):
            return p.split("=", 1)[1].strip()
    return ""

async def fetch_account_profile(cookie_str: str, bds_token: str = None) -> dict:
    """
    Query TeraBox to retrieve user profile metadata:
    username, unmasked email (gmail), uk, and avatar.
    """
    if not cookie_str:
        return {}
    from downloader import parse_cookies, BASE_API, UA, qp
    cookies_dict = parse_cookies(cookie_str)
    cookies_dict['PANWEB'] = '1'
    headers = {'User-Agent': UA, 'Referer': 'https://dm.1024terabox.com/main'}

    try:
        async with httpx.AsyncClient(headers=headers, cookies=cookies_dict, follow_redirects=True, timeout=12.0) as client:
            # 1. Scrape bdstoken and uk from /main
            r = await client.get(f"{BASE_API}/main")
            m_uk = re.search(r'["\']uk["\']\s*:\s*["\']?(\d+)', r.text)
            m_bds = re.search(r'["\']bdstoken["\']\s*:\s*["\']([a-f0-9]{32})["\']', r.text)
            uk = m_uk.group(1) if m_uk else None
            bds = bds_token or (m_bds.group(1) if m_bds else "")

            if not uk:
                r_login = await client.get(f"{BASE_API}/api/check/login")
                data_login = r_login.json()
                if data_login.get("errno") == 0 and data_login.get("uk"):
                    uk = str(data_login.get("uk"))

            if not uk:
                return {}

            params = {
                "need_relation": "0",
                "need_secret_info": "1",
                "user_list": json.dumps([uk]),
                "bdstoken": bds,
            }
            r_info = await client.get(f"{BASE_API}/api/user/getinfo?{qp()}", params=params)
            info = r_info.json()
            if info.get("errno") == 0 and info.get("records"):
                rec = info["records"][0]
                return {
                    "username": rec.get("uname") or rec.get("nick_name") or "",
                    "email": rec.get("bind_res") or rec.get("email") or "",
                    "uk": str(rec.get("uk") or uk),
                    "avatar_url": rec.get("avatar_url") or "",
                    "vip_type": rec.get("vip_type", 0),
                }
    except Exception as e:
        logger.debug("Failed to fetch profile for account: %s", e)
    return {}

def get_all_accounts():
    """Fetch all accounts from Upstash Redis using resilient JSON parsing."""
    if not redis_client:
        return {}
    try:
        raw_accounts = redis_client.hgetall(ACCOUNTS_HASH_KEY) or {}
        accounts = {}
        for acc_id, raw_val in raw_accounts.items():
            acc_id_str = acc_id.decode("utf-8") if isinstance(acc_id, bytes) else acc_id
            data = safe_json_loads(raw_val)
            if data:
                accounts[acc_id_str] = data
        return accounts
    except Exception as e:
        logger.error("Failed to fetch accounts from Redis: %s", e)
        return {}

def get_next_healthy_account():
    """
    Selects the least recently used healthy account from the pool (Round-Robin),
    sets it as the active account, and returns its credentials.
    """
    if not redis_client:
        return None, None

    try:
        accounts = get_all_accounts()
        healthy_accounts = {
            acc_id: data for acc_id, data in accounts.items()
            if data.get("status", "healthy") == "healthy"
        }

        if not healthy_accounts:
            logger.error("No healthy accounts available in the pool!")
            return None, None

        # Sort by last_used timestamp to round-robin
        sorted_accounts = sorted(healthy_accounts.items(), key=lambda x: x[1].get("last_used", 0))
        selected_id, selected_data = sorted_accounts[0]

        # Update last_used timestamp in Redis to place it at the back of the queue
        selected_data["last_used"] = int(time.time())
        redis_client.hset(ACCOUNTS_HASH_KEY, selected_id, json.dumps(selected_data))
        
        # Store active account ID
        redis_client.set(ACTIVE_ACCOUNT_KEY, selected_id)
        logger.info("Rotated and selected healthy account: %s", selected_id)
        return selected_id, selected_data
    except Exception as e:
        logger.error("Error selecting next healthy account: %s", e)
        return None, None

def mark_account_unhealthy(account_id, reason="unknown"):
    """Mark an account as unhealthy in the Redis pool to prevent reuse."""
    if not redis_client or not account_id:
        return
    
    try:
        accounts = get_all_accounts()
        if account_id in accounts:
            data = accounts[account_id]
            data["status"] = "unhealthy"
            data["unhealthy_reason"] = reason
            data["unhealthy_at"] = int(time.time())
            redis_client.hset(ACCOUNTS_HASH_KEY, account_id, json.dumps(data))
            logger.warning("Account '%s' marked UNHEALTHY. Reason: %s", account_id, reason)
    except Exception as e:
        logger.error("Failed to mark account %s unhealthy: %s", account_id, e)
