import json
import time
from api.redis_client import redis_client

ACCOUNTS_HASH_KEY = "terabridge:accounts"
ACTIVE_ACCOUNT_KEY = "terabridge:active_account_id"

def get_all_accounts():
    """Fetch all accounts from Upstash Redis."""
    if not redis_client:
        return {}
    try:
        raw_accounts = redis_client.hgetall(ACCOUNTS_HASH_KEY) or {}
        accounts = {}
        for acc_id, raw_val in raw_accounts.items():
            try:
                accounts[acc_id] = json.loads(raw_val)
            except Exception:
                pass
        return accounts
    except Exception as e:
        print(f"[AccountPool][ERROR] Failed to fetch accounts from Redis: {e}", flush=True)
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
            print("[AccountPool][ERROR] No healthy accounts available in the pool!", flush=True)
            return None, None

        # Sort by last_used timestamp to round-robin
        sorted_accounts = sorted(healthy_accounts.items(), key=lambda x: x[1].get("last_used", 0))
        selected_id, selected_data = sorted_accounts[0]

        # Update last_used timestamp in Redis to place it at the back of the queue
        selected_data["last_used"] = int(time.time())
        redis_client.hset(ACCOUNTS_HASH_KEY, selected_id, json.dumps(selected_data))
        
        # Store active account ID
        redis_client.set(ACTIVE_ACCOUNT_KEY, selected_id)
        print(f"[AccountPool] Rotated and selected healthy account: {selected_id}", flush=True)

        return selected_id, selected_data
    except Exception as e:
        print(f"[AccountPool][ERROR] Error selecting next healthy account: {e}", flush=True)
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
            print(f"[AccountPool] Account '{account_id}' marked UNHEALTHY. Reason: {reason}", flush=True)
    except Exception as e:
        print(f"[AccountPool][ERROR] Failed to mark account {account_id} unhealthy: {e}", flush=True)
