"""
api/account_manager.py — Runtime credential sync from the Redis account pool.

Bridges api/account_pool.py (pure pool logic) and downloader.py (global credentials).
Called at startup and periodically by ConfigRefreshMiddleware.
"""
import json
import logging

from api.redis_client import redis_client
from api.account_pool import (
    ACCOUNTS_HASH_KEY,
    ACTIVE_ACCOUNT_KEY,
    get_next_healthy_account,
    safe_json_loads,
)

logger = logging.getLogger("terabridge.account_manager")


def load_config_from_redis():
    """
    Read the active account from Redis and push its credentials into
    downloader's global session state.

    No-op when Redis is not configured.
    """
    # Deferred import: downloader uses globals that must be readable
    # before this function is called, but we must not import at module
    # level to avoid circular-import issues during startup.
    from downloader import update_credentials
    from api.routes.resolve import set_active_account_id

    if not redis_client:
        return

    try:
        active_id = redis_client.get(ACTIVE_ACCOUNT_KEY)
        if isinstance(active_id, bytes):
            active_id = active_id.decode("utf-8")

        creds = None

        if active_id:
            raw_creds = redis_client.hget(ACCOUNTS_HASH_KEY, active_id)
            if raw_creds:
                creds = safe_json_loads(raw_creds)

        # If the stored active account is unhealthy (or missing), rotate
        if not creds or creds.get("status") != "healthy":
            active_id, creds = get_next_healthy_account()

        if creds:
            set_active_account_id(active_id)
            update_credentials(
                cookie=creds.get("cookie"),
                js_token=creds.get("js_token"),
                bds_token=creds.get("bds_token"),
                logid=creds.get("logid"),
            )
            logger.info("Synchronized active pool account: %s", active_id)

    except Exception as exc:
        logger.warning("Failed to load config from Redis pool: %s", exc)
