import os
import logging

try:
    from upstash_redis import Redis as SyncRedis
except ImportError:
    SyncRedis = None

try:
    from upstash_redis.asyncio import Redis as AsyncRedis
except ImportError:
    AsyncRedis = None

logger = logging.getLogger("terabridge.redis")

# Try loading env in case it is imported standalone
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

UPSTASH_REDIS_REST_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

redis_client = None
async_redis_client = None

if UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN:
    if SyncRedis is not None:
        try:
            redis_client = SyncRedis(url=UPSTASH_REDIS_REST_URL, token=UPSTASH_REDIS_REST_TOKEN)
            logger.info("Initialized sync Upstash Redis client.")
        except Exception as e:
            logger.error("Failed to initialize sync Upstash Redis: %s", e)
            redis_client = None

    if AsyncRedis is not None:
        try:
            async_redis_client = AsyncRedis(url=UPSTASH_REDIS_REST_URL, token=UPSTASH_REDIS_REST_TOKEN)
            logger.info("Initialized async Upstash Redis client.")
        except Exception as e:
            logger.error("Failed to initialize async Upstash Redis: %s", e)
            async_redis_client = None
    elif not AsyncRedis:
        logger.warning("AsyncRedis not available; falling back to sync or local in-memory.")
else:
    logger.info("Upstash Redis credentials not detected. Caching and Rate Limiting will use local in-memory.")


def get_async_redis():
    """Return the active async Redis client, or None."""
    global async_redis_client
    return async_redis_client
