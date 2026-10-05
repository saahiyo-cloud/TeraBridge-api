import os
import logging
try:
    from upstash_redis import Redis
except ImportError:
    Redis = None

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

if UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN and Redis is not None:
    try:
        redis_client = Redis(url=UPSTASH_REDIS_REST_URL, token=UPSTASH_REDIS_REST_TOKEN)
        redis_client.ping()
        logger.info("Successfully connected to Upstash Redis.")
    except Exception as e:
        logger.error("Failed to initialize Upstash Redis: %s", e)
        redis_client = None
elif not Redis and (UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN):
    logger.warning("Upstash Redis credentials present, but 'upstash-redis' package is not installed. Falling back to local in-memory.")
else:
    logger.info("Upstash Redis credentials not detected. Caching and Rate Limiting will use local in-memory.")
