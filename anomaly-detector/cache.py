import json
import logging
import os

logger = logging.getLogger(__name__)

# Cache TTL: 5 minutes. Acts as a staleness guard between model retrains.
# LFU eviction (allkeys-lfu) is configured at the Redis server level and
# handles memory pressure independently of this TTL.
CACHE_TTL_SECONDS = int(os.environ.get("SENTRY_CACHE_TTL", 300))
KEY_PREFIX = "sentry:ep"


class EndpointCache:
    """
    Redis-backed result cache for anomaly predictions.

    Keys are namespaced as `sentry:ep:<METHOD>:<path>`.
    LFU eviction is handled by Redis server policy (allkeys-lfu) — 
    frequently-accessed endpoints survive memory pressure while rare
    endpoints are evicted first. The TTL ensures stale results are 
    periodically re-evaluated even when Redis has free memory.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self._client = None
        try:
            import redis
            self._client = redis.from_url(redis_url, decode_responses=True)
            # Ping to verify the connection is live
            self._client.ping()
            logger.info(f"✓ Redis cache connected at {redis_url}")

            # Auto-configure Redis settings programmatically to reduce manual setup hassle
            try:
                max_mem = os.environ.get("SENTRY_REDIS_MAXMEMORY", "64mb")
                self._client.config_set("maxmemory", max_mem)
                self._client.config_set("maxmemory-policy", "allkeys-lfu")
                logger.info(f"✓ Programmatically configured Redis: maxmemory={max_mem}, policy=allkeys-lfu")
            except Exception as config_err:
                # Fail gracefully if CONFIG commands are disabled/restricted (common in production/managed environments)
                logger.warning(
                    f"⚠ Redis connected, but config update failed ({config_err}). "
                    "Ensure maxmemory-policy is set to allkeys-lfu in your Redis settings."
                )

        except Exception as e:
            logger.warning(
                f"⚠ Redis unavailable ({e}). Predictions will run without caching."
            )
            self._client = None

    def _key(self, method: str, path: str) -> str:
        # Sanitize the path so it doesn't clash with Redis key separators
        safe_path = path.replace(":", "_")
        return f"{KEY_PREFIX}:{method.upper()}:{safe_path}"

    def get(self, method: str, path: str) -> dict | None:
        """Returns the cached prediction result, or None on cache miss / Redis down."""
        if self._client is None:
            return None
        try:
            raw = self._client.get(self._key(method, path))
            if raw is None:
                return None
            result = json.loads(raw)
            result["cached"] = True
            return result
        except Exception as e:
            logger.warning(f"⚠ Redis GET failed: {e}")
            return None

    def set(self, method: str, path: str, result: dict) -> None:
        """Stores a prediction result with the configured TTL."""
        if self._client is None:
            return
        try:
            # Don't cache anomalous results — we always want those re-evaluated
            if result.get("is_anomaly"):
                return
            payload = json.dumps(result)
            self._client.setex(self._key(method, path), CACHE_TTL_SECONDS, payload)
        except Exception as e:
            logger.warning(f"⚠ Redis SET failed: {e}")

    def flush_model_cache(self) -> int:
        """
        Deletes all endpoint cache keys. Called after every model swap to 
        ensure stale results from the previous model are never served.
        Returns the number of keys deleted.
        """
        if self._client is None:
            return 0
        try:
            # SCAN is non-blocking and safe for production (unlike KEYS *)
            deleted = 0
            cursor = 0
            pattern = f"{KEY_PREFIX}:*"
            while True:
                cursor, keys = self._client.scan(cursor, match=pattern, count=100)
                if keys:
                    deleted += self._client.delete(*keys)
                if cursor == 0:
                    break
            logger.info(f"✓ Redis model cache flushed: {deleted} keys deleted")
            return deleted
        except Exception as e:
            logger.warning(f"⚠ Redis cache flush failed: {e}")
            return 0

    @property
    def is_available(self) -> bool:
        return self._client is not None
