"""Optional caching of immutable inventory context, never prediction decisions."""
import hashlib
import json

class InventoryCache:
    def __init__(self, redis_url='redis://localhost:6379', ttl=60):
        self.ttl = ttl
        self.client = None
        try:
            import redis
            client = redis.from_url(redis_url, decode_responses=True, socket_timeout=1)
            client.ping()
            self.client = client
        except Exception:
            pass

    def _key(self, inventory_version, operation_key):
        return 'sentry:inventory:' + hashlib.sha256(json.dumps([inventory_version, operation_key]).encode()).hexdigest()

    def get(self, inventory_version, operation_key):
        if self.client is None:
            return None
        try:
            raw = self.client.get(self._key(inventory_version, operation_key))
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def set(self, inventory_version, operation_key, context):
        if self.client is not None:
            try:
                self.client.setex(self._key(inventory_version, operation_key), self.ttl, json.dumps(context))
            except Exception:
                pass
