import diskcache
import os
from typing import Any
from ..config import CACHE_DIR, CACHE_TTL

class ScanCache:
    def __init__(self):
        self.cache = diskcache.Cache(CACHE_DIR)

    def get(self, key: str) -> Any:
        """Retrieve a value from the cache."""
        return self.cache.get(key)

    def set(self, key: str, value: Any, ttl: int = CACHE_TTL) -> None:
        """Set a value in the cache with a TTL."""
        self.cache.set(key, value, expire=ttl)

    def clear(self) -> None:
        """Clear the cache."""
        self.cache.clear()

    def close(self) -> None:
        """Close the cache."""
        self.cache.close()
