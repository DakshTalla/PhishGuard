"""A small thread-safe TTL + LRU cache.

WHY our own instead of a library: it is ~40 lines, and being able to explain
every line beats a dependency. Two instances are used:
  * scan results, keyed by "mode:normalised-url" (10 minutes), so a page that
    is opened repeatedly is scored once;
  * host intel (DNS/TLS/WHOIS), keyed by host (6 hours), because many URLs on
    the same site share it and WHOIS servers rate-limit aggressive callers.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Callable


class TTLCache:
    def __init__(self, max_items: int = 5000, ttl_seconds: float = 600,
                 clock: Callable[[], float] = time.monotonic):
        self.max_items = max_items
        self.ttl = ttl_seconds
        self._clock = clock  # injectable so tests can move time forward
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()  # FastAPI runs sync endpoints in a thread pool
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Any | None:
        with self._lock:
            item = self._data.get(key)
            if item is None or item[0] < self._clock():
                if item is not None:
                    del self._data[key]  # expired
                self.misses += 1
                return None
            self._data.move_to_end(key)  # mark as recently used
            self.hits += 1
            return item[1]

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = (self._clock() + self.ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self.max_items:
                self._data.popitem(last=False)  # evict the least recently used

    def stats(self) -> dict:
        with self._lock:
            total = self.hits + self.misses
            return {"size": len(self._data), "hits": self.hits, "misses": self.misses,
                    "hit_rate": round(self.hits / total, 4) if total else 0.0}
