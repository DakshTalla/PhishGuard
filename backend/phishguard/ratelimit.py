"""Per-client token-bucket rate limiter.

Each client (IP address) has a bucket holding up to `capacity` tokens that
refills at `refill_per_sec`. A request spends tokens; with too few left it is
rejected with HTTP 429 and a Retry-After header.

WHY a token bucket rather than "N requests per minute": it allows short
bursts (opening ten tabs at once) while still capping the long-run rate.
WHY full scans cost more: they make outbound DNS, TLS, WHOIS and HTTP calls,
so without a higher price one client could use our server to hammer others.
"""
from __future__ import annotations

import threading
import time
from typing import Callable


class TokenBucketLimiter:
    def __init__(self, capacity: float = 30, refill_per_sec: float = 0.5,
                 clock: Callable[[], float] = time.monotonic, max_clients: int = 10_000):
        self.capacity = capacity
        self.refill = refill_per_sec
        self._clock = clock
        self._max_clients = max_clients
        self._buckets: dict[str, tuple[float, float]] = {}  # client -> (tokens, last update)
        self._lock = threading.Lock()

    def take(self, client: str, cost: float = 1) -> tuple[bool, float]:
        """Try to spend `cost` tokens. Returns (allowed, seconds until allowed)."""
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(client, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill)
            if tokens >= cost:
                self._buckets[client] = (tokens - cost, now)
                allowed, wait = True, 0.0
            else:
                self._buckets[client] = (tokens, now)
                allowed, wait = False, (cost - tokens) / self.refill
            if len(self._buckets) > self._max_clients:
                self._forget_full_buckets(now)
        return allowed, wait

    def _forget_full_buckets(self, now: float) -> None:
        """Drop clients whose bucket has refilled: they are indistinguishable
        from new clients, and this keeps memory bounded."""
        for client, (tokens, last) in list(self._buckets.items()):
            if tokens + (now - last) * self.refill >= self.capacity:
                del self._buckets[client]
