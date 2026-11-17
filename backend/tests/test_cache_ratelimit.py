from phishguard.cache import TTLCache
from phishguard.ratelimit import TokenBucketLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_cache_expires_after_ttl():
    clock = FakeClock()
    cache = TTLCache(ttl_seconds=10, clock=clock)
    cache.set("k", 1)
    assert cache.get("k") == 1
    clock.now += 11
    assert cache.get("k") is None
    assert cache.stats()["hits"] == 1 and cache.stats()["misses"] == 1


def test_cache_evicts_least_recently_used():
    cache = TTLCache(max_items=2)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.get("a")          # "a" is now the most recently used
    cache.set("c", 3)       # so "b" is evicted
    assert cache.get("b") is None and cache.get("a") == 1 and cache.get("c") == 3


def test_token_bucket_allows_burst_then_limits():
    clock = FakeClock()
    limiter = TokenBucketLimiter(capacity=3, refill_per_sec=1, clock=clock)
    assert [limiter.take("ip")[0] for _ in range(4)] == [True, True, True, False]
    allowed, wait = limiter.take("ip")
    assert not allowed and wait == 1.0
    clock.now += 1
    assert limiter.take("ip")[0]


def test_expensive_requests_cost_more_and_clients_are_separate():
    clock = FakeClock()
    limiter = TokenBucketLimiter(capacity=5, refill_per_sec=1, clock=clock)
    assert limiter.take("a", cost=5)[0]
    assert not limiter.take("a", cost=5)[0]
    assert limiter.take("b", cost=5)[0]  # another client has its own bucket


def test_limiter_memory_is_bounded():
    clock = FakeClock()
    limiter = TokenBucketLimiter(capacity=2, refill_per_sec=1, clock=clock, max_clients=10)
    for i in range(10):
        limiter.take(f"ip{i}")
    clock.now += 100  # every bucket has refilled
    limiter.take("one-more")
    assert len(limiter._buckets) <= 2
