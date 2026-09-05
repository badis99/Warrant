"""Tests for the TTL cache (injectable clock, no sleeping)."""

from core.cache import TTLCache


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_returns_stored_value_before_expiry():
    clock = _Clock()
    cache = TTLCache(ttl_seconds=10, now=clock)
    cache.set("k", [1, 2, 3])
    clock.t = 9.0
    assert cache.get("k") == [1, 2, 3]


def test_expires_after_ttl():
    clock = _Clock()
    cache = TTLCache(ttl_seconds=10, now=clock)
    cache.set("k", "v")
    clock.t = 10.0
    assert cache.get("k") is None


def test_miss_returns_none():
    cache = TTLCache(ttl_seconds=10, now=_Clock())
    assert cache.get("absent") is None


def test_empty_list_is_cached_distinctly_from_a_miss():
    # OSV "no record" is an empty list, not None — it must be cacheable.
    cache = TTLCache(ttl_seconds=10, now=_Clock())
    cache.set("k", [])
    assert cache.get("k") == []
