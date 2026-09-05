"""A tiny time-to-live cache.

Advisories change slowly, so a short TTL (hours) is a sound invalidation
strategy: simple, with a small bounded staleness window. Event-based
invalidation would be more precise but needs a change feed — unwarranted here.
In production this would be backed by disk or Redis so it survives restarts and
is shared across workers; the in-memory form is enough for a single process.

The clock is injectable so expiry can be tested without sleeping.
"""

from __future__ import annotations

import time
from typing import Any, Callable


class TTLCache:
    def __init__(self, ttl_seconds: float, now: Callable[[], float] = time.monotonic):
        self._ttl = ttl_seconds
        self._now = now
        self._store: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Any | None:
        item = self._store.get(key)
        if item is None:
            return None
        value, expires_at = item
        if self._now() >= expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (value, self._now() + self._ttl)
