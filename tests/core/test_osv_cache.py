"""The OSV client should reuse a cached response instead of re-querying."""

import json
from pathlib import Path

import httpx

from core.cache import TTLCache
from core.osv import query_vulns
from warrant.models import Package

FIXTURES = Path("tests/fixtures/osv")


def _counting_client(counter: dict) -> httpx.Client:
    certifi = json.loads((FIXTURES / "certifi.json").read_text(encoding="utf-8"))

    def handler(request: httpx.Request) -> httpx.Response:
        counter["calls"] += 1
        return httpx.Response(200, json=certifi)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_second_query_is_served_from_cache():
    counter = {"calls": 0}
    cache = TTLCache(ttl_seconds=3600)
    pkg = Package(ecosystem="PyPI", name="certifi", version="2023.5.7", tag="DIRECT")

    with _counting_client(counter) as client:
        first = query_vulns([pkg], client=client, cache=cache)
        second = query_vulns([pkg], client=client, cache=cache)

    assert counter["calls"] == 1                 # network hit only once
    assert [c.osv_id for c in first] == [c.osv_id for c in second]
