import json
from pathlib import Path

import httpx

from core.osv import query_vulns
from core.version_match import is_version_affected
from warrant.models import Package

FIXTURES = Path("tests/fixtures/osv")


def _mock_client() -> httpx.Client:
    certifi = json.loads((FIXTURES / "certifi.json").read_text(encoding="utf-8"))
    empty = json.loads((FIXTURES / "empty.json").read_text(encoding="utf-8"))

    def handler(request: httpx.Request) -> httpx.Response:
        name = json.loads(request.content)["package"]["name"].lower()
        body = certifi if name == "certifi" else empty
        return httpx.Response(200, json=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _pkg(name: str, version: str) -> Package:
    return Package(ecosystem="PyPI", name=name, version=version, tag="DIRECT")


def test_parses_aliases_and_fixed_versions():
    with _mock_client() as client:
        candidates = query_vulns([_pkg("certifi", "2023.5.7")], client=client)

    assert candidates, "certifi should return advisories"
    # The e-Tugra advisory (CVE-2023-37920, fixed in 2023.7.22) must be present.
    cve_37920 = [c for c in candidates if "CVE-2023-37920" in c.aliases]
    assert cve_37920
    assert "2023.7.22" in cve_37920[0].fixed_versions
    assert cve_37920[0].affected_ranges


def test_git_commit_hashes_are_not_treated_as_fixed_versions():
    with _mock_client() as client:
        candidates = query_vulns([_pkg("certifi", "2023.5.7")], client=client)

    for c in candidates:
        for fixed in c.fixed_versions:
            # A 40-char hex string is a git commit, never a release version.
            assert not (len(fixed) == 40 and all(ch in "0123456789abcdef" for ch in fixed))


def test_empty_response_means_no_record_not_safe():
    # OSV returning {} is "no advisory found", which is NOT a safety guarantee.
    # query_vulns reports it as an empty candidate list; callers must not read
    # absence as "safe".
    with _mock_client() as client:
        candidates = query_vulns([_pkg("nonexistent-xyz", "1.0.0")], client=client)
    assert candidates == []


def test_batches_multiple_packages():
    with _mock_client() as client:
        candidates = query_vulns(
            [_pkg("certifi", "2023.5.7"), _pkg("nonexistent-xyz", "1.0.0")],
            client=client,
        )
    # Only certifi contributes candidates; the unknown package adds none.
    assert candidates
    assert all(c.package.name == "certifi" for c in candidates)


def test_end_to_end_with_deterministic_resolver():
    # The whole point: OSV supplies ranges, our resolver decides affectedness.
    with _mock_client() as client:
        candidates = query_vulns([_pkg("certifi", "2023.5.7")], client=client)

    # Isolate ONE advisory: a version safe from this bug may still be affected
    # by a different, later certifi advisory, so we must check per-CVE.
    def affected_by(cve: str, version: str) -> bool:
        matching = [c for c in candidates if cve in c.aliases]
        return any(
            is_version_affected(version, c.affected_ranges) for c in matching
        )

    assert affected_by("CVE-2023-37920", "2023.5.7") is True    # before the fix
    assert affected_by("CVE-2023-37920", "2023.7.22") is False   # patched boundary
