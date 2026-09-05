"""Tests for reconciling OSV records that alias the same CVE."""

from core.reconcile import reconcile
from warrant.models import Package, VulnCandidate

_PKG = Package(ecosystem="PyPI", name="pkg", version="1.0", tag="DIRECT")


def _cand(osv_id, aliases, fixed):
    return VulnCandidate(
        package=_PKG, osv_id=osv_id, aliases=aliases,
        affected_ranges=[{"type": "ECOSYSTEM",
                          "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        fixed_versions=[fixed],
    )


def test_merges_records_sharing_a_cve():
    ghsa = _cand("GHSA-1", ["CVE-2020-1", "PYSEC-a"], "1.1")
    pysec = _cand("PYSEC-a", ["CVE-2020-1", "GHSA-1"], "1.1")

    out = reconcile([ghsa, pysec])

    assert len(out) == 1
    # Merged record keeps every id as a citation.
    assert "CVE-2020-1" in out[0].aliases
    assert "GHSA-1" in out[0].aliases and "PYSEC-a" in out[0].aliases


def test_distinct_cves_stay_separate():
    a = _cand("GHSA-1", ["CVE-2020-1"], "1.1")
    b = _cand("GHSA-2", ["CVE-2021-2"], "2.0")
    assert len(reconcile([a, b])) == 2


def test_record_without_cve_is_keyed_by_osv_id():
    a = _cand("PYSEC-only", [], "1.1")
    assert len(reconcile([a])) == 1
