"""Tests for computing the minimal safe upgrade (deterministic)."""

from core.remediate import minimal_safe_version
from warrant.models import Package, VulnCandidate


def _candidate(fixed: str) -> VulnCandidate:
    return VulnCandidate(
        package=Package(ecosystem="PyPI", name="pkg", version="0", tag="DIRECT"),
        osv_id=f"OSV-{fixed}",
        aliases=[],
        affected_ranges=[{"type": "ECOSYSTEM",
                          "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        fixed_versions=[fixed],
    )


def test_single_advisory_returns_its_fix():
    assert minimal_safe_version("5.3", [_candidate("5.4")]) == "5.4"


def test_picks_smallest_version_that_clears_all_advisories():
    # 5.4 clears the first advisory but is still inside the second (< 6.0).
    target = minimal_safe_version("5.3", [_candidate("5.4"), _candidate("6.0")])
    assert target == "6.0"


def test_returns_none_when_no_fix_is_known():
    unfixed = VulnCandidate(
        package=Package(ecosystem="PyPI", name="pkg", version="1.0", tag="DIRECT"),
        osv_id="OSV-x", aliases=[], affected_ranges=[
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        fixed_versions=[],
    )
    assert minimal_safe_version("1.0", [unfixed]) is None


def test_ignores_fixes_at_or_below_current_version():
    # A "fix" not greater than the installed version cannot be the upgrade.
    assert minimal_safe_version("5.5", [_candidate("5.4")]) is None
