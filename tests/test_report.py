"""Tests for deterministic report assembly (no LLM)."""

from warrant.models import AffectedFinding, Package, VulnCandidate
from warrant.rag.breakage import BreakageReport
from warrant.rag.reachability import Reachability
from warrant.report import build_report


def _finding(name, version, osv_id, verdict="affected") -> AffectedFinding:
    return AffectedFinding(
        candidate=VulnCandidate(
            package=Package(ecosystem="PyPI", name=name, version=version, tag="DIRECT"),
            osv_id=osv_id, aliases=[f"CVE-{osv_id}"],
            affected_ranges=[], fixed_versions=[],
        ),
        verdict=verdict,
    )


def _state():
    return {
        "affected": [
            _finding("safe-pkg", "1.0", "OSV-A"),      # not-reachable
            _finding("hot-pkg", "2.0", "OSV-B"),        # reachable
        ],
        "reachability": {
            "OSV-A": Reachability(verdict="not-reachable", confidence=0.8),
            "OSV-B": Reachability(verdict="reachable", confidence=0.9),
        },
        "remediation": {"safe-pkg": "1.1", "hot-pkg": "2.1"},
        "breakage": {
            "safe-pkg": BreakageReport(breaking=False, notes=[], effort_hint="drop-in"),
            "hot-pkg": BreakageReport(breaking=True, notes=["renamed api"], effort_hint="~1h"),
        },
    }


def test_reachable_findings_rank_first():
    report = build_report(_state())
    assert report["status"] == "findings"
    assert report["findings"][0]["package"] == "hot-pkg"   # reachable outranks


def test_finding_carries_target_breakage_and_citations():
    report = build_report(_state())
    hot = report["findings"][0]
    assert hot["target_version"] == "2.1"
    assert hot["breaking"] is True
    assert hot["breakage_notes"] == ["renamed api"]
    # Citations: the advisory ids/aliases are attached.
    assert "CVE-OSV-B" in hot["advisories"][0]["aliases"]


def test_summary_counts_reachable():
    report = build_report(_state())
    assert report["summary"]["packages_affected"] == 2
    assert report["summary"]["reachable"] == 1


def test_empty_state_is_clean():
    assert build_report({})["status"] == "clean"
