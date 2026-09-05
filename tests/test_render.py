"""Tests for rendering a report as a human-readable plan."""

from warrant.render import render_report


def _report():
    return {
        "status": "findings",
        "summary": {"packages_affected": 1, "reachable": 1},
        "findings": [{
            "package": "pillow", "version": "9.2.0",
            "verdict": "affected",
            "advisories": [{
                "osv_id": "GHSA-x", "aliases": ["CVE-2022-45198", "GHSA-x"],
                "reachability": "reachable", "confidence": 0.9,
            }],
            "target_version": "9.3.0",
            "breaking": True,
            "breakage_notes": ["Image.open signature changed"],
            "effort_hint": "~1h",
        }],
    }


def test_renders_key_facts():
    text = render_report(_report(), source="poetry.lock")
    assert "pillow 9.2.0" in text
    assert "9.3.0" in text                     # target version
    assert "CVE-2022-45198" in text            # citation
    assert "REACHABLE" in text.upper()
    assert "BREAKING" in text.upper()          # breakage surfaced
    assert "poetry.lock" in text               # source named


def test_clean_report_says_so():
    text = render_report({"status": "clean", "findings": []})
    assert "no" in text.lower() and "affected" in text.lower()


def test_finding_without_fix_is_handled():
    report = _report()
    report["findings"][0]["target_version"] = None
    text = render_report(report)
    assert "no fix" in text.lower()
