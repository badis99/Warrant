"""Render a structured report as a human-readable remediation plan.

Turns the machine JSON into the ranked, cited, plain-language plan a developer
actually acts on — the shape shown in the README.
"""

from __future__ import annotations

_RULE = "-" * 68  # ASCII rule (safe on every terminal, incl. Windows cp1252)

# Most-severe reachability first, and the marker for each.
_SEVERITY = {"reachable": 0, "unknown": 1, "uncertain": 1, "not-reachable": 2}
_ICON = {"reachable": "[REACHABLE]", "uncertain": "[UNCERTAIN]",
         "unknown": "[UNCERTAIN]", "not-reachable": "[NOT REACHABLE]"}


def _worst_reachability(advisories: list[dict]) -> str:
    if not advisories:
        return "unknown"
    return min(advisories, key=lambda a: _SEVERITY.get(a["reachability"], 1))["reachability"]


def _cves(finding: dict) -> list[str]:
    seen: list[str] = []
    for advisory in finding["advisories"]:
        for alias in advisory["aliases"]:
            if alias.upper().startswith("CVE-") and alias not in seen:
                seen.append(alias)
    return seen


def render_report(report: dict, source: str = "") -> str:
    findings = report.get("findings", [])
    if report.get("status") != "findings" or not findings:
        return "Warrant — no known-affected packages found."

    summary = report.get("summary", {})
    lines = [
        f"Warrant — remediation plan{f' for {source}' if source else ''}",
        f"{summary.get('packages_affected', len(findings))} package(s) affected "
        f"· {summary.get('reachable', 0)} reachable",
        "",
    ]

    for finding in findings:
        reach = _worst_reachability(finding["advisories"])
        target = finding.get("target_version")
        upgrade = f"upgrade to {target}" if target else "NO FIX AVAILABLE"
        cves = _cves(finding) or [a["osv_id"] for a in finding["advisories"]]

        lines.append(_RULE)
        lines.append(
            f"{_ICON.get(reach, '[UNCERTAIN]')}  "
            f"{finding['package']} {finding['version']}  ->  {upgrade}"
        )
        verdict = finding["verdict"].replace("-", " ")
        lines.append(f"    Why:   {verdict}; reachability {reach}. "
                     f"Advisories: {', '.join(cves)}")
        if target:
            if finding.get("breaking"):
                note = (finding.get("breakage_notes") or ["breaking changes"])[0]
                lines.append(f"    Fix:   {target} — BREAKING: {note}")
            else:
                effort = finding.get("effort_hint") or "no breaking changes"
                lines.append(f"    Fix:   {target} — drop-in ({effort})")
        else:
            lines.append("    Fix:   no fixed version published yet")
        lines.append(f"    Cite:  {', '.join(cves)}")

    lines.append(_RULE)
    return "\n".join(lines)
