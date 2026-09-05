"""Deterministic assembly of the final cited remediation plan.

Composition is intentionally NOT done by an LLM: every value here (verdict,
target version, breakage notes, citations) was already produced upstream, so
assembling and ranking it in code guarantees each claim stays traceable. The
LLM's role is confined to the reachability and breakage judgments feeding in.

Findings are grouped by package and ranked so the ones that most need attention
(reachable, with a known fix) come first.
"""

from __future__ import annotations

# Lower sorts first.
_REACH_PRIORITY = {"reachable": 0, "uncertain": 1, "not-reachable": 2, "unknown": 1}


def build_report(state: dict) -> dict:
    affected = state.get("affected", [])
    reachability = state.get("reachability", {})
    remediation = state.get("remediation", {})
    breakage = state.get("breakage", {})

    groups: dict[str, dict] = {}
    for finding in affected:
        candidate = finding.candidate
        name = candidate.package.name
        group = groups.setdefault(name, {
            "package": name,
            "version": candidate.package.version,
            "verdict": finding.verdict,
            "advisories": [],
        })
        reach = reachability.get(candidate.osv_id)
        group["advisories"].append({
            "osv_id": candidate.osv_id,
            "aliases": candidate.aliases,
            "reachability": reach.verdict if reach else "unknown",
            "confidence": reach.confidence if reach else 0.0,
        })

    findings: list[dict] = []
    for name, group in groups.items():
        report = breakage.get(name)
        best = min(
            (_REACH_PRIORITY.get(a["reachability"], 1) for a in group["advisories"]),
            default=1,
        )
        target = remediation.get(name)
        findings.append({
            **group,
            "target_version": target,
            "breaking": report.breaking if report else None,
            "breakage_notes": report.notes if report else [],
            "effort_hint": report.effort_hint if report else "",
            "_priority": best,
        })

    # Rank: reachable first, then findings that actually have a fix, then name.
    findings.sort(key=lambda f: (f["_priority"], f["target_version"] is None, f["package"]))
    for f in findings:
        f.pop("_priority")

    reachable = sum(
        1 for f in findings
        if any(a["reachability"] == "reachable" for a in f["advisories"])
    )

    return {
        "status": "findings" if findings else "clean",
        "summary": {"packages_affected": len(findings), "reachable": reachable},
        "findings": findings,
    }
