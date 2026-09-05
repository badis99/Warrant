"""Reconcile OSV records that describe the same vulnerability.

OSV often returns several records for one CVE (a GHSA entry and a PYSEC entry
that alias each other). Collapsing them by CVE removes duplicate findings — and
duplicate LLM calls downstream — while keeping every id as a citation. This is
the CVE <-> GHSA <-> OSV reconciliation the design calls for; it is deterministic.
"""

from __future__ import annotations

from warrant.models import VulnCandidate


def _cve_key(candidate: VulnCandidate) -> str:
    for alias in candidate.aliases:
        if alias.upper().startswith("CVE-"):
            return alias.upper()
    return candidate.osv_id  # no CVE: key by its own id (kept distinct)


def reconcile(candidates: list[VulnCandidate]) -> list[VulnCandidate]:
    """Collapse candidates that share a CVE into one, unioning their ids,
    ranges, and fixed versions."""
    groups: dict[str, list[VulnCandidate]] = {}
    for candidate in candidates:
        groups.setdefault(_cve_key(candidate), []).append(candidate)

    merged: list[VulnCandidate] = []
    for group in groups.values():
        base = group[0]
        aliases = sorted(
            {a for c in group for a in c.aliases} | {c.osv_id for c in group}
        )
        ranges = [r for c in group for r in c.affected_ranges]
        fixed = sorted({f for c in group for f in c.fixed_versions})
        merged.append(VulnCandidate(
            package=base.package,
            osv_id=base.osv_id,
            aliases=aliases,
            affected_ranges=ranges,
            fixed_versions=fixed,
        ))
    return merged
