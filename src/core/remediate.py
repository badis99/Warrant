"""Deterministic remediation: the minimal safe upgrade.

Given the installed version and every advisory affecting the package, find the
smallest published `fixed` version that is greater than the current version AND
not affected by any of the advisories. Uses the Phase 1 resolver for the
"is this target still affected?" check — never an LLM.
"""

from __future__ import annotations

from packaging.version import InvalidVersion, Version

from core.version_match import is_version_affected
from warrant.models import VulnCandidate


def minimal_safe_version(
    current_version: str,
    candidates: list[VulnCandidate],
) -> str | None:
    """Smallest fixed version > current that clears every advisory, or None.

    None means no known fix upgrades away from all advisories (e.g. an
    unfixed vulnerability, or every fix is at/below the installed version).
    """
    try:
        current = Version(current_version)
    except InvalidVersion:
        return None

    # Collect candidate targets: published fixes strictly above the current
    # version, sorted ascending so we can take the first that is fully safe.
    targets: set[str] = set()
    for candidate in candidates:
        for fixed in candidate.fixed_versions:
            try:
                if Version(fixed) > current:
                    targets.add(fixed)
            except InvalidVersion:
                continue

    for target in sorted(targets, key=Version):
        if not any(
            is_version_affected(target, c.affected_ranges) for c in candidates
        ):
            return target
    return None
