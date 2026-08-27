"""Deterministic PEP 440 version-range matching.

The architectural heart of Warrant: given an installed version and OSV's
structured affected `ranges`, decide — by exact rules, never by an LLM —
whether the version is affected.

OSV encodes an affected window as an ordered list of events on a version
timeline (introduced / fixed / last_affected / limit). We evaluate them with
the `packaging` library so PEP 440 ordering (pre-releases, post-releases,
epochs) is exactly correct.
"""

from __future__ import annotations

from packaging.version import InvalidVersion, Version

# Sort priority so that at an equal version an `introduced` event is processed
# before a boundary that ends the window.
_KIND_ORDER = {"introduced": 0, "fixed": 1, "last_affected": 1, "limit": 1}


def _event_version(event: dict) -> Version:
    """The version threshold of a single OSV event. `introduced: "0"` sorts
    below every real release."""
    raw = next(iter(event.values()))
    if raw == "0":
        return Version("0")
    return Version(raw)


def _range_affects(version: Version, osv_range: dict) -> bool:
    """Run OSV's toggle algorithm over one range's events, in ascending order.

    Walking events low-to-high, each event whose threshold the version has
    reached flips the `affected` flag; the last such event wins.
    """
    events = osv_range.get("events", [])
    try:
        ordered = sorted(
            events,
            key=lambda e: (
                _event_version(e),
                _KIND_ORDER.get(next(iter(e)), 1),
            ),
        )
    except InvalidVersion:
        return False

    affected = False
    for event in ordered:
        kind, raw = next(iter(event.items()))
        threshold = Version("0") if raw == "0" else Version(raw)

        if kind == "introduced" and version >= threshold:
            affected = True
        elif kind == "fixed" and version >= threshold:
            affected = False
        elif kind == "last_affected" and version > threshold:
            affected = False
        elif kind == "limit" and version >= threshold:
            affected = False
    return affected


def is_version_affected(version: str, osv_ranges: list[dict]) -> bool:
    """True if `version` falls inside ANY of the OSV affected ranges.

    Args:
        version: the installed version string (PEP 440).
        osv_ranges: the `affected[].ranges` list from an OSV record.

    Returns:
        Whether the version is affected. GIT ranges (commit-based) are skipped;
        an unparseable installed version is treated as not affected.
    """
    try:
        parsed = Version(version)
    except InvalidVersion:
        return False

    for osv_range in osv_ranges:
        if osv_range.get("type") == "GIT":
            continue
        if _range_affects(parsed, osv_range):
            return True
    return False
