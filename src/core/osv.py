""" Design notes:
- /v1/querybatch returns only vuln IDs (no ranges), so we use /v1/query, which
  returns full records including `affected[].ranges` and `aliases`.
- An empty OSV response means "no record found", which is NOT "safe". This
  client reports it as an empty candidate list; callers must not conflate the
  two.
"""

from __future__ import annotations

import re

import httpx

from warrant.models import Package, VulnCandidate

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_DEFAULT_TIMEOUT = 20.0


def _normalize(name: str) -> str:
    """PEP 503 name normalization so 'PyYAML' and 'pyyaml' compare equal."""
    return re.sub(r"[-_.]+", "-", name.lower())


def _candidate_from_vuln(vuln: dict, package: Package) -> VulnCandidate | None:
    """Build a VulnCandidate from one OSV record, keeping only the ranges and
    fixed versions that belong to `package`. Returns None if the record does
    not actually list this package with a version range."""
    target = _normalize(package.name)
    ranges: list[dict] = []
    fixed_versions: list[str] = []

    for affected in vuln.get("affected", []):
        affected_pkg = affected.get("package", {})
        if affected_pkg.get("ecosystem") != package.ecosystem:
            continue
        if _normalize(affected_pkg.get("name", "")) != target:
            continue
        for osv_range in affected.get("ranges", []):
            ranges.append(osv_range)
            # Skip GIT ranges: their "fixed" events are commit hashes, not
            # release versions.
            if osv_range.get("type") == "GIT":
                continue
            for event in osv_range.get("events", []):
                if "fixed" in event:
                    fixed_versions.append(event["fixed"])

    if not ranges:
        return None

    return VulnCandidate(
        package=package,
        osv_id=vuln["id"],
        aliases=list(vuln.get("aliases", [])),
        affected_ranges=ranges,
        fixed_versions=fixed_versions,
    )


def query_vulns(
    packages: list[Package],
    client: httpx.Client | None = None,
) -> list[VulnCandidate]:
    """Query OSV for every package and return the advisory candidates found.

    Args:
        packages: packages to look up (only ecosystem + name are sent).
        client: an httpx.Client to use; if None, one is created and closed.
            Injecting a client lets tests replay recorded responses.

    Returns:
        One VulnCandidate per (package, matching OSV record). An empty list for
        a package means "no record found", not "safe".
    """
    own_client = client is None
    client = client or httpx.Client(timeout=_DEFAULT_TIMEOUT)
    try:
        candidates: list[VulnCandidate] = []
        for package in packages:
            response = client.post(
                OSV_QUERY_URL,
                json={"package": {
                    "ecosystem": package.ecosystem,
                    "name": package.name,
                }},
            )
            response.raise_for_status()
            for vuln in response.json().get("vulns", []):
                candidate = _candidate_from_vuln(vuln, package)
                if candidate is not None:
                    candidates.append(candidate)
        return candidates
    finally:
        if own_client:
            client.close()
