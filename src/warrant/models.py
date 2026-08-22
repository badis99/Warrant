from dataclasses import dataclass
from typing import Literal

@dataclass
class Package:
    ecosystem: str
    name: str
    version: str
    tag: Literal["SELF","DIRECT","INDIRECT"]

@dataclass
class VulnCandidate():
    package: Package
    osv_id: str
    aliases: list[str]      # CVE / GHSA / OSV
    affected_ranges: list[dict]   # raw OSV affected.ranges
    fixed_versions: list[str]

@dataclass
class AffectedFinding():
    candidate: VulnCandidate
    verdict: Literal["affected", "affected-transitively"]