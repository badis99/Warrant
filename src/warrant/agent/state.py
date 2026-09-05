"""The shared state that flows between graph nodes.

Each node reads what it needs and returns a partial update; LangGraph merges
updates key-by-key (last write wins). This is the concrete form of the design
doc's WarrantState, covering the pipeline built through Phase 4.
"""

from __future__ import annotations

from typing import TypedDict

from warrant.models import AffectedFinding, Package, VulnCandidate
from warrant.rag.reachability import Reachability


class WarrantState(TypedDict, total=False):
    lockfile_path: str
    packages: list[Package]
    candidates: list[VulnCandidate]
    affected: list[AffectedFinding]
    reachability: dict[str, Reachability]
    report: dict
