"""Graph nodes — thin wrappers over the already-tested core/ and rag/ functions.

Each node takes the state and returns a partial update. Deterministic nodes
(parse, applicability) never touch an LLM; the fuzzy judgment lives only in the
reachability node.
"""

from __future__ import annotations

import re
from collections import defaultdict

from core.osv import query_vulns
from core.reconcile import reconcile
from core.remediate import minimal_safe_version
from core.resolve import resolve_graph
from core.version_match import is_version_affected
from warrant.models import AffectedFinding
from warrant.rag.reachability import assess_reachability
from warrant.report import build_report


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def parse_node(state: dict) -> dict:
    """Lockfile -> tagged packages (SELF/DIRECT/INDIRECT). Deterministic."""
    return {"packages": resolve_graph(state["lockfile_path"])}


def query_node(state: dict) -> dict:
    """Packages -> OSV advisory candidates. Deterministic (network)."""
    return {"candidates": query_vulns(state["packages"])}


def applicability_node(state: dict) -> dict:
    """Keep only candidates whose installed version is actually affected, and
    tag each as directly or transitively affected. Deterministic — the version
    verdict is PEP 440 math, never an LLM."""
    tags = {_normalize(p.name): p.tag for p in state.get("packages", [])}
    affected: list[AffectedFinding] = []
    for candidate in reconcile(state.get("candidates", [])):
        pkg = candidate.package
        if not is_version_affected(pkg.version, candidate.affected_ranges):
            continue
        transitive = tags.get(_normalize(pkg.name)) == "INDIRECT"
        affected.append(AffectedFinding(
            candidate=candidate,
            verdict="affected-transitively" if transitive else "affected",
        ))
    return {"affected": affected}


def route_after_applicability(state: dict) -> str:
    """The conditional edge: short-circuit to a clean report if nothing is
    affected, otherwise proceed to reachability. This branch is why the
    pipeline is a graph and not a straight line."""
    return "reachability" if state.get("affected") else "clean"


def clean_report_node(state: dict) -> dict:
    return {"report": {"status": "clean", "findings": []}}


def reachability_node(state: dict) -> dict:
    """Judge reachability for each affected finding (LLM over prose).

    Note: a real code-usage source (scanning the project for how the package is
    used) is a later input; until then we pass the advisory and an explicit
    'not analyzed' usage, so the model correctly returns low-confidence /
    uncertain rather than pretending to know.
    """
    results = {}
    for finding in state.get("affected", []):
        candidate = finding.candidate
        advisory = "; ".join(candidate.aliases) or candidate.osv_id
        results[candidate.osv_id] = assess_reachability(
            candidate.package.name, advisory, "code usage not analyzed"
        )
    return {"reachability": results}


def remediation_node(state: dict) -> dict:
    """Minimal safe upgrade per affected package. Deterministic (PEP 440)."""
    by_package: dict[str, list] = defaultdict(list)
    current: dict[str, str] = {}
    for finding in state.get("affected", []):
        candidate = finding.candidate
        by_package[candidate.package.name].append(candidate)
        current[candidate.package.name] = candidate.package.version

    remediation = {
        name: minimal_safe_version(current[name], candidates)
        for name, candidates in by_package.items()
    }
    return {"remediation": remediation}


def breakage_node(state: dict) -> dict:
    """Assess breaking changes for each proposed upgrade (RAG over changelogs)."""
    from warrant.rag.breakage import assess_breakage
    from warrant.rag.naive_index import _default_embed, load_corpus
    from warrant.rag.retrieve import HybridIndex

    remediation = state.get("remediation", {})
    current = {
        f.candidate.package.name: f.candidate.package.version
        for f in state.get("affected", [])
    }
    targets = {name: t for name, t in remediation.items() if t}
    if not targets:
        return {"breakage": {}}

    index = HybridIndex(load_corpus(), embed=_default_embed)
    results = {}
    for name, target in targets.items():
        chunks = index.retrieve(f"{name} {target} changelog breaking changes", k=3)
        changelog = "\n".join(c.text for c in chunks)
        results[name] = assess_breakage(name, current[name], target, changelog)
    return {"breakage": results}


def report_node(state: dict) -> dict:
    """Compose the final cited plan. Deterministic (no LLM)."""
    return {"report": build_report(state)}
