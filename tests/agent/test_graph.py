"""Tests for the LangGraph assembly.

The graph's network/LLM nodes are injectable, so we exercise the wiring and the
conditional short-circuit edge without touching the network. parse runs for
real (offline lockfile parsing).
"""

from warrant.agent.graph import build_graph
from warrant.agent.nodes import applicability_node, route_after_applicability
from warrant.models import Package, VulnCandidate


def _range(fixed: str) -> list[dict]:
    return [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]


def _candidate(name: str, version: str, fixed: str) -> VulnCandidate:
    return VulnCandidate(
        package=Package(ecosystem="PyPI", name=name, version=version, tag="DIRECT"),
        osv_id=f"OSV-{name}",
        aliases=[f"CVE-{name}"],
        affected_ranges=_range(fixed),
        fixed_versions=[fixed],
    )


def test_route_clean_when_nothing_affected():
    assert route_after_applicability({"affected": []}) == "clean"
    assert route_after_applicability({}) == "clean"


def test_route_reachability_when_something_affected():
    assert route_after_applicability({"affected": [object()]}) == "reachability"


def test_applicability_filters_by_version_and_tags_transitive():
    packages = [Package(ecosystem="PyPI", name="pyyaml", version="5.3", tag="INDIRECT")]
    affected_cand = _candidate("pyyaml", "5.3", "5.4")   # 5.3 < 5.4 -> affected
    safe_cand = _candidate("pyyaml", "5.3", "5.0")        # 5.3 >= 5.0 -> not affected

    out = applicability_node(
        {"packages": packages, "candidates": [affected_cand, safe_cand]}
    )

    assert len(out["affected"]) == 1
    assert out["affected"][0].verdict == "affected-transitively"


def test_graph_short_circuits_to_clean_report():
    graph = build_graph(query_node=lambda s: {"candidates": []})
    final = graph.invoke({"lockfile_path": "fixtures/simple/uv.lock"})
    assert final["report"]["status"] == "clean"


def test_graph_routes_to_reachability_when_affected():
    cand = _candidate("pillow", "9.2.0", "9.3.0")   # 9.2.0 < 9.3.0 -> affected

    def stub_reachability(state):
        ids = [f.candidate.osv_id for f in state["affected"]]
        return {"report": {"status": "findings", "findings": ids}}

    graph = build_graph(
        query_node=lambda s: {"candidates": [cand]},
        reachability_node=stub_reachability,
    )
    final = graph.invoke({"lockfile_path": "fixtures/simple/uv.lock"})

    assert final["report"]["status"] == "findings"
    assert "OSV-pillow" in final["report"]["findings"]
