r"""Assemble the Warrant pipeline as a LangGraph state machine.

    START -> parse -> query -> applicability --(conditional)--> clean_report -> END
                                             \--(affected)----> reachability -> END

The conditional edge after `applicability` is the reason this is a graph, not a
linear chain: when nothing is affected we skip all the RAG/LLM work and emit a
clean report directly.

The network (`query`) and LLM (`reachability`) nodes are injectable so the
wiring can be tested without touching either.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from warrant.agent import nodes
from warrant.agent.state import WarrantState


def build_graph(
    *,
    query_node=nodes.query_node,
    reachability_node=nodes.reachability_node,
):
    graph = StateGraph(WarrantState)

    graph.add_node("parse", nodes.parse_node)
    graph.add_node("query", query_node)
    graph.add_node("applicability", nodes.applicability_node)
    graph.add_node("clean_report", nodes.clean_report_node)
    graph.add_node("reachability", reachability_node)

    graph.add_edge(START, "parse")
    graph.add_edge("parse", "query")
    graph.add_edge("query", "applicability")
    graph.add_conditional_edges(
        "applicability",
        nodes.route_after_applicability,
        {"clean": "clean_report", "reachability": "reachability"},
    )
    graph.add_edge("clean_report", END)
    graph.add_edge("reachability", END)

    return graph.compile()
