"""Tests for BM25, Reciprocal Rank Fusion, and the hybrid retriever."""

import numpy as np

from warrant.rag.index import BM25Index
from warrant.rag.naive_index import Chunk, load_corpus
from warrant.rag.retrieve import HybridIndex, reciprocal_rank_fusion

CORPUS = "corpus/advisories.jsonl"


def test_rrf_ranks_agreed_top_first():
    # "a" is ranked highly by both lists; it should win the fusion.
    fused = reciprocal_rank_fusion([["a", "b", "c"], ["a", "c", "b"]])
    assert fused[0] == "a"


def test_rrf_rewards_appearing_in_both_lists():
    # "x" is mid in both; "y" is top of one but absent from the other.
    fused = reciprocal_rank_fusion([["y", "x"], ["x"]])
    # x: 1/(60+2) + 1/(60+1); y: 1/(60+1). x should edge ahead.
    assert fused[0] == "x"


def test_bm25_ranks_exact_identifier_first():
    chunks = load_corpus(CORPUS)
    bm25 = BM25Index(chunks)
    ranked = bm25.ranked_ids("CVE-2023-37920")
    assert ranked[0] == "adv-certifi-cve-2023-37920"


VOCAB = ["apple", "banana"]


def _bow(texts):
    return np.array(
        [[float(t.lower().split().count(w)) for w in VOCAB] for t in texts],
        dtype=float,
    )


def test_hybrid_returns_k_chunks():
    chunks = [
        Chunk(id="c1", text="apple"),
        Chunk(id="c2", text="banana"),
        Chunk(id="c3", text="apple banana"),
    ]
    index = HybridIndex(chunks, embed=_bow)
    results = index.retrieve("apple", k=2)
    assert len(results) == 2
    assert all(isinstance(c, Chunk) for c in results)
