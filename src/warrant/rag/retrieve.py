"""Hybrid retrieval: fuse dense (embedding) and BM25 (keyword) rankings.

Reciprocal Rank Fusion combines the two by rank position, so the incompatible
score scales of cosine similarity and BM25 never have to be reconciled.
"""

from __future__ import annotations

from warrant.rag.index import BM25Index
from warrant.rag.naive_index import Chunk, Embedder, NaiveIndex

_RRF_K = 60


def reciprocal_rank_fusion(rankings: list[list[str]], k: int = _RRF_K) -> list[str]:
    """Fuse several ranked id lists into one. Higher fused score = better."""
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, chunk_id in enumerate(ranking, start=1):
            scores[chunk_id] = scores.get(chunk_id, 0.0) + 1.0 / (k + rank)
    return sorted(scores, key=lambda c: -scores[c])


class HybridIndex:
    def __init__(self, chunks: list[Chunk], embed: Embedder):
        self._by_id = {c.id: c for c in chunks}
        self._n = len(chunks)
        self._dense = NaiveIndex(chunks, embed=embed)
        self._bm25 = BM25Index(chunks)

    def retrieve(self, query: str, k: int) -> list[Chunk]:
        dense_ids = [c.id for c in self._dense.retrieve(query, self._n)]
        bm25_ids = self._bm25.ranked_ids(query)
        fused = reciprocal_rank_fusion([dense_ids, bm25_ids])
        return [self._by_id[cid] for cid in fused[:k]]
