"""Ranking metrics for Track 1 (retrieval).

Each query in Warrant's retrieval eval has exactly ONE correct ("gold") chunk,
so these are the single-relevant-item forms of the standard metrics:

- recall@k     : 1 if the gold chunk is in the top k, else 0 (a.k.a. hit@k).
- reciprocal rank : 1 / rank of the gold chunk (0 if absent).
- nDCG@k       : 1 / log2(rank + 1) if the gold chunk is in the top k, else 0.
                 (With one relevant item, the ideal DCG is 1, so DCG == nDCG.)

All functions take a ranked list of chunk ids (best first) and the gold id.
"""

from __future__ import annotations

import math


def _rank_of(ranked_ids: list[str], gold_id: str) -> int | None:
    """1-based rank of gold_id in ranked_ids, or None if absent."""
    for position, chunk_id in enumerate(ranked_ids, start=1):
        if chunk_id == gold_id:
            return position
    return None


def recall_at_k(ranked_ids: list[str], gold_id: str, k: int) -> float:
    rank = _rank_of(ranked_ids, gold_id)
    return 1.0 if rank is not None and rank <= k else 0.0


def reciprocal_rank(ranked_ids: list[str], gold_id: str) -> float:
    rank = _rank_of(ranked_ids, gold_id)
    return 1.0 / rank if rank is not None else 0.0


def ndcg_at_k(ranked_ids: list[str], gold_id: str, k: int) -> float:
    rank = _rank_of(ranked_ids, gold_id)
    if rank is None or rank > k:
        return 0.0
    return 1.0 / math.log2(rank + 1)


def aggregate(
    per_query: list[tuple[list[str], str]],
    k: int,
) -> dict[str, float]:
    """Mean recall@k, MRR, and nDCG@k over many queries.

    Args:
        per_query: one (ranked_ids, gold_id) pair per query.
        k: cutoff for recall@k and nDCG@k.

    Returns:
        {"recall@k": float, "mrr": float, "ndcg@k": float} with k substituted
        into the recall/ndcg keys (e.g. "recall@5").
    """
    n = len(per_query)
    if n == 0:
        return {f"recall@{k}": 0.0, "mrr": 0.0, f"ndcg@{k}": 0.0}

    recall_sum = sum(recall_at_k(r, g, k) for r, g in per_query)
    rr_sum = sum(reciprocal_rank(r, g) for r, g in per_query)
    ndcg_sum = sum(ndcg_at_k(r, g, k) for r, g in per_query)

    return {
        f"recall@{k}": recall_sum / n,
        "mrr": rr_sum / n,
        f"ndcg@{k}": ndcg_sum / n,
    }
