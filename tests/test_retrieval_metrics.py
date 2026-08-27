import math

import pytest

from evals.retrieval_metrics import (
    aggregate,
    ndcg_at_k,
    recall_at_k,
    reciprocal_rank,
)

# A single ranked list used across several tests. The gold item "c" sits at
# rank 3 (1-based), so every metric has a value we can compute by hand.
RANKED = ["a", "b", "c", "d", "e", "f"]


def test_recall_at_k_hit_inside_k():
    # "c" is at rank 3, so it is inside the top 5 and the top 3.
    assert recall_at_k(RANKED, "c", k=5) == 1.0
    assert recall_at_k(RANKED, "c", k=3) == 1.0


def test_recall_at_k_miss_outside_k():
    # "c" is at rank 3, so it is NOT inside the top 2.
    assert recall_at_k(RANKED, "c", k=2) == 0.0


def test_recall_at_k_gold_absent_is_zero():
    assert recall_at_k(RANKED, "zzz", k=5) == 0.0


def test_reciprocal_rank_is_one_over_rank():
    assert reciprocal_rank(["a", "b", "c"], "a") == 1.0        # rank 1
    assert reciprocal_rank(RANKED, "c") == pytest.approx(1 / 3)  # rank 3
    assert reciprocal_rank(RANKED, "zzz") == 0.0                 # absent


def test_ndcg_at_k_rewards_higher_rank():
    # Ideal (gold at rank 1): DCG = IDCG = 1/log2(2) = 1.0
    assert ndcg_at_k(["c", "a", "b"], "c", k=5) == pytest.approx(1.0)
    # Gold at rank 3: 1/log2(3+1) = 1/log2(4) = 0.5
    assert ndcg_at_k(RANKED, "c", k=5) == pytest.approx(0.5)
    # Gold at rank 3 but k=2 -> not counted -> 0
    assert ndcg_at_k(RANKED, "c", k=2) == 0.0


def test_aggregate_means_across_queries():
    # q1: gold "a" at rank 1 -> recall@5=1, rr=1,   ndcg@5=1
    # q2: gold "z" at rank 3 -> recall@5=1, rr=1/3, ndcg@5=0.5
    per_query = [
        (["a", "b"], "a"),
        (["x", "y", "z"], "z"),
    ]
    result = aggregate(per_query, k=5)

    assert result["recall@5"] == pytest.approx(1.0)          # (1 + 1) / 2
    assert result["mrr"] == pytest.approx((1 + 1 / 3) / 2)   # 2/3
    assert result["ndcg@5"] == pytest.approx((1 + 0.5) / 2)  # 0.75


def test_aggregate_empty_is_zero_not_crash():
    result = aggregate([], k=5)
    assert result == {"recall@5": 0.0, "mrr": 0.0, "ndcg@5": 0.0}
