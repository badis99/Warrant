"""Track 1 — retrieval eval for the naive (embedding-only) baseline.

Loads the advisory/changelog corpus and the labeled query->gold-chunk set,
runs the naive dense retriever over every query, and reports recall@5, MRR,
and nDCG@5 overall and per category. The per-category view is the point: the
`close_name` query is expected to score poorly, which is the evidence that
justifies adding BM25 in Phase 3.

Run:  uv run python -m evals.track1_retrieval
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from warrant.rag.naive_index import NaiveIndex, _default_embed, load_corpus
from evals.retrieval_metrics import aggregate

CORPUS_PATH = Path("corpus/advisories.jsonl")
DATASET_PATH = Path("evals/datasets/retrieval.jsonl")
K = 5


@dataclass
class Query:
    id: str
    text: str
    gold_chunk_id: str
    category: str


def load_queries(path: Path = DATASET_PATH) -> list[Query]:
    queries: list[Query] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            queries.append(
                Query(
                    id=row["id"],
                    text=row["query"],
                    gold_chunk_id=row["gold_chunk_id"],
                    category=row["category"],
                )
            )
    return queries


def run(index, name: str) -> dict:
    """Score any retriever exposing .retrieve(query, k) -> list[Chunk]."""
    corpus = load_corpus(CORPUS_PATH)
    queries = load_queries()
    depth = len(corpus)  # retrieve the full ranking; metrics apply the cutoff.

    per_query: list[tuple[list[str], str]] = []
    by_category: dict[str, list[tuple[list[str], str]]] = defaultdict(list)

    for q in queries:
        ranked_ids = [c.id for c in index.retrieve(q.text, k=depth)]
        pair = (ranked_ids, q.gold_chunk_id)
        per_query.append(pair)
        by_category[q.category].append(pair)

    overall = aggregate(per_query, k=K)

    print(f"Track 1 - retrieval: {name} ({len(queries)} queries)")
    for cutoff in (1, 3, 5):
        scores = aggregate(per_query, k=cutoff)
        print(f"  recall@{cutoff}: {scores[f'recall@{cutoff}']:.3f}")
    print(f"  MRR:      {overall['mrr']:.3f}")
    print(f"  nDCG@{K}:  {overall[f'ndcg@{K}']:.3f}")

    print("  MRR by category:")
    for category in sorted(by_category):
        cat_scores = aggregate(by_category[category], k=K)
        n = len(by_category[category])
        print(f"    {category:<12} {cat_scores['mrr']:.3f}  (n={n})")

    return overall


if __name__ == "__main__":
    from warrant.rag.retrieve import HybridIndex

    corpus = load_corpus(CORPUS_PATH)
    run(NaiveIndex(corpus, embed=_default_embed), "naive dense baseline")
    print()
    run(HybridIndex(corpus, embed=_default_embed), "hybrid (dense + BM25, RRF)")
