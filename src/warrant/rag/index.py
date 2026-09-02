"""BM25 keyword index.

Complements dense retrieval: BM25 scores by literal term overlap, so it excels
at exact tokens embeddings blur — package names and identifiers like
`CVE-2023-37920` or `GHSA-g4mx-q9vg-27p4`. The tokenizer keeps hyphens and dots
so those identifiers and version numbers stay single tokens.
"""

from __future__ import annotations

import re

from rank_bm25 import BM25Okapi

from warrant.rag.naive_index import Chunk

_TOKEN = re.compile(r"[a-z0-9][a-z0-9.\-]*")


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class BM25Index:
    def __init__(self, chunks: list[Chunk]):
        self._chunks = chunks
        self._bm25 = BM25Okapi([tokenize(c.text) for c in chunks])

    def ranked_ids(self, query: str) -> list[str]:
        """All chunk ids ranked by BM25 score, best first."""
        scores = self._bm25.get_scores(tokenize(query))
        order = sorted(range(len(scores)), key=lambda i: -scores[i])
        return [self._chunks[i].id for i in order]
