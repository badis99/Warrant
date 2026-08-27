from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import numpy as np

DEFAULT_CORPUS_PATH = Path("corpus/advisories.jsonl")
DEFAULT_MODEL = "minishlab/potion-base-8M"

# Type of an embedder: many texts in -> a 2-D array (n_texts, dim) out.
Embedder = Callable[[list[str]], np.ndarray]


@dataclass
class Chunk:
    id: str
    text: str


def load_corpus(path: str | Path = DEFAULT_CORPUS_PATH) -> list[Chunk]:
    chunks: list[Chunk] = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            chunks.append(Chunk(id=row["id"], text=row["text"]))
    return chunks


def _l2_normalize(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return matrix / norms


class NaiveIndex:

    def __init__(self, chunks: list[Chunk], embed: Embedder):
        self._chunks = chunks
        self._embed = embed
        matrix = embed([c.text for c in chunks])
        self._matrix = _l2_normalize(np.asarray(matrix, dtype=float))

    def retrieve(self, query: str, k: int) -> list[Chunk]:
        query_vec = _l2_normalize(
            np.asarray(self._embed([query]), dtype=float)
        )[0]
        # Cosine similarity == dot product of L2-normalized vectors.
        scores = self._matrix @ query_vec
        # argsort descending, take top k.
        order = np.argsort(-scores)[:k]
        return [self._chunks[i] for i in order]


_default_model = None


def _default_embed(texts: list[str]) -> np.ndarray:
    global _default_model
    if _default_model is None:
        from model2vec import StaticModel

        _default_model = StaticModel.from_pretrained(DEFAULT_MODEL)
    return _default_model.encode(texts)


def naive_retrieve(
    query: str,
    k: int,
    corpus_path: str | Path = DEFAULT_CORPUS_PATH,
) -> list[Chunk]:
    
    index = NaiveIndex(load_corpus(corpus_path), embed=_default_embed)
    return index.retrieve(query, k)
