"""Tests for the naive (embedding-only) retriever's ranking logic.

We inject a tiny deterministic bag-of-words embedder so the cosine/top-k logic
is tested exactly, with no model download. The real harness injects model2vec.
"""

import numpy as np

from warrant.rag.naive_index import Chunk, NaiveIndex, load_corpus

VOCAB = ["apple", "banana", "cherry"]


def bow_embed(texts: list[str]) -> np.ndarray:
    """Count occurrences of each vocab word. Deterministic, no model needed."""
    rows = []
    for text in texts:
        words = text.lower().split()
        rows.append([float(words.count(w)) for w in VOCAB])
    return np.array(rows, dtype=float)


CHUNKS = [
    Chunk(id="c1", text="apple apple"),   # vector [2, 0, 0]
    Chunk(id="c2", text="banana"),         # vector [0, 1, 0]
    Chunk(id="c3", text="apple banana"),   # vector [1, 1, 0]
]


def test_retrieve_ranks_by_cosine_similarity():
    index = NaiveIndex(CHUNKS, embed=bow_embed)

    # Query "apple" -> [1,0,0]. Cosine: c1=1.0, c3=1/sqrt(2)~0.707, c2=0.0
    results = index.retrieve("apple", k=2)

    assert [c.id for c in results] == ["c1", "c3"]


def test_retrieve_respects_k():
    index = NaiveIndex(CHUNKS, embed=bow_embed)
    results = index.retrieve("apple", k=1)
    assert [c.id for c in results] == ["c1"]


def test_retrieve_returns_chunk_objects_with_text():
    index = NaiveIndex(CHUNKS, embed=bow_embed)
    top = index.retrieve("apple", k=1)[0]
    assert isinstance(top, Chunk)
    assert top.id == "c1"
    assert top.text == "apple apple"


def test_retrieve_handles_out_of_vocab_query_without_crashing():
    # "cherry" appears in no chunk -> query norm nonzero but all sims 0.
    # Should still return k chunks, not raise.
    index = NaiveIndex(CHUNKS, embed=bow_embed)
    results = index.retrieve("cherry", k=2)
    assert len(results) == 2


def test_load_corpus_reads_jsonl(tmp_path):
    path = tmp_path / "corpus.jsonl"
    path.write_text(
        '{"id": "x1", "text": "first chunk"}\n'
        "\n"  # blank line should be skipped
        '{"id": "x2", "text": "second chunk"}\n',
        encoding="utf-8",
    )

    chunks = load_corpus(path)

    assert [c.id for c in chunks] == ["x1", "x2"]
    assert chunks[0].text == "first chunk"
