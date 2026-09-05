"""Enforce the architectural rule: the deterministic core never touches an LLM.

If this test ever fails, version-range decisions have leaked into a model — the
one thing the whole project forbids. It runs in CI like any other test.
"""

from pathlib import Path

CORE_DIR = Path("src/core")

# Substrings that would indicate the deterministic core reached for an LLM,
# retrieval, or the agent layer.
FORBIDDEN = ["groq", "warrant.llm", "warrant.rag", "model2vec", "langgraph",
             "assess_reachability", "assess_breakage", "openai"]


def test_core_never_imports_an_llm():
    offenders = []
    for path in CORE_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        for token in FORBIDDEN:
            if token in text:
                offenders.append(f"{path}: contains '{token}'")
    assert not offenders, (
        "src/core must stay deterministic (no LLM/RAG). Offenders:\n"
        + "\n".join(offenders)
    )
