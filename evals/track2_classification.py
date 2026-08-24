"""Track 2 — end-to-end classification eval (Phase 0 baseline runner).

Runs the DELIBERATELY NAIVE classifier (which asks the LLM to do version math)
over the labeled dataset and scores it. This hits the real LLM, so it is NOT a
pytest test -- run it explicitly:

    uv run python -m evals.track2_classification

Each dataset line (evals/datasets/classification.jsonl) is expected to look like:

    {"package": "pillow", "version": "9.2.0",
     "affected_range": ">=0,<9.3.0", "gold": "affected", "note": "GHSA-xxxx"}

`affected_range` is null for packages with no known advisory (trivially safe).
In Phase 2 this range will come live from OSV; in Phase 0 you record it by hand
as part of labeling (Task 0.4).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from warrant.baseline import naive_is_affected
from warrant.models import Package
from evals.metrics import precision_recall_f1

DATASET_PATH = Path("evals/datasets/classification.jsonl")


def load_dataset(path: Path = DATASET_PATH) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _classify_row(row: dict, classify: Callable[[Package, str], str]) -> str:
    """Predict a label for one dataset row using the naive classifier.

    Rows with no advisory (affected_range is null) are trivially not-affected,
    so we skip the LLM call entirely. Everything else is handed to the naive
    classifier -- including the boundary cases it is expected to fumble.
    """
    affected_range = row.get("affected_range")
    if not affected_range:
        return "not-affected"

    package = Package(
        ecosystem="PyPI",
        name=row["package"],
        version=row["version"],
        tag="DIRECT",
    )
    return classify(package, affected_range)


def run_baseline(
    dataset: list[dict],
    classify: Callable[[Package, str], str] = naive_is_affected,
) -> tuple[list[str], list[str]]:
    """Run the classifier over the dataset; return (predictions, gold).

    `classify` is injectable so a test can pass a fake instead of the real LLM.
    """
    predictions = [_classify_row(row, classify) for row in dataset]
    gold = [row["gold"] for row in dataset]
    return predictions, gold


def main() -> None:
    dataset = load_dataset()
    predictions, gold = run_baseline(dataset)
    scores = precision_recall_f1(predictions, gold)

    print(f"Track 2 -- classification baseline ({len(dataset)} cases)\n")
    print(f"{'class':<24} {'P':>6} {'R':>6} {'F1':>6}")
    for label, s in scores["per_class"].items():
        print(f"{label:<24} {s['precision']:>6.2f} {s['recall']:>6.2f} {s['f1']:>6.2f}")
    m = scores["macro"]
    print(f"{'MACRO':<24} {m['precision']:>6.2f} {m['recall']:>6.2f} {m['f1']:>6.2f}")


if __name__ == "__main__":
    main()