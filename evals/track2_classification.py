from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from warrant.models import Package
from warrant.baseline import naive_is_affected
from evals.metrics import precision_recall_f1

DATASET_PATH = Path("evals/datasets/classification.jsonl")

POSITIVE_LABELS = {"affected", "affected-transitively"}


@dataclass
class Case:
    name: str
    version: str
    affected_range: str | None
    gold_label: str


def load_cases(path: Path = DATASET_PATH) -> list[Case]:
    cases: list[Case] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            cases.append(
                Case(
                    name=row["package"],
                    version=row["version"],
                    affected_range=row.get("affected_range"),
                    gold_label=row["label"],
                )
            )
    return cases


def classify(case: Case) -> str:
    if case.affected_range is None:
        return "not-affected"
    package = Package(
        ecosystem="PyPI",
        name=case.name,
        version=case.version,
        tag="DIRECT",
    )
    return naive_is_affected(package, case.affected_range)


def run() -> dict:
    cases = load_cases()

    predictions: list[bool] = []
    gold: list[bool] = []
    misses: list[str] = []

    for case in cases:
        pred_label = classify(case)
        pred_positive = pred_label in POSITIVE_LABELS
        gold_positive = case.gold_label in POSITIVE_LABELS

        predictions.append(pred_positive)
        gold.append(gold_positive)

        if pred_positive != gold_positive:
            misses.append(
                f"  {case.name} {case.version} "
                f"(range {case.affected_range}): "
                f"predicted={pred_label}, gold={case.gold_label}"
            )

    scores = precision_recall_f1(predictions, gold)

    print(f"Track 2 - classification ({len(cases)} cases)")
    print(f"  precision: {scores['macro']['precision']:.3f}")
    print(f"  recall:    {scores['macro']['recall']:.3f}")
    print(f"  f1:        {scores['macro']['f1']:.3f}")
    if misses:
        print(f"\n  {len(misses)} incorrect case(s):")
        print("\n".join(misses))

    return scores


if __name__ == "__main__":
    run()