"""Track 2 - end-to-end affected/not-affected classification.

Two classifiers run on the SAME dataset:

- deterministic : core.version_match.is_version_affected (PEP 440, no LLM)
- naive         : warrant.baseline.naive_is_affected (asks the LLM to do the
                  version math - the strawman Phase 1 beats)

Run:  uv run python -m evals.track2_classification              # deterministic
      uv run python -m evals.track2_classification naive        # LLM baseline
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from core.version_match import is_version_affected
from evals.metrics import precision_recall_f1

DATASET_PATH = Path("evals/datasets/classification.jsonl")

POSITIVE_LABELS = {"affected", "affected-transitively"}


@dataclass
class Case:
    id: str
    name: str
    version: str
    gold_label: str
    category: str
    osv_ranges: list = field(default_factory=list)


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
                    id=row["id"],
                    name=row["package"],
                    version=row["version"],
                    gold_label=row["label"],
                    category=row["category"],
                    osv_ranges=row.get("osv_ranges", []),
                )
            )
    return cases


def render_range_text(osv_ranges: list) -> str | None:
    """Render OSV ranges as a human-readable interval for the LLM prompt."""
    if not osv_ranges:
        return None
    parts: list[str] = []
    for osv_range in osv_ranges:
        low = high = None
        high_inclusive = False
        for event in osv_range.get("events", []):
            if "introduced" in event:
                low = event["introduced"]
            elif "fixed" in event:
                high, high_inclusive = event["fixed"], False
            elif "last_affected" in event:
                high, high_inclusive = event["last_affected"], True
        seg = "" if (low is None or low == "0") else f">= {low}"
        if high is not None:
            seg = (seg + ", " if seg else "") + (
                f"<= {high}" if high_inclusive else f"< {high}"
            )
        parts.append(seg or "all versions")
    return "; ".join(parts)


def classify_deterministic(case: Case) -> str:
    """PEP 440 range math. No LLM. Binary affected/not-affected."""
    if is_version_affected(case.version, case.osv_ranges):
        return "affected"
    return "not-affected"


def classify_naive(case: Case) -> str:
    """Hand the range math to the LLM (the forbidden thing, on purpose)."""
    from warrant.baseline import naive_is_affected
    from warrant.models import Package

    range_text = render_range_text(case.osv_ranges)
    if range_text is None:
        return "not-affected"
    package = Package(
        ecosystem="PyPI", name=case.name, version=case.version, tag="DIRECT"
    )
    return naive_is_affected(package, range_text)


def run(classifier: Callable[[Case], str], name: str) -> dict:
    cases = load_cases()

    predictions: list[bool] = []
    gold: list[bool] = []
    misses: list[str] = []
    boundary_correct = boundary_total = 0

    for case in cases:
        pred_label = classifier(case)
        pred_positive = pred_label in POSITIVE_LABELS
        gold_positive = case.gold_label in POSITIVE_LABELS
        correct = pred_positive == gold_positive

        predictions.append(pred_positive)
        gold.append(gold_positive)

        if case.category == "boundary_safe":
            boundary_total += 1
            boundary_correct += int(correct)

        if not correct:
            misses.append(
                f"  [{case.category}] {case.id} ({case.version}): "
                f"predicted={pred_label}, gold={case.gold_label}"
            )

    scores = precision_recall_f1(predictions, gold)
    boundary_acc = boundary_correct / boundary_total if boundary_total else 0.0

    print(f"Track 2 - classification: {name} ({len(cases)} cases)")
    print(f"  boundary accuracy: {boundary_acc:.3f}  "
          f"({boundary_correct}/{boundary_total} boundary_safe cases)")
    print(f"  precision: {scores['macro']['precision']:.3f}")
    print(f"  recall:    {scores['macro']['recall']:.3f}")
    print(f"  f1:        {scores['macro']['f1']:.3f}")
    if misses:
        print(f"\n  {len(misses)} incorrect case(s):")
        print("\n".join(misses))

    return {"scores": scores, "boundary_acc": boundary_acc}


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "deterministic"
    if mode == "naive":
        run(classify_naive, "naive LLM baseline")
    else:
        run(classify_deterministic, "deterministic PEP 440 resolver")
