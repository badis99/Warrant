"""Reachability eval — accuracy of the LLM's reachable/not-reachable/uncertain
judgment against the hand-labeled gold set.

Hits the real LLM, so run it explicitly:
    uv run python -m evals.reachability_eval

Reports overall accuracy, per-label accuracy, and a calibration check
(mean confidence on correct vs. incorrect predictions).
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from warrant.rag.reachability import assess_reachability

DATASET_PATH = Path("evals/datasets/reachability.jsonl")


@dataclass
class Case:
    id: str
    package: str
    advisory: str
    code_usage: str
    gold_label: str


def load_cases(path: Path = DATASET_PATH) -> list[Case]:
    cases: list[Case] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            cases.append(Case(
                id=row["id"],
                package=row["package"],
                advisory=row["advisory"],
                code_usage=row["code_usage"],
                gold_label=row["gold_label"],
            ))
    return cases


def run() -> dict:
    cases = load_cases()

    correct = 0
    per_label_total: dict[str, int] = defaultdict(int)
    per_label_correct: dict[str, int] = defaultdict(int)
    conf_when_right: list[float] = []
    conf_when_wrong: list[float] = []
    misses: list[str] = []

    for case in cases:
        result = assess_reachability(case.package, case.advisory, case.code_usage)
        hit = result.verdict == case.gold_label

        per_label_total[case.gold_label] += 1
        if hit:
            correct += 1
            per_label_correct[case.gold_label] += 1
            conf_when_right.append(result.confidence)
        else:
            conf_when_wrong.append(result.confidence)
            misses.append(
                f"  {case.id}: predicted={result.verdict} "
                f"(conf {result.confidence:.2f}), gold={case.gold_label}"
            )

    accuracy = correct / len(cases) if cases else 0.0

    def _mean(xs: list[float]) -> float:
        return sum(xs) / len(xs) if xs else 0.0

    print(f"Reachability eval ({len(cases)} hand-labeled cases)")
    print(f"  accuracy: {accuracy:.3f}  ({correct}/{len(cases)})")
    print("  per-label accuracy:")
    for label in sorted(per_label_total):
        c, t = per_label_correct[label], per_label_total[label]
        print(f"    {label:<14} {c}/{t}")
    print("  calibration (mean confidence):")
    print(f"    when correct:   {_mean(conf_when_right):.2f}")
    print(f"    when incorrect: {_mean(conf_when_wrong):.2f}")
    if misses:
        print(f"\n  {len(misses)} incorrect case(s):")
        print("\n".join(misses))

    return {"accuracy": accuracy}


if __name__ == "__main__":
    run()
