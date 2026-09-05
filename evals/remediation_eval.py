"""Remediation-target eval — does the deterministic resolver pick the right
minimal safe version? No LLM, so it is reproducible and CI-friendly.

Run:  uv run python -m evals.remediation_eval
"""

from __future__ import annotations

import json
from pathlib import Path

from core.remediate import minimal_safe_version
from warrant.models import Package, VulnCandidate

DATASET_PATH = Path("evals/datasets/remediation.jsonl")


def _fixed_from(ranges: list[dict]) -> list[str]:
    return [
        e["fixed"]
        for r in ranges if r.get("type") != "GIT"
        for e in r.get("events", []) if "fixed" in e
    ]


def run() -> dict:
    correct = 0
    rows = []
    with DATASET_PATH.open(encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    misses = []
    for row in rows:
        candidate = VulnCandidate(
            package=Package(ecosystem="PyPI", name=row["package"],
                            version=row["current"], tag="DIRECT"),
            osv_id=row["id"], aliases=[],
            affected_ranges=row["osv_ranges"],
            fixed_versions=_fixed_from(row["osv_ranges"]),
        )
        target = minimal_safe_version(row["current"], [candidate])
        if target == row["expected_target"]:
            correct += 1
        else:
            misses.append(f"  {row['id']}: got {target}, expected {row['expected_target']}")

    accuracy = correct / len(rows) if rows else 0.0
    print(f"Remediation-target eval ({len(rows)} cases)")
    print(f"  target accuracy: {accuracy:.3f}  ({correct}/{len(rows)})")
    if misses:
        print("\n".join(misses))
    return {"accuracy": accuracy}


if __name__ == "__main__":
    run()
