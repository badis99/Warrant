"""CI eval gate: fail the build if a quality metric regresses.

Runs only the DETERMINISTIC evals so the gate is fast, hermetic, and needs no
LLM, network, or API key — a green gate means the deterministic guarantees
(version math, remediation targets, transitive tagging) still hold exactly.
The LLM-dependent evals (reachability, breakage) are measured separately with a
budget; gating on them would make CI flaky and costly.

    uv run python -m evals.gate      # exits non-zero on any regression
"""

from __future__ import annotations

import sys

from evals.remediation_eval import run as run_remediation
from evals.track2_classification import classify_deterministic
from evals.track2_classification import run as run_classification

# Minimum acceptable value per metric. The deterministic layer is exact, so
# these are all 1.0 — any drop is a real regression.
THRESHOLDS = {
    "remediation_target_accuracy": 1.0,
    "classification_exact_accuracy": 1.0,
    "classification_f1": 1.0,
}


def check() -> list[str]:
    """Run the deterministic evals; return a list of threshold violations."""
    failures: list[str] = []

    remediation = run_remediation()
    if remediation["accuracy"] < THRESHOLDS["remediation_target_accuracy"]:
        failures.append(
            f"remediation target accuracy {remediation['accuracy']:.3f} "
            f"< {THRESHOLDS['remediation_target_accuracy']}"
        )

    classification = run_classification(classify_deterministic, "deterministic (gate)")
    if classification["exact_acc"] < THRESHOLDS["classification_exact_accuracy"]:
        failures.append(
            f"classification exact accuracy {classification['exact_acc']:.3f} "
            f"< {THRESHOLDS['classification_exact_accuracy']}"
        )
    f1 = classification["scores"]["macro"]["f1"]
    if f1 < THRESHOLDS["classification_f1"]:
        failures.append(f"classification F1 {f1:.3f} < {THRESHOLDS['classification_f1']}")

    return failures


def main() -> None:
    failures = check()
    if failures:
        print("\nEVAL GATE FAILED:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\nEVAL GATE PASSED")


if __name__ == "__main__":
    main()
