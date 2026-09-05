"""The eval gate must currently pass (no regressions in the deterministic evals)."""

from evals.gate import check


def test_no_regressions():
    failures = check()
    assert failures == [], "eval gate regressions:\n" + "\n".join(failures)
