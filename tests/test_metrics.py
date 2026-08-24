import pytest

from evals.metrics import _prf_from_counts, precision_recall_f1


def test_prf_from_perfect_counts():
    assert _prf_from_counts(tp=5, fp=0, fn=0) == {
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }


def test_prf_guards_divide_by_zero():
    # No predictions and no golds for this class -> all zero, no crash.
    assert _prf_from_counts(tp=0, fp=0, fn=0) == {
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
    }


def test_prf_is_harmonic_mean_not_arithmetic():
    # tp=1, fp=1, fn=0 -> precision=0.5, recall=1.0
    # arithmetic mean would be 0.75; the harmonic mean (F1) is 2/3.
    scores = _prf_from_counts(tp=1, fp=1, fn=0)
    assert scores["precision"] == 0.5
    assert scores["recall"] == 1.0
    assert scores["f1"] == pytest.approx(2 / 3)


def test_multiclass_per_class_and_macro():
    gold = [
        "affected",
        "affected",
        "not-affected",
        "not-affected",
        "affected-transitively",
    ]
    predictions = [
        "affected",                # correct
        "not-affected",            # miss: an affected case called safe
        "not-affected",            # correct
        "affected",                # false alarm
        "affected-transitively",   # correct
    ]

    result = precision_recall_f1(predictions, gold)

    # Hand-computed (one-vs-rest per class):
    #   affected:               tp=1 fp=1 fn=1 -> P=.5  R=.5  F1=.5
    #   not-affected:           tp=1 fp=1 fn=1 -> P=.5  R=.5  F1=.5
    #   affected-transitively:  tp=1 fp=0 fn=0 -> P=1   R=1   F1=1
    assert result["per_class"]["affected"] == {"precision": 0.5, "recall": 0.5, "f1": 0.5}
    assert result["per_class"]["not-affected"] == {"precision": 0.5, "recall": 0.5, "f1": 0.5}
    assert result["per_class"]["affected-transitively"] == {"precision": 1.0, "recall": 1.0, "f1": 1.0}

    # Macro = unweighted mean across the 3 classes = (0.5 + 0.5 + 1.0) / 3
    assert result["macro"]["precision"] == pytest.approx(2 / 3)
    assert result["macro"]["recall"] == pytest.approx(2 / 3)
    assert result["macro"]["f1"] == pytest.approx(2 / 3)


def test_length_mismatch_raises():
    with pytest.raises(ValueError):
        precision_recall_f1(["affected"], ["affected", "not-affected"])