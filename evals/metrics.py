from __future__ import annotations


def _counts(
    predictions: list[str],
    gold: list[str],
    positive_label: str,
) -> tuple[int, int, int]:
    tp = fp = fn = 0
    for pred, actual in zip(predictions, gold):
        if pred == positive_label and actual == positive_label:
            tp += 1
        elif pred == positive_label and actual != positive_label:
            fp += 1
        elif pred != positive_label and actual == positive_label:
            fn += 1
    return tp, fp, fn


def _prf_from_counts(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    return {"precision": precision, "recall": recall, "f1": f1}


def precision_recall_f1(
    predictions: list[str],
    gold: list[str],
    labels: list[str] | None = None,
) -> dict:
    """Per-class and macro-averaged precision/recall/F1.

    Args:
        predictions: predicted label per case.
        gold: gold label per case, aligned positionally with `predictions`.
        labels: label set to score. Defaults to the sorted union of labels
            seen. Pass an explicit list for stable table columns across runs.

    Returns:
        {
          "per_class": {label: {"precision", "recall", "f1"}},
          "macro":     {"precision", "recall", "f1"},
        }
    """
    if len(predictions) != len(gold):
        raise ValueError(
            f"predictions ({len(predictions)}) and gold ({len(gold)}) "
            "must be the same length"
        )

    if labels is None:
        labels = sorted(set(gold) | set(predictions))

    per_class = {
        label: _prf_from_counts(*_counts(predictions, gold, label))
        for label in labels
    }

    n = len(labels)
    macro = {
        metric: (
            sum(scores[metric] for scores in per_class.values()) / n
            if n
            else 0.0
        )
        for metric in ("precision", "recall", "f1")
    }

    return {"per_class": per_class, "macro": macro}