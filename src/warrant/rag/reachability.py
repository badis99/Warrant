"""Reachability reasoning — the one place the LLM makes a judgment.

Given an advisory's prose and how the code uses the package, the model decides
whether the vulnerability is actually reachable, with a confidence and cited
evidence. This is *advisory-condition reasoning*, not a static-analysis
soundness proof: the verdict includes `uncertain` precisely so the model can
decline when the evidence is thin, and confidence is always reported.

The LLM callable is injectable so tests run without the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from warrant.rag.llm_json import parse_json_reply

_VERDICTS = {"reachable", "not-reachable", "uncertain"}


@dataclass
class Reachability:
    verdict: str            # reachable | not-reachable | uncertain
    confidence: float       # 0.0 .. 1.0
    condition: str = ""     # the advisory condition the judgment turns on
    evidence: list[str] = field(default_factory=list)


_UNCERTAIN = Reachability(verdict="uncertain", confidence=0.0)


def _build_prompt(package: str, advisory_text: str, code_usage: str) -> str:
    return (
        "You are assessing whether a known vulnerability is actually reachable "
        f"in a project that depends on `{package}`.\n\n"
        f"ADVISORY (may state a condition for exploitability):\n{advisory_text}\n\n"
        f"HOW THE PROJECT USES THE PACKAGE:\n{code_usage}\n\n"
        "Decide if the vulnerability is reachable given this usage. If the "
        "advisory names a condition (a specific function or configuration) and "
        "the usage does not meet it, answer not-reachable. If the evidence is "
        "insufficient, answer uncertain.\n\n"
        "Respond with ONLY a JSON object:\n"
        '{"verdict": "reachable|not-reachable|uncertain", '
        '"confidence": 0.0-1.0, '
        '"condition": "the deciding condition", '
        '"evidence": ["short quotes or facts you relied on"]}'
    )


def _parse(raw: str) -> Reachability:
    data = parse_json_reply(raw)
    if data is None:
        return _UNCERTAIN

    verdict = str(data.get("verdict", "")).strip().lower()
    if verdict not in _VERDICTS:
        verdict = "uncertain"

    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    condition = str(data.get("condition", ""))
    evidence = data.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = [str(evidence)]

    return Reachability(
        verdict=verdict,
        confidence=confidence,
        condition=condition,
        evidence=[str(e) for e in evidence],
    )


def _default_complete(prompt: str) -> str:
    from warrant.llm import complete

    return complete(prompt)


def assess_reachability(
    package: str,
    advisory_text: str,
    code_usage: str,
    complete=None,
) -> Reachability:
    """Judge whether a vulnerability is reachable given how the code uses it.

    Args:
        package: the dependency name.
        advisory_text: retrieved advisory prose (may carry a condition).
        code_usage: how the project uses the package.
        complete: an LLM callable prompt->text; defaults to warrant.llm.complete.

    Returns:
        A Reachability with verdict, confidence, deciding condition, and cited
        evidence. Malformed model output degrades to uncertain (confidence 0).
    """
    complete = complete or _default_complete
    return _parse(complete(_build_prompt(package, advisory_text, code_usage)))
