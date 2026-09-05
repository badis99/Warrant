"""Breaking-change assessment — RAG/LLM over changelog prose.

OSV gives the fixed version but says nothing about what an upgrade breaks. That
lives in changelogs and migration notes. The model reads the changelog between
the current and target versions and reports whether the upgrade is breaking,
with each note grounded in that text. Every claim must trace to the changelog,
never invented.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from warrant.rag.llm_json import parse_json_reply


@dataclass
class BreakageReport:
    breaking: bool
    notes: list[str] = field(default_factory=list)
    effort_hint: str = ""


_UNKNOWN = BreakageReport(
    breaking=False, notes=["assessment unavailable"], effort_hint="unknown"
)


def _build_prompt(package: str, current: str, target: str, changelog: str) -> str:
    return (
        f"Assess whether upgrading `{package}` from {current} to {target} is a "
        "breaking change for a caller.\n\n"
        f"CHANGELOG / RELEASE NOTES between {current} and {target}:\n{changelog}\n\n"
        "Base every claim on the changelog above; do not invent changes. If the "
        "notes only describe bug/security fixes, it is not breaking.\n\n"
        "Respond with ONLY a JSON object:\n"
        '{"breaking": true|false, '
        '"notes": ["specific breaking changes, each grounded in the changelog"], '
        '"effort_hint": "rough effort to adapt, e.g. drop-in / ~1 hour"}'
    )


def _coerce_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes", "1"}


def _default_complete(prompt: str) -> str:
    from warrant.llm import complete

    return complete(prompt)


def assess_breakage(
    package: str,
    current: str,
    target: str,
    changelog: str,
    complete=None,
) -> BreakageReport:
    """Judge whether current -> target is a breaking upgrade, from the changelog.

    Malformed model output degrades to a conservative 'unknown' report rather
    than asserting a confident answer.
    """
    complete = complete or _default_complete
    data = parse_json_reply(complete(_build_prompt(package, current, target, changelog)))
    if data is None:
        return _UNKNOWN

    notes = data.get("notes", [])
    if not isinstance(notes, list):
        notes = [str(notes)]

    return BreakageReport(
        breaking=_coerce_bool(data.get("breaking", False)),
        notes=[str(n) for n in notes],
        effort_hint=str(data.get("effort_hint", "")),
    )
