"""Tests for breaking-change assessment output parsing (LLM mocked)."""

from warrant.rag.breakage import BreakageReport, assess_breakage


def _reply(text: str):
    return lambda prompt: text


def test_parses_breaking_true():
    reply = ('{"breaking": true, "notes": ["client.fetch() renamed to get()"], '
             '"effort_hint": "about an hour"}')
    r = assess_breakage("somelib", "2.4", "3.0", "changelog...", complete=_reply(reply))
    assert isinstance(r, BreakageReport)
    assert r.breaking is True
    assert r.notes
    assert "hour" in r.effort_hint


def test_parses_non_breaking():
    reply = '{"breaking": false, "notes": [], "effort_hint": "drop-in"}'
    r = assess_breakage("pkg", "1.0", "1.0.1", "bugfix only", complete=_reply(reply))
    assert r.breaking is False


def test_malformed_output_is_conservative_unknown():
    r = assess_breakage("pkg", "1.0", "2.0", "cl", complete=_reply("no json"))
    assert r.breaking is False
    assert r.effort_hint == "unknown"


def test_prompt_carries_changelog_and_versions():
    seen = {}

    def spy(prompt: str):
        seen["p"] = prompt
        return '{"breaking": false}'

    assess_breakage("pkg", "1.2.3", "2.0.0", "CHANGELOG_MARKER", complete=spy)
    assert "CHANGELOG_MARKER" in seen["p"]
    assert "1.2.3" in seen["p"] and "2.0.0" in seen["p"]
