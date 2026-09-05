"""Tests for robust JSON extraction from reasoning-model output."""

from warrant.rag.llm_json import parse_json_reply


def test_reads_answer_after_think_block():
    raw = (
        "<think>\nLet me consider... maybe {\"verdict\": \"wrong\"}\n</think>\n"
        '{"verdict": "reachable", "confidence": 0.9}'
    )
    data = parse_json_reply(raw)
    assert data == {"verdict": "reachable", "confidence": 0.9}


def test_falls_back_to_json_inside_think_when_answer_truncated():
    # No closing </think> answer; the only JSON is inside the thinking.
    raw = '<think>\nMy answer: {"breaking": true}\n'
    data = parse_json_reply(raw)
    assert data == {"breaking": True}


def test_returns_none_when_no_json():
    assert parse_json_reply("no json here at all") is None
    assert parse_json_reply("") is None
