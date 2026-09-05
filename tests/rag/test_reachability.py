"""Tests for reachability reasoning output parsing (LLM mocked).

Quality is measured separately by the reachability eval; these tests pin the
structure: that we turn whatever the model says into a well-formed
Reachability, and degrade to `uncertain` rather than crashing on bad output.
"""

from warrant.rag.reachability import Reachability, assess_reachability


def _fixed_reply(text: str):
    return lambda prompt: text


def test_parses_clean_json():
    reply = (
        '{"verdict": "reachable", "confidence": 0.9, '
        '"condition": "calls yaml.load on untrusted input", '
        '"evidence": ["advisory: exploitable via yaml.load"]}'
    )
    r = assess_reachability("pyyaml", "advisory...", "code calls yaml.load",
                            complete=_fixed_reply(reply))
    assert isinstance(r, Reachability)
    assert r.verdict == "reachable"
    assert r.confidence == 0.9
    assert "yaml.load" in r.condition
    assert r.evidence


def test_parses_json_wrapped_in_prose_and_fences():
    reply = (
        "Sure, here is my analysis:\n```json\n"
        '{"verdict": "not-reachable", "confidence": 0.7, '
        '"condition": "requires proxy config", "evidence": ["n/a"]}\n```'
    )
    r = assess_reachability("urllib3", "adv", "no proxy used",
                            complete=_fixed_reply(reply))
    assert r.verdict == "not-reachable"
    assert r.confidence == 0.7


def test_unknown_verdict_becomes_uncertain():
    reply = '{"verdict": "maybe", "confidence": 0.5}'
    r = assess_reachability("x", "adv", "usage", complete=_fixed_reply(reply))
    assert r.verdict == "uncertain"


def test_malformed_output_degrades_to_uncertain():
    r = assess_reachability("x", "adv", "usage",
                            complete=_fixed_reply("I think it might be reachable"))
    assert r.verdict == "uncertain"
    assert r.confidence == 0.0


def test_confidence_is_clamped_to_unit_interval():
    high = assess_reachability("x", "a", "u",
                               complete=_fixed_reply('{"verdict":"reachable","confidence":1.7}'))
    low = assess_reachability("x", "a", "u",
                              complete=_fixed_reply('{"verdict":"reachable","confidence":-0.3}'))
    assert high.confidence == 1.0
    assert low.confidence == 0.0


def test_prompt_carries_advisory_and_code_usage():
    seen = {}

    def spy(prompt: str):
        seen["prompt"] = prompt
        return '{"verdict":"uncertain","confidence":0.0}'

    assess_reachability("pyyaml", "ADVISORY_MARKER", "CODE_USAGE_MARKER",
                        complete=spy)
    assert "ADVISORY_MARKER" in seen["prompt"]
    assert "CODE_USAGE_MARKER" in seen["prompt"]
