"""Extract a JSON object from reasoning-model output.

Models like qwen wrap their analysis in <think>...</think>, which may itself
contain example JSON. We prefer the answer AFTER the thinking, and fall back to
any parseable object in the whole reply (e.g. if the final answer was truncated
by the token limit). Our schemas have no nested objects, so a non-greedy {...}
captures exactly one object.
"""

from __future__ import annotations

import json
import re

_THINK = re.compile(r"<think>.*?</think>", re.DOTALL)
_JSON_OBJECT = re.compile(r"\{.*?\}", re.DOTALL)


def _last_json_object(text: str) -> dict | None:
    result: dict | None = None
    for match in _JSON_OBJECT.finditer(text):
        try:
            parsed = json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            result = parsed
    return result


def parse_json_reply(raw: str) -> dict | None:
    """Return the last well-formed JSON object in `raw`, preferring the text
    after any <think> block. None if nothing parseable is found."""
    raw = raw or ""
    return _last_json_object(_THINK.sub("", raw)) or _last_json_object(raw)
