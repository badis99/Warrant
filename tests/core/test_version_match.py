"""Boundary tests for deterministic PEP 440 range matching.

These encode exactly the traps the naive LLM baseline gets wrong: the fixed
boundary is EXCLUSIVE, the introduced boundary is INCLUSIVE, and pre-releases
must sort per PEP 440. If these pass, the killer artifact is real.
"""

from core.version_match import is_version_affected


def _range(*events: dict) -> list[dict]:
    """Wrap events in a single ECOSYSTEM range, as OSV nests them."""
    return [{"type": "ECOSYSTEM", "events": list(events)}]


CLOSED = _range({"introduced": "1.2.0"}, {"fixed": "1.4.5"})


def test_fixed_boundary_is_exclusive():
    # The classic off-by-one: the fixed version itself is NOT affected.
    assert is_version_affected("1.4.5", CLOSED) is False


def test_one_patch_below_fixed_is_affected():
    assert is_version_affected("1.4.4", CLOSED) is True


def test_introduced_boundary_is_inclusive():
    assert is_version_affected("1.2.0", CLOSED) is True


def test_below_introduced_is_not_affected():
    assert is_version_affected("1.1.9", CLOSED) is False


def test_introduced_zero_means_from_the_beginning():
    r = _range({"introduced": "0"}, {"fixed": "5.4"})
    assert is_version_affected("5.3", r) is True
    assert is_version_affected("5.4", r) is False   # patched boundary
    assert is_version_affected("6.0.1", r) is False  # well above the fix


def test_open_range_with_no_fix():
    # introduced but never fixed -> everything at/above introduced is affected.
    r = _range({"introduced": "1.0"})
    assert is_version_affected("2.0", r) is True
    assert is_version_affected("0.9", r) is False


def test_last_affected_is_inclusive_upper_bound():
    r = _range({"introduced": "1.0"}, {"last_affected": "1.5"})
    assert is_version_affected("1.5", r) is True    # last_affected is inclusive
    assert is_version_affected("1.6", r) is False


def test_prerelease_sorts_below_final_per_pep440():
    r = _range({"introduced": "0"}, {"fixed": "2.0"})
    assert is_version_affected("2.0rc1", r) is True   # rc1 < 2.0 final
    assert is_version_affected("2.0", r) is False


def test_multiple_intervals_in_one_range():
    r = _range(
        {"introduced": "1.0"},
        {"fixed": "1.5"},
        {"introduced": "2.0"},
        {"fixed": "2.5"},
    )
    assert is_version_affected("1.2", r) is True
    assert is_version_affected("1.7", r) is False   # gap between intervals
    assert is_version_affected("2.3", r) is True
    assert is_version_affected("2.6", r) is False


def test_affected_if_any_range_matches():
    ranges = _range({"introduced": "1.0"}, {"fixed": "1.1"})
    ranges += [{"type": "ECOSYSTEM",
                "events": [{"introduced": "3.0"}, {"fixed": "3.2"}]}]
    assert is_version_affected("3.1", ranges) is True
    assert is_version_affected("2.0", ranges) is False


def test_no_ranges_means_not_affected():
    assert is_version_affected("1.0", []) is False
