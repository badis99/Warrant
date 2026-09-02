"""Tests for reconstructing the dependency graph from a uv.lock.

The lockfile already records each package's dependencies, so we can tag every
package SELF / DIRECT / INDIRECT without installing or hitting the network.
"""

from core.resolve import resolve_graph


def _by_name(packages) -> dict:
    return {p.name: p for p in packages}


def test_tags_self_direct_and_indirect():
    packages = _by_name(resolve_graph("fixtures/transitive/uv.lock"))

    assert packages["myapp"].tag == "SELF"        # the root project
    assert packages["some-lib"].tag == "DIRECT"   # declared by the root
    assert packages["pyyaml"].tag == "INDIRECT"   # pulled in via some-lib


def test_preserves_versions():
    packages = _by_name(resolve_graph("fixtures/transitive/uv.lock"))
    assert packages["pyyaml"].version == "5.3"
    assert packages["pyyaml"].ecosystem == "PyPI"


def test_falls_back_to_direct_when_no_root_marked():
    # The simple fixture has no editable/virtual root, so the graph can't be
    # reconstructed; every package is conservatively tagged DIRECT.
    packages = resolve_graph("fixtures/simple/uv.lock")
    assert packages
    assert all(p.tag == "DIRECT" for p in packages)
