"""deps.dev client + resolver dispatcher tests (recorded responses)."""

import json
from pathlib import Path

import httpx

from core.depsdev import resolve_via_depsdev
from core.resolve import resolve_dependencies
from warrant.models import Package

FIXTURES = Path("tests/fixtures/depsdev")


def _mock_client() -> httpx.Client:
    body = json.loads((FIXTURES / "jinja2.json").read_text(encoding="utf-8"))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _by_name(packages) -> dict:
    return {p.name: p for p in packages}


def test_parses_relations_and_ecosystem():
    pkg = Package(ecosystem="PyPI", name="jinja2", version="3.1.4", tag="SELF")
    with _mock_client() as client:
        packages = _by_name(resolve_via_depsdev(pkg, client=client))

    assert packages["jinja2"].tag == "SELF"
    assert packages["markupsafe"].tag == "DIRECT"
    # deps.dev reports system "PYPI"; we normalize it to our "PyPI".
    assert packages["markupsafe"].ecosystem == "PyPI"
    assert packages["markupsafe"].version == "3.0.3"


def test_dispatcher_uses_lockfile_when_given_a_path():
    packages = _by_name(
        resolve_dependencies(lockfile_path="fixtures/transitive/uv.lock")
    )
    assert packages["pyyaml"].tag == "INDIRECT"   # came from resolve_graph


def test_dispatcher_uses_depsdev_when_given_a_package():
    pkg = Package(ecosystem="PyPI", name="jinja2", version="3.1.4", tag="SELF")
    with _mock_client() as client:
        packages = _by_name(resolve_dependencies(package=pkg, client=client))
    assert packages["markupsafe"].tag == "DIRECT"  # came from deps.dev


def test_dispatcher_requires_one_source():
    try:
        resolve_dependencies()
    except ValueError:
        return
    raise AssertionError("expected ValueError when no source is given")
