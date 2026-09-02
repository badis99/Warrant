"""Reconstruct the dependency graph from a lockfile.

A uv.lock already contains the fully resolved tree, so this is deterministic
and offline: we read each package's declared dependencies and tag every node by
its relation to the root project:

- SELF     : the root project itself (marked with an editable/virtual source).
- DIRECT   : a dependency the root declares explicitly.
- INDIRECT : a package reachable only through other dependencies.

When no root is marked (e.g. a bare package list), the graph can't be
reconstructed and every package is conservatively tagged DIRECT.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from warrant.models import Package


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def _is_root(package: dict) -> bool:
    source = package.get("source", {})
    return "editable" in source or "virtual" in source


def resolve_graph(lockfile_path: str) -> list[Package]:
    with Path(lockfile_path).open("rb") as f:
        data = tomllib.load(f)

    raw_packages = data.get("package", [])
    root = next((p for p in raw_packages if _is_root(p)), None)

    if root is None:
        # Can't determine the tree; fall back to tagging everything DIRECT.
        return [
            Package(ecosystem="PyPI", name=p["name"], version=p["version"],
                    tag="DIRECT")
            for p in raw_packages
        ]

    direct_names = {
        _normalize(dep["name"]) for dep in root.get("dependencies", [])
    }

    result: list[Package] = []
    for p in raw_packages:
        name = p["name"]
        if p is root:
            tag = "SELF"
        elif _normalize(name) in direct_names:
            tag = "DIRECT"
        else:
            tag = "INDIRECT"
        result.append(
            Package(ecosystem="PyPI", name=name, version=p["version"], tag=tag)
        )
    return result


def resolve_dependencies(
    *,
    lockfile_path: str | None = None,
    package: Package | None = None,
    client=None,
) -> list[Package]:
    """Pick the right resolver for the input.

    Prefer a lockfile (offline, already resolved); fall back to deps.dev only
    when all we have is a manifest package with no lock.
    """
    if lockfile_path is not None:
        return resolve_graph(lockfile_path)
    if package is not None:
        from core.depsdev import resolve_via_depsdev

        return resolve_via_depsdev(package, client=client)
    raise ValueError("provide either lockfile_path or package")
