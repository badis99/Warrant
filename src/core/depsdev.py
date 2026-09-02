"""
Only needed when we have a manifest but no lockfile (a lockfile already carries
the resolved tree, so `core.resolve.resolve_graph` handles that case). The
dependencies endpoint returns nodes already tagged SELF / DIRECT / INDIRECT.
"""

from __future__ import annotations

import httpx

from warrant.models import Package

_DEPSDEV_URL = (
    "https://api.deps.dev/v3/systems/pypi/packages/{name}/versions/{version}"
    ":dependencies"
)
_DEFAULT_TIMEOUT = 20.0

# deps.dev uppercases the ecosystem; map it back to our canonical form.
_SYSTEM_TO_ECOSYSTEM = {"PYPI": "PyPI"}


def resolve_via_depsdev(
    package: Package,
    client: httpx.Client | None = None,
) -> list[Package]:
    """Return the resolved dependency nodes for `package` from deps.dev."""
    own_client = client is None
    client = client or httpx.Client(timeout=_DEFAULT_TIMEOUT)
    try:
        response = client.get(
            _DEPSDEV_URL.format(name=package.name, version=package.version)
        )
        response.raise_for_status()
        nodes = response.json().get("nodes", [])

        packages: list[Package] = []
        for node in nodes:
            version_key = node.get("versionKey", {})
            system = version_key.get("system", "")
            packages.append(
                Package(
                    ecosystem=_SYSTEM_TO_ECOSYSTEM.get(system, system),
                    name=version_key.get("name", ""),
                    version=version_key.get("version", ""),
                    tag=node.get("relation", "INDIRECT"),
                )
            )
        return packages
    finally:
        if own_client:
            client.close()
