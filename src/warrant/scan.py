"""Command-line scan: read a lockfile and print the remediation plan.

    uv run python -m warrant.scan path/to/uv.lock

No server, no JSON — just the human-readable plan.
"""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    try:  # let non-ASCII package names print on legacy Windows consoles
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if not argv:
        print("usage: python -m warrant.scan <path-to-lockfile>")
        return 2

    from warrant.agent.graph import build_graph
    from warrant.render import render_report

    path = argv[0]
    final = build_graph().invoke({"lockfile_path": path})
    print(render_report(final["report"], source=path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
