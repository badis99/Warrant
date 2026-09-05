"""FastAPI service wrapping the Warrant pipeline.

POST /scan with a lockfile's contents returns the cited remediation report.
The scan function is injectable so the HTTP layer can be tested without the
network or an LLM.

Run:  uv run uvicorn warrant.api:app --reload
"""

from __future__ import annotations

import os
import tempfile

from fastapi import FastAPI
from pydantic import BaseModel


class ScanRequest(BaseModel):
    lockfile: str


def _default_scan(lockfile_text: str) -> dict:
    """Write the lockfile to a temp file, run the graph, return the report."""
    from warrant.agent.graph import build_graph

    with tempfile.NamedTemporaryFile(
        "w", suffix=".lock", delete=False, encoding="utf-8"
    ) as handle:
        handle.write(lockfile_text)
        path = handle.name
    try:
        final = build_graph().invoke({"lockfile_path": path})
        return final["report"]
    finally:
        os.unlink(path)


def create_app(scan_fn=_default_scan, enable_caching: bool = True) -> FastAPI:
    if enable_caching:
        from core.osv import enable_cache

        enable_cache()

    app = FastAPI(title="Warrant", version="0.1.0")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/scan")
    def scan(request: ScanRequest) -> dict:
        return scan_fn(request.lockfile)

    return app


app = create_app()
