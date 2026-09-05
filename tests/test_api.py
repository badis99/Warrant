"""API tests via TestClient — the scan function is stubbed, so no network/LLM."""

from fastapi.testclient import TestClient

from warrant.api import create_app


def _client(scan_fn):
    return TestClient(create_app(scan_fn=scan_fn, enable_caching=False))


def test_health():
    client = _client(lambda text: {"status": "clean"})
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_scan_returns_the_report():
    def stub(lockfile_text: str) -> dict:
        return {"status": "findings", "findings": [{"package": "pyyaml"}]}

    client = _client(stub)
    resp = client.post("/scan", json={"lockfile": "[[package]]\nname='x'"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "findings"
    assert body["findings"][0]["package"] == "pyyaml"


def test_scan_text_format_returns_human_readable_plan():
    def stub(lockfile_text: str) -> dict:
        return {
            "status": "findings",
            "summary": {"packages_affected": 1, "reachable": 1},
            "findings": [{
                "package": "pillow", "version": "9.2.0", "verdict": "affected",
                "advisories": [{"osv_id": "X", "aliases": ["CVE-1"],
                                "reachability": "reachable", "confidence": 0.9}],
                "target_version": "9.3.0", "breaking": False,
                "breakage_notes": [], "effort_hint": "drop-in",
            }],
        }

    client = _client(stub)
    resp = client.post("/scan?format=text", json={"lockfile": "x"})
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert "pillow 9.2.0" in resp.text
    assert "9.3.0" in resp.text


def test_scan_rejects_missing_lockfile():
    client = _client(lambda text: {})
    resp = client.post("/scan", json={})
    assert resp.status_code == 422   # request validation failure
