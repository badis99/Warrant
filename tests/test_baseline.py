def test_parses_affected_reply(monkeypatch):
    import warrant.baseline as baseline
    from warrant.models import Package
    
    monkeypatch.setattr(baseline, "complete", lambda prompt, **kw: "affected")

    result = baseline.naive_is_affected(Package(ecosystem='PyPI', name='pillow', version='9.2.0', tag='DIRECT'), ">=1.2.0 <9.2.0")

    assert result == "affected"   # did MY code map the reply correctly?