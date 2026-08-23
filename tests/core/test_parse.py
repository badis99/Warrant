from core.parse import parse_lockfile
from warrant.models import Package

def test_parse_1():
    assert parse_lockfile('fixtures/simple/uv.lock') == [Package(ecosystem='PyPI', name='pillow', version='9.2.0', tag='DIRECT'), Package(ecosystem='PyPI', name='httpx', version='0.28.1', tag='DIRECT'), Package(ecosystem='PyPI', name='packaging', version='26.3', tag='DIRECT')]