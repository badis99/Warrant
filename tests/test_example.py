from warrant.models import Package


def test_package():
    package = Package(
        ecosystem="PyPI",
        name="pillow",
        version="9.2.0",
        tag="DIRECT",
    )

    assert package.ecosystem == "PyPI"
    assert package.name == "pillow"
    assert package.version == "9.2.0"
    assert package.tag == "DIRECT"

    identical_package = Package(
        ecosystem="PyPI",
        name="pillow",
        version="9.2.0",
        tag="DIRECT",
    )

    assert package == identical_package