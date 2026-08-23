import tomllib
from warrant.models import Package

def parse_lockfile(path: str):
    with open(path, "rb") as f:
        data = tomllib.load(f)

    pacakages = [Package("PyPI",package["name"],package["version"],"DIRECT") for package in data["package"]] # Fix the "DIRECT" later on

    return pacakages