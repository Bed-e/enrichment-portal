import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(source: str, case: str) -> dict[str, Any]:
    """A scrubbed recorded response. HTTP sources: {"status_code", "body"}; Team Cymru:
    {"queries": {name: {"rcode", "txt"}}}. See scripts/record_fixtures.py."""
    return json.loads((FIXTURES / source / f"{case}.json").read_text())


@pytest.fixture
def internetdb_ok() -> dict[str, Any]:
    return load_fixture("shodan_internetdb", "ok_8_8_8_8")


@pytest.fixture
def internetdb_no_data() -> dict[str, Any]:
    return load_fixture("shodan_internetdb", "no_data")


@pytest.fixture
def rdap_ok() -> dict[str, Any]:
    return load_fixture("rdap", "ok_8_8_8_8")


@pytest.fixture
def rdap_no_data() -> dict[str, Any]:
    return load_fixture("rdap", "no_data")


@pytest.fixture
def cymru_ok() -> dict[str, Any]:
    return load_fixture("team_cymru", "ok_8_8_8_8")


@pytest.fixture
def cymru_no_data() -> dict[str, Any]:
    return load_fixture("team_cymru", "no_data")
