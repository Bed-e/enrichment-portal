import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(source: str, case: str) -> dict[str, Any]:
    """A scrubbed recorded response: {"status_code": ..., "body": ...}."""
    return json.loads((FIXTURES / source / f"{case}.json").read_text())


@pytest.fixture
def internetdb_ok() -> dict[str, Any]:
    return load_fixture("shodan_internetdb", "ok_8_8_8_8")


@pytest.fixture
def internetdb_no_data() -> dict[str, Any]:
    return load_fixture("shodan_internetdb", "no_data")
