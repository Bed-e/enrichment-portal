import json
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings

FIXTURES = Path(__file__).parent / "fixtures"
KEY_VARIABLES = ("ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY", "VIRUSTOTAL_API_KEY", "IPINFO_TOKEN")


def load_fixture(source: str, case: str) -> dict[str, Any]:
    """A scrubbed recorded response. HTTP sources: {"status_code", "body"}; Team Cymru:
    {"queries": {name: {"rcode", "txt"}}}. See scripts/record_fixtures.py."""
    return json.loads((FIXTURES / source / f"{case}.json").read_text())


@pytest.fixture(autouse=True)
def no_real_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never see the developer's real keys (design.md D13).

    A developer's .env holds real keys. Without this, a test that builds the app would read
    them, make the keyed sources "configured" and try real calls. Tests that need a key pass a
    clearly fake one explicitly.
    """
    for name in KEY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("app.main.get_settings", lambda: Settings(_env_file=None))


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


@pytest.fixture
def abuseipdb_ok() -> dict[str, Any]:
    return load_fixture("abuseipdb", "ok_8_8_8_8")


@pytest.fixture
def abuseipdb_no_data() -> dict[str, Any]:
    return load_fixture("abuseipdb", "no_data")


@pytest.fixture
def greynoise_no_data() -> dict[str, Any]:
    return load_fixture("greynoise", "no_data")


@pytest.fixture
def virustotal_ok() -> dict[str, Any]:
    return load_fixture("virustotal", "ok_8_8_8_8")


@pytest.fixture
def ipinfo_ok() -> dict[str, Any]:
    return load_fixture("ipinfo", "ok_8_8_8_8")


@pytest.fixture
def ipinfo_bogon() -> dict[str, Any]:
    return load_fixture("ipinfo", "bogon_192_0_2_1")
