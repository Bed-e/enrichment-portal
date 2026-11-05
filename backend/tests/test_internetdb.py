from ipaddress import ip_address
from typing import Any

import httpx
import pytest
import respx

from app.sources.shodan_internetdb import ShodanInternetDB

URL = "https://internetdb.shodan.io/8.8.8.8"


@pytest.fixture
async def client():
    async with httpx.AsyncClient() as http:
        yield ShodanInternetDB(http, "https://internetdb.shodan.io", timeout=8.0)


@pytest.fixture
def router():
    with respx.mock(assert_all_mocked=True) as router:
        yield router


async def test_ok(client, router, internetdb_ok: dict[str, Any]) -> None:
    router.get(URL).respond(200, json=internetdb_ok["body"])
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "ok"
    assert result.name == "shodan_internetdb"
    assert result.summary == {
        "open_ports": [53, 443],
        "tags": ["pqc"],
        "vulns": [],
        "hostnames": ["dns.google", "zccflorida.com"],
        "cpes": [],
    }
    assert result.raw == internetdb_ok["body"]
    assert result.error is None
    assert result.latency_ms is not None


async def test_no_data(client, router, internetdb_no_data: dict[str, Any]) -> None:
    router.get(URL).respond(404, json=internetdb_no_data["body"])
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "no_data"
    assert result.summary is None


async def test_timeout(client, router) -> None:
    router.get(URL).mock(side_effect=httpx.ConnectTimeout("slow"))
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "timeout"
    assert result.summary is None and result.raw is None
    assert "8" in (result.error or "")


async def test_rate_limited(client, router) -> None:
    router.get(URL).respond(429, json={"detail": "slow down"})
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "rate_limited"


async def test_server_error(client, router) -> None:
    router.get(URL).respond(500, text="boom")
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "error"
    assert "500" in (result.error or "")


async def test_connection_error(client, router) -> None:
    router.get(URL).mock(side_effect=httpx.ConnectError("down"))
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "error"


async def test_invalid_json_is_an_error_not_a_crash(client, router) -> None:
    router.get(URL).respond(200, text="<html>not json</html>")
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "error"
