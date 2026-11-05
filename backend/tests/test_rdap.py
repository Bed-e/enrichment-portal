from ipaddress import ip_address
from typing import Any

import httpx
import pytest
import respx

from app.sources.ratelimit import RateLimiter
from app.sources.rdap import Rdap
from tests.fakes import FakeClock

URL = "https://rdap.org/ip/8.8.8.8"


@pytest.fixture
async def client():
    # follow_redirects=True matches how the app builds its shared client (app/main.py).
    async with httpx.AsyncClient(follow_redirects=True) as http:
        yield Rdap(http, "https://rdap.org", timeout=8.0)


@pytest.fixture
def router():
    with respx.mock(assert_all_mocked=True) as router:
        yield router


async def test_ok(client, router, rdap_ok: dict[str, Any]) -> None:
    router.get(URL).respond(200, json=rdap_ok["body"])
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "ok"
    assert result.name == "rdap"
    assert result.summary == {
        "network_name": "GOGL",
        "network_range": "8.8.8.0 - 8.8.8.255",
        "org_name": "Google LLC",
        "country": None,  # ARIN records carry no country
        "registry": "arin",
        "registration_date": "2023-12-28",
        "last_changed": "2023-12-28",
        "abuse_email": "network-abuse@google.com",
    }
    assert result.raw == rdap_ok["body"]
    assert result.error is None
    assert result.latency_ms is not None


async def test_follows_the_redirect_to_the_registry(
    client, router, rdap_ok: dict[str, Any]
) -> None:
    registry_url = "https://rdap.arin.net/registry/ip/8.8.8.8"
    router.get(URL).respond(302, headers={"Location": registry_url})
    router.get(registry_url).respond(200, json=rdap_ok["body"])
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "ok"
    assert result.summary["registry"] == "arin"


async def test_no_data(client, router, rdap_no_data: dict[str, Any]) -> None:
    router.get(URL).respond(404, json=rdap_no_data["body"])
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "no_data"
    assert result.summary is None
    assert result.raw == rdap_no_data["body"]


async def test_timeout(client, router) -> None:
    router.get(URL).mock(side_effect=httpx.ReadTimeout("slow"))
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "timeout"
    assert result.summary is None and result.raw is None
    assert "8" in (result.error or "")


async def test_http_429_is_rate_limited(client, router) -> None:
    router.get(URL).respond(429, text="Too Many Requests")
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "rate_limited"
    assert "429" in (result.error or "")


async def test_blocked_403_is_an_error(client, router) -> None:
    router.get(URL).respond(403, text="blocked")
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "error"
    assert "403" in (result.error or "")


async def test_server_error(client, router) -> None:
    router.get(URL).respond(503, text="down")
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "error"


async def test_connection_error(client, router) -> None:
    router.get(URL).mock(side_effect=httpx.ConnectError("down"))
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "error"


async def test_invalid_json_is_an_error_not_a_crash(client, router) -> None:
    router.get(URL).respond(200, text="<html>not json</html>")
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "error"


async def test_sparse_record_gives_none_values_not_a_crash(client, router) -> None:
    router.get(URL).respond(200, json={"objectClassName": "ip network"})
    result = await client.lookup(ip_address("8.8.8.8"))
    assert result.status == "ok"
    assert set(result.summary.values()) == {None}


async def test_own_rate_limit_stops_calls_before_they_reach_rdap(router) -> None:
    clock = FakeClock()
    limiter = RateLimiter(1, 10.0, clock=clock, sleep=clock.sleep)
    route = router.get(URL).respond(200, json={})
    async with httpx.AsyncClient() as http:
        rdap = Rdap(http, "https://rdap.org", timeout=8.0, limiter=limiter)
        first = await rdap.lookup(ip_address("8.8.8.8"))
        second = await rdap.lookup(ip_address("8.8.8.8"))
    assert first.status == "ok"
    assert second.status == "rate_limited"
    assert route.call_count == 1
