"""AbuseIPDB, GreyNoise, VirusTotal and ipinfo Lite (design.md M2).

The behaviour all four share is tested once, parametrized. The per-source parsing follows.
Recorded fixtures are used where one exists; the rest come from tests/synthetic.py, whose
bodies are built from the providers' documented shapes and labelled as such.
"""

from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any

import httpx
import pytest
import respx
from pydantic import SecretStr

from app.sources.abuseipdb import AbuseIPDB
from app.sources.greynoise import GreyNoise
from app.sources.ipinfo import IpinfoLite
from app.sources.ratelimit import RateLimiter
from app.sources.virustotal import VirusTotal
from tests import synthetic
from tests.fakes import FakeClock

IP = ip_address("8.8.8.8")


@dataclass
class Spec:
    make: Callable[[httpx.AsyncClient, str], Any]
    url: str
    header: str
    header_value: Callable[[str], str]
    quota_body: Any


SPECS = {
    "abuseipdb": Spec(
        lambda http, key: AbuseIPDB(http, "https://api.abuseipdb.com", 8.0, SecretStr(key)),
        "https://api.abuseipdb.com/api/v2/check",
        "key",
        lambda key: key,
        synthetic.ABUSEIPDB_QUOTA,
    ),
    "greynoise": Spec(
        lambda http, key: GreyNoise(http, "https://api.greynoise.io", 8.0, SecretStr(key)),
        "https://api.greynoise.io/v3/community/8.8.8.8",
        "key",
        lambda key: key,
        synthetic.GREYNOISE_QUOTA,
    ),
    "virustotal": Spec(
        lambda http, key: VirusTotal(http, "https://www.virustotal.com", 8.0, SecretStr(key)),
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        "x-apikey",
        lambda key: key,
        synthetic.VIRUSTOTAL_QUOTA,
    ),
    "ipinfo": Spec(
        lambda http, key: IpinfoLite(http, "https://api.ipinfo.io", 8.0, SecretStr(key)),
        "https://api.ipinfo.io/lite/8.8.8.8",
        "authorization",
        lambda key: f"Bearer {key}",
        {"message": "rate limit"},
    ),
}


@pytest.fixture(params=sorted(SPECS))
def name(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture
def spec(name: str) -> Spec:
    return SPECS[name]


@pytest.fixture
def key(name: str) -> str:
    return synthetic.FAKE_KEYS[name]


@pytest.fixture
def router():
    with respx.mock(assert_all_mocked=True) as router:
        yield router


@pytest.fixture
async def http():
    async with httpx.AsyncClient() as http:
        yield http


# --- behaviour shared by all four ---------------------------------------------------------


async def test_not_configured_without_a_key(spec: Spec, http, key: str) -> None:
    assert spec.make(http, "").is_configured() is False
    configured = spec.make(http, key)
    assert configured.is_configured() is True
    assert configured.requires_key is True


async def test_key_travels_only_in_the_request_header(spec: Spec, http, router, key: str) -> None:
    route = router.get(spec.url).respond(500, text="boom")
    await spec.make(http, key).lookup(IP)
    request = route.calls.last.request
    assert request.headers[spec.header] == spec.header_value(key)
    assert key not in str(request.url)  # never in the URL, so never in a logged URL
    assert request.content == b""


@pytest.mark.parametrize("status", [401, 403])
async def test_rejected_key_is_an_error_that_does_not_echo_the_key(
    spec: Spec, http, router, key: str, status: int
) -> None:
    router.get(spec.url).respond(status, json={"message": f"bad key {key}"})
    result = await spec.make(http, key).lookup(IP)
    assert result.status == "error"
    assert result.error == f"API key rejected (HTTP {status})"
    assert key not in result.model_dump_json()


async def test_429_is_rate_limited_with_the_providers_message(
    spec: Spec, http, router, key: str
) -> None:
    router.get(spec.url).respond(429, json=spec.quota_body)
    result = await spec.make(http, key).lookup(IP)
    assert result.status == "rate_limited"
    assert result.error and result.error.startswith("HTTP 429")
    assert result.summary is None and result.raw is None


async def test_a_key_echoed_in_a_429_message_is_redacted(
    spec: Spec, http, router, key: str
) -> None:
    echoing = {"message": f"key {key} over quota", "error": {"message": f"key {key} over quota"}}
    echoing["errors"] = [{"detail": f"key {key} over quota"}]
    router.get(spec.url).respond(429, json=echoing)
    result = await spec.make(http, key).lookup(IP)
    assert result.status == "rate_limited"
    assert key not in result.model_dump_json()
    assert "REDACTED" in (result.error or "")


async def test_timeout(spec: Spec, http, router, key: str) -> None:
    router.get(spec.url).mock(side_effect=httpx.ReadTimeout("slow"))
    result = await spec.make(http, key).lookup(IP)
    assert result.status == "timeout"
    assert result.error == "No response within 8 s"
    assert result.summary is None and result.raw is None


async def test_transport_error_message_has_no_url_or_key(
    spec: Spec, http, router, key: str
) -> None:
    router.get(spec.url).mock(side_effect=httpx.ConnectError(f"cannot reach {spec.url} {key}"))
    result = await spec.make(http, key).lookup(IP)
    assert result.status == "error"
    assert result.error == "Request failed: ConnectError"
    assert key not in result.model_dump_json()


async def test_server_error(spec: Spec, http, router, key: str) -> None:
    router.get(spec.url).respond(503, text="down")
    result = await spec.make(http, key).lookup(IP)
    assert result.status == "error"
    assert "503" in (result.error or "")


async def test_invalid_json_is_an_error_not_a_crash(spec: Spec, http, router, key: str) -> None:
    router.get(spec.url).respond(200, text="<html>not json</html>")
    result = await spec.make(http, key).lookup(IP)
    assert result.status == "error"


# --- AbuseIPDB ------------------------------------------------------------------------------


@pytest.fixture
async def abuse(http):
    return SPECS["abuseipdb"].make(http, synthetic.FAKE_KEYS["abuseipdb"])


async def test_abuseipdb_ok(abuse, router, abuseipdb_ok: dict[str, Any]) -> None:
    route = router.get(SPECS["abuseipdb"].url).respond(200, json=abuseipdb_ok["body"])
    result = await abuse.lookup(IP)
    assert result.status == "ok"
    assert result.summary == {
        "abuse_confidence_score": 0,
        "total_reports": 198,
        "num_distinct_users": 70,
        "last_reported_at": "2026-11-05T20:10:59+00:00",
        "usage_type": "Content Delivery Network",
        "isp": "Google LLC",
        "domain": "google.com",
        "country_code": "US",
        "is_tor": False,
        "is_whitelisted": True,
    }
    assert result.raw == abuseipdb_ok["body"]
    assert dict(route.calls.last.request.url.params) == {
        "ipAddress": "8.8.8.8",
        "maxAgeInDays": "90",
    }


async def test_abuseipdb_reported_ip(abuse, router) -> None:
    router.get(SPECS["abuseipdb"].url).respond(200, json=synthetic.ABUSEIPDB_REPORTED)
    result = await abuse.lookup(IP)
    assert result.status == "ok"
    assert result.summary["abuse_confidence_score"] == 100
    assert result.summary["is_whitelisted"] is False


async def test_abuseipdb_zero_reports_is_no_data(
    abuse, router, abuseipdb_no_data: dict[str, Any]
) -> None:
    router.get(SPECS["abuseipdb"].url).respond(200, json=abuseipdb_no_data["body"])
    result = await abuse.lookup(IP)
    assert result.status == "no_data"
    assert result.summary is None
    assert result.raw == abuseipdb_no_data["body"]


async def test_abuseipdb_429_message_is_shown(abuse, router) -> None:
    router.get(SPECS["abuseipdb"].url).respond(429, json=synthetic.ABUSEIPDB_QUOTA)
    result = await abuse.lookup(IP)
    assert result.error == (
        "HTTP 429: Daily rate limit of 1000 requests exceeded for this endpoint."
    )


# --- GreyNoise ------------------------------------------------------------------------------


@pytest.fixture
async def greynoise(http):
    return SPECS["greynoise"].make(http, synthetic.FAKE_KEYS["greynoise"])


async def test_greynoise_ok(greynoise, router) -> None:
    router.get(SPECS["greynoise"].url).respond(200, json=synthetic.GREYNOISE_OK)
    result = await greynoise.lookup(IP)
    assert result.status == "ok"
    assert result.summary == {
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "unknown",
        "last_seen": "2026-11-04",
        "link": "https://viz.greynoise.io/ip/203.0.114.7",
        "message": "Success",
    }
    assert result.raw == synthetic.GREYNOISE_OK


async def test_greynoise_404_is_no_data(greynoise, router, greynoise_no_data: dict) -> None:
    assert greynoise_no_data["status_code"] == 404  # as recorded
    router.get(SPECS["greynoise"].url).respond(404, json=greynoise_no_data["body"])
    result = await greynoise.lookup(IP)
    assert result.status == "no_data"
    assert result.summary is None
    assert result.raw == greynoise_no_data["body"]


async def test_greynoise_400_is_an_error(greynoise, router) -> None:
    router.get(SPECS["greynoise"].url).respond(400, json={"message": "invalid ip"})
    result = await greynoise.lookup(IP)
    assert result.status == "error"
    assert "400" in (result.error or "")


# --- VirusTotal -----------------------------------------------------------------------------


@pytest.fixture
async def virustotal(http):
    return SPECS["virustotal"].make(http, synthetic.FAKE_KEYS["virustotal"])


async def test_virustotal_ok(virustotal, router, virustotal_ok: dict[str, Any]) -> None:
    router.get(SPECS["virustotal"].url).respond(200, json=virustotal_ok["body"])
    result = await virustotal.lookup(IP)
    assert result.status == "ok"
    assert result.summary == {
        "malicious": 1,
        "suspicious": 0,
        "harmless": 54,
        "undetected": 37,
        "reputation": 564,
        "asn": 15169,
        "as_owner": "Google LLC",
        "country": "US",
        "network": "8.8.8.0/24",
    }
    assert result.raw == virustotal_ok["body"]


async def test_virustotal_404_is_no_data(virustotal, router) -> None:
    router.get(SPECS["virustotal"].url).respond(404, json=synthetic.VIRUSTOTAL_NOT_FOUND)
    result = await virustotal.lookup(IP)
    assert result.status == "no_data"
    assert result.summary is None


async def test_virustotal_429_message_is_shown(virustotal, router) -> None:
    router.get(SPECS["virustotal"].url).respond(429, json=synthetic.VIRUSTOTAL_QUOTA)
    result = await virustotal.lookup(IP)
    assert result.status == "rate_limited"
    assert result.error == "HTTP 429: Quota exceeded for this API key"


async def test_virustotal_own_limiter_allows_four_a_minute_then_refuses(http, router) -> None:
    clock = FakeClock()
    limiter = RateLimiter(4, 60.0, clock=clock, sleep=clock.sleep)
    vt = VirusTotal(http, "https://www.virustotal.com", 8.0, SecretStr("k"), limiter=limiter)
    route = router.get(SPECS["virustotal"].url).respond(404, json=synthetic.VIRUSTOTAL_NOT_FOUND)
    statuses = [(await vt.lookup(IP)).status for _ in range(5)]
    assert statuses == ["no_data"] * 4 + ["rate_limited"]
    assert route.call_count == 4  # the fifth call never reached VirusTotal
    clock.now = 60.0  # a minute later the window has opened again
    assert (await vt.lookup(IP)).status == "no_data"


async def test_virustotal_only_ever_uses_the_ip_lookup_endpoint(
    virustotal, router, virustotal_ok: dict[str, Any]
) -> None:
    """Nothing is uploaded or submitted for analysis (design.md D19)."""
    route = router.get(SPECS["virustotal"].url).respond(200, json=virustotal_ok["body"])
    await virustotal.lookup(IP)
    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.path == "/api/v3/ip_addresses/8.8.8.8"
    assert router.calls.call_count == 1


# --- ipinfo Lite ----------------------------------------------------------------------------


@pytest.fixture
async def ipinfo(http):
    return SPECS["ipinfo"].make(http, synthetic.FAKE_KEYS["ipinfo"])


async def test_ipinfo_ok(ipinfo, router, ipinfo_ok: dict[str, Any]) -> None:
    router.get(SPECS["ipinfo"].url).respond(200, json=ipinfo_ok["body"])
    result = await ipinfo.lookup(IP)
    assert result.status == "ok"
    assert result.summary == {
        "asn": "AS15169",
        "as_name": "Google LLC",
        "as_domain": "google.com",
        "country_code": "US",
        "country": "United States",
        "continent_code": "NA",
        "continent": "North America",
    }
    assert result.raw == ipinfo_ok["body"]


async def test_ipinfo_bogon_is_no_data(ipinfo, router, ipinfo_bogon: dict[str, Any]) -> None:
    router.get(SPECS["ipinfo"].url).respond(200, json=ipinfo_bogon["body"])
    result = await ipinfo.lookup(IP)
    assert result.status == "no_data"
    assert result.summary is None
    assert result.raw == ipinfo_bogon["body"]


async def test_ipinfo_404_is_no_data(ipinfo, router) -> None:
    router.get(SPECS["ipinfo"].url).respond(404, json=synthetic.IPINFO_NOT_FOUND)
    assert (await ipinfo.lookup(IP)).status == "no_data"
