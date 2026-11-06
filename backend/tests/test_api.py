import re
from typing import Any

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests import synthetic
from tests.fakes import FakeResolver

KEYLESS = ["shodan_internetdb", "rdap", "team_cymru"]
KEYED = ["abuseipdb", "greynoise", "virustotal", "ipinfo"]
SOURCE_NAMES = KEYLESS + KEYED

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def url(source: str, ip: str = "8.8.8.8") -> str:
    return {
        "shodan_internetdb": f"https://internetdb.shodan.io/{ip}",
        "rdap": f"https://rdap.org/ip/{ip}",
        "abuseipdb": ABUSEIPDB_URL,
        "greynoise": f"https://api.greynoise.io/v3/community/{ip}",
        "virustotal": f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        "ipinfo": f"https://api.ipinfo.io/lite/{ip}",
    }[source]


@pytest.fixture
def router():
    with respx.mock(assert_all_mocked=True) as router:
        yield router


@pytest.fixture
def resolver(cymru_ok: dict[str, Any]) -> FakeResolver:
    """The fake DNS resolver the app uses. Tests change `.queries` or `.error` to alter it."""
    return FakeResolver(cymru_ok)


@pytest.fixture
def client(router, resolver: FakeResolver) -> TestClient:
    """The app with no API keys, as on a fresh clone."""
    return TestClient(create_app(resolver=resolver), raise_server_exceptions=False)


@pytest.fixture
def keyed_client(router, resolver: FakeResolver) -> TestClient:
    """The app with a (fake) key for every keyed source."""
    settings = Settings(
        _env_file=None,
        abuseipdb_api_key=synthetic.FAKE_KEYS["abuseipdb"],
        greynoise_api_key=synthetic.FAKE_KEYS["greynoise"],
        virustotal_api_key=synthetic.FAKE_KEYS["virustotal"],
        ipinfo_token=synthetic.FAKE_KEYS["ipinfo"],
    )
    return TestClient(create_app(settings, resolver=resolver), raise_server_exceptions=False)


def assert_error_shape(response: httpx.Response, status: int, error: str) -> None:
    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error", "message"}
    assert body["error"] == error
    assert body["message"]


def by_name(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {source["name"]: source for source in body["sources"]}


def test_healthz(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ip_with_results_returns_all_seven_sources_in_one_response(
    keyed_client: TestClient,
    router,
    internetdb_ok: dict[str, Any],
    rdap_ok: dict[str, Any],
    abuseipdb_ok: dict[str, Any],
    virustotal_ok: dict[str, Any],
    ipinfo_ok: dict[str, Any],
) -> None:
    router.get(url("shodan_internetdb")).respond(200, json=internetdb_ok["body"])
    router.get(url("rdap")).respond(200, json=rdap_ok["body"])
    router.get(url("abuseipdb")).respond(200, json=abuseipdb_ok["body"])
    router.get(url("greynoise")).respond(200, json=synthetic.GREYNOISE_OK)
    router.get(url("virustotal")).respond(200, json=virustotal_ok["body"])
    router.get(url("ipinfo")).respond(200, json=ipinfo_ok["body"])
    response = keyed_client.get("/api/v1/ip/8.8.8.8")
    assert response.status_code == 200
    body = response.json()
    assert body["lookup_id"] is None
    assert body["ip"] == "8.8.8.8"
    assert body["ip_version"] == 4
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body["queried_at"])
    assert body["classification"] == {"category": "global", "is_global": True, "explanation": None}
    assert [s["name"] for s in body["sources"]] == SOURCE_NAMES
    sources = by_name(body)
    assert {name: s["status"] for name, s in sources.items()} == dict.fromkeys(SOURCE_NAMES, "ok")
    assert sources["shodan_internetdb"]["display_name"] == "Shodan InternetDB"
    assert sources["shodan_internetdb"]["summary"]["open_ports"] == [53, 443]
    assert sources["shodan_internetdb"]["raw"] == internetdb_ok["body"]
    assert sources["rdap"]["summary"]["org_name"] == "Google LLC"
    assert sources["team_cymru"]["summary"]["asn"] == 15169
    assert sources["abuseipdb"]["summary"]["total_reports"] == 198
    assert sources["greynoise"]["summary"]["classification"] == "malicious"
    assert sources["virustotal"]["summary"]["asn"] == 15169
    assert sources["ipinfo"]["summary"]["as_domain"] == "google.com"
    assert sources["abuseipdb"]["raw"] == abuseipdb_ok["body"]
    assert all(s["error"] is None for s in sources.values())
    # The (synthetic) GreyNoise answer says "malicious", so every source feeds one verdict.
    verdict = body["verdict"]
    assert verdict["level"] == "malicious"
    assert verdict["rules_version"] == "0.2"
    signals = {(r["source"], r["weight"]) for r in verdict["reasons"]}
    assert ("greynoise", "high") in signals
    assert ("virustotal", "low") in signals  # 8.8.8.8's one VirusTotal detection


def test_without_keys_the_app_is_m1_plus_four_not_configured_cards(
    client: TestClient, router, internetdb_ok: dict[str, Any], rdap_ok: dict[str, Any]
) -> None:
    # Only the three keyless routes exist: a call to a keyed source would fail the test.
    router.get(url("shodan_internetdb")).respond(200, json=internetdb_ok["body"])
    router.get(url("rdap")).respond(200, json=rdap_ok["body"])
    response = client.get("/api/v1/ip/8.8.8.8")
    assert response.status_code == 200
    body = response.json()
    assert [s["name"] for s in body["sources"]] == SOURCE_NAMES
    sources = by_name(body)
    assert [sources[n]["status"] for n in KEYLESS] == ["ok"] * 3
    for name in KEYED:
        assert sources[name]["status"] == "not_configured"
        assert sources[name]["latency_ms"] is None  # no call was made
        assert sources[name]["error"] == "No API key set"
        assert sources[name]["summary"] is None and sources[name]["raw"] is None
    assert body["verdict"]["level"] == "no_known_bad"  # not_configured never makes it cleaner
    assert "Not answered:" in body["verdict"]["summary"]
    assert "AbuseIPDB (not configured)" in body["verdict"]["summary"]


def test_ip_no_source_knows_returns_no_data_from_every_source(
    keyed_client: TestClient,
    router,
    resolver: FakeResolver,
    internetdb_no_data: dict[str, Any],
    rdap_no_data: dict[str, Any],
    cymru_no_data: dict[str, Any],
    abuseipdb_no_data: dict[str, Any],
    greynoise_no_data: dict[str, Any],
    ipinfo_bogon: dict[str, Any],
) -> None:
    # A global address. Each mocked source answers with its recorded "unknown IP" response,
    # except VirusTotal, which never returns one (see tests/synthetic.py). The recordings of the
    # keyless sources came from non-global addresses, so the Cymru query name is re-keyed.
    ip = "203.0.114.7"
    (answer,) = cymru_no_data["queries"].values()
    resolver.queries = {"7.114.0.203.origin.asn.cymru.com": answer}
    router.get(url("shodan_internetdb", ip)).respond(404, json=internetdb_no_data["body"])
    router.get(url("rdap", ip)).respond(404, json=rdap_no_data["body"])
    router.get(url("abuseipdb")).respond(200, json=abuseipdb_no_data["body"])
    router.get(url("greynoise", ip)).respond(404, json=greynoise_no_data["body"])
    router.get(url("virustotal", ip)).respond(404, json=synthetic.VIRUSTOTAL_NOT_FOUND)
    router.get(url("ipinfo", ip)).respond(200, json=ipinfo_bogon["body"])
    response = keyed_client.get(f"/api/v1/ip/{ip}")
    assert response.status_code == 200  # nobody knowing the IP is an answer, not an error
    body = response.json()
    assert [s["name"] for s in body["sources"]] == SOURCE_NAMES
    assert all(s["status"] == "no_data" for s in body["sources"])
    assert all(s["summary"] is None for s in body["sources"])
    assert body["verdict"]["level"] == "no_known_bad"  # "no known bad", never "clean" (D8)


def test_private_ip_is_not_sent_to_any_source(
    keyed_client: TestClient, router, resolver: FakeResolver
) -> None:
    # `router` has no routes and assert_all_mocked=True: any outbound call would fail the test.
    response = keyed_client.get("/api/v1/ip/10.0.0.5")
    assert response.status_code == 200
    body = response.json()
    assert body["classification"]["category"] == "private"
    assert body["classification"]["is_global"] is False
    assert "10.0.0.5" in body["classification"]["explanation"]
    assert body["verdict"]["level"] == "not_applicable"
    assert [s["name"] for s in body["sources"]] == SOURCE_NAMES
    for source in body["sources"]:
        assert source["status"] == "skipped"
        assert source["latency_ms"] is None
        assert source["error"] == "Not queried: private address"
    assert router.calls.call_count == 0
    assert resolver.asked == []


def test_one_source_failing_does_not_stop_the_others(
    client: TestClient, router, internetdb_ok: dict[str, Any]
) -> None:
    router.get(url("shodan_internetdb")).respond(200, json=internetdb_ok["body"])
    router.get(url("rdap")).mock(side_effect=httpx.ReadTimeout("slow"))
    response = client.get("/api/v1/ip/8.8.8.8")
    assert response.status_code == 200  # a failing source is not an API error
    sources = by_name(response.json())
    assert [s["name"] for s in response.json()["sources"]] == SOURCE_NAMES
    # The response says which source failed, and why.
    assert sources["rdap"]["status"] == "timeout"
    assert sources["rdap"]["error"] == "No response within 8 s"
    assert sources["rdap"]["summary"] is None and sources["rdap"]["raw"] is None
    # The others still returned their data.
    assert sources["shodan_internetdb"]["status"] == "ok"
    assert sources["shodan_internetdb"]["summary"]["open_ports"] == [53, 443]
    assert sources["team_cymru"]["status"] == "ok"
    assert sources["team_cymru"]["summary"]["asn"] == 15169
    # The verdict names the missing source instead of looking cleaner.
    verdict = response.json()["verdict"]
    assert verdict["level"] == "no_known_bad"
    assert "RDAP (timeout)" in verdict["summary"]


def test_a_rate_limited_keyed_source_is_reported_and_the_others_still_return(
    keyed_client: TestClient,
    router,
    internetdb_ok: dict[str, Any],
    rdap_ok: dict[str, Any],
    abuseipdb_ok: dict[str, Any],
    virustotal_ok: dict[str, Any],
    ipinfo_ok: dict[str, Any],
) -> None:
    router.get(url("shodan_internetdb")).respond(200, json=internetdb_ok["body"])
    router.get(url("rdap")).respond(200, json=rdap_ok["body"])
    router.get(url("abuseipdb")).respond(200, json=abuseipdb_ok["body"])
    router.get(url("greynoise")).respond(429, json=synthetic.GREYNOISE_QUOTA)  # weekly quota
    router.get(url("virustotal")).respond(200, json=virustotal_ok["body"])
    router.get(url("ipinfo")).respond(200, json=ipinfo_ok["body"])
    response = keyed_client.get("/api/v1/ip/8.8.8.8")
    assert response.status_code == 200
    sources = by_name(response.json())
    assert sources["greynoise"]["status"] == "rate_limited"
    assert "Weekly lookup limit reached" in sources["greynoise"]["error"]
    assert sources["greynoise"]["summary"] is None
    assert [sources[n]["status"] for n in SOURCE_NAMES if n != "greynoise"] == ["ok"] * 6
    verdict = response.json()["verdict"]
    # A spent quota does not wreck the verdict, and the recorded 8.8.8.8 data is not a red flag.
    assert verdict["level"] == "no_known_bad"
    assert "GreyNoise Community (rate limited)" in verdict["summary"]


def test_rate_limited_flagging_source_makes_the_verdict_unknown(
    client: TestClient, router, rdap_ok: dict[str, Any]
) -> None:
    router.get(url("shodan_internetdb")).respond(429, json={"detail": "slow down"})
    router.get(url("rdap")).respond(200, json=rdap_ok["body"])
    response = client.get("/api/v1/ip/8.8.8.8")
    sources = by_name(response.json())
    assert sources["shodan_internetdb"]["status"] == "rate_limited"
    assert "429" in sources["shodan_internetdb"]["error"]
    assert sources["rdap"]["status"] == "ok"
    assert sources["team_cymru"]["status"] == "ok"
    # InternetDB is the only source that can flag an IP (M1 rules), so without it: unknown.
    assert response.json()["verdict"]["level"] == "unknown"


def test_every_source_failing_still_returns_200_and_says_why(
    client: TestClient, router, resolver: FakeResolver
) -> None:
    router.get(url("shodan_internetdb")).mock(side_effect=httpx.ConnectTimeout("slow"))
    router.get(url("rdap")).respond(500, text="boom")
    resolver.error = RuntimeError("dns down")
    response = client.get("/api/v1/ip/8.8.8.8")
    assert response.status_code == 200
    body = response.json()
    assert by_name(body)["shodan_internetdb"]["status"] == "timeout"
    assert by_name(body)["rdap"]["status"] == "error"
    assert by_name(body)["team_cymru"]["status"] == "error"
    assert all(by_name(body)[n]["status"] == "not_configured" for n in KEYED)
    assert all(s["error"] for s in body["sources"])
    assert body["verdict"]["level"] == "unknown"
    assert "No source could answer" in body["verdict"]["summary"]


@pytest.mark.parametrize("bad", ["not-an-ip", "999.1.1.1", "8.8.8", "8.8.8.8.8", "abc.def"])
def test_invalid_ip_is_a_400_not_a_crash(client: TestClient, bad: str) -> None:
    assert_error_shape(client.get(f"/api/v1/ip/{bad}"), 400, "invalid_ip")


@pytest.mark.parametrize("v6", ["2001:db8::1", "::1", "2606:4700::1111"])
def test_ipv6_is_unsupported_before_m4(client: TestClient, v6: str) -> None:
    response = client.get(f"/api/v1/ip/{v6}")
    assert_error_shape(response, 400, "unsupported_ip_version")
    assert response.json()["message"] == "IPv6 support is planned for a later version."


def test_unknown_route_is_404(client: TestClient) -> None:
    assert_error_shape(client.get("/api/v1/nope"), 404, "not_found")


def test_wrong_method_uses_the_error_shape(client: TestClient) -> None:
    assert_error_shape(client.post("/api/v1/ip/8.8.8.8"), 405, "method_not_allowed")


def test_malformed_request_is_400_invalid_request(router) -> None:
    app = create_app()

    @app.get("/api/v1/_probe")
    async def probe(limit: int) -> dict[str, int]:
        return {"limit": limit}

    response = TestClient(app).get("/api/v1/_probe", params={"limit": "abc"})
    assert_error_shape(response, 400, "invalid_request")


def test_unexpected_error_is_500_internal_error(router) -> None:
    app = create_app()

    @app.get("/api/v1/_boom")
    async def boom() -> None:
        raise RuntimeError("secret detail must not leak")

    response = TestClient(app, raise_server_exceptions=False).get("/api/v1/_boom")
    assert_error_shape(response, 500, "internal_error")
    assert "secret detail" not in response.text
