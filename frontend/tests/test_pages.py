from typing import Any

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

BACKEND = "http://backend.test"


def contract_response(**overrides: Any) -> dict[str, Any]:
    """A response shaped like the backend contract (design.md section 3)."""
    body: dict[str, Any] = {
        "lookup_id": None,
        "ip": "8.8.8.8",
        "ip_version": 4,
        "queried_at": "2026-11-05T14:02:11Z",
        "classification": {"category": "global", "is_global": True, "explanation": None},
        "verdict": {
            "level": "unknown",
            "summary": "Verdict rules are added in M1.",
            "reasons": [],
            "rules_version": "0.0",
        },
        "sources": [
            {
                "name": "shodan_internetdb",
                "display_name": "Shodan InternetDB",
                "status": "ok",
                "latency_ms": 184,
                "summary": {
                    "open_ports": [53, 443],
                    "tags": [],
                    "vulns": [],
                    "hostnames": ["dns.google"],
                    "cpes": [],
                },
                "raw": {"ip": "8.8.8.8", "ports": [53, 443], "hostnames": ["dns.google"]},
                "error": None,
            }
        ],
    }
    body.update(overrides)
    return body


@pytest.fixture
def router():
    with respx.mock(assert_all_mocked=True) as router:
        yield router


@pytest.fixture
def client(router) -> TestClient:
    return TestClient(create_app(Settings(backend_url=BACKEND)))


def test_healthz_does_not_call_the_backend(client: TestClient, router) -> None:
    response = client.get("/healthz")
    assert response.json() == {"status": "ok"}
    assert router.calls.call_count == 0


def test_index_shows_the_form(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert '<form method="post" action="/lookup"' in response.text
    assert 'name="ip"' in response.text
    assert "<script" not in response.text  # no JavaScript (D15)


def test_static_css_is_served(client: TestClient) -> None:
    assert client.get("/static/styles.css").status_code == 200


def test_global_ip_shows_verdict_source_card_and_raw_json(client: TestClient, router) -> None:
    route = router.get(f"{BACKEND}/api/v1/ip/8.8.8.8").respond(200, json=contract_response())
    response = client.post("/lookup", data={"ip": "8.8.8.8"})
    assert response.status_code == 200
    assert route.call_count == 1
    html = response.text
    assert "Unknown" in html and "Verdict rules are added in M1." in html
    assert "Shodan InternetDB" in html
    assert "53, 443" in html
    assert "dns.google" in html
    assert "<details>" in html and "Raw response" in html
    assert '"ports": [' in html  # the raw JSON is shown


def test_private_ip_shows_label_and_explanation(client: TestClient, router) -> None:
    body = contract_response(
        ip="10.0.0.5",
        classification={
            "category": "private",
            "is_global": False,
            "explanation": "10.0.0.5 is a private address (RFC 1918).",
        },
        verdict={
            "level": "not_applicable",
            "summary": "Private address. External sources were not queried.",
            "reasons": [],
            "rules_version": "0.0",
        },
        sources=[
            {
                "name": "shodan_internetdb",
                "display_name": "Shodan InternetDB",
                "status": "skipped",
                "latency_ms": None,
                "summary": None,
                "raw": None,
                "error": "Not queried: private address",
            }
        ],
    )
    router.get(f"{BACKEND}/api/v1/ip/10.0.0.5").respond(200, json=body)
    html = client.post("/lookup", data={"ip": "10.0.0.5"}).text
    assert "Private address." in html
    assert "10.0.0.5 is a private address (RFC 1918)." in html
    assert "Not queried: private address" in html
    assert "<details>" not in html  # nothing raw to show


def test_rate_limited_source_has_its_own_message(client: TestClient, router) -> None:
    body = contract_response()
    body["sources"][0].update(status="rate_limited", summary=None, raw=None, error="HTTP 429")
    router.get(f"{BACKEND}/api/v1/ip/8.8.8.8").respond(200, json=body)
    html = client.post("/lookup", data={"ip": "8.8.8.8"}).text
    assert "Quota reached" in html


def test_backend_400_is_shown_inline(client: TestClient, router) -> None:
    router.get(f"{BACKEND}/api/v1/ip/garbage").respond(
        400, json={"error": "invalid_ip", "message": "That is not a valid IP address."}
    )
    response = client.post("/lookup", data={"ip": "garbage"})
    assert response.status_code == 200
    assert "That is not a valid IP address." in response.text
    assert 'value="garbage"' in response.text


def test_ipv6_message_is_shown_inline(client: TestClient, router) -> None:
    router.get(f"{BACKEND}/api/v1/ip/::1").respond(
        400,
        json={
            "error": "unsupported_ip_version",
            "message": "IPv6 support is planned for a later version.",
        },
    )
    html = client.post("/lookup", data={"ip": "::1"}).text
    assert "IPv6 support is planned for a later version." in html


def test_empty_input_never_calls_the_backend(client: TestClient, router) -> None:
    html = client.post("/lookup", data={"ip": "   "}).text
    assert "Enter an IP address." in html
    assert router.calls.call_count == 0


@pytest.mark.parametrize(
    "effect",
    [
        httpx.ConnectError("down"),
        httpx.ConnectTimeout("slow"),
        httpx.Response(500, text="boom"),
        httpx.Response(502, text="bad gateway"),
        httpx.Response(404, json={"error": "not_found", "message": "x"}),
        httpx.Response(200, text="<html>not json</html>"),
        httpx.Response(200, json={"unexpected": "shape"}),
    ],
)
def test_backend_trouble_shows_unavailable_not_a_crash(
    client: TestClient, router, effect: Exception | httpx.Response
) -> None:
    route = router.get(f"{BACKEND}/api/v1/ip/8.8.8.8")
    if isinstance(effect, Exception):
        route.mock(side_effect=effect)
    else:
        route.mock(return_value=effect)
    response = client.post("/lookup", data={"ip": "8.8.8.8"})
    assert response.status_code == 200
    assert "Backend unavailable" in response.text
    assert "Traceback" not in response.text


def test_user_input_is_one_url_segment_and_html_escaped(client: TestClient, router) -> None:
    route = router.get(url__regex=r"http://backend\.test/api/v1/ip/.*").respond(
        400, json={"error": "invalid_ip", "message": "That is not a valid IP address."}
    )
    html = client.post("/lookup", data={"ip": "../healthz<script>alert(1)</script>"}).text
    assert route.call_count == 1
    raw_path = route.calls.last.request.url.raw_path.decode()
    assert raw_path.startswith("/api/v1/ip/..%2Fhealthz%3Cscript%3E")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def three_source_response() -> dict[str, Any]:
    """The design.md section 3 example: two sources ok and one timed out."""
    body = contract_response()
    body["sources"] += [
        {
            "name": "rdap",
            "display_name": "RDAP",
            "status": "ok",
            "latency_ms": 612,
            "summary": {
                "network_name": "GOGL",
                "network_range": "8.8.8.0 - 8.8.8.255",
                "org_name": "Google LLC",
                "country": None,
                "registry": "arin",
                "registration_date": "2023-12-28",
                "last_changed": "2023-12-28",
                "abuse_email": "network-abuse@google.com",
            },
            "raw": {"name": "GOGL"},
            "error": None,
        },
        {
            "name": "team_cymru",
            "display_name": "Team Cymru IP to ASN",
            "status": "timeout",
            "latency_ms": 8000,
            "summary": None,
            "raw": None,
            "error": "No DNS answer within 8 s",
        },
    ]
    return body


def test_three_sources_render_three_cards_and_a_failed_one_says_why(
    client: TestClient, router
) -> None:
    router.get(f"{BACKEND}/api/v1/ip/8.8.8.8").respond(200, json=three_source_response())
    response = client.post("/lookup", data={"ip": "8.8.8.8"})
    assert response.status_code == 200
    html = response.text
    assert html.count('<article class="card') == 3
    for name in ("Shodan InternetDB", "RDAP", "Team Cymru IP to ASN"):
        assert name in html
    assert "Google LLC" in html and "network-abuse@google.com" in html  # RDAP summary fields
    assert 'class="card status-timeout"' in html
    assert "No DNS answer within 8 s" in html  # the failed source's reason
    assert html.count("<details>") == 2  # raw responses only for sources that answered


def seven_source_response() -> dict[str, Any]:
    """Seven sources as the M2 backend returns them: five answer, one is out of quota and one
    has no key set."""
    body = three_source_response()
    body["sources"][2].update(
        status="ok",
        latency_ms=90,
        summary={"asn": 15169, "as_name": "GOOGLE - Google LLC, US", "bgp_prefix": "8.8.8.0/24"},
        raw={"origin": ["15169 | 8.8.8.0/24 | US | arin | 2023-12-28"]},
        error=None,
    )
    body["sources"] += [
        {
            "name": "abuseipdb",
            "display_name": "AbuseIPDB",
            "status": "ok",
            "latency_ms": 210,
            "summary": {"abuse_confidence_score": 0, "total_reports": 198, "is_whitelisted": True},
            "raw": {"data": {"abuseConfidenceScore": 0}},
            "error": None,
        },
        {
            "name": "greynoise",
            "display_name": "GreyNoise Community",
            "status": "rate_limited",
            "latency_ms": 120,
            "summary": None,
            "raw": None,
            "error": "HTTP 429: Weekly lookup limit reached.",
        },
        {
            "name": "virustotal",
            "display_name": "VirusTotal",
            "status": "ok",
            "latency_ms": 400,
            "summary": {"malicious": 1, "suspicious": 0, "harmless": 54, "undetected": 37},
            "raw": {"data": {"attributes": {}}},
            "error": None,
        },
        {
            "name": "ipinfo",
            "display_name": "ipinfo Lite",
            "status": "not_configured",
            "latency_ms": None,
            "summary": None,
            "raw": None,
            "error": "No API key set",
        },
    ]
    return body


def test_seven_sources_render_seven_cards_with_distinct_states(client: TestClient, router) -> None:
    router.get(f"{BACKEND}/api/v1/ip/8.8.8.8").respond(200, json=seven_source_response())
    html = client.post("/lookup", data={"ip": "8.8.8.8"}).text
    assert html.count('<article class="card') == 7
    for name in ("AbuseIPDB", "GreyNoise Community", "VirusTotal", "ipinfo Lite"):
        assert name in html
    assert "total reports" in html  # a keyed source's summary fields are readable
    # A spent quota is its own grey card, not an error and not "no data".
    assert 'class="card status-rate_limited"' in html
    assert "Quota reached" in html
    assert "Weekly lookup limit reached" in html  # the provider's message is shown
    # A missing key is a distinct, quiet card that says what to do.
    assert 'class="card status-not_configured"' in html
    assert "no API key is set on the backend" in html


def test_ipinfo_attribution_is_shown_on_every_page(client: TestClient, router) -> None:
    router.get(f"{BACKEND}/api/v1/ip/8.8.8.8").respond(200, json=contract_response())
    for html in (client.get("/").text, client.post("/lookup", data={"ip": "8.8.8.8"}).text):
        assert '<a href="https://ipinfo.io"' in html
        assert "IPinfo" in html


def test_frontend_holds_no_key_and_none_reaches_the_page(
    router, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.config import Settings as FrontendSettings

    # The frontend's settings have no field that could hold a key (design.md D2).
    assert set(FrontendSettings.model_fields) == {"backend_url", "backend_timeout_seconds"}
    keys = {
        "ABUSEIPDB_API_KEY": "FAKE-ABUSEIPDB-KEY-0000",
        "GREYNOISE_API_KEY": "FAKE-GREYNOISE-KEY-0000",
        "VIRUSTOTAL_API_KEY": "FAKE-VIRUSTOTAL-KEY-0000",
        "IPINFO_TOKEN": "FAKE-IPINFO-TOKEN-0000",
    }
    for name, value in keys.items():
        monkeypatch.setenv(name, value)
    client = TestClient(create_app(Settings(backend_url=BACKEND)))
    route = router.get(f"{BACKEND}/api/v1/ip/8.8.8.8").respond(200, json=seven_source_response())
    pages = [client.get("/").text, client.post("/lookup", data={"ip": "8.8.8.8"}).text]
    for html in pages:
        for value in keys.values():
            assert value not in html
    request = route.calls.last.request  # and the frontend forwards no key to the backend
    for value in keys.values():
        assert value not in str(request.url) and value not in " ".join(request.headers.values())
