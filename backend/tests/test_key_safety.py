"""API keys never leak (design.md section 4, "Key handling"; milestone M2).

Fake keys are used throughout. A key may appear in exactly one place: the request header the
provider's own client sends it in. It must never appear in the API response, in logs, in a URL,
in an error message, or in a request to any other provider.
"""

import logging
from typing import Any

import pytest
import respx
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests import synthetic
from tests.fakes import FakeResolver

# provider host -> the key that belongs to it
OWNERS = {
    "api.abuseipdb.com": synthetic.FAKE_KEYS["abuseipdb"],
    "api.greynoise.io": synthetic.FAKE_KEYS["greynoise"],
    "www.virustotal.com": synthetic.FAKE_KEYS["virustotal"],
    "api.ipinfo.io": synthetic.FAKE_KEYS["ipinfo"],
}
ALL_KEYS = list(OWNERS.values())


def keyed_settings() -> Settings:
    return Settings(
        _env_file=None,
        abuseipdb_api_key=synthetic.FAKE_KEYS["abuseipdb"],
        greynoise_api_key=synthetic.FAKE_KEYS["greynoise"],
        virustotal_api_key=synthetic.FAKE_KEYS["virustotal"],
        ipinfo_token=synthetic.FAKE_KEYS["ipinfo"],
    )


@pytest.fixture
def router():
    with respx.mock(assert_all_mocked=True) as router:
        yield router


def mock_every_source(router, fixtures: dict[str, Any]) -> None:
    router.get("https://internetdb.shodan.io/8.8.8.8").respond(
        200, json=fixtures["internetdb"]["body"]
    )
    router.get("https://rdap.org/ip/8.8.8.8").respond(200, json=fixtures["rdap"]["body"])
    router.get("https://api.abuseipdb.com/api/v2/check").respond(
        200, json=fixtures["abuseipdb"]["body"]
    )
    router.get("https://api.greynoise.io/v3/community/8.8.8.8").respond(
        200, json=synthetic.GREYNOISE_OK
    )
    router.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").respond(
        200, json=fixtures["virustotal"]["body"]
    )
    router.get("https://api.ipinfo.io/lite/8.8.8.8").respond(200, json=fixtures["ipinfo"]["body"])


@pytest.fixture
def fixtures(
    internetdb_ok, rdap_ok, abuseipdb_ok, virustotal_ok, ipinfo_ok
) -> dict[str, dict[str, Any]]:
    return {
        "internetdb": internetdb_ok,
        "rdap": rdap_ok,
        "abuseipdb": abuseipdb_ok,
        "virustotal": virustotal_ok,
        "ipinfo": ipinfo_ok,
    }


def test_settings_hide_keys_from_repr_and_dumps() -> None:
    settings = keyed_settings()
    for key in ALL_KEYS:
        assert key not in repr(settings)
        assert key not in str(settings)
        assert key not in settings.model_dump_json()
    assert settings.abuseipdb_api_key.get_secret_value() == synthetic.FAKE_KEYS["abuseipdb"]


def test_keys_are_absent_from_the_response_logs_and_urls(
    router, fixtures, cymru_ok, caplog: pytest.LogCaptureFixture
) -> None:
    mock_every_source(router, fixtures)
    caplog.set_level(logging.DEBUG)  # capture everything, including httpx's request log lines
    app = create_app(keyed_settings(), resolver=FakeResolver(cymru_ok))
    response = TestClient(app).get("/api/v1/ip/8.8.8.8")

    assert response.status_code == 200
    assert all(s["status"] == "ok" for s in response.json()["sources"])  # real keyed lookups ran
    for key in ALL_KEYS:
        assert key not in response.text, "a key is in the API response"
        assert key not in caplog.text, "a key is in the logs"
        assert key not in str(response.headers), "a key is in the response headers"
    assert router.calls.call_count == 6  # every HTTP source was called
    for call in router.calls:
        request = call.request
        for key in ALL_KEYS:
            assert key not in str(request.url), "a key is in a request URL"
            assert key.encode() not in request.content


def test_each_key_goes_only_to_its_own_provider(router, fixtures, cymru_ok) -> None:
    mock_every_source(router, fixtures)
    app = create_app(keyed_settings(), resolver=FakeResolver(cymru_ok))
    TestClient(app).get("/api/v1/ip/8.8.8.8")
    for call in router.calls:
        request = call.request
        sent = " ".join(request.headers.values())
        owner = OWNERS.get(request.url.host)
        for key in ALL_KEYS:
            if key == owner:
                assert key in sent  # the provider that owns it does receive it
            else:
                assert key not in sent, f"{key} was sent to {request.url.host}"


def test_keyless_sources_get_no_credentials(router, fixtures, cymru_ok) -> None:
    mock_every_source(router, fixtures)
    app = create_app(keyed_settings(), resolver=FakeResolver(cymru_ok))
    TestClient(app).get("/api/v1/ip/8.8.8.8")
    for call in router.calls:
        if call.request.url.host in ("internetdb.shodan.io", "rdap.org"):
            assert "authorization" not in call.request.headers
            assert "key" not in call.request.headers


@pytest.mark.parametrize("source", ["abuseipdb", "greynoise", "virustotal", "ipinfo"])
def test_a_provider_that_echoes_the_key_in_an_error_does_not_leak_it(
    router, fixtures, cymru_ok, source: str
) -> None:
    mock_every_source(router, fixtures)
    key = synthetic.FAKE_KEYS[source]
    echo = {"message": key, "error": {"message": key}, "errors": [{"detail": key}]}
    routes = {
        "abuseipdb": "https://api.abuseipdb.com/api/v2/check",
        "greynoise": "https://api.greynoise.io/v3/community/8.8.8.8",
        "virustotal": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        "ipinfo": "https://api.ipinfo.io/lite/8.8.8.8",
    }
    router.get(routes[source]).respond(429, json=echo)  # overrides the earlier ok route
    app = create_app(keyed_settings(), resolver=FakeResolver(cymru_ok))
    response = TestClient(app).get("/api/v1/ip/8.8.8.8")
    assert response.status_code == 200
    assert key not in response.text
    assert next(s for s in response.json()["sources"] if s["name"] == source)["status"] in (
        "rate_limited",
        "ok",
    )
