import re
from typing import Any

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.main import create_app

INTERNETDB_8888 = "https://internetdb.shodan.io/8.8.8.8"


@pytest.fixture
def router():
    with respx.mock(assert_all_mocked=True) as router:
        yield router


@pytest.fixture
def client(router) -> TestClient:
    return TestClient(create_app(), raise_server_exceptions=False)


def assert_error_shape(response: httpx.Response, status: int, error: str) -> None:
    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error", "message"}
    assert body["error"] == error
    assert body["message"]


def test_healthz(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_global_ip(client: TestClient, router, internetdb_ok: dict[str, Any]) -> None:
    router.get(INTERNETDB_8888).respond(200, json=internetdb_ok["body"])
    response = client.get("/api/v1/ip/8.8.8.8")
    assert response.status_code == 200
    body = response.json()
    assert body["lookup_id"] is None
    assert body["ip"] == "8.8.8.8"
    assert body["ip_version"] == 4
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body["queried_at"])
    assert body["classification"] == {"category": "global", "is_global": True, "explanation": None}
    assert body["verdict"]["level"] == "unknown"
    assert body["verdict"]["rules_version"] == "0.0"
    assert body["verdict"]["reasons"] == []
    (source,) = body["sources"]
    assert source["name"] == "shodan_internetdb"
    assert source["display_name"] == "Shodan InternetDB"
    assert source["status"] == "ok"
    assert source["summary"]["open_ports"] == [53, 443]
    assert source["raw"] == internetdb_ok["body"]
    assert source["error"] is None


def test_private_ip_is_not_sent_to_any_source(client: TestClient, router) -> None:
    # `router` has no routes and assert_all_mocked=True: any outbound call would fail the test.
    response = client.get("/api/v1/ip/10.0.0.5")
    assert response.status_code == 200
    body = response.json()
    assert body["classification"]["category"] == "private"
    assert body["classification"]["is_global"] is False
    assert "10.0.0.5" in body["classification"]["explanation"]
    assert body["verdict"]["level"] == "not_applicable"
    (source,) = body["sources"]
    assert source["status"] == "skipped"
    assert source["latency_ms"] is None
    assert source["error"] == "Not queried: private address"
    assert router.calls.call_count == 0


def test_source_failure_is_not_an_api_error(client: TestClient, router) -> None:
    router.get(INTERNETDB_8888).mock(side_effect=httpx.ConnectTimeout("slow"))
    response = client.get("/api/v1/ip/8.8.8.8")
    assert response.status_code == 200
    body = response.json()
    assert body["sources"][0]["status"] == "timeout"
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
