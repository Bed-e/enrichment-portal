"""Shodan InternetDB client. Keyless; GET https://internetdb.shodan.io/{ip}, 404 = no data."""

import time
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import httpx

from app.core.models import SourceResult, SourceStatus

USER_AGENT = "enrichment-portal (educational project)"


class ShodanInternetDB:
    name = "shodan_internetdb"
    display_name = "Shodan InternetDB"
    requires_key = False

    def __init__(self, http: httpx.AsyncClient, base_url: str, timeout: float) -> None:
        self._http = http
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def is_configured(self) -> bool:
        return True

    async def lookup(self, ip: IPv4Address | IPv6Address) -> SourceResult:
        started = time.monotonic()

        def result(status: SourceStatus, **kwargs: Any) -> SourceResult:
            latency = int((time.monotonic() - started) * 1000)
            return SourceResult(
                name=self.name,
                display_name=self.display_name,
                status=status,
                latency_ms=latency,
                **kwargs,
            )

        try:
            response = await self._http.get(
                f"{self._base_url}/{ip}",
                headers={"User-Agent": USER_AGENT},
                timeout=self._timeout,
            )
        except httpx.TimeoutException:
            return result("timeout", error=f"No response within {self._timeout:g} s")
        except httpx.HTTPError as exc:
            return result("error", error=f"Request failed: {type(exc).__name__}")
        except Exception as exc:  # a client never raises to the service
            return result("error", error=f"Unexpected failure: {type(exc).__name__}")

        try:
            body = response.json()
        except ValueError:
            body = None

        if response.status_code == 200 and isinstance(body, dict):
            return result("ok", summary=self._summarize(body), raw=body)
        if response.status_code == 404:
            return result("no_data", raw=body, error="InternetDB has no data for this IP")
        if response.status_code == 429:
            return result("rate_limited", error="HTTP 429: too many requests to InternetDB")
        return result("error", error=f"Unexpected response: HTTP {response.status_code}")

    @staticmethod
    def _summarize(body: dict[str, Any]) -> dict[str, Any]:
        return {
            "open_ports": body.get("ports") or [],
            "tags": body.get("tags") or [],
            "vulns": body.get("vulns") or [],
            "hostnames": body.get("hostnames") or [],
            "cpes": body.get("cpes") or [],
        }
