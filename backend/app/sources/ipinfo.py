"""ipinfo Lite client. Free token, unlimited; GET /lite/{ip}.

The token goes in an `Authorization: Bearer` header, not in the URL, so it can never appear in a
logged URL (design.md section 4). Attribution is required (CC BY-SA 4.0); the frontend shows a
credit link. Bogon addresses get HTTP 200 with only {"ip", "bogon": true}, which is `no_data`.
"""

import time
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import httpx
from pydantic import SecretStr

from app.core.models import SourceResult
from app.sources.base import fetch_json, finished_result, key_or_quota_failure


class IpinfoLite:
    name = "ipinfo"
    display_name = "ipinfo Lite"
    requires_key = True

    def __init__(
        self, http: httpx.AsyncClient, base_url: str, timeout: float, token: SecretStr
    ) -> None:
        self._http = http
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._token = token.get_secret_value()

    def is_configured(self) -> bool:
        return bool(self._token)

    async def lookup(self, ip: IPv4Address | IPv6Address) -> SourceResult:
        started = time.monotonic()
        fetched = await fetch_json(
            self,
            self._http,
            f"{self._base_url}/lite/{ip}",
            headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            timeout=self._timeout,
            started=started,
        )
        if isinstance(fetched, SourceResult):
            return fetched
        response, body = fetched

        message = None
        if isinstance(body, dict):
            message = body.get("message") or body.get("error") or body.get("title")
        failure = key_or_quota_failure(
            self, response, started, message if isinstance(message, str) else None, self._token
        )
        if failure:
            return failure
        if response.status_code == 200 and isinstance(body, dict):
            if body.get("bogon"):
                return finished_result(
                    self,
                    "no_data",
                    started,
                    raw=body,
                    error="ipinfo has no data for a bogon address",
                )
            return finished_result(self, "ok", started, summary=self._summarize(body), raw=body)
        if response.status_code == 404:
            return finished_result(
                self, "no_data", started, raw=body, error="ipinfo has no data for this IP"
            )
        return finished_result(
            self, "error", started, error=f"Unexpected response: HTTP {response.status_code}"
        )

    @staticmethod
    def _summarize(body: dict[str, Any]) -> dict[str, Any]:
        return {
            "asn": body.get("asn"),
            "as_name": body.get("as_name"),
            "as_domain": body.get("as_domain"),
            "country_code": body.get("country_code"),
            "country": body.get("country"),
            "continent_code": body.get("continent_code"),
            "continent": body.get("continent"),
        }
