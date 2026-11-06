"""GreyNoise Community client. Free key; GET /v3/community/{ip}, header `key`.

Limit: 50 lookups a week, shared with the GreyNoise Visualizer, so this source is often rate
limited (an accepted trade-off, design.md section 4). 404 means GreyNoise has never seen the IP
scanning the internet and it is not in RIOT, which is `no_data`.
"""

import time
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import httpx
from pydantic import SecretStr

from app.core.models import SourceResult
from app.sources.base import fetch_json, finished_result, key_or_quota_failure


class GreyNoise:
    name = "greynoise"
    display_name = "GreyNoise Community"
    requires_key = True

    def __init__(
        self, http: httpx.AsyncClient, base_url: str, timeout: float, api_key: SecretStr
    ) -> None:
        self._http = http
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._key = api_key.get_secret_value()

    def is_configured(self) -> bool:
        return bool(self._key)

    async def lookup(self, ip: IPv4Address | IPv6Address) -> SourceResult:
        started = time.monotonic()
        fetched = await fetch_json(
            self,
            self._http,
            f"{self._base_url}/v3/community/{ip}",
            headers={"key": self._key, "Accept": "application/json"},
            timeout=self._timeout,
            started=started,
        )
        if isinstance(fetched, SourceResult):
            return fetched
        response, body = fetched

        message = body.get("message") if isinstance(body, dict) else None
        failure = key_or_quota_failure(self, response, started, message, self._key)
        if failure:
            return failure
        if response.status_code == 200 and isinstance(body, dict):
            return finished_result(self, "ok", started, summary=self._summarize(body), raw=body)
        if response.status_code == 404:
            return finished_result(
                self, "no_data", started, raw=body, error="GreyNoise has not seen this IP"
            )
        return finished_result(
            self, "error", started, error=f"Unexpected response: HTTP {response.status_code}"
        )

    @staticmethod
    def _summarize(body: dict[str, Any]) -> dict[str, Any]:
        return {
            "noise": body.get("noise"),
            "riot": body.get("riot"),
            "classification": body.get("classification"),
            "name": body.get("name"),
            "last_seen": body.get("last_seen"),
            "link": body.get("link"),
            "message": body.get("message"),
        }
