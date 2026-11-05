"""VirusTotal client. Free key; GET /api/v3/ip_addresses/{ip}, header `x-apikey`.

Only this read-only IP lookup is ever used; nothing is uploaded or submitted for analysis
(design.md D19). Public API limits: 4 requests a minute (kept by our own limiter) and 500 a day.
A minute quota and a daily quota both come back as HTTP 429, so any 429 is `rate_limited` with
VirusTotal's message. 404 means VirusTotal has no object for the IP.
"""

import time
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import httpx
from pydantic import SecretStr

from app.core.models import SourceResult
from app.sources.base import fetch_json, finished_result, key_or_quota_failure
from app.sources.ratelimit import RateLimiter


class VirusTotal:
    name = "virustotal"
    display_name = "VirusTotal"
    requires_key = True

    def __init__(
        self,
        http: httpx.AsyncClient,
        base_url: str,
        timeout: float,
        api_key: SecretStr,
        limiter: RateLimiter | None = None,
    ) -> None:
        self._http = http
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._key = api_key.get_secret_value()
        self._limiter = limiter or RateLimiter(max_calls=4, period=60.0)

    def is_configured(self) -> bool:
        return bool(self._key)

    async def lookup(self, ip: IPv4Address | IPv6Address) -> SourceResult:
        started = time.monotonic()
        # Waiting longer than the source timeout would hang the lookup, so give up instead.
        if not await self._limiter.acquire(max_wait=self._timeout):
            return finished_result(
                self,
                "rate_limited",
                started,
                error="Own VirusTotal rate limit reached (4 per minute)",
            )
        fetched = await fetch_json(
            self,
            self._http,
            f"{self._base_url}/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": self._key, "Accept": "application/json"},
            timeout=self._timeout,
            started=started,
        )
        if isinstance(fetched, SourceResult):
            return fetched
        response, body = fetched

        error = body.get("error") if isinstance(body, dict) else None
        message = error.get("message") if isinstance(error, dict) else None
        failure = key_or_quota_failure(self, response, started, message, self._key)
        if failure:
            return failure
        if response.status_code == 200 and isinstance(body, dict):
            attributes = (body.get("data") or {}).get("attributes")
            if isinstance(attributes, dict):
                summary = self._summarize(attributes)
                return finished_result(self, "ok", started, summary=summary, raw=body)
        if response.status_code == 404:
            return finished_result(
                self, "no_data", started, raw=body, error="VirusTotal has no record of this IP"
            )
        return finished_result(
            self, "error", started, error=f"Unexpected response: HTTP {response.status_code}"
        )

    @staticmethod
    def _summarize(attributes: dict[str, Any]) -> dict[str, Any]:
        stats = attributes.get("last_analysis_stats") or {}
        return {
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"),
            "undetected": stats.get("undetected"),
            "reputation": attributes.get("reputation"),
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner"),
            "country": attributes.get("country"),
            "network": attributes.get("network"),
        }
