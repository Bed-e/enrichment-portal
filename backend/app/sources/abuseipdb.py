"""AbuseIPDB client. Free key; GET /api/v2/check, header `Key` (design.md section 4).

Limit: 1,000 checks a day. A 429 means that quota is used up. An IP with no reports at all is
reported as `no_data`: the source answered but has nothing to say about it.
"""

import time
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import httpx
from pydantic import SecretStr

from app.core.models import SourceResult
from app.sources.base import fetch_json, finished_result, key_or_quota_failure

MAX_AGE_DAYS = 90


class AbuseIPDB:
    name = "abuseipdb"
    display_name = "AbuseIPDB"
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
            f"{self._base_url}/api/v2/check",
            headers={"Key": self._key, "Accept": "application/json"},
            params={"ipAddress": str(ip), "maxAgeInDays": MAX_AGE_DAYS},
            timeout=self._timeout,
            started=started,
        )
        if isinstance(fetched, SourceResult):
            return fetched
        response, body = fetched

        errors = body.get("errors") if isinstance(body, dict) else None
        message = errors[0].get("detail") if errors and isinstance(errors[0], dict) else None
        failure = key_or_quota_failure(self, response, started, message, self._key)
        if failure:
            return failure
        data = body.get("data") if isinstance(body, dict) else None
        if response.status_code == 200 and isinstance(data, dict):
            if not data.get("totalReports"):
                return finished_result(
                    self,
                    "no_data",
                    started,
                    raw=body,
                    error="AbuseIPDB has no reports for this IP",
                )
            return finished_result(self, "ok", started, summary=self._summarize(data), raw=body)
        return finished_result(
            self, "error", started, error=f"Unexpected response: HTTP {response.status_code}"
        )

    @staticmethod
    def _summarize(data: dict[str, Any]) -> dict[str, Any]:
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "num_distinct_users": data.get("numDistinctUsers"),
            "last_reported_at": data.get("lastReportedAt"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "country_code": data.get("countryCode"),
            "is_tor": data.get("isTor"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
