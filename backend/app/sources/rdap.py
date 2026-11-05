"""RDAP client, queried through the rdap.org bootstrap service. Keyless.

GET https://rdap.org/ip/{ip} redirects (302) to the regional registry that holds the record;
the shared HTTP client follows the redirect. rdap.org answers 404 when no RDAP service covers
the address, and 429 when more than 10 requests arrive within 10 s (design.md section 4).
"""

import time
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import httpx

from app.core.models import SourceResult
from app.sources.base import finished_result
from app.sources.ratelimit import RateLimiter

USER_AGENT = "enrichment-portal (educational project)"
REGISTRIES = ("arin", "ripe", "apnic", "lacnic", "afrinic")


class Rdap:
    name = "rdap"
    display_name = "RDAP"
    requires_key = False

    def __init__(
        self,
        http: httpx.AsyncClient,
        base_url: str,
        timeout: float,
        limiter: RateLimiter | None = None,
    ) -> None:
        self._http = http
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        # rdap.org allows 10 requests per 10 s. Our limiter stays under that.
        self._limiter = limiter or RateLimiter(max_calls=10, period=10.0)

    def is_configured(self) -> bool:
        return True

    async def lookup(self, ip: IPv4Address | IPv6Address) -> SourceResult:
        started = time.monotonic()
        # Waiting longer than the source timeout would hang the lookup, so give up instead.
        if not await self._limiter.acquire(max_wait=self._timeout):
            return finished_result(
                self, "rate_limited", started, error="Own RDAP rate limit reached (10 per 10 s)"
            )
        try:
            response = await self._http.get(
                f"{self._base_url}/ip/{ip}",
                headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"},
                timeout=self._timeout,
            )
        except httpx.TimeoutException:
            return finished_result(
                self, "timeout", started, error=f"No response within {self._timeout:g} s"
            )
        except httpx.HTTPError as exc:
            return finished_result(
                self, "error", started, error=f"Request failed: {type(exc).__name__}"
            )
        except Exception as exc:  # a client never raises to the service
            return finished_result(
                self, "error", started, error=f"Unexpected failure: {type(exc).__name__}"
            )

        try:
            body = response.json()
        except ValueError:
            body = None

        if response.status_code == 200 and isinstance(body, dict):
            return finished_result(self, "ok", started, summary=self._summarize(body), raw=body)
        if response.status_code == 404:
            return finished_result(
                self, "no_data", started, raw=body, error="No RDAP record covers this IP"
            )
        if response.status_code == 429:
            return finished_result(
                self, "rate_limited", started, error="HTTP 429: too many requests to RDAP"
            )
        return finished_result(
            self, "error", started, error=f"Unexpected response: HTTP {response.status_code}"
        )

    @classmethod
    def _summarize(cls, body: dict[str, Any]) -> dict[str, Any]:
        start, end = body.get("startAddress"), body.get("endAddress")
        entities = body.get("entities") or []
        registrant = next((e for e in entities if "registrant" in (e.get("roles") or [])), None)
        return {
            "network_name": body.get("name"),
            "network_range": f"{start} - {end}" if start and end else None,
            "org_name": _vcard_value((registrant or {}).get("vcardArray"), "fn")
            or next(
                (v for v in (_vcard_value(e.get("vcardArray"), "fn") for e in entities) if v),
                None,
            ),
            "country": body.get("country"),
            "registry": cls._registry(body),
            "registration_date": _event_date(body, "registration"),
            "last_changed": _event_date(body, "last changed"),
            "abuse_email": _abuse_email(entities),
        }

    @staticmethod
    def _registry(body: dict[str, Any]) -> str | None:
        hosts = [str(body.get("port43") or "")] + [
            str(link.get("href") or "") for link in body.get("links") or []
        ]
        for host in hosts:
            for registry in REGISTRIES:
                if registry in host.lower():
                    return registry
        return None


def _vcard_value(vcard: Any, field: str) -> str | None:
    """One property (such as 'fn' or 'email') from a jCard array, or None."""
    try:
        for item in vcard[1]:
            if item[0] == field and item[3]:
                return str(item[3])
    except (TypeError, IndexError, KeyError):
        pass
    return None


def _event_date(body: dict[str, Any], action: str) -> str | None:
    for event in body.get("events") or []:
        if event.get("eventAction") == action and event.get("eventDate"):
            return str(event["eventDate"])[:10]  # keep the date, drop the time
    return None


def _abuse_email(entities: list[dict[str, Any]]) -> str | None:
    """The email of the nearest entity with the 'abuse' role, searching nested entities."""
    for entity in entities:
        if "abuse" in (entity.get("roles") or []):
            email = _vcard_value(entity.get("vcardArray"), "email")
            if email:
                return email
        nested = _abuse_email(entity.get("entities") or [])
        if nested:
            return nested
    return None
