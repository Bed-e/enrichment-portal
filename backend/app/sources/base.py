"""The interface every source client implements (design.md section 2)."""

import time
from collections.abc import Mapping
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Protocol

import httpx

from app.core.models import SourceResult, SourceStatus


class SourceClient(Protocol):
    name: str
    display_name: str
    requires_key: bool

    def is_configured(self) -> bool: ...

    async def lookup(self, ip: IPv4Address | IPv6Address) -> SourceResult: ...


def finished_result(
    source: SourceClient, status: SourceStatus, started: float, **kwargs: Any
) -> SourceResult:
    """A result for a source that was called; `started` is a time.monotonic() reading."""
    return SourceResult(
        name=source.name,
        display_name=source.display_name,
        status=status,
        latency_ms=int((time.monotonic() - started) * 1000),
        **kwargs,
    )


def result_without_call(source: SourceClient, status: SourceStatus, error: str) -> SourceResult:
    """A result for a source that was not queried (no latency, no data)."""
    return SourceResult(
        name=source.name,
        display_name=source.display_name,
        status=status,
        latency_ms=None,
        summary=None,
        raw=None,
        error=error,
    )


def redact(text: str, secret: str) -> str:
    """Remove a key from text before it goes into an error message (design.md section 4)."""
    return text.replace(secret, "REDACTED") if secret else text


async def fetch_json(
    source: SourceClient,
    http: httpx.AsyncClient,
    url: str,
    *,
    headers: Mapping[str, str],
    params: Mapping[str, Any] | None = None,
    timeout: float,
    started: float,
) -> tuple[httpx.Response, Any] | SourceResult:
    """GET and parse JSON. Returns a failed SourceResult for a timeout or transport error.

    Error messages carry only the exception's type name, never the URL or headers, so a key can
    not end up in them.
    """
    try:
        response = await http.get(url, headers=headers, params=params, timeout=timeout)
    except httpx.TimeoutException:
        return finished_result(
            source, "timeout", started, error=f"No response within {timeout:g} s"
        )
    except httpx.HTTPError as exc:
        return finished_result(
            source, "error", started, error=f"Request failed: {type(exc).__name__}"
        )
    except Exception as exc:  # a client never raises to the service
        return finished_result(
            source, "error", started, error=f"Unexpected failure: {type(exc).__name__}"
        )
    try:
        body = response.json()
    except ValueError:
        body = None
    return response, body


def key_or_quota_failure(
    source: SourceClient,
    response: httpx.Response,
    started: float,
    provider_message: str | None,
    secret: str,
) -> SourceResult | None:
    """The outcomes every keyed source shares: a rejected key (401/403) and a quota (429).

    A 429 becomes `rate_limited` with the provider's own message, never `error` (design.md
    section 4, "Quota behaviour"). Returns None for any other status.
    """
    if response.status_code in (401, 403):
        return finished_result(
            source, "error", started, error=f"API key rejected (HTTP {response.status_code})"
        )
    if response.status_code == 429:
        detail = redact((provider_message or "")[:200], secret)
        suffix = f": {detail}" if detail else ""
        return finished_result(source, "rate_limited", started, error=f"HTTP 429{suffix}")
    return None
