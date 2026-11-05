"""The interface every source client implements (design.md section 2)."""

import time
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Protocol

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
