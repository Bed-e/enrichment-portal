"""Runs one lookup from start to finish. Knows nothing about HTTP requests or HTML."""

import asyncio
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address

from app.core.ip_classify import classify
from app.core.models import LookupResponse, SourceResult
from app.core.verdict import compute_verdict
from app.sources.base import SourceClient, result_without_call


class LookupService:
    def __init__(self, sources: list[SourceClient]) -> None:
        self._sources = sources

    async def lookup(self, ip: IPv4Address | IPv6Address) -> LookupResponse:
        classification = classify(ip)
        if classification.is_global:
            results = list(await asyncio.gather(*(self._query(s, ip) for s in self._sources)))
        else:
            reason = f"Not queried: {classification.category.replace('_', ' ')} address"
            results = [result_without_call(s, "skipped", reason) for s in self._sources]
        return LookupResponse(
            lookup_id=None,
            ip=str(ip),
            ip_version=ip.version,
            queried_at=datetime.now(UTC).replace(microsecond=0),
            classification=classification,
            verdict=compute_verdict(classification, results),
            sources=results,
        )

    @staticmethod
    async def _query(source: SourceClient, ip: IPv4Address | IPv6Address) -> SourceResult:
        if not source.is_configured():
            return result_without_call(source, "not_configured", "No API key set")
        try:
            return await source.lookup(ip)
        except Exception as exc:  # defensive: one bad source must not fail the lookup
            return SourceResult(
                name=source.name,
                display_name=source.display_name,
                status="error",
                error=f"Unexpected failure: {type(exc).__name__}",
            )
