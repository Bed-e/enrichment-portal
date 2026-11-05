"""Team Cymru IP-to-ASN client. Keyless; DNS TXT queries (design.md section 4).

Two queries per lookup:
  <reversed-ip>.origin.asn.cymru.com  ->  "ASN | prefix | country | registry | allocated"
  AS<n>.asn.cymru.com                 ->  "ASN | country | registry | allocated | AS name"
The origin zone has no AS name, hence the second query. NXDOMAIN on the origin zone means the
address is not in any announced prefix. The resolver is a parameter so tests inject a fake.
"""

import asyncio
import time
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.core.models import SourceResult
from app.sources.base import finished_result, result_without_call

ASN_ZONE = "asn.cymru.com"


class TxtResolver(Protocol):
    async def resolve_txt(self, name: str) -> list[str] | None:
        """TXT strings for `name`, or None when the name does not exist (NXDOMAIN or no TXT).

        Timeouts and other DNS failures raise dns.exception.DNSException.
        """
        ...


class DnsTxtResolver:
    """The real resolver, backed by dnspython."""

    def __init__(self, timeout: float) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout

    async def resolve_txt(self, name: str) -> list[str] | None:
        try:
            answer = await self._resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        return [b"".join(rdata.strings).decode() for rdata in answer]


class TeamCymru:
    name = "team_cymru"
    display_name = "Team Cymru IP to ASN"
    requires_key = False

    def __init__(self, resolver: TxtResolver, timeout: float) -> None:
        self._resolver = resolver
        self._timeout = timeout

    def is_configured(self) -> bool:
        return True

    async def lookup(self, ip: IPv4Address | IPv6Address) -> SourceResult:
        if ip.version != 4:
            return result_without_call(self, "skipped", "IPv6 is not supported yet")
        started = time.monotonic()
        try:
            # One deadline covers both queries, so the source never exceeds its timeout.
            async with asyncio.timeout(self._timeout):
                return await self._query(ip, started)
        except (TimeoutError, dns.exception.Timeout):
            return finished_result(
                self, "timeout", started, error=f"No DNS answer within {self._timeout:g} s"
            )
        except dns.exception.DNSException as exc:
            return finished_result(
                self, "error", started, error=f"DNS query failed: {type(exc).__name__}"
            )
        except Exception as exc:  # a client never raises to the service
            return finished_result(
                self, "error", started, error=f"Unexpected failure: {type(exc).__name__}"
            )

    async def _query(self, ip: IPv4Address, started: float) -> SourceResult:
        reversed_ip = ip.reverse_pointer.removesuffix(".in-addr.arpa")
        origin_txt = await self._resolver.resolve_txt(f"{reversed_ip}.origin.{ASN_ZONE}")
        if not origin_txt:
            return finished_result(
                self, "no_data", started, error="No announced prefix covers this IP"
            )
        fields = _fields(origin_txt[0], 5)
        asn_text = fields[0].split()[0] if fields and fields[0].split() else ""
        if fields is None or not asn_text.isdigit():
            return finished_result(
                self, "error", started, error="Unexpected answer format from Team Cymru"
            )
        # A prefix can have several origin ASNs ("15169 36040"); the first one is reported.
        asn = int(asn_text)
        as_txt = await self._resolver.resolve_txt(f"AS{asn}.{ASN_ZONE}")
        as_fields = _fields(as_txt[0], 5) if as_txt else None
        summary: dict[str, Any] = {
            "asn": asn,
            "as_name": as_fields[4] if as_fields else None,
            "bgp_prefix": fields[1] or None,
            "country_code": fields[2] or None,
            "registry": fields[3] or None,
            "allocated_date": fields[4] or None,
        }
        raw = {"origin": origin_txt, "as": as_txt or []}
        return finished_result(self, "ok", started, summary=summary, raw=raw)


def _fields(txt: str, count: int) -> list[str] | None:
    """Split a pipe-delimited TXT answer into `count` trimmed fields, or None if too short."""
    parts = [p.strip() for p in txt.split("|", count - 1)]
    return parts if len(parts) == count else None
