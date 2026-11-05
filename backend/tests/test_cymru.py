import asyncio
from ipaddress import ip_address
from typing import Any

import dns.exception
import dns.resolver

from app.sources.cymru import TeamCymru
from tests.fakes import FakeResolver

ORIGIN = "8.8.8.8.origin.asn.cymru.com"
AS_NAME = "AS15169.asn.cymru.com"


def client(resolver, timeout: float = 8.0) -> TeamCymru:
    return TeamCymru(resolver, timeout)


class FixedResolver:
    """Returns the same answers whatever the name, for the odd-answer cases."""

    def __init__(self, *answers: list[str] | None) -> None:
        self._answers = list(answers)

    async def resolve_txt(self, name: str) -> list[str] | None:
        return self._answers.pop(0)


async def test_ok(cymru_ok: dict[str, Any]) -> None:
    resolver = FakeResolver(cymru_ok)
    result = await client(resolver).lookup(ip_address("8.8.8.8"))
    assert result.status == "ok"
    assert result.name == "team_cymru"
    assert result.summary == {
        "asn": 15169,
        "as_name": "GOOGLE - Google LLC, US",
        "bgp_prefix": "8.8.8.0/24",
        "country_code": "US",
        "registry": "arin",
        "allocated_date": "2023-12-28",
    }
    assert resolver.asked == [ORIGIN, AS_NAME]  # reversed IP, then the AS name query
    assert result.raw == {
        "origin": cymru_ok["queries"][ORIGIN]["txt"],
        "as": cymru_ok["queries"][AS_NAME]["txt"],
    }
    assert result.error is None and result.latency_ms is not None


async def test_no_data_when_no_prefix_announces_the_ip(cymru_no_data: dict[str, Any]) -> None:
    resolver = FakeResolver(cymru_no_data)
    result = await client(resolver).lookup(ip_address("192.0.2.1"))
    assert result.status == "no_data"
    assert result.summary is None
    assert resolver.asked == ["1.2.0.192.origin.asn.cymru.com"]  # no AS query without an ASN


async def test_timeout() -> None:
    resolver = FakeResolver(error=dns.exception.Timeout())
    result = await client(resolver).lookup(ip_address("8.8.8.8"))
    assert result.status == "timeout"
    assert "8" in (result.error or "")
    assert result.summary is None and result.raw is None


async def test_one_deadline_covers_both_queries() -> None:
    class Hangs:
        async def resolve_txt(self, name: str) -> list[str] | None:
            await asyncio.sleep(60)

    result = await client(Hangs(), timeout=0.01).lookup(ip_address("8.8.8.8"))
    assert result.status == "timeout"


async def test_dns_failure_is_an_error() -> None:
    resolver = FakeResolver(error=dns.resolver.NoNameservers())
    result = await client(resolver).lookup(ip_address("8.8.8.8"))
    assert result.status == "error"
    assert "NoNameservers" in (result.error or "")


async def test_unexpected_exception_is_an_error_not_a_crash() -> None:
    result = await client(FakeResolver(error=RuntimeError("bug"))).lookup(ip_address("8.8.8.8"))
    assert result.status == "error"


async def test_malformed_answer_is_an_error() -> None:
    for bad in (["garbage"], ["abc | 1.0.0.0/24 | US | arin | 2000-01-01"], ["15169 | only"]):
        result = await client(FixedResolver(bad)).lookup(ip_address("8.8.8.8"))
        assert result.status == "error", bad


async def test_several_origin_asns_reports_the_first() -> None:
    resolver = FixedResolver(
        ["15169 36040 | 8.8.8.0/24 | US | arin | 2023-12-28"],
        ["15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"],
    )
    result = await client(resolver).lookup(ip_address("8.8.8.8"))
    assert result.status == "ok"
    assert result.summary["asn"] == 15169


async def test_missing_as_name_still_gives_the_origin_data() -> None:
    resolver = FixedResolver(["15169 | 8.8.8.0/24 | US | arin | 2023-12-28"], None)
    result = await client(resolver).lookup(ip_address("8.8.8.8"))
    assert result.status == "ok"
    assert result.summary["as_name"] is None
    assert result.summary["bgp_prefix"] == "8.8.8.0/24"


async def test_ipv6_is_skipped_until_m4() -> None:
    resolver = FakeResolver()
    result = await client(resolver).lookup(ip_address("2001:db8::1"))
    assert result.status == "skipped"
    assert resolver.asked == []
