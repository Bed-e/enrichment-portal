from ipaddress import ip_address

from app.core.models import SourceResult
from app.services.lookup import LookupService


class Exploding:
    name = "exploding"
    display_name = "Exploding"
    requires_key = False

    def is_configured(self) -> bool:
        return True

    async def lookup(self, ip) -> SourceResult:
        raise RuntimeError("bug in a client")


class Unconfigured(Exploding):
    name = "unconfigured"
    requires_key = True

    def is_configured(self) -> bool:
        return False


async def test_a_raising_source_becomes_an_error_result() -> None:
    response = await LookupService([Exploding()]).lookup(ip_address("8.8.8.8"))
    (source,) = response.sources
    assert source.status == "error"
    assert response.verdict.level == "unknown"


async def test_unconfigured_source_is_not_configured_and_not_called() -> None:
    response = await LookupService([Unconfigured()]).lookup(ip_address("8.8.8.8"))
    (source,) = response.sources
    assert source.status == "not_configured"
    assert source.latency_ms is None


async def test_every_registered_source_appears_even_when_skipped() -> None:
    service = LookupService([Exploding(), Unconfigured()])
    response = await service.lookup(ip_address("192.168.0.1"))
    assert [s.status for s in response.sources] == ["skipped", "skipped"]
    assert response.verdict.level == "not_applicable"
