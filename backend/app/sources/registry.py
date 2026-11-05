"""The list of registered sources. Adding a source means adding it here."""

import httpx

from app.config import Settings
from app.sources.base import SourceClient
from app.sources.cymru import DnsTxtResolver, TeamCymru, TxtResolver
from app.sources.rdap import Rdap
from app.sources.shodan_internetdb import ShodanInternetDB


def build_sources(
    settings: Settings, http: httpx.AsyncClient, resolver: TxtResolver | None = None
) -> list[SourceClient]:
    timeout = settings.source_timeout_seconds
    return [
        ShodanInternetDB(http, settings.internetdb_base_url, timeout),
        Rdap(http, settings.rdap_base_url, timeout),
        TeamCymru(resolver or DnsTxtResolver(timeout), timeout),
    ]
