"""The list of registered sources. Adding a source means adding it here."""

import httpx

from app.config import Settings
from app.sources.base import SourceClient
from app.sources.shodan_internetdb import ShodanInternetDB


def build_sources(settings: Settings, http: httpx.AsyncClient) -> list[SourceClient]:
    return [
        ShodanInternetDB(http, settings.internetdb_base_url, settings.source_timeout_seconds),
    ]
