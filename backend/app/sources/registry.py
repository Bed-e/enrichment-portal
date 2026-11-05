"""The list of registered sources. Adding a source means adding it here."""

import httpx

from app.config import Settings
from app.sources.abuseipdb import AbuseIPDB
from app.sources.base import SourceClient
from app.sources.cymru import DnsTxtResolver, TeamCymru, TxtResolver
from app.sources.greynoise import GreyNoise
from app.sources.ipinfo import IpinfoLite
from app.sources.rdap import Rdap
from app.sources.shodan_internetdb import ShodanInternetDB
from app.sources.virustotal import VirusTotal


def build_sources(
    settings: Settings, http: httpx.AsyncClient, resolver: TxtResolver | None = None
) -> list[SourceClient]:
    timeout = settings.source_timeout_seconds
    return [
        ShodanInternetDB(http, settings.internetdb_base_url, timeout),
        Rdap(http, settings.rdap_base_url, timeout),
        TeamCymru(resolver or DnsTxtResolver(timeout), timeout),
        AbuseIPDB(http, settings.abuseipdb_base_url, timeout, settings.abuseipdb_api_key),
        GreyNoise(http, settings.greynoise_base_url, timeout, settings.greynoise_api_key),
        VirusTotal(http, settings.virustotal_base_url, timeout, settings.virustotal_api_key),
        IpinfoLite(http, settings.ipinfo_base_url, timeout, settings.ipinfo_token),
    ]
