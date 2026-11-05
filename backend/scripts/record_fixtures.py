"""Record real source responses as test fixtures (design.md D13).

Run by hand from backend/, never in CI:

    uv run python scripts/record_fixtures.py            # keyless sources + keyed except GreyNoise
    uv run python scripts/record_fixtures.py greynoise  # name sources to record only those

GreyNoise is left out of the default run because its free tier allows only 50 lookups a week,
shared with the GreyNoise Visualizer (design.md section 4); name it to record it.

Raw responses go to tests/fixtures/_raw/ (gitignored). Scrubbed copies go to
tests/fixtures/<source>/<case>.json: only the response (status and body, or DNS answers) is
kept, never request URLs or headers, and every configured key value is replaced by REDACTED.
Keys are read from the repo's .env through the backend's own settings and are never printed.
A keyed source whose key is not set is skipped.

HTTP sources are stored as {"status_code": int, "body": ...}. Team Cymru is DNS, stored as
{"queries": {"<name>": {"rcode": "NOERROR" | "NXDOMAIN" | "NOANSWER", "txt": [str, ...]}}}.
"""

import json
import sys
import time
from pathlib import Path
from typing import Any

import dns.exception
import dns.name
import dns.rcode
import dns.resolver
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

HAS_DATA_IP = "8.8.8.8"
NO_DATA_IP = "192.0.2.1"  # TEST-NET-1: InternetDB and Team Cymru know nothing about it
# ARIN does have a record for 192.0.2.1 (TEST-NET-1), so RDAP needs an address in space that
# the RDAP bootstrap does not cover: rdap.org answers 404 for it.
RDAP_NO_DATA_IP = "240.0.0.1"
# A global address that AbuseIPDB has no reports for and GreyNoise should never have seen.
# (Documentation and reserved ranges do not work: people report 192.0.2.1 to AbuseIPDB, and
# GreyNoise answers 400 for non-routable addresses.)
UNSEEN_GLOBAL_IP = "203.0.114.7"

# (source, case, URL) for the keyless HTTP sources. rdap.org redirects to the right registry;
# the recorded response is the final one, after following the redirect.
KEYLESS_HTTP_CASES = [
    ("shodan_internetdb", "ok_8_8_8_8", f"https://internetdb.shodan.io/{HAS_DATA_IP}"),
    ("shodan_internetdb", "no_data", f"https://internetdb.shodan.io/{NO_DATA_IP}"),
    ("rdap", "ok_8_8_8_8", f"https://rdap.org/ip/{HAS_DATA_IP}"),
    ("rdap", "no_data", f"https://rdap.org/ip/{RDAP_NO_DATA_IP}"),
]
CYMRU_CASES = [("ok_8_8_8_8", HAS_DATA_IP), ("no_data", NO_DATA_IP)]

KEYLESS = ["shodan_internetdb", "rdap", "team_cymru"]
KEYED = ["abuseipdb", "virustotal", "ipinfo", "greynoise"]
DEFAULT_SOURCES = [*KEYLESS, "abuseipdb", "virustotal", "ipinfo"]
VIRUSTOTAL_PAUSE_SECONDS = 16  # the public API allows 4 requests a minute


def keyed_requests(settings: Settings, source: str) -> list[tuple[str, str, dict[str, str]]]:
    """(case, URL, headers) for one keyed source. The only place a key is unwrapped."""
    if source == "abuseipdb":
        key = {"Key": settings.abuseipdb_api_key.get_secret_value(), "Accept": "application/json"}
        url = "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress="
        return [("ok_8_8_8_8", url + HAS_DATA_IP, key), ("no_data", url + UNSEEN_GLOBAL_IP, key)]
    if source == "virustotal":
        key = {"x-apikey": settings.virustotal_api_key.get_secret_value()}
        url = "https://www.virustotal.com/api/v3/ip_addresses/"
        # VirusTotal answers 200 for any valid IP, so there is no real "unknown IP" response to
        # record. Its 404 and 429 bodies are built in the tests from the documented shape.
        return [("ok_8_8_8_8", url + HAS_DATA_IP, key)]
    if source == "greynoise":
        key = {"key": settings.greynoise_api_key.get_secret_value(), "Accept": "application/json"}
        url = "https://api.greynoise.io/v3/community/"
        # Only the "not seen" case is recorded. 8.8.8.8 and 1.1.1.1 both came back 404 on the
        # free Community tier, so no real "ok" response has been seen; the tests build one from
        # the documented shape and say so. Each lookup costs 1 of the 50 a week.
        return [("no_data", url + UNSEEN_GLOBAL_IP, key)]
    if source == "ipinfo":
        # Sent as a Bearer header so the token never appears in a URL (design.md section 4).
        key = {"Authorization": f"Bearer {settings.ipinfo_token.get_secret_value()}"}
        url = "https://api.ipinfo.io/lite/"
        return [("ok_8_8_8_8", url + HAS_DATA_IP, key), ("bogon_192_0_2_1", url + NO_DATA_IP, key)]
    raise ValueError(source)


def key_for(settings: Settings, source: str) -> str:
    return {
        "abuseipdb": settings.abuseipdb_api_key,
        "virustotal": settings.virustotal_api_key,
        "greynoise": settings.greynoise_api_key,
        "ipinfo": settings.ipinfo_token,
    }[source].get_secret_value()


def secret_values(settings: Settings) -> list[str]:
    """Every configured key value, for scrubbing. Never printed."""
    return [v for v in (key_for(settings, s) for s in KEYED) if v]


def scrub(text: str, secrets: list[str]) -> str:
    for value in secrets:
        text = text.replace(value, "REDACTED")
    return text


def write(source: str, case: str, record: dict[str, Any], secrets: list[str]) -> None:
    raw_dir = FIXTURES / "_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    # newline="\n" keeps LF endings on Windows so re-recording does not churn the diff.
    (raw_dir / f"{source}__{case}.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8", newline="\n"
    )
    out_dir = FIXTURES / source
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{case}.json").write_text(
        scrub(json.dumps(record, indent=2), secrets) + "\n", encoding="utf-8", newline="\n"
    )


def query_txt(resolver: dns.resolver.Resolver, name: str) -> dict[str, Any]:
    try:
        answer = resolver.resolve(name, "TXT")
    except dns.resolver.NXDOMAIN:
        return {"rcode": "NXDOMAIN", "txt": []}
    except dns.resolver.NoAnswer:
        return {"rcode": "NOANSWER", "txt": []}
    txt = [b"".join(rdata.strings).decode() for rdata in answer]
    return {"rcode": dns.rcode.to_text(answer.response.rcode()), "txt": txt}


def record_cymru(case: str, ip: str, secrets: list[str]) -> None:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    reversed_ip = ".".join(reversed(ip.split(".")))
    origin = f"{reversed_ip}.origin.asn.cymru.com"
    queries = {origin: query_txt(resolver, origin)}
    if queries[origin]["txt"]:
        asn = queries[origin]["txt"][0].split("|")[0].split()[0]
        as_name = f"AS{asn}.asn.cymru.com"
        queries[as_name] = query_txt(resolver, as_name)
    write("team_cymru", case, {"queries": queries}, secrets)
    print(f"team_cymru/{case}: " + ", ".join(f"{q['rcode']}" for q in queries.values()))


def record_http(
    http: httpx.Client,
    source: str,
    case: str,
    url: str,
    headers: dict[str, str],
    secrets: list[str],
) -> None:
    response = http.get(url, headers=headers)
    try:
        body = response.json()
    except ValueError:
        body = response.text
    write(source, case, {"status_code": response.status_code, "body": body}, secrets)
    print(f"{source}/{case}: HTTP {response.status_code}")  # never the URL or headers


def main(wanted: list[str]) -> None:
    unknown = [s for s in wanted if s not in KEYLESS + KEYED]
    if unknown:
        sys.exit(f"Unknown source(s): {', '.join(unknown)}. Choose from {KEYLESS + KEYED}")
    settings = Settings()
    secrets = secret_values(settings)
    base_headers = {
        "User-Agent": "enrichment-portal (educational project)",
        "Accept": "application/rdap+json, application/json",
    }
    with httpx.Client(timeout=15, headers=base_headers, follow_redirects=True) as http:
        for source, case, url in KEYLESS_HTTP_CASES:
            if source in wanted:
                record_http(http, source, case, url, {}, secrets)
        for source in KEYED:
            if source not in wanted:
                continue
            if not key_for(settings, source):
                print(f"{source}: no key set in .env, skipped")
                continue
            for index, (case, url, headers) in enumerate(keyed_requests(settings, source)):
                if source == "virustotal" and index:
                    time.sleep(VIRUSTOTAL_PAUSE_SECONDS)
                record_http(http, source, case, url, headers, secrets)
    if "team_cymru" in wanted:
        for case, ip in CYMRU_CASES:
            record_cymru(case, ip, secrets)


if __name__ == "__main__":
    main(sys.argv[1:] or DEFAULT_SOURCES)
