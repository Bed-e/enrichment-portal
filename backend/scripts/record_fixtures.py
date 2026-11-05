"""Record real source responses as test fixtures (design.md D13).

Run by hand from backend/, never in CI:   uv run python scripts/record_fixtures.py

Raw responses go to tests/fixtures/_raw/ (gitignored). Scrubbed copies go to
tests/fixtures/<source>/<case>.json: only the response (status and body, or DNS answers) is
kept, never request URLs or headers, and any configured key value is replaced by REDACTED.
All three M1 sources are keyless, so no keys are involved; the scrubbing still runs so the
same script is safe once keyed sources are added.

HTTP sources are stored as {"status_code": int, "body": ...}. Team Cymru is DNS, stored as
{"queries": {"<name>": {"rcode": "NOERROR" | "NXDOMAIN" | "NOANSWER", "txt": [str, ...]}}}.
"""

import json
import os
from pathlib import Path
from typing import Any

import dns.exception
import dns.name
import dns.rcode
import dns.resolver
import httpx

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
ENV_EXAMPLE = Path(__file__).resolve().parents[2] / ".env.example"

HAS_DATA_IP = "8.8.8.8"
NO_DATA_IP = "192.0.2.1"  # TEST-NET-1: InternetDB and Team Cymru know nothing about it
# ARIN does have a record for 192.0.2.1 (TEST-NET-1), so RDAP needs an address in space that
# the RDAP bootstrap does not cover: rdap.org answers 404 for it.
RDAP_NO_DATA_IP = "240.0.0.1"

# (source, case, URL) for the HTTP sources. rdap.org redirects to the right registry; the
# recorded response is the final one, after following the redirect.
HTTP_CASES = [
    ("shodan_internetdb", "ok_8_8_8_8", f"https://internetdb.shodan.io/{HAS_DATA_IP}"),
    ("shodan_internetdb", "no_data", f"https://internetdb.shodan.io/{NO_DATA_IP}"),
    ("rdap", "ok_8_8_8_8", f"https://rdap.org/ip/{HAS_DATA_IP}"),
    ("rdap", "no_data", f"https://rdap.org/ip/{RDAP_NO_DATA_IP}"),
]
CYMRU_CASES = [("ok_8_8_8_8", HAS_DATA_IP), ("no_data", NO_DATA_IP)]


def secret_values() -> list[str]:
    """Values of every variable named in .env.example that is set in this environment."""
    names = [
        line.split("=", 1)[0].strip()
        for line in ENV_EXAMPLE.read_text().splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    ]
    return [os.environ[n] for n in names if os.environ.get(n)]


def scrub(text: str) -> str:
    for value in secret_values():
        text = text.replace(value, "REDACTED")
    return text


def write(source: str, case: str, record: dict[str, Any]) -> None:
    raw_dir = FIXTURES / "_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    # newline="\n" keeps LF endings on Windows so re-recording does not churn the diff.
    (raw_dir / f"{source}__{case}.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8", newline="\n"
    )
    out_dir = FIXTURES / source
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{case}.json").write_text(
        scrub(json.dumps(record, indent=2)) + "\n", encoding="utf-8", newline="\n"
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


def record_cymru(case: str, ip: str) -> None:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    reversed_ip = ".".join(reversed(ip.split(".")))
    origin = f"{reversed_ip}.origin.asn.cymru.com"
    queries = {origin: query_txt(resolver, origin)}
    if queries[origin]["txt"]:
        asn = queries[origin]["txt"][0].split("|")[0].split()[0]
        as_name = f"AS{asn}.asn.cymru.com"
        queries[as_name] = query_txt(resolver, as_name)
    write("team_cymru", case, {"queries": queries})
    print(f"team_cymru/{case}: " + ", ".join(f"{q['rcode']}" for q in queries.values()))


def main() -> None:
    headers = {
        "User-Agent": "enrichment-portal (educational project)",
        "Accept": "application/rdap+json, application/json",
    }
    with httpx.Client(timeout=15, headers=headers, follow_redirects=True) as http:
        for source, case, url in HTTP_CASES:
            response = http.get(url)
            try:
                body = response.json()
            except ValueError:
                body = response.text
            write(source, case, {"status_code": response.status_code, "body": body})
            print(f"{source}/{case}: HTTP {response.status_code}")
    for case, ip in CYMRU_CASES:
        record_cymru(case, ip)


if __name__ == "__main__":
    main()
