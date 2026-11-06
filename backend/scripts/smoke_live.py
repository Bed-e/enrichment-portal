"""Check that the real clients still parse the real sources (design.md D13, "Refreshing").

Run by hand from backend/, never in CI:

    uv run python scripts/smoke_live.py [IP] [--greynoise]

It makes one live lookup (default 8.8.8.8) through the same clients the app uses and checks that
each source answered with the summary keys from design.md section 3. A failure usually means a
provider changed its format: re-run scripts/record_fixtures.py and review the fixture diff.

- Keys are read from the repo's .env through the backend's settings and are never printed.
  A keyed source with no key is reported as skipped, not as a failure.
- GreyNoise is skipped unless you pass --greynoise: its free tier allows only 50 lookups a week,
  shared with the GreyNoise Visualizer, and every run would spend one.
- It writes nothing to disk.
"""

import asyncio
import sys
from ipaddress import ip_address
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.sources.registry import build_sources  # noqa: E402

EXPECTED_KEYS = {
    "shodan_internetdb": {"open_ports", "tags", "vulns", "hostnames", "cpes"},
    "rdap": {
        "network_name",
        "network_range",
        "org_name",
        "country",
        "registry",
        "registration_date",
        "last_changed",
        "abuse_email",
    },
    "team_cymru": {"asn", "as_name", "bgp_prefix", "country_code", "registry", "allocated_date"},
    "abuseipdb": {
        "abuse_confidence_score",
        "total_reports",
        "num_distinct_users",
        "last_reported_at",
        "usage_type",
        "isp",
        "domain",
        "country_code",
        "is_tor",
        "is_whitelisted",
    },
    "greynoise": {"noise", "riot", "classification", "name", "last_seen", "link", "message"},
    "virustotal": {
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "reputation",
        "asn",
        "as_owner",
        "country",
        "network",
    },
    "ipinfo": {
        "asn",
        "as_name",
        "as_domain",
        "country_code",
        "country",
        "continent_code",
        "continent",
    },
}
# 8.8.8.8 is not in GreyNoise's Community data, so "no_data" is a normal answer from it.
ACCEPTED_STATUSES = {"greynoise": ("ok", "no_data")}


async def main(ip_text: str, include_greynoise: bool) -> int:
    ip = ip_address(ip_text)
    failures = 0
    async with httpx.AsyncClient(follow_redirects=True) as http:
        sources = build_sources(get_settings(), http)
        runnable = []
        for source in sources:
            if source.name == "greynoise" and not include_greynoise:
                print("skip greynoise (saves its 50-a-week quota; pass --greynoise to include)")
            elif not source.is_configured():
                print(f"skip {source.name} (no key set in .env)")
            else:
                runnable.append(source)
        results = await asyncio.gather(*(s.lookup(ip) for s in runnable))
    for result in results:
        problems = []
        if result.status not in ACCEPTED_STATUSES.get(result.name, ("ok",)):
            problems.append(f"status {result.status}: {result.error}")
        elif result.status == "ok":
            missing = EXPECTED_KEYS[result.name] - set(result.summary or {})
            empty = [k for k, v in (result.summary or {}).items() if v in (None, "", [])]
            if missing:
                problems.append(f"missing summary keys {sorted(missing)}")
            if empty:  # not a failure: some keys are legitimately empty (e.g. no tags)
                print(f"  note: empty values in {result.name}: {sorted(empty)}")
        failures += bool(problems)
        print(f"{'FAIL' if problems else 'ok  '} {result.name} ({result.latency_ms} ms)")
        for problem in problems:
            print(f"  - {problem}")
    return 1 if failures else 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    sys.exit(asyncio.run(main(args[0] if args else "8.8.8.8", "--greynoise" in sys.argv)))
