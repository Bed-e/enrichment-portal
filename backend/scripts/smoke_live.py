"""Check that the real clients still parse the real sources (design.md D13, "Refreshing").

Run by hand from backend/, never in CI:   uv run python scripts/smoke_live.py [IP]

It makes one live lookup (default 8.8.8.8) through the same clients the app uses, and checks
that every source answered `ok` with the summary keys from design.md section 3. A failure here
usually means a provider changed its format: re-run scripts/record_fixtures.py and review the
fixture diff. It writes nothing to disk and needs no keys.
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
}


async def main(ip_text: str) -> int:
    ip = ip_address(ip_text)
    failures = 0
    async with httpx.AsyncClient(follow_redirects=True) as http:
        sources = build_sources(get_settings(), http)
        results = await asyncio.gather(*(s.lookup(ip) for s in sources))
    for result in results:
        problems = []
        if result.status != "ok":
            problems.append(f"status {result.status}: {result.error}")
        else:
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
    sys.exit(asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8")))
