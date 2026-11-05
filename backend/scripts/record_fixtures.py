"""Record real source responses as test fixtures (design.md D13).

Run by hand from backend/, never in CI:   uv run python scripts/record_fixtures.py

Raw responses go to tests/fixtures/_raw/ (gitignored). Scrubbed copies, body only, with any
configured key value replaced by REDACTED, go to tests/fixtures/<source>/<case>.json.
InternetDB is keyless, so no keys are involved yet.
"""

import json
import os
from pathlib import Path

import httpx

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
ENV_EXAMPLE = Path(__file__).resolve().parents[2] / ".env.example"

# (source, case, URL). One IP with data and one with no data (InternetDB answers 404).
CASES = [
    ("shodan_internetdb", "ok_8_8_8_8", "https://internetdb.shodan.io/8.8.8.8"),
    ("shodan_internetdb", "no_data", "https://internetdb.shodan.io/192.0.2.1"),
]


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


def main() -> None:
    raw_dir = FIXTURES / "_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    with httpx.Client(
        timeout=15, headers={"User-Agent": "enrichment-portal (educational project)"}
    ) as http:
        for source, case, url in CASES:
            response = http.get(url)
            record = {"status_code": response.status_code, "body": response.json()}
            (raw_dir / f"{source}__{case}.json").write_text(json.dumps(record, indent=2))
            out_dir = FIXTURES / source
            out_dir.mkdir(parents=True, exist_ok=True)
            # Only status and body are kept: no request URL, no headers.
            (out_dir / f"{case}.json").write_text(scrub(json.dumps(record, indent=2)) + "\n")
            print(f"{source}/{case}: HTTP {response.status_code}")


if __name__ == "__main__":
    main()
