# Enrichment Portal

A web app a SOC analyst uses to enrich one IP address from free threat-intel sources. It is an educational project and is not for commercial or production use.

It is two separate Python programs:

- **`backend/`** is a JSON API (FastAPI). It does all the work and follows the contract in [design.md](design.md) section 3.
- **`frontend/`** is the web page (FastAPI + Jinja2, no JavaScript). It gets all its data by calling the backend's API.

Status: milestone 2. Seven sources are queried together: three that need no key (Shodan InternetDB, RDAP via rdap.org, Team Cymru IP to ASN) and four that use a free key (AbuseIPDB, GreyNoise Community, VirusTotal, ipinfo Lite). The overall verdict follows the rules in [docs/verdict-rules.md](docs/verdict-rules.md). See [design.md](design.md) for the plan.

## Requirements

- [uv](https://docs.astral.sh/uv/) (it installs Python 3.12 for you if needed)
- Internet access when running the app (the backend calls Shodan InternetDB and RDAP over HTTPS and Team Cymru over DNS). The tests need none.

## Install

Run once in each part, from the repo root. The commands are on separate lines so they work in PowerShell, Command Prompt, bash and zsh alike:

```bash
cd backend
uv sync
cd ../frontend
uv sync
cd ..
```

`uv sync` creates and manages a `.venv` inside each folder. You do not need to create or activate a virtual environment yourself, because `uv run` uses it automatically. If another environment is active in your terminal, run `deactivate` first.

## Run

Start the backend first, in one terminal:

```bash
cd backend
uv run uvicorn app.main:app --reload --port 8000
```

Then the frontend, in a second terminal:

```bash
cd frontend
uv run uvicorn app.main:app --reload --port 8001
```

- Open <http://127.0.0.1:8001> and enter an IPv4 address such as `8.8.8.8`.
- Call the API directly: `curl http://127.0.0.1:8000/api/v1/ip/8.8.8.8`
- Health checks: `/healthz` on each port.

The frontend finds the backend through `BACKEND_URL` (default `http://127.0.0.1:8000`). Settings can be put in environment variables or in a `.env` file at the repo root; copy `.env.example` to start. The app works with no keys at all (see below). `.env` is gitignored and must never be committed.

## API keys (optional)

Three sources need nothing. The other four each use a free key, and the app runs without them: a source with no key shows a "Not configured" card, the other sources still answer, and the verdict says which sources did not.

| Variable | Source | Where to get a free key | Free limit |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | AbuseIPDB | account at abuseipdb.com | 1,000 checks a day |
| `GREYNOISE_API_KEY` | GreyNoise Community | account at greynoise.io; needs a business email (Gmail, Hotmail and similar get no key) | 50 lookups a week, shared with the GreyNoise Visualizer |
| `VIRUSTOTAL_API_KEY` | VirusTotal | account at virustotal.com | 4 a minute, 500 a day; non-commercial use only |
| `IPINFO_TOKEN` | ipinfo Lite | account at ipinfo.io | unlimited; the app shows ipinfo's credit link |

To add keys:

1. Copy the template to `.env` in the repo root, next to `.env.example`. For example `cp .env.example .env`, or `Copy-Item .env.example .env` in PowerShell.
2. Open `.env` in your editor and paste each key after the `=`, with no quotes and no spaces. Leave out any you do not have.
3. Check that git ignores it: `git check-ignore .env` should print `.env`.
4. Restart the backend. Only the backend reads the keys; the frontend never sees them.

Never paste a key into chat, an issue, a commit or a log. If one leaks, revoke it at the provider and make a new one. The tests need no keys and ignore your `.env` completely.

When a quota runs out (GreyNoise's will, within a few days of normal use), its card turns grey with "Quota reached" and the lookup still works.

## Test and lint

Run in each part (`backend` and `frontend`):

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Tests never make real network calls and need no API key. Sockets are blocked, HTTP is mocked with `respx`, and Team Cymru's DNS answers come from a fake resolver, all from saved fixtures. You can run them with the network off.

## Recording fixtures (maintainers)

`backend/scripts/record_fixtures.py` calls the real sources and saves scrubbed responses under `backend/tests/fixtures/<source>/`. It needs the network and your keys from `.env`, is run by hand, and is never run in CI. It never prints a key, and it replaces any key value with `REDACTED`. Unscrubbed copies go to the gitignored `tests/fixtures/_raw/`. GreyNoise is left out of the default run because each lookup spends one of its 50 a week; name it to record it, for example `uv run python scripts/record_fixtures.py greynoise`:

```bash
cd backend
uv run python scripts/record_fixtures.py
```

To check by hand that the real clients still parse the live sources (it makes one real lookup, skips any source with no key, skips GreyNoise unless you add `--greynoise`, and is never run in CI):

```bash
cd backend
uv run python scripts/smoke_live.py
```
