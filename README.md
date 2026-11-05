# Enrichment Portal

A web app a SOC analyst uses to enrich one IP address from free threat-intel sources. It is an educational project and is not for commercial or production use.

It is two separate Python programs:

- **`backend/`** is a JSON API (FastAPI). It does all the work and follows the contract in [design.md](design.md) section 3.
- **`frontend/`** is the web page (FastAPI + Jinja2, no JavaScript). It gets all its data by calling the backend's API.

Status: milestone 1. Three keyless sources (Shodan InternetDB, RDAP via rdap.org and Team Cymru IP to ASN) are queried together, and the overall verdict follows the rules in [docs/verdict-rules.md](docs/verdict-rules.md). See [design.md](design.md) for the plan.

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

The frontend finds the backend through `BACKEND_URL` (default `http://127.0.0.1:8000`). Settings can be put in environment variables or in a `.env` file at the repo root; copy `.env.example` to start. M0 and M1 need no API keys. `.env` is gitignored and must never be committed.

## Test and lint

Run in each part (`backend` and `frontend`):

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Tests never make real network calls and need no API key. Sockets are blocked, HTTP is mocked with `respx`, and Team Cymru's DNS answers come from a fake resolver, all from saved fixtures. You can run them with the network off.

## Recording fixtures (maintainers)

`backend/scripts/record_fixtures.py` calls the three real sources and saves scrubbed responses under `backend/tests/fixtures/<source>/`. It needs the network, is run by hand, and is never run in CI. Unscrubbed copies go to the gitignored `tests/fixtures/_raw/`:

```bash
cd backend
uv run python scripts/record_fixtures.py
```

To check by hand that the real clients still parse the live sources (it makes one real lookup, needs no key, and is never run in CI):

```bash
cd backend
uv run python scripts/smoke_live.py
```
