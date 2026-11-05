# Enrichment Portal

A web app a SOC analyst uses to enrich one IP address from free threat-intel sources. It is an educational project and is not for commercial or production use.

It is two separate Python programs:

- **`backend/`** is a JSON API (FastAPI). It does all the work and follows the contract in [design.md](design.md) section 3.
- **`frontend/`** is the web page (FastAPI + Jinja2, no JavaScript). It gets all its data by calling the backend's API.

Status: milestone 0. One real source (Shodan InternetDB, no key needed) is wired end to end. See [design.md](design.md) for the plan.

## Requirements

- [uv](https://docs.astral.sh/uv/) (it installs Python 3.12 for you if needed)
- Internet access when running the app (the backend calls Shodan InternetDB). The tests need none.

## Install

Run once in each part:

```bash
cd backend && uv sync
cd frontend && uv sync
```

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

The frontend finds the backend through `BACKEND_URL` (default `http://127.0.0.1:8000`). Settings can be put in environment variables or in a `.env` file at the repo root; copy `.env.example` to start. M0 needs no API keys. `.env` is gitignored and must never be committed.

## Test and lint

Run in each part (`backend` and `frontend`):

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Tests never make real network calls: sockets are blocked and HTTP is mocked from saved fixtures.

## Recording fixtures (maintainers)

`backend/scripts/record_fixtures.py` calls the real source and saves scrubbed responses under `backend/tests/fixtures/`. It is run by hand, never in CI:

```bash
cd backend
uv run python scripts/record_fixtures.py
```
