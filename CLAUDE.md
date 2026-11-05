# Enrichment Portal

The full design, decisions (D1–D18), API contract and milestones live in [design.md](design.md). Read it before starting any work. If a requirement there is ambiguous or conflicts with what you find, ask rather than guess.

## Working rules

1. **One milestone at a time.** Work only on the current milestone from `design.md` section 6, and stop at the end of it for review. Do not start the next milestone. Plan first and wait for approval before writing code.
2. **Never commit secrets.** No API keys, tokens, `.env` files, lookup databases, logs, or unscrubbed recorded responses (see "Values that must never leave this machine" in `design.md` section 4). Check `git status` and the staged diff before every commit.
3. **No real network calls in tests.** Tests use fixtures only: `respx` for HTTP, a fake resolver for DNS, enforced by `pytest-socket` (D13). Tests must never need a real key or consume a provider's quota.

## Architecture rules

- Python only. The backend (`backend/`) and the frontend (`frontend/`) are separate programs, and the frontend gets its data only from the backend's JSON API over HTTP (D2). It never imports backend code.
- API keys live only in the backend's environment or `.env`, never in code and never in the frontend.
- Never upload files or URLs to VirusTotal. Use only its IP lookup endpoint (D19).
- At most two containers (one per part).
- Everything reaches `main` through a pull request.

## Other notes

- Before writing each source client, check the provider's current documentation and update `design.md` section 4 if anything differs.
- Write `docs/verdict-rules.md` before implementing the verdict engine, so the rules can be reviewed separately from the code.
## Commands

Run from `backend/` or `frontend/` (each has its own `pyproject.toml`, `uv.lock` and `.python-version`):

- Install: `uv sync`
- Run backend: `uv run uvicorn app.main:app --reload --port 8000`
- Run frontend: `uv run uvicorn app.main:app --reload --port 8001` (reads `BACKEND_URL`)
- Test: `uv run pytest` (sockets are blocked by `--disable-socket`)
- Lint and format: `uv run ruff check .` and `uv run ruff format --check .`
- Record fixtures by hand (backend only, never in CI): `uv run python scripts/record_fixtures.py`

CI runs lint, format check and tests for both parts.
