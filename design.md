# IOC Enrichment Portal — Design

Status: draft v0.1
Owner: Ben
Implementer: Claude Code

---

## 1. Goal, and what is out of scope

### Goal

A web app a SOC analyst uses to enrich one IP address. The analyst types an IP. The app queries several free threat-intel and registration sources at the same time and shows two things on one page:

1. **An overall verdict**: a single, clearly explained judgment such as *Malicious*, *Suspicious*, *No known bad* or *Unknown*.
2. **Per-source detail**: what each source said, in readable form, with the raw response available on demand.

The app runs locally on my machine first. It must be structured so that it can later be hosted for classmates and instructors to use, without a rewrite.

It is two separate programs, both written entirely in Python: a **backend** (the JSON API that does all the work) and a **frontend** (the web UI). The frontend gets all its data from the backend's API and has no other route to it (D2).

### In scope (across all milestones)

- Single-IP lookup, IPv4 first and IPv6 in a later milestone
- Detecting private and reserved addresses, labelling them, and explaining what that means for the results
- Keyless sources first (Shodan InternetDB, RDAP, Team Cymru), then keyed sources (AbuseIPDB, GreyNoise Community, VirusTotal, ipinfo Lite)
- An overall verdict produced by explicit, reviewable rules
- A backend JSON API, and a separate Python frontend that uses only that API
- Lookup history and export to JSON and CSV (later milestone)
- User login (later milestone)
- Automated tests and a GitHub Actions CI check for every milestone

### Out of scope

- **Caching of source responses.** Every lookup queries the sources live. This is a deliberate decision; see D5.
- **Uploading files or URLs to VirusTotal or any other service.** The app only looks up IP addresses; it never submits anything for analysis (D19).
- Bulk lookups (pasting many IPs at once)
- Other IOC types: domains, URLs, file hashes, email addresses
- Streaming or progressive results; the page receives all sources together
- Automated response actions (blocking, ticket creation, SIEM write-back)
- Ingesting threat feeds or building a local intel database
- Commercial or production use. This is an educational project and will never be used commercially or in a production SOC (D18).

---

## 2. Architecture: the parts and how they talk to each other

```
 Browser (plain HTML forms, no JavaScript)
     │  GET /  and  POST /lookup  (full pages)
     ▼
 FRONTEND  (frontend/, FastAPI + Jinja2)
     │  HTTP + JSON, server to server: GET /api/v1/ip/{ip}
     │  (the frontend's only source of data)
     ▼
 BACKEND  (backend/, FastAPI, JSON API only)
  └─ api routes
      ▼
 LookupService.lookup(ip)
  ├─ 1. ip_classify   → validate, find version, classify private/reserved/global
  ├─ 2. source clients run concurrently (asyncio.gather), each with its own timeout
  │      ├─ ShodanInternetDB   (HTTPS, keyless)
  │      ├─ RDAP via rdap.org  (HTTPS, keyless, follows redirect to the RIR)
  │      ├─ TeamCymru          (DNS TXT queries, keyless)
  │      └─ [M2] AbuseIPDB, GreyNoise, VirusTotal, ipinfo Lite (HTTPS, keyed)
  ├─ 3. normalizer    → each client returns a SourceResult with a common shape
  ├─ 4. verdict engine → applies the rules to the SourceResults → Verdict
  └─ 5. [M3] repository → saves the lookup to SQLite for history and export
```

### Components

Paths below that start with `app/` belong to the backend and sit inside `backend/`, except where a component is labelled as the frontend.

**Frontend (`frontend/app/`).** A separate FastAPI + Jinja2 program, server-rendered, with no JavaScript. The index page has an input form. Submitting it sends `POST /lookup` to the frontend, which calls the backend's `GET /api/v1/ip/{ip}` with `httpx` (in `backend_client.py`) and renders a page with the verdict banner and one card per source. Each source's raw response is collapsible using the HTML `<details>` element. The frontend contains no lookup, verdict or source logic and never imports backend code; it knows the backend only by its URL (`BACKEND_URL`) and by the contract in section 3, which it checks with its own small Pydantic models. The browser never talks to the backend, so no CORS is needed.

If the backend returns 400, the frontend shows the backend's message inline on the page. If the backend is unreachable, times out or returns a 5xx, it shows a clear "backend unavailable" message. Neither case crashes the frontend or shows a stack trace (D16).

**API layer (`app/api/`).** JSON endpoints defined in section 3. Pydantic models define request and response shapes, and those models are the contract.

**LookupService (`app/services/lookup.py`).** Runs one lookup from start to finish. It knows nothing about HTTP requests or HTML.

**IP classifier (`app/core/ip_classify.py`).** Uses Python's `ipaddress` module. Returns the version and a category: `global`, `private`, `loopback`, `link_local`, `shared` (CGNAT, 100.64.0.0/10), `multicast`, `reserved`, `unspecified` or `documentation`. It also returns a human-readable explanation for every non-global category.

**Source clients (`app/sources/`).** One module per source, all implementing the same interface:

```python
class SourceClient(Protocol):
    name: str                  # e.g. "shodan_internetdb"
    display_name: str          # e.g. "Shodan InternetDB"
    requires_key: bool
    def is_configured(self) -> bool: ...
    async def lookup(self, ip: IPv4Address | IPv6Address) -> SourceResult: ...
```

A client never raises to the service. Timeouts, HTTP errors, rate limits and "no data" all become a `SourceResult` with the matching `status`. Adding a source means adding one module and registering it, with no changes elsewhere.

**Outbound rate limiter (`app/sources/ratelimit.py`).** An in-memory limiter per source, so the app never exceeds a published limit such as RDAP's 10 requests in 10 s or VirusTotal's 4 per minute. It throttles outgoing calls only; it does not store responses, so it is not a cache.

**Verdict engine (`app/core/verdict.py`).** A pure function `(classification, list[SourceResult]) -> Verdict`. The rules are stored as data or in one clearly marked module, and they carry a `rules_version`. See D7.

**Config (`app/config.py`).** `pydantic-settings` reads API keys, timeouts and the database URL from environment variables or `.env`. Nothing is hard-coded per machine. The frontend has its own config that reads only `BACKEND_URL`; keys exist only in the backend's environment.

**Repository (`app/db/`, M3).** SQLAlchemy with SQLite locally. The database URL comes from config, so moving to Postgres later is a config change.

### Proposed layout

```
enrichment-portal/            (the repository root)
├─ backend/                   (the JSON API; its own pyproject.toml and uv.lock)
│  ├─ app/
│  │  ├─ main.py
│  │  ├─ config.py
│  │  ├─ api/routes.py
│  │  ├─ core/ip_classify.py
│  │  ├─ core/verdict.py
│  │  ├─ core/models.py        (Pydantic: SourceResult, Verdict, LookupResponse…)
│  │  ├─ services/lookup.py
│  │  ├─ sources/base.py, ratelimit.py, shodan_internetdb.py, rdap.py, cymru.py
│  │  │          (M2) abuseipdb.py, greynoise.py, virustotal.py, ipinfo.py
│  │  └─ db/                   (M3)
│  ├─ tests/
│  │  ├─ fixtures/             (saved example responses per source)
│  │  └─ test_*.py
│  └─ scripts/                 (record_fixtures.py, smoke_live.py)
├─ frontend/                   (the web UI; its own pyproject.toml and uv.lock)
│  ├─ app/
│  │  ├─ main.py
│  │  ├─ config.py             (BACKEND_URL only)
│  │  ├─ backend_client.py     (httpx calls to the backend API)
│  │  ├─ routes.py
│  │  ├─ templates/            (base.html, index.html, _result.html, …)
│  │  └─ static/               (styles.css)
│  └─ tests/                   (backend mocked with respx)
├─ docs/verdict-rules.md       (proposed rules, for my review)
├─ .github/workflows/ci.yml
├─ .env.example
└─ README.md
```

---

## 3. API contract

All JSON endpoints live under `/api/v1`. Times are UTC ISO 8601.

### `GET /api/v1/ip/{ip}`

Runs a live lookup of one IP.

**200 OK.** This is an example of the full M1 response. M0 returns the same shape with only the `shodan_internetdb` entry in `sources`, and with the placeholder verdict described under "Field rules". The IP is a real public address, but every value below is illustrative, and real responses will differ. It shows all three M1 sources, with two `ok` and one `timeout`.

```json
{
  "lookup_id": null,
  "ip": "8.8.8.8",
  "ip_version": 4,
  "queried_at": "2026-11-05T14:02:11Z",
  "classification": {
    "category": "global",
    "is_global": true,
    "explanation": null
  },
  "verdict": {
    "level": "no_known_bad",
    "summary": "No red flags found. Only context sources were checked, not reputation sources, so this is weak evidence.",
    "reasons": [],
    "rules_version": "0.1"
  },
  "sources": [
    {
      "name": "shodan_internetdb",
      "display_name": "Shodan InternetDB",
      "status": "ok",
      "latency_ms": 184,
      "summary": {
        "open_ports": [53, 443],
        "tags": [],
        "vulns": [],
        "hostnames": ["dns.google"],
        "cpes": []
      },
      "raw": { "...": "unmodified source response" },
      "error": null
    },
    {
      "name": "rdap",
      "display_name": "RDAP",
      "status": "ok",
      "latency_ms": 612,
      "summary": {
        "network_name": "EXAMPLE-NET",
        "network_range": "8.8.8.0 - 8.8.8.255",
        "org_name": "Google LLC",
        "country": "US",
        "registry": "arin",
        "registration_date": "2014-03-14",
        "last_changed": "2023-12-28",
        "abuse_email": "abuse@example.com"
      },
      "raw": { "...": "unmodified source response" },
      "error": null
    },
    {
      "name": "team_cymru",
      "display_name": "Team Cymru IP to ASN",
      "status": "timeout",
      "latency_ms": 8000,
      "summary": null,
      "raw": null,
      "error": "No DNS answer within 8 s"
    }
  ]
}
```

**Field rules**

- In M0 there is no verdict engine. For a global IP the verdict is the fixed placeholder `unknown` with `rules_version` `"0.0"`, empty `reasons`, and the summary "Verdict rules are added in M1." Private and reserved IPs are `not_applicable` as below.
- `lookup_id` is `null` until M3. From M3 on it is the history record ID.
- `verdict.level` is one of `malicious`, `suspicious`, `no_known_bad`, `unknown` or `not_applicable`. `not_applicable` is used for private and reserved IPs that were not sent to external sources. The app never returns "clean"; see D8.
- `verdict.reasons` lists every signal that contributed to the verdict, each as `{"source", "signal", "weight"}`. `weight` is `high`, `medium` or `low`. What each weight means, and which combinations produce which level, is defined in `docs/verdict-rules.md`. An empty list means no signal fired.
- If no source ends in `ok` or `no_data` (every source timed out, errored, was rate-limited or is not configured), `verdict.level` is `unknown` and `verdict.summary` says that no source could answer.
- `sources[].status` is one of:
  - `ok` — data returned
  - `no_data` — the source answered but knows nothing about this IP
  - `timeout`
  - `rate_limited` — HTTP 429 or quota exhausted
  - `error` — any other failure; `error` holds a short message
  - `not_configured` — a keyed source with no key set
  - `skipped` — not queried, for example because the IP is private; `error` holds the reason
- `sources[].summary` is the normalized, source-specific readable data. It is `null` unless `status` is `ok`. The keys for the M1 sources are listed below, and M2 adds the keyed sources to that table.
- `sources[].raw` is the unmodified source response, shown collapsed in the UI. It is `null` when there was no response.
- Every registered source always appears in `sources`, whatever its status, so the UI can show all cards.
- `latency_ms` is `null` for `skipped` and `not_configured` sources, since no call was made.

**Summary keys for M1 sources.** Any key may be `null` or empty when the source doesn't provide it.

| Source (`name`) | Keys |
|---|---|
| `shodan_internetdb` | `open_ports` (list of int), `tags` (list of str), `vulns` (list of CVE IDs), `hostnames` (list of str), `cpes` (list of str) |
| `rdap` | `network_name`, `network_range`, `org_name`, `country`, `registry` (`arin`, `ripe`, `apnic`, `lacnic` or `afrinic`), `registration_date`, `last_changed`, `abuse_email` |
| `team_cymru` | `asn` (int), `as_name`, `bgp_prefix`, `country_code`, `registry`, `allocated_date` |

**Private or reserved IP example (200 OK).** The classification includes an explanation, every source is `skipped`, and the verdict level is `not_applicable`:

```json
{
  "lookup_id": null,
  "ip": "10.0.0.5",
  "ip_version": 4,
  "queried_at": "2026-11-05T14:05:40Z",
  "classification": {
    "category": "private",
    "is_global": false,
    "explanation": "10.0.0.5 is a private address (RFC 1918). It is not routable on the public internet, so public threat-intel sources have no data on it. If it appeared in an alert, the activity originated inside your network or behind NAT/VPN; investigate with internal tools such as DHCP logs, asset inventory and EDR."
  },
  "verdict": {
    "level": "not_applicable",
    "summary": "Private address. External sources were not queried.",
    "reasons": [],
    "rules_version": "0.1"
  },
  "sources": [
    { "name": "shodan_internetdb", "display_name": "Shodan InternetDB", "status": "skipped",
      "latency_ms": null, "summary": null, "raw": null, "error": "Not queried: private address" },
    { "name": "rdap", "display_name": "RDAP", "status": "skipped",
      "latency_ms": null, "summary": null, "raw": null, "error": "Not queried: private address" },
    { "name": "team_cymru", "display_name": "Team Cymru IP to ASN", "status": "skipped",
      "latency_ms": null, "summary": null, "raw": null, "error": "Not queried: private address" }
  ]
}
```

**Errors**

| Status | When | Body |
|---|---|---|
| 400 | Not a valid IP address | `{"error": "invalid_ip", "message": "…"}` |
| 400 | IPv6 before M4 | `{"error": "unsupported_ip_version", "message": "IPv6 support is planned for a later version."}` |
| 400 | Any other malformed request, e.g. a non-numeric `limit` (M3) | `{"error": "invalid_request", "message": "…"}` |
| 404 | Unknown route, or (M3) a lookup ID that doesn't exist | `{"error": "not_found", "message": "…"}` |
| 500 | Unexpected server error | `{"error": "internal_error", "message": "…"}` |

Every error from `/api/v1` uses this `{"error", "message"}` shape. FastAPI's built-in handlers return `{"detail": …}` instead, for 404s, 405s, 422 validation errors and unhandled exceptions, so the app registers custom exception handlers that convert all of them to this shape. FastAPI's 422 becomes 400 `invalid_request`. Tests assert the shape for every row above.

Sources failing is **not** an API error. The response is still 200, with per-source statuses.

### `GET /healthz`

Returns `{"status": "ok"}`. It does not call external sources.

### Frontend routes (HTML, served by the frontend, not part of the JSON contract)

- `GET /` — the lookup page
- `POST /lookup` — form field `ip`; the frontend calls the backend API and renders the results, or an inline message for invalid or unsupported input, or a "backend unavailable" message (D16)
- `GET /healthz` — the frontend's own `{"status": "ok"}`; it does not call the backend
- (M3) `GET /history`, `GET /history/{id}` — built from the backend's `/api/v1/lookups` endpoints

### Added in M3: history and export

- `GET /api/v1/lookups?limit=50&offset=0` — list past lookups (id, ip, queried_at, verdict level)
- `GET /api/v1/lookups/{id}` — the stored `LookupResponse`
- `GET /api/v1/lookups/{id}/export?format=json|csv` — download one lookup. The CSV has one row per source: ip, queried_at, source, status, key summary fields, verdict level.

### Added in M5: auth

All frontend routes except `/healthz` and the login pages require an authenticated session, and the backend API must not be reachable by anyone but the frontend. The details are decided at M5.

---

## 4. Data sources: keys, limits and terms

Endpoints, limits and terms below are as understood when this was written. Claims marked *(checked 11/5/26)* were confirmed against the provider's own page on that date. **Claude Code must check each one against the provider's current documentation before implementing that client**, and update this table if anything differs.

### Keyless (Shodan InternetDB in Milestone 0, the others in Milestone 1)

| Source | How it is queried | Key | Limit | What it contributes | Terms to check |
|---|---|---|---|---|---|
| Shodan InternetDB | `GET https://internetdb.shodan.io/{ip}`; 404 means no data | None | None published; the app self-limits politely | Open ports, CPEs, hostnames, tags (e.g. `tor`, `vpn`, `c2`, `compromised`), known CVEs | Free for non-commercial use |
| RDAP via rdap.org | `GET https://rdap.org/ip/{ip}`; follow the redirect to the right RIR | None | 10 requests in 10 s *(checked 11/5/26)* | Network name, owning organization, allocation range, registration dates, abuse contact | rdap.org is a bootstrap redirector; data comes from the RIRs |
| Team Cymru IP to ASN | DNS TXT query to `<reversed-ip>.origin.asn.cymru.com`, then `AS<n>.asn.cymru.com` for the AS name | None | None published | ASN, BGP prefix, country, registry, AS name | Fine for low volume; Cymru asks heavy users to use bulk whois instead |

### Keyed (Milestone 2)

| Source | How it is queried | Key | Limit | What it contributes | Terms to check |
|---|---|---|---|---|---|
| AbuseIPDB | `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`, header `Key` | Free account key | 1,000 checks a day | Abuse confidence score (0–100), report count, last reported, usage type, ISP, Tor flag | Review the API terms on sign-up |
| GreyNoise Community | `GET https://api.greynoise.io/v3/community/{ip}`, header `key` *(checked 11/5/26)* | Free account key; a business-email account is needed for a key (Gmail, Hotmail, ProtonMail, iCloud and similar get none) *(checked 11/5/26)* | **50 a week**, shared with the GreyNoise Visualizer *(checked 11/5/26)* | Whether the IP is internet background noise or a known benign service; classification (benign/malicious/unknown); owning organization name *(checked 11/5/26)* | Community tier is for non-commercial use |
| VirusTotal | `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}`, header `x-apikey` | Free account key | 4 a minute, 500 a day | Vendor detection counts (malicious, suspicious, harmless, undetected), reputation, ASN, country | Public API is not allowed in commercial products or workflows. This app only uses the IP lookup endpoint and never the file or URL upload endpoints (D19) |
| ipinfo Lite | `GET https://api.ipinfo.io/lite/{ip}?token=…` | Free token | Unlimited *(checked 11/5/26)* | ASN, AS name and domain, country, continent | **Attribution required** (CC BY-SA 4.0); one credit link to ipinfo in the app satisfies it *(checked 11/5/26)* |

### Key handling

- Keys are read only from environment variables (`ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `VIRUSTOTAL_API_KEY`, `IPINFO_TOKEN`) or a local `.env`.
- `.env` is in `.gitignore`. `.env.example` lists every variable with no values.
- Keys are never logged, never returned in API responses, never sent to the browser and never put in URLs that get logged. ipinfo puts its token in the query string, so the HTTP client's logging must redact it.
- Keys exist only in the backend's environment. The frontend is configured with `BACKEND_URL` alone and never holds, receives or forwards a key.
- A missing key makes that source `not_configured`. The app still starts and the other sources still work.

### Values that must never leave this machine

API keys aren't the only sensitive values. None of the following may be committed or pushed:

| Value | Where it lives | Protection |
|---|---|---|
| API keys and tokens | `.env` | Gitignored. Never in logs, API responses, HTML or test fixtures |
| Lookup history (M3) | `data/*.db` | Gitignored. It is a record of what was investigated |
| Exports (M3) | Relayed by the frontend from the backend to the browser as a download | Never written inside the repository |
| Unscrubbed recorded responses | `tests/fixtures/_raw/` | Gitignored. Only scrubbed copies are committed (D13) |
| Application logs | `logs/` | Gitignored. Key redaction applies |

`.gitignore` must cover `.env`, `data/`, `logs/`, `tests/fixtures/_raw/` and `*.db`.

**CI has no secrets and needs none.** No repository secrets are configured on GitHub, because every test runs on fixtures.

**The lookups themselves are disclosed.** Every public IP an analyst looks up is sent to each enabled provider, which may log it. Looking an IP up tells those providers you are interested in it. This is inherent to an enrichment tool and is accepted. Private and reserved addresses are never sent (D9).

### Quota behaviour (important because there is no cache)

GreyNoise's 50 a week will run out after a few days of normal use (lookups I do by hand in the GreyNoise Visualizer count against the same 50), and VirusTotal will hit 4 a minute if the analyst looks up IPs quickly. Required behaviour:

- The outbound rate limiter queues or rejects calls that would exceed a per-minute or per-10-second limit. A call that would wait longer than the source timeout returns `rate_limited` instead of hanging.
- An HTTP 429 from a provider becomes `rate_limited`, with the provider's message in `error`.
- The UI shows a rate-limited source as a distinct grey card ("Quota reached — try later"), not as an error and not as "no data".
- The verdict engine treats `rate_limited` and `not_configured` the same as missing evidence. They never make a verdict look cleaner.

**Accepted trade-off: GreyNoise will often be unavailable.** With no cache (D5), the 50 weekly lookups will usually be used up within a few days, so for much of each week the GreyNoise card shows "Quota reached." This is accepted. The behaviour above makes sure an exhausted quota never breaks a lookup or skews the verdict, but it does not solve the shortage.

---

## 5. Decisions, each with its reason

**D1 — Python 3.12, FastAPI and Jinja2, as two separate programs.**
The project is Python only, with no JavaScript written or loaded. A FastAPI backend serves the typed JSON API, and a separate FastAPI + Jinja2 frontend renders the HTML. Splitting them keeps the API a real boundary, so a future client or a different frontend needs no backend change, and team deployment is straightforward. Streamlit and NiceGUI were rejected because they hide the HTML layer behind their own framework, and a plain Jinja2 page needs nothing from them. Django was rejected as heavier than needed for a single-user local tool.

**D2 — The frontend gets all its data from the backend's JSON API over HTTP, and nothing else.**
This keeps the two parts genuinely separate: the frontend never imports backend code, never reads its database and never holds a key. The backend can be tested, hosted and replaced independently. The cost is one extra HTTP hop and a second process to run, which is accepted. The frontend turns every backend outcome (success, 400, backend down) into something readable, so neither a bad IP nor a dead backend crashes it.

**D3 — Sources are queried concurrently with `httpx.AsyncClient` and `asyncio.gather`, each with its own timeout (default 8 s, configurable).**
The page receives all sources together, so total latency is the slowest source. Per-source timeouts put a hard ceiling on that wait.

**D4 — All sources return together in one response, not streamed.**
This was my choice. It keeps the API and the UI simple. A slow source costs at most its timeout, and it shows as `timeout` rather than blocking forever.

**D5 — No caching. Every lookup is live.**
This was my choice. It guarantees fresh data and avoids stale-intel bugs. The cost is accepted: GreyNoise will be unavailable for much of each week, and VirusTotal may be rate-limited during quick bursts of lookups. The quota behaviour in section 4 keeps this from breaking lookups, but does not remove it. M3 history stores past lookups for the analyst to look back at, but stored results are never reused to answer a new lookup.

**D6 — One keyless source first (M0), the other keyless sources next (M1), all keyed sources together later (M2).**
M0 and M1 can be built and tested with no accounts or secrets, and M0 proves out the whole architecture with a single real source. Note that the keyless sources give context (exposure, ownership, ASN) rather than reputation, so the M1 verdict is provisional and leans heavily on Shodan tags. In M1 a public IP with no red flags gets `no_known_bad`, and the verdict summary must say that only context sources were checked, so the analyst can see how little evidence it rests on.

**D7 — Claude Code proposes the verdict rules and I review them before they are final.**
Verdict logic is a judgment call that should be visible and owned by the analyst, not buried in code. Claude Code writes the proposed rules in `docs/verdict-rules.md`: each rule's condition, resulting level and rationale. I approve them, and only then is the milestone done. The rules are versioned (`rules_version`), and every verdict lists the signals that produced it.

**D8 — Verdict levels avoid the word "clean".**
"No known bad" states honestly that the sources found nothing, which is not the same as proving the IP is safe. `unknown` is used when too few sources answered to say anything.

**D9 — Private and reserved IPs are labelled, explained and not sent to external sources.**
Public intel sources have no data on these addresses. Sending them would add noise and could leak internal addressing to third parties. The UI shows a clear label and the explanation text from section 3. If I later want them queried anyway, this becomes a config flag.

**D10 — IPv4 only until M4.**
This keeps M1–M3 focused. The classifier and models use `ipaddress` types from the start, so enabling IPv6 mostly means removing a guard and checking each source's IPv6 support.

**D11 — Configuration comes from environment variables via `pydantic-settings`. A Dockerfile for each part is added by M5, so there are at most two containers.**
This is what makes "local now, wider deployment later" a configuration change rather than a refactor.

**D12 — SQLite through SQLAlchemy for history (M3).**
It has zero setup locally, and the same code runs on Postgres when the app is deployed for a team.

**D13 — Tests never call real APIs. HTTP is mocked with `respx` and DNS with a fake resolver, using saved fixture responses.**
CI must be fast and deterministic, and must not use up quotas or need secrets.

- **Recording.** Fixtures are recorded from real responses by `scripts/record_fixtures.py`, which is run by hand with real keys and never in CI. It calls each source for a small set of chosen IPs (one per status where possible: data, no data, and private) and writes the raw responses to `tests/fixtures/_raw/`, which is gitignored.
- **Scrubbing.** The same script then writes scrubbed copies to `tests/fixtures/<source>/<case>.json`. Only response bodies are kept, request URLs and headers are dropped (ipinfo's token is in the URL), and any value matching a configured key is replaced with `REDACTED`. A test fails if any committed fixture contains a string that looks like a key from `.env.example`'s variable names.
- **Refreshing.** Fixtures are re-recorded when a provider changes its format. That is noticed by the manual `scripts/smoke_live.py`, which calls real sources and checks that the clients still parse the responses. Refreshing is a deliberate, reviewed commit.
- **Enforcement.** "No real network calls" is guaranteed, not just a rule. `pytest-socket` blocks all sockets during tests, `respx` is configured with `assert_all_mocked=True` so any unmocked HTTP request fails, and the Cymru client takes its DNS resolver as a parameter so tests inject a fake one. Frontend tests mock the backend API with `respx` in the same way and never start a real backend.
- **Time.** The rate limiter takes its clock as a parameter, so tests advance time instantly instead of sleeping.

**D14 — Tooling: `uv` for dependencies, `ruff` for lint and format, `pytest` with `pytest-asyncio`, and GitHub Actions CI on every push and pull request.**
`uv` produces a lockfile, so CI installs exactly the same dependency versions as the local machine, and it installs in seconds. `ruff` is one tool that replaces a linter, a formatter and an import sorter, and it runs fast enough to use on every save. `pytest-asyncio` is needed because every source client is async. GitHub Actions is built into GitHub, where the repository lives, so CI needs no extra service. CI running lint and tests is part of every milestone's definition of done.

**D15 — No JavaScript.**
The frontend is server-rendered HTML and CSS only, and the raw responses collapse using the HTML `<details>` element. There is no HTMX and there are no CDN scripts. The app then works offline and loads no third-party code, which matters for a security tool, and the project stays Python only.

**D16 — A bad IP is a message, not a crash, at both layers.**
The backend returns 400 with the `{"error", "message"}` shape. The frontend turns that into an inline message on the lookup page, and shows a "backend unavailable" message if the backend can't be reached or returns a 5xx. It never shows a stack trace or a raw error body.

**D17 — Supporting libraries: Python 3.12+, httpx, Pydantic and dnspython.**
- *Python 3.12+*: modern asyncio (`TaskGroup` and `asyncio.timeout`, which the concurrent lookups and per-source timeouts rely on) and modern typing, and every library here supports it.
- *httpx*: an async HTTP client, needed by the backend to query sources concurrently and by the frontend to call the backend, and the client that `respx` mocks for tests.
- *Pydantic*: FastAPI's native model layer. One class definition gives validation, the JSON shape and the auto-generated API docs, so the contract in section 3 is enforced by the code itself.
- *dnspython*: Team Cymru is queried through DNS TXT records, which Python's standard library cannot look up. dnspython has an async resolver that fits the concurrent design.

**D18 — This is an educational project and will not be used commercially.**
The app is built to the standard of a SOC tool, but only for learning. Several free tiers it depends on (Shodan InternetDB, GreyNoise Community and the VirusTotal public API) are restricted to non-commercial use. Using them is acceptable because this project stays non-commercial.

**D19 — The app never uploads anything to VirusTotal or any other provider.**
Only the read-only IP lookup endpoint is used. VirusTotal's file and URL submission endpoints are never called, because anything submitted becomes visible to other VirusTotal users.

---

## 6. Milestones, each with a definition of done

These definitions apply to **every** milestone, in addition to the milestone's own list:

- CI (GitHub Actions: `ruff check`, `ruff format --check`, `pytest`, run for both the backend and the frontend) is green on `main`.
- New code has tests. No test makes a real network call.
- The README's install and run instructions for both the backend and the frontend still work from a fresh clone.
- The work reaches `main` through a pull request.
- This document is updated if a decision changed during the milestone.

### M0 — Skeleton, CI and one real source

The thinnest end-to-end slice that is skeletal but functional: one real source, queried through the backend API that follows the section 3 contract, and shown by the separate frontend. The source is Shodan InternetDB because it is keyless, needs no account and has the simplest response.

**Layout, tooling and CI**

- The repo has the layout from section 2: `backend/` and `frontend/`, each with its own `pyproject.toml` and `uv.lock` managed with `uv`. The root has `.env.example` and a `.gitignore` covering every path in "Values that must never leave this machine" (section 4).
- pytest in both projects is configured so that any real network connection fails the test run (D13).
- `.github/workflows/ci.yml` runs lint, format check and tests for both projects, and passes.
- The README covers install, run and test for both parts.

**Backend**

- `/healthz` and `GET /api/v1/ip/{ip}` for IPv4, following section 3.
- The IP classifier (`ip_classify.py`) with every category and an explanation for each non-global one. Private and reserved addresses get `not_applicable`, the source is `skipped`, and no external call is made (D9).
- The `SourceClient` interface and a source registry, with one registered source: the Shodan InternetDB client. Before writing it, I check InternetDB's current documentation and update section 4 if anything differs. It handles `ok`, `no_data` (404), `timeout`, `rate_limited` (429) and `error`, and never raises to the service.
- `LookupService` runs the registered sources concurrently, each with its own timeout (D3).
- **There is no verdict engine yet.** For a global IP the verdict is a fixed placeholder: level `unknown`, `rules_version` `"0.0"`, and the summary "Verdict rules are added in M1." The `unknown` level is used because nothing yet judges the evidence, and the placeholder never claims an IP is safe (D8). If InternetDB returned nothing usable, the summary says no source could answer.
- Error responses for every row of the section 3 errors table that applies in M0: `invalid_ip`, `unsupported_ip_version` (IPv6), `invalid_request`, `not_found` and `internal_error`, all as `{"error", "message"}` through custom exception handlers. An invalid IP gets a 400, never a crash.

**Frontend**

- `GET /` shows the lookup form, and `POST /lookup` calls the backend API and renders the verdict banner and the Shodan InternetDB card, with the raw response in a collapsible `<details>` element.
- A private or reserved IP shows its label and explanation. An invalid or IPv6 input shows the backend's message inline (D16). A stopped backend shows "backend unavailable".
- The frontend's own `/healthz`.

**Fixtures**

- `backend/scripts/record_fixtures.py` is run by hand and never in CI. It records InternetDB responses for a known IP with data and an IP with no data, writes them to the gitignored `tests/fixtures/_raw/`, and writes scrubbed copies to `tests/fixtures/shodan_internetdb/` (D13). InternetDB is keyless, so no keys are involved.

**Tests** (none makes a real network call)

- The classifier, including every category.
- The InternetDB client against fixtures for `ok`, `no_data`, `timeout`, `rate_limited` and `error`.
- The API endpoint for a global, a private and an invalid IP, and the error shape for every row listed above.
- The frontend, with the backend mocked by `respx`: it renders the verdict and the source card from a contract response, shows the inline message for a 400, and shows "backend unavailable" when the backend can't be reached or returns a 5xx.

**Done when:** a fresh clone, then `uv sync` in each part, then running both lets me look up a known public IP in the browser and see the real InternetDB card, look up a private IP and see its label and explanation, enter garbage and see an inline message, and stop the backend and see "backend unavailable". Tests pass and CI is green.

### M1 — The remaining keyless sources and the verdict rules

- RDAP (via rdap.org) and Team Cymru clients are implemented, each handling `ok`, `no_data`, `timeout` and `error`. Before writing each, I check its current documentation and update section 4 if anything differs.
- The outbound rate limiter keeps RDAP within 10 requests per 10 s.
- `docs/verdict-rules.md` contains the proposed provisional rules, and **I have reviewed and approved them** before the verdict engine is written (D7). The verdict engine then replaces the M0 placeholder, and `rules_version` becomes `"0.1"`.
- The frontend shows one card per source with readable summary fields for all three sources.
- Fixtures for RDAP and Team Cymru are recorded and scrubbed with `scripts/record_fixtures.py` (D13), and no committed fixture contains a key. `scripts/smoke_live.py` is added.
- Tests cover: each new client against fixtures for each status; the verdict engine for each rule, including the all-sources-failed case; the API endpoint's verdict for a global and a private IP; the rate limiter, using an injected clock; and the frontend rendering three cards and the verdict.

**Done when:** looking up a known public IP, a private IP and garbage input in the browser each behaves as described with all three sources, all tests and CI pass, and the rules are approved.

### M2 — Keyed sources

- The AbuseIPDB, GreyNoise Community, VirusTotal and ipinfo Lite clients are implemented, with keys from the environment.
- Each keyed source shows `not_configured` when its key is missing, and the app still works.
- Quota behaviour from section 4 is in place: rate limiter settings for VirusTotal, and 429 handling for all sources. Rate-limited cards are visually distinct.
- ipinfo attribution is shown in the UI.
- Keys are proven absent from logs, API responses and HTML. There is a test that asserts this.
- Verdict rules are updated to use the reputation sources, `rules_version` is bumped, and **I have reviewed and approved them**.
- Tests use fixtures for every status of every new source, including `rate_limited` and `not_configured`.

**Done when:** with all keys set, a lookup shows seven source cards and a verdict that cites the reputation sources; with no keys set, the app behaves exactly as M1 plus four `not_configured` cards; and CI is green.

### M3 — Lookup history and export

- Every lookup of a global IP is saved to SQLite with its full response and `rules_version`.
- The frontend's `/history` lists past lookups (newest first, with ip, time and verdict level), and each opens the stored result, using only the backend's lookups endpoints.
- The history and export endpoints from section 3 are implemented. Export works as JSON and CSV.
- The database URL is configurable. Tests use a temporary database.

**Done when:** after several lookups, history shows them, both export formats download correctly and open in a viewer or spreadsheet, and CI is green.

### M4 — IPv6

- IPv6 input is accepted. The classifier covers IPv6 private and reserved ranges (ULA, link-local, loopback, documentation and so on) with explanations.
- Each source's IPv6 support is checked. Sources that don't support IPv6 return `skipped` with a reason. Team Cymru uses its IPv6 query zone if it is supported.
- Tests cover IPv6 classification and each source's IPv6 behaviour.

**Done when:** a public IPv6 lookup, a ULA lookup and an IPv4 lookup all work in the UI, and CI is green.

### M5 — Login and deployment readiness

Goal: a hosted copy that classmates and instructors can log in to and use. Hosting changes three things, and this milestone must handle them:

- **Shared quotas.** Every user's lookups spend the same API keys, so the daily and weekly limits are shared across all users. GreyNoise in particular will run out even faster.
- **Keys on a server.** Keys move from a local `.env` to the host's secret settings, still never in the repository.
- **Terms.** Check that each provider's free terms allow one personal key to serve other users. If one doesn't, that source is disabled on the hosted copy.

- Login protects every frontend route except `/healthz` and the login pages, and the backend API is reachable only by the frontend. The method (local accounts or SSO, and how the backend trusts the frontend) is decided at the start of this milestone and recorded as a new decision.
- A Dockerfile is added for each part, giving at most two containers, and each runs with config purely from environment variables.
- The app is verified working against Postgres via the database URL.

**Done when:** an unauthenticated request is redirected to login, the container runs from env config alone, and CI is green.

---

## Notes for Claude Code

- Work one milestone at a time, and stop at the end of each for my review.
- Python only. The frontend gets its data only from the backend's API (D2).
- Never upload files or URLs to VirusTotal (D19).
- Everything reaches `main` through a pull request.
- Before writing each source client, check its current documentation and update section 4 if the endpoint, limits or terms differ.
- Write the verdict rules proposal **before** implementing the verdict engine, so I can review the logic separately from the code.
- If a requirement here is ambiguous or conflicts with what you find, ask rather than guess.
