# SentinelAI V2 — Developer Runbook

Complete, repository-verified guide for standing up SentinelAI V2 on a clean machine, exercising
every capability, running the tests, understanding timestamps, and cleaning up without residue.

Every command, route, page, setting, and expected result in this document was executed or read from
the current source tree. Nothing here is aspirational.

- **Primary reference:** this file.
- **Deeper demo internals:** [`demo_runbook.md`](./demo_runbook.md) narrates what each demo stage does.
- **API reference (runtime):** <http://localhost:8000/docs> when `DEBUG=true`.

---

## Table of contents

1. [Architecture at a glance](#1-architecture-at-a-glance)
2. [Prerequisites](#2-prerequisites)
3. [Clean-machine setup](#3-clean-machine-setup)
4. [Environment variables](#4-environment-variables)
5. [Authentication and roles](#5-authentication-and-roles)
6. [Health verification](#6-health-verification)
7. [Running the 20-stage demo](#7-running-the-20-stage-demo)
8. [Gemini / external-provider behaviour](#8-gemini--external-provider-behaviour)
9. [Capability verification matrix](#9-capability-verification-matrix)
10. [Running the tests](#10-running-the-tests)
11. [Timestamps: the authoritative guide](#11-timestamps-the-authoritative-guide)
12. [Cleanup and pre-demo drift verification](#12-cleanup-and-pre-demo-drift-verification)
13. [Known gotchas](#13-known-gotchas)
14. [Appendix A — full API surface](#appendix-a--full-api-surface)
15. [Appendix B — full frontend route map](#appendix-b--full-frontend-route-map)

---

## 1. Architecture at a glance

SentinelAI V2 is a FastAPI backend plus a React single-page console, both talking to PostgreSQL.

| Tier | Technology | Notes |
| --- | --- | --- |
| API | FastAPI (Python 3.12) | ASGI object is `app.main:app` |
| Console | React 19 + Vite 8 + TanStack Query | dev server on `:5173`, proxies `/api` → `:8000` |
| Primary store | PostgreSQL 17 | All detections, correlations, risk, reports, SOAR, hunts, audit |
| Streaming | Kafka 3.9.0 (KRaft) | Health-checked; **not** exercised by the demo |
| Vector store | Qdrant (client only) | `qdrant-client` is installed and configured, but **no API route and no demo stage uses it** |
| LLM | Gemini (optional) | Absent key degrades gracefully; see [§8](#8-gemini--external-provider-behaviour) |

### V2 scope boundaries — read this before documenting behaviour

These are deliberate V2 decisions, not bugs. The console states them on-screen, and this runbook
repeats them so they are never "fixed" by mistake:

| Capability | V2 reality |
| --- | --- |
| **Policy (Step 24)** | The engine decides in memory, but every `REQUIRES_APPROVAL` decision is snapshotted onto its `approval_requests` row. `/policy` therefore renders real decisions — read from those snapshots, never re-derived. Outcomes other than `REQUIRES_APPROVAL` are not persisted and are not listed. |
| **Responses (Step 25)** | Every action runs against `MockResponseProvider` and never touches real infrastructure. No persistence, no API. `/responses` renders `Not available` with a `simulation` badge. |
| **Attack Paths** | Derived at request time from persisted correlation membership, risk, and relationships. Nothing is stored as a graph. |
| **Investigations** | An investigation ID is **not persisted**. `/investigations` is composed live from recent detections, correlations, and incident memories. |
| **MITRE ATT&CK** | V2 ships **no technique mapper**. The demo lists evidence-backed rule matches and deliberately invents no ATT&CK ID. |
| **SOAR** | Executions are persisted with full provenance, but every response action is a simulation. A run additionally requires a verifiable human grant: `approval_id` plus a matching `policy_decision_id` and `action_type`. |

### Four capabilities that cannot be demonstrated in V2 — and why

These are **architecture gaps, not defects**, and they are deliberately left unimplemented rather than faked.
No table, endpoint, or stored record exists for them, so the console states the reason on-screen instead of
inventing data. Each row cites the code that makes the gap explicit.

| Capability | What is missing | Authoritative evidence |
| --- | --- | --- |
| **P1 — Normalized security events** | Events are produced by normalization and enrichment, then dropped. No table, no repository, no query layer, no `/api/security-events` route. Detections and correlation members keep only `event_id`. | `backend/app/schemas/normalized_event.py:23` — the contract carries "no database tables, and no API endpoints". Verified against the live schema: zero tables match `event`. |
| **P3 — Multi-event correlation** | The only strategy is same-event. Two detections correlate **iff** they share an identical `event_id`, so an attack chain spanning several events cannot form one correlation. | `backend/app/services/correlation/strategy.py` — `SIGNAL_SHARED_EVENT` is the sole grouping signal; temporal proximity and entity signals are explicitly refused as documented over-correlation risks. |
| **P4 — Persisted investigation results** | `InvestigationResult` is a domain contract only. No agent, no persistence, no read/query service, no route — an investigation id is never stored. | `backend/app/schemas/investigation.py:1-17` — "contains no investigation agent, no LLM, ... and no inference of any kind". Verified: zero tables match `investig`. |
| **P5 — Persisted threat attribution** | The Step 14 module is contract-only by design; attribution is computed transiently and never stored, so there is no verdict to read back. | `backend/app/schemas/threat_attribution.py:6-9` — "does not ... persist attribution assessments, expose an API". Verified: zero tables match `attribution`. |

Closing any of these requires new tables, repositories, query layers and routes — a V3 schema change, which is
out of scope here. Raising the V2 baseline to add them is a deliberate follow-up decision, not a bug fix.

---

## 2. Prerequisites

Versions actually used to produce every result in this document:

| Tool | Version | Notes |
| --- | --- | --- |
| Python | 3.12.13 | Use 3.12; the venv was built with it |
| Node.js | v24.18.0 | |
| npm | 11.16.0 | |
| Docker | 29.8.0 | |
| Docker Compose | v5.5.1 | plugin style, i.e. `docker compose` |

PostgreSQL and Kafka are supplied by Docker, so no local installation of either is needed.

---

## 3. Clean-machine setup

Run all commands from the repository root unless a step says otherwise.

### 3.1 Infrastructure

```bash
docker compose up -d postgres kafka
docker compose ps
```

`docker-compose.yml` defines **only** two services:

| Service | Image | Port | Notes |
| --- | --- | --- | --- |
| `postgres` | `postgres:17` | `5432` | DB `sentinelai`, user `sentinelai_user`; data in the `postgres_data` volume |
| `kafka` | `apache/kafka:3.9.0` | `9092` | KRaft mode, **no ZooKeeper** |

> **There is no Qdrant service.** If you need a real Qdrant for experimentation, run it yourself and
> point `QDRANT_URL` at it. Nothing in the demo or the API requires one.

> Kafka runs with auto-topic creation **disabled**. The demo never touches Kafka, so no topic
> provisioning step is needed for this runbook.

Confirm PostgreSQL is up before continuing:

```bash
docker compose exec postgres pg_isready -U sentinelai_user -d sentinelai
```

### 3.2 Backend

```bash
cd backend
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

> Use **`backend/requirements.txt`**. The repository-root `requirements.txt` is a UTF-16-encoded,
> outdated snapshot (it pins `alembic==1.19.1` while the backend installs `1.16.5`). Do not install it.

Create the environment file:

```bash
cp .env.example .env
```

Then set at minimum:

```dotenv
DATABASE_URL=postgresql+psycopg://sentinelai_user:1234@127.0.0.1:5432/sentinelai
JWT_SECRET=<generate-a-long-random-value>
```

Generate a JWT secret with:

```bash
python3.12 -c "import secrets; print(secrets.token_urlsafe(48))"
```

> Declare `DATABASE_URL` **once**. The template ships it twice (an empty line first, the real value
> later); the last assignment wins, but the duplicate is confusing — remove the empty one.
>
> `1234` is the development password committed in `docker-compose.yml`. It is fine for local work only.
> Never reuse it outside a developer machine.

### 3.3 Migrations

Migrations live in **`backend/app/database/postgres/migrations/`**, wired up by `backend/alembic.ini`.
There is no `backend/alembic/` directory.

```bash
cd backend
.venv/bin/alembic upgrade head
```

The chain is linear and ends at a single head:

```bash
.venv/bin/alembic heads    # -> c3d4e5f6a1b2 (head)
.venv/bin/alembic current  # -> c3d4e5f6a1b2 (head)
```

14 migrations run in order. They create the schema and seed the three SOC **roles** — they do **not**
create any user account:

```
f121c4c8aa7d  create_foundational_tables
  -> 8c0b00d20101  create_threat_intel_tables
  -> e2f4a6c8d1e3  create_detection_tables
  -> 72c9d41e8b3f  create_correlation_tables
  -> 4a6c8d0e1f2a  create_risk_assessment_tables
  -> 5b7e9f0a2c3d  create_incident_memory_tables
  -> 4c8f2d1a9b3e  create_detection_as_code_tables
  -> 5d9e0b7c2f4a6d81  portable_dac_source_hash_check
  -> 6a1b2c3d4e5f  create_soar_tables
  -> 7a1b2c3d4e5f  create_threat_hunt_tables
  -> 8a1b2c3d4e5f  create_incident_reports_table
  -> 9c2d4e6f8a1b  seed_soc_roles            <-- roles admin / analyst / ciso
  -> a1b2c3d4e5f6  create_approval_request_tables
  -> c3d4e5f6a1b2  align_threat_hunt_fk_ondelete   <-- HEAD
```

### 3.4 Start the backend

```bash
cd backend
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

With `DEBUG=true`, interactive API docs are served at <http://localhost:8000/docs>.

### 3.5 Start the console

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The console is at <http://localhost:5173>. `vite.config.ts` proxies `/api` to
`http://localhost:8000`, so the browser makes same-origin requests and CORS is not a concern.

---

## 4. Environment variables

All settings are read by `backend/app/core/config.py` from `backend/.env`.

### Core

| Variable | Local value | Purpose |
| --- | --- | --- |
| `APP_VERSION` | `0.1.0` | Surfaced as `version` by `GET /` |
| `APP_NAME` | `SentinelAI` | Defined in `Settings` but **not surfaced by any endpoint** |
| `ENVIRONMENT` | `development` | |
| `DEBUG` | `true` | Enables `/docs` and the OpenAPI schema |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | |
| `LOG_LEVEL` | `INFO` | |
| `DATABASE_URL` | see [§3.2](#32-backend) | SQLAlchemy `psycopg` DSN |
| `JWT_SECRET` | *required* | HS256 signing key |
| `JWT_ALGORITHM` | `HS256` | |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access-token lifetime |

### Kafka

| Variable | Local value | Purpose |
| --- | --- | --- |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Used by `/api/health/kafka` only |

### Gemini (optional)

| Variable | Default | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | *(empty)* | When empty, model-backed checks are skipped |
| `GEMINI_MODEL` | `gemini-3.8-flash` | |
| `GEMINI_TIMEOUT_SECONDS` | `60` | |
| `GEMINI_MAX_RETRIES` | `2` | |

### Threat-intel providers (optional, independent)

| Variable | Default | Skipped when empty |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Yes |
| `ABUSEIPDB_API_KEY` | *(empty)* | Yes |
| `OTX_API_KEY` | *(empty)* | Yes |

Each also has a `*_TIMEOUT_SECONDS` companion (default `30`).

### Qdrant (present but unwired)

| Variable | Default | Reality |
| --- | --- | --- |
| `QDRANT_URL` | `http://localhost:6333` | No API route reads it |
| `QDRANT_API_KEY` | *(empty)* | Same |
| `EMBEDDING_PROVIDER` | `deterministic` | Deterministic hash embeddings, no external call |

**Do not add a Qdrant startup step to this runbook.** The library is installed for future retrieval
work; the current API surface (69 operations, listed in Appendix A) exposes nothing Qdrant-backed.

---

## 5. Authentication and roles

JWT bearer tokens, HS256, 30-minute expiry. `GET /api/auth/login` and `GET /api/auth/register` are
public; everything else under `/api` requires `Authorization: Bearer <token>`.

### 5.1 There is no sign-up UI and no seeded admin

This is the most common stumbling block on a clean machine:

- The console ships a **login page only** — `/login` is the sole public route.
- `POST /api/auth/register` is public, but it always assigns the **`analyst`** role.
- Migrations seed the `admin`, `analyst`, and `ciso` **roles**, never a user.

So the first account is an analyst, and admin-only pages are unreachable until you promote it.

### 5.2 Create the first account (curl)

```bash
cd backend

curl -s -X POST http://localhost:8000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"<strong-password>"}'
```

Verified response: HTTP `201`, and the `role` is `"analyst"`.

### 5.3 Confirm the analyst role is what you expect

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"<strong-password>"}' \
  | python3.12 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -s http://localhost:8000/api/users/me -H "Authorization: Bearer $TOKEN"
```

```json
{ "id": "…", "email": "you@example.com", "is_active": true, "role": "analyst" }
```

The login response contains exactly `access_token` and `token_type` — there is **no `expires_in`
field**, so do not script against one.

### 5.4 Prove the RBAC boundary (analyst)

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  http://localhost:8000/api/audit/logs -H "Authorization: Bearer $TOKEN"
# -> 403   (audit is admin-only)
```

### 5.5 Promote to admin

There is no self-service promotion API. Do it once from the venv:

```bash
cd backend
.venv/bin/python - <<'PY'
from sqlalchemy import select
from app.database.postgres.session import SessionLocal
from app.models.role import Role
from app.models.user import User

s = SessionLocal()
admin = s.execute(select(Role).where(Role.name == "admin")).scalar_one()
u = s.execute(select(User).where(User.email == "you@example.com")).scalar_one()
u.role_id = admin.id
s.commit()
print(f"{u.email} -> {u.role_id}")
s.close()
PY
```

Re-login (the old token still carries the `analyst` claim) and the admin endpoints open up:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"<strong-password>"}' \
  | python3.12 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

for p in audit/logs users/admin-test soar/executions; do
  curl -s -o /dev/null -w "/api/$p -> %{http_code}\n" \
    "http://localhost:8000/api/$p" -H "Authorization: Bearer $TOKEN"
done
# /api/audit/logs -> 200
# /api/users/admin-test -> 200
# /api/soar/executions -> 200
```

### 5.6 Console session handling

- The token is kept in `localStorage` under the key `sentinel.soc.token`.
- `AppShell` redirects to `/login` whenever no token is present.
- Any `401` fires an `UNAUTHORIZED_EVENT` that also redirects to `/login`.
- Logging out clears the stored token.

### 5.7 Role capability summary

| Capability | analyst | ciso | admin |
| --- | :---: | :---: | :---: |
| Read detections / correlations / risk / intel / memories | ✅ | ✅ | ✅ |
| Read Threat Hunts, create/run/cancel hunts | ✅ | ✅ | ✅ |
| Read + generate Incident Reports | ✅ | ✅ | ✅ |
| Read Attack Path | ✅ | ✅ | ✅ |
| Read SOAR playbooks / executions | ✅ | ✅ | ✅ |
| **Execute / dry-run / cancel SOAR** | ❌ | ❌ | ✅ |
| **Read & write Audit logs** | ❌ | ❌ | ✅ |
| **Data ingest (`POST /api/ingest/events`)** | ✅ | ✅ | ✅ |
| Detection-as-Code read | ✅ | ✅ | ✅ |
| Detection-as-Code validate | ✅ | ✅ | ✅ |
| **Detection-as-Code deploy / release / rollback / enable** | ❌ | ❌ | ✅ |
| `GET /api/users/admin-test`, `GET /api/users/security-test` | ❌ | ❌ | ✅ |

---

## 6. Health verification

| Endpoint | Auth | Checks |
| --- | --- | --- |
| `GET /` | public | service identity |
| `GET /health` | public | `SELECT 1` against PostgreSQL |
| `GET /api/health/database` | bearer | database health |
| `GET /api/health/kafka` | bearer | Kafka broker reachability |

```bash
curl -s http://localhost:8000/health
TOKEN=<token from §5.5>
curl -s http://localhost:8000/api/health/database -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8000/api/health/kafka     -H "Authorization: Bearer $TOKEN"
```

Verified responses:

```jsonc
// GET /
{"message":"SentinelAI API","version":"0.1.0","status":"running"}

// GET /health  (public)
{"status":"healthy","environment":"development","database":"healthy"}
```

The console's **System health** page (`/system`) renders the two authenticated checks. A Kafka
failure there does **not** mean the demo or the API is broken — see [§1](#1-architecture-at-a-glance).

---

## 7. Running the 20-stage demo

The demo exercises the real services and writes to PostgreSQL. **It does not need the HTTP server
running** — `scripts/run_demo_dataset.py` contains zero HTTP calls and drives the real service layer
through the same database session. Keep the API and console up separately if you want to click
through the pages.

```bash
cd backend
.venv/bin/python -m app.cli demo --scenario full
```

`full` is the only scenario shipped. Input is the frozen 10-event dataset
`backend/demo_datasets/00_full_soc_scenario/attack_chain.jsonl`.

### 7.1 What a passing run looks like

```
SENTINELAI DEMO  [full]
run_id: 8d852449-dd07-53d0-a6df-2b59d3885c13   (30.17s)

[ 1/20] INGESTION              PASS
      collected 10 event(s) through the real FileLogCollector
[ 2/20] NORMALIZATION          PASS
      normalized 10 event(s); identity preserved
[ 3/20] DETECTION              PASS
      9 real detection(s) fired against 9 deployed rule(s)
[ 4/20] THREAT INTELLIGENCE    PASS
      agent extracted 1 indicator(s); 2 provider lookup(s)
[ 5/20] CORRELATION            PASS
      primary correlation holds 7 detection(s)
[ 6/20] MITRE ATT&CK           PASS
      evidence-backed rule matches are listed; SentinelAI V2 ships no technique mapper, so no ATT&CK id is invented
[ 7/20] RISK                   PASS
      scored 0.628571 (RiskLevel.HIGH) with the deterministic engine
[ 8/20] INVESTIGATION          PASS
      correlation_id=…
[ 9/20] EXPLAINABILITY         PASS
[10/20] ATTRIBUTION            PASS
[11/20] INCIDENT MEMORY        PASS
[12/20] NATURAL LANGUAGE SOC   PASS
[13/20] POLICY                 PASS
[14/20] HITL                   PASS
[15/20] RESPONSE               PASS
[16/20] SOAR                   PASS
[17/20] THREAT HUNTING         PASS
[18/20] INCIDENT REPORT        PASS
[19/20] ATTACK PATH            PASS
[20/20] DASHBOARD              PASS
[x ] DETECTION-AS-CODE      PASS  (exercised, not a checklist row)

==============================================================
DEMO SUMMARY  PASS=20  SKIPPED=0  FAILED=0
```

Then it prints the created IDs and the exact console URLs to open:

```
report_id: …
approval_id: …
soar_execution_id: …
hunt_id: …
investigation_id: …

Frontend (existing routes):
  Dashboard              http://localhost:5173/dashboard
  Incidents              http://localhost:5173/incidents
  ...
  Incident Detail        http://localhost:5173/incidents/<correlation_id>
  Correlation Detail     http://localhost:5173/correlations/<correlation_id>
  Attack Path            http://localhost:5173/attack-paths/<correlation_id>

Clean up afterwards with: python -m app.cli demo --clean
```

### 7.1a Runtime depends on outbound network

Measured on this machine, same dataset and same code:

| Invocation | Wall clock | Provider lookups |
| --- | --- | --- |
| `--offline` | **5s** | `0 provider lookup(s)` |
| default (real keys set, network reachable) | ~30s | `2 provider lookup(s)` |
| default (real keys set, **network unreachable**) | **hangs** — hundreds of seconds | timeouts |

When `OTX_API_KEY` / `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` are set in `backend/.env`, the demo
makes **real outbound HTTP calls** to those providers. Each provider retries up to 3 attempts at its
own `*_TIMEOUT_SECONDS` (default `30`), so a machine with no outbound access burns roughly
`3 providers × 3 attempts × 30s` before the stage gives up — it does not fail fast, and it can look
like a hang:

```
AlienVault OTX request timed out (attempt 1/3)
Threat-intel lookup failed: provider=AlienVault OTX indicator_type=ip indicator='10.20.30.40' error_type=provider_error
```

The stage still reports `PASS`, because an unreachable third party is not a demo failure.

> **For routine local verification use `--offline`.** It runs in seconds, is fully deterministic, and
> exercises everything except the live provider calls. Reserve the default (online) run for when you
> specifically want to confirm provider connectivity.

Deterministic values you can rely on across runs — these were reproduced on every run:

| Output | Value |
| --- | --- |
| detections fired | `9` |
| detections in the primary correlation | `7` |
| risk score / level | `0.628571` / `HIGH` |
| indicators extracted | `1` |

### 7.2 Read the summary correctly

`DEMO SUMMARY` counts **stages**, not individual checks (`app/cli.py:425`). Twenty stages pass.
Individual checks *inside* a stage can be `skipped` without changing the summary — for example, with
no Gemini key the `investigation`, `natural_language_soc`, and `incident_reports` stages all report
`PASS` while some of their items report `skipped`. Inspect `--json` if you need item-level detail.

### 7.3 CLI flags

| Flag | Effect |
| --- | --- |
| `--scenario full` | the only scenario; required for the real run |
| `--json` | machine-readable output |
| `--clean` | remove every row created by tracked demo runs, then report drift |
| `--run` | leave the created rows in place (i.e. do not auto-clean) |
| `--no-gemini` | do not build a real Gemini client |
| `--offline` | force an empty threat-intel provider registry — **use this by default for local runs** |
| `--reject` | drive the HITL path down the reject branch |

> ⚠️ **`--no-gemini` has two different meanings.** With a key configured it skips model-backed work
> cleanly. **Without** a key the incident-report stage still calls the real service, which fails and
> persists a governed `failed` report row. See [§8](#8-gemini--external-provider-behaviour).

---

## 8. Gemini / external-provider behaviour

A missing key is a supported configuration, never a crash. All three paths were executed.

| Configuration | Investigation | NL SOC | Incident Reports |
| --- | --- | --- | --- |
| **No `GEMINI_API_KEY`** | check `skipped` — "no Gemini API key is configured" | check `skipped` | stage `PASS`; service runs, refuses to fabricate, **persists one row with `status: failed`** |
| `--no-gemini`, key present | skipped | skipped | skipped, **no row written** |
| `--no-gemini`, no key | skipped | skipped | service runs → `failed` row (same as row 1) |
| Key present | real call | real call | real call, report row generated |

Two consequences worth internalising:

1. **`SKIPPED=0` in the summary does not mean "no checks were skipped."** See [§7.2](#72-read-the-summary-correctly).
2. **An absent key still leaves a row in `incident_reports`.** It is a genuine governed failure with
   provenance, not a stub. `REPORT_INTERNAL` was the observed error classification when the provider
   could not be constructed. If you assert "no report rows exist after a demo" and you ran the demo
   without a key, that assertion is wrong — check `status`, not row existence.

The demo's Incident Reports stage also enforces a **citation gate**: the model may only cite IDs from
the catalog the builder assembled, so a dangling citation cannot become report content.

Threat intel behaves the same way per provider: a provider with no key is reported as skipped. OTX
reaching out for a RFC1918 address (`10.20.30.40`) logs
`Threat-intel lookup failed: provider=AlienVault OTX … error_type=provider_error` and the stage still
passes — an unreachable third party is not a demo failure.

---

## 9. Capability verification matrix

Each row: open the page, and confirm the API returns data. `GET`-shaped rows work for any role;
mutations are admin-only as noted.

| Capability | Page | Key API | Expected after a demo run |
| --- | --- | --- | --- |
| Dashboard | `/dashboard` | `correlationsApi.recent`, `risksApi.recent`, `detectionsApi.recent`, `approvalsApi.recent`, `memoriesApi.recent`, `detectionRulesApi.*`, `threatIntelligenceApi.listIndicators`, `healthApi.*` | **KPI "Active incidents" counts correlation status `active` only.** Panel `Incidents · risk + correlation join` spans **all** statuses. |
| Incidents list | `/incidents` | `correlationsApi.recent`, `risksApi.recent` | one row per correlation with risk score |
| Incident detail | `/incidents/{correlationId}` | `correlationsApi.get` | detections, risk, memory, report, attack path |
| Detections | `/detections` | `detectionsApi.recent` | 9 detections from the dataset |
| Detection rules | `/detection-rules` | `detectionRulesApi.list`, `.analytics`, `detectionsApi.recent` | 9 deployed rules + hit analytics |
| Detection-as-Code | `/detection-as-code` | `detectionAsCodeApi.list/.get/.validate` *(admin for deploy/release/rollback/enable)* | revisions + validation |
| Data ingest | `/data-ingest` | `ingestApi.format`, `ingestApi.events` *(admin/analyst)* | supported format contract |
| Correlations | `/correlations`, `/correlations/{id}` | `correlationsApi.recent`, `.get` | primary correlation with 7 detections |
| Risk | `/risk` | `risksApi.recent` | 0.628571 / `HIGH` |
| Threat intelligence | `/threat-intelligence` | `threatIntelligenceApi.listIndicators`, `.indicator` | 1 extracted indicator |
| Investigations | `/investigations` | `detectionsApi.recent`, `correlationsApi.recent`, `memoriesApi.recent` | composed live; **no investigation rows exist** |
| Policy | `/policy` | *none* | `Not available` panel — in-memory only |
| Responses | `/responses` | *none* | `Not available` (simulation) panel |
| SOAR | `/soar` | `soarApi.playbooks`, `.executions`, `.dryRun`, `.execute`, `.cancel` *(admin)* | 1 execution, simulated outcome |
| HITL approvals | via Dashboard / SOAR | `approvalsApi.recent`, `.approve`, `.reject` *(admin)* | 1 approval; try approve **and** reject branches |
| Threat hunting | `/threat-hunting` | `threatHuntingApi.create`, `.run`, `.hunt`, `.evidence`, `.findings`, `.timeline`, `.cancel` | 1 hunt with timeline + findings |
| Incident reports | `/incident-reports` | `incidentReportsApi.list`, `.report`, `.generate` | 1 row; `failed` if no Gemini key ([§8](#8-gemini--external-provider-behaviour)) |
| Attack paths | `/attack-paths`, `/attack-paths/{correlationId}` | `attackPathsApi.graph` | derived graph; nothing persisted |
| Incident memory | within Incident detail | `memoriesApi.recent` | 1 memory row |
| Audit | `/audit` *(admin)* | `auditApi.logs` | registration + demo actions |
| System health | `/system` | `healthApi.database`, `healthApi.kafka` | database `ok`; Kafka per broker |
| Settings | `/settings` | `authApi.me` | signed-in user; the "Application" panel is **hardcoded frontend literals**, not an API response |
| SOC search | `/search?q=…` | `socApi.query` | needs Gemini for parsing; allowlisted operations only |

**Correlation drill-downs** are useful for spot checks:

```bash
CID=<correlation_id printed by the demo>
curl -s "http://localhost:8000/api/correlations/$CID"                          -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:8000/api/risk-assessments/correlation/$CID"         -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:8000/api/attack-paths/$CID"                         -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:8000/api/incident-memories/correlation/$CID"        -H "Authorization: Bearer $TOKEN"
```

**Threat hunting** — the create boundary is strict and rejects anything outside its closed sets with
`422`. `name`, `hunt_type`, `start_time`, and `end_time` are all **required**; the window is
timezone-aware and bounded, and `hunt_type` must be one of `authentication_anomaly`, `indicator_hunt`,
`privilege_activity`, `multi_stage_activity`, `detection_review`.

```bash
HUNT=$(curl -s -X POST http://localhost:8000/api/threat-hunts \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "runbook probe hunt",
        "hunt_type": "detection_review",
        "start_time": "2026-09-27T00:00:00Z",
        "end_time": "2026-09-30T00:00:00Z",
        "filters": [{"field": "severity", "operator": "equals", "value": "high"}]
      }')

HID=$(echo "$HUNT" | python3.12 -c 'import json,sys; print(json.load(sys.stdin)["hunt_id"])')
curl -s -X POST "http://localhost:8000/api/threat-hunts/$HID/run" -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:8000/api/threat-hunts/$HID/findings"  -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:8000/api/threat-hunts/$HID/timeline"  -H "Authorization: Bearer $TOKEN"
```

Verified: creation returns `status: draft`, `run` flips it to `completed`, and `findings` /
`timeline` return `200`.

Two validation traps, both returning `422` with a clear message:

- **Severity values are lowercase.** `"HIGH"` is rejected; the closed set is
  `critical`, `high`, `low`, `medium`.
- **Emails need a real TLD.** Registering `probe@local` fails validation.

Closed `field` values are: `event_id`, `detection_id`, `rule_id`, `rule_type`, `severity`,
`correlation_id`, `correlation_status`, `risk_level`, `indicator_type`, `indicator_value`,
`memory_type`, `audit_action`, `audit_resource`, `actor_ip`. Operators are `equals`, `not_equals`,
`in`, `not_in`, `contains`, `starts_with`, `ends_with` — and `in` / `not_in` take a `values` array
rather than a single `value`.

> A hunt evaluates against **every** detection in the database within the window, not only
> demo-created ones. Never assert counts from a wide window on a shared database — filter with
> `equals` on a known value, and prefer running the demo on a clean database.

---

## 10. Running the tests

### 10.1 Backend

```bash
cd backend
.venv/bin/python -m pytest -q
```

Verified on a clean baseline:

```
5052 passed, 3 skipped, 5 warnings in 45.36s
```

Targeted runs:

```bash
.venv/bin/python -m pytest tests/unit/test_threat_hunt_api.py -q      # 25 passed
.venv/bin/python -m pytest tests/integration/test_demo_cli_e2e.py -q
```

> **The suite uses the configured PostgreSQL database — there is no transactional rollback and no
> dedicated test database.** Tests persist fixture rows. Always run `demo --clean` **before**
> `pytest`, and never point the suite at a database you care about. See
> [§12](#12-cleanup-and-pre-demo-drift-verification) and [§13](#13-known-gotchas).

> `run_tests.ps1` in the repository root is a **Windows-only** helper hardcoded to
> `D:\Projects\Sentinel AI\backend`. It is not portable; ignore it on macOS and Linux.

### 10.2 Frontend

```bash
cd frontend
npm test              # vitest run -> 132 passed (16 files)
npm run lint
npx tsc -b --noEmit
npm run build
```

---

## 11. Timestamps: the authoritative guide

This section exists because several layers render the same instant differently. **Most differences are
not defects; two of them are genuine inconsistencies, documented in [§11.5](#115-the-two-genuine-inconsistencies).**

### 11.1 What the database stores

- All **72** SQLAlchemy timestamp columns use `DateTime(timezone=True)`.
- Verified against the live schema: **72 `timestamptz` columns, zero naive `timestamp` columns.**

`timestamptz` does **not** store a timezone or an offset. It stores an absolute instant, normalised to
UTC internally. PostgreSQL renders it in whatever zone the **current session** is set to — currently
**`Asia/Kolkata`** (`+05:30`).

### 11.2 Layer-by-layer behaviour

| Layer | Rendering | Verified output |
| --- | --- | --- |
| PostgreSQL raw SQL | session zone — `Asia/Kolkata` | `2026-10-01 17:49:46.982192+05:30` |
| REST API — **most** endpoints | **UTC**, `Z` suffix | `2026-10-01T12:19:46.982192Z` |
| REST API — **threat hunts, detection rules** | session offset, `+05:30` | `2026-10-01T18:10:01.593781+05:30` |
| Console (`src/lib/formats.ts`) | **UTC**, labelled `UTC` | `01 Oct 2026 12:19:46 UTC` |
| Datetime `<input>` (`threat-hunting-page.tsx`) | **browser local** for display only | re-encoded to the same instant on submit |

### 11.3 The API is *not* uniformly UTC — verified per endpoint

Only `app/services/correlation_query.py` and `app/services/detection_query.py` normalise with
`_as_utc()`. Other services return ORM rows directly, so Pydantic serialises whatever offset the
session handed back. Measured against a live demo run:

| Endpoint | Rendering |
| --- | --- |
| `GET /api/correlations/{id}` | `Z` |
| `GET /api/detections/recent` | `Z` |
| `GET /api/risk-assessments/recent` | `Z` |
| `GET /api/incident-reports` | `Z` |
| `GET /api/threat-intelligence/indicators` | `Z` |
| `GET /api/approvals/recent` | `Z` |
| `GET /api/soar/executions` | `Z` |
| **`GET /api/threat-hunts/*`** | **`+05:30`** |
| **`GET /api/detection-rules`** (`last_matched_at`) | **`+05:30`** |

All of these are the **same instant**. For example, one demo run produced:

```
detection_rules.last_matched_at   2026-10-01T18:10:01.593781+05:30   ==   12:40:01.593781Z
detections.detected_at            2026-10-01T12:40:01.601448Z
```

The console shows both as `01 Oct 2026 12:40:01 UTC`, because `formatDateTime` calls
`new Date(value)` — which parses both forms to the same instant — and then reads the **UTC**
components with `getUTC*()`. So the inconsistency is invisible in the UI and only surfaces in raw
`curl` output.

> **Rule of thumb: treat every timestamp as UTC, and parse the offset rather than eyeballing the
> string.** Never assert on the literal suffix (`Z` vs `+05:30`) — it varies by endpoint and by the
> server's session timezone. If a value has an offset, `new Date(value)` / `datetime.fromisoformat`
> handles it correctly.

### 11.4 How to compare safely

Always pin the session timezone before reading raw SQL:

```sql
SET TIME ZONE 'UTC';
SHOW timezone;                 -- UTC

SELECT now();                  -- always UTC after the SET
```

To render a specific column explicitly:

```sql
SELECT id, detected_at AT TIME ZONE 'UTC' AS detected_at_utc
FROM detection_results
ORDER BY detected_at DESC
LIMIT 5;
```

### 11.5 The two genuine inconsistencies

1. **The API renders two endpoints in session-local time** ([§11.3](#113-the-api-is-not-uniformly-utc--verified-per-endpoint)).
   `GET /api/threat-hunts/*` and `GET /api/detection-rules` return `+05:30` where everything else
   returns `Z`. The instants are correct and the console normalises them; only raw `curl` output
   differs. If you script against the API, **parse the offset** rather than pattern-matching `Z`.

2. **The demo dataset's own timestamps.** The frozen input file's first event is
   `2026-09-28T10:00:00+00:00`, but `scripts/run_demo_dataset.py` passes `clock=NOW` to detection and
   correlation evaluation. **The resulting detections and correlations are stamped with the moment you
   ran the demo, not with the dataset's dates.** Seeing today's date on freshly demoed rows is
   correct behaviour — do not "fix" it.

A third difference is cosmetic and intentional: the `/threat-hunting` datetime inputs use
`toLocalInput()`, which reads `getFullYear()` / `getMonth()` / `getDate()` / `getHours()` /
`getMinutes()` from the browser, so the box shows **your local wall-clock time**. On submit
`toIso()` calls `new Date(local).toISOString()`, re-encoding the correct instant. If your browser is
UTC+5:30, an input reading `19:56` means `14:26Z`.

### 11.6 Worked example

`2026-09-30T19:56:31Z` means **19:56:31 UTC**. In the current session timezone that is:

```
2026-09-30 19:56:31 UTC   ==   2026-10-01 01:26:31.000000+05:30
```

If a raw `SELECT` shows `2026-10-01 01:26:31+05:30`, it matches — the date has not moved.

---

## 12. Cleanup and pre-demo drift verification

Every demo run records the exact rows it created in `backend/.demo_state.json` (gitignored).
Cleanup is **identity-based**: it deletes those specific rows, never a table truncate, so it is safe
on a database with other data.

```bash
cd backend
.venv/bin/python -m app.cli demo --clean
```

A clean result:

```json
{"status": "PASS", "drift_after_cleanup": "NONE"}
```

`drift_after_cleanup` compares post-cleanup row counts against the snapshot taken **when the run
started**. `NONE` means nothing was left behind.

> **Drift is a baseline comparison, so anything that changes table counts in between will report
> drift — in either direction.** Running `pytest` between the demo and the clean inflates counts;
> deleting a row by hand makes `after` *smaller* than `baseline` and also reports `FAIL`. Both are
> reported, for example:
>
> ```json
> {"drift_after_cleanup": {"users": {"after": 503, "baseline": 504}}, "status": "FAIL"}
> ```
>
> **`FAIL` on drift does not mean demo rows survived.** Cleanup is identity-based, so the demo's own
> rows are always removed. Verify that directly before concluding anything went wrong:
>
> ```bash
> cd backend
> .venv/bin/python - <<'PY'
> import json
> from sqlalchemy import select
> from app.database.postgres.session import SessionLocal
> from app.models.threat_hunt import ThreatHuntRow
> s = SessionLocal()
> orphans = sum(
>     1 for r in json.load(open('.demo_state.json'))['runs']
>     if (e := r['entities'].get('hunt_id'))
>     and s.execute(select(ThreatHuntRow.hunt_id).where(ThreatHuntRow.hunt_id == str(e))).first()
> )
> print('orphaned demo rows:', orphans)
> s.close()
> PY
> ```

### Pre-demo checklist

```bash
cd backend
.venv/bin/python -m app.cli demo --clean   # expect drift_after_cleanup: NONE
ls .demo_state.json 2>/dev/null && echo "state file still present" || echo "no tracked runs"
.venv/bin/python -m app.cli demo --scenario full
```

Run `--clean` **before** `--scenario full**, and keep `pytest` out of the window between a run and its
clean — see [§13](#13-known-gotchas).

### Recovering from a stale state file

If the baseline is stale and the orphan check above returns `0`, drop the file and re-verify:

```bash
cd backend
rm -f .demo_state.json
.venv/bin/python -m app.cli demo --clean     # -> drift_after_cleanup: NONE, status: PASS
```

Never delete the state file *instead of* cleaning: that is how orphans actually get left behind.

---

## 13. Known gotchas

| Symptom | Cause | Fix |
| --- | --- | --- |
| Audit page returns 403 / shows nothing | you are still `analyst` | promote per [§5.5](#55-promote-to-admin), then **re-login** |
| No way to sign up in the UI | only `/login` exists by design | register via `curl` ([§5.2](#52-create-the-first-account-curl)) |
| Login response has no `expires_in` | the field is not implemented | use the 30-minute default from config |
| `pytest` reports 3 errors | a demo run was left in `.demo_state.json`, so `test_demo_cli_e2e.py` cannot assume a pristine state | run `demo --clean` first |
| `demo --clean` reports `status: FAIL` with a diff | the baseline is a **count comparison**; `pytest` rows inflate it, manual deletes deflate it | demo rows are still removed — verify with the orphan check in [§12](#12-cleanup-and-pre-demo-drift-verification), then reset the stale state file |
| Demo shows today's date, dataset says 2026-09-28 | the runner stamps rows with `clock=NOW` | expected; see [§11.5](#115-the-two-genuine-inconsistencies) |
| `SKIPPED=0` but some checks were skipped | the summary counts stages, not checks | use `--json` |
| An incident report row exists with `status: failed` | no Gemini key; the service persisted a governed failure | expected; see [§8](#8-gemini--external-provider-behaviour) |
| Kafka health red but demo fine | demo never uses Kafka | ignore for V2 verification |
| `pip install -r requirements.txt` installed `alembic==1.19.1` | you used the **root** UTF-16 requirements file | install from `backend/requirements.txt` |
| OTX error lines in demo output | the dataset uses a private IP; OTX rejects it | expected; stage still passes |
| Demo appears to hang for many minutes | real provider keys are set but outbound network is unreachable; each provider retries 3× at 30s | re-run with `--offline` ([§7.1a](#71a-runtime-depends-on-outbound-network)) |
| Threat-hunt counts look wrong | an unbounded window matched non-demo rows | filter with `equals` on a known value |
| `POST /api/threat-hunts` → `422`, "value 'HIGH' is not in the closed set" | severity is validated against a lowercase enum | use `critical` / `high` / `low` / `medium` |
| `POST /api/auth/register` → `422`, "part after the @-sign is not valid" | the email validator requires a dotted domain | `you@example.com`, not `you@local` |
| Two endpoints return `+05:30` where the rest return `Z` | hunt and detection-rule services skip `_as_utc()` | parse the offset, don't match on `Z` ([§11.3](#113-the-api-is-not-uniformly-utc--verified-per-endpoint)) |

---

## Appendix A — full API surface

69 operations. Authentication: **public** = no token; **all others** require
`Authorization: Bearer <token>`.

```
GET    /
GET    /health                                    (public)
POST   /api/auth/login                             (public)
POST   /api/auth/register                          (public)

GET    /api/users/me
GET    /api/users/admin-test                       (admin)
GET    /api/users/security-test                    (admin)

GET    /api/health/database
GET    /api/health/kafka

POST   /api/ingest/events                          (admin, analyst)
GET    /api/ingest/format

GET    /api/detections/recent
GET    /api/detections/{detection_id}
GET    /api/detections/event/{event_id}
GET    /api/detections/rule/{rule_id}
GET    /api/detection-analyses/{event_id}
GET    /api/detection-analyses/{event_id}/failures
GET    /api/detection-rules
GET    /api/detection-rules/analytics
GET    /api/detection-rules/{rule_id}

GET    /api/detection-as-code
GET    /api/detection-as-code/{rule_id}
POST   /api/detection-as-code/validate             (admin, analyst)
POST   /api/detection-as-code/deploy               (admin)
POST   /api/detection-as-code/release              (admin)
POST   /api/detection-as-code/rollback             (admin)
POST   /api/detection-as-code/enabled              (admin)

GET    /api/correlations/recent
GET    /api/correlations/{correlation_id}
GET    /api/correlations/detection/{detection_id}
GET    /api/correlations/event/{event_id}

GET    /api/risk-assessments/recent
GET    /api/risk-assessments/{risk_assessment_id}
GET    /api/risk-assessments/correlation/{correlation_id}

GET    /api/threat-intelligence/indicators
GET    /api/threat-intelligence/indicators/{indicator_id}
GET    /api/threat-intelligence/indicators/{indicator_id}/events

GET    /api/incident-memories
GET    /api/incident-memories/recent
GET    /api/incident-memories/{memory_id}
GET    /api/incident-memories/correlation/{correlation_id}

GET    /api/incident-reports
GET    /api/incident-reports/{report_id}
POST   /api/incident-reports/generate

GET    /api/attack-paths/{correlation_id}          (derived, nothing persisted)

GET    /api/approvals
GET    /api/approvals/recent
GET    /api/approvals/{approval_id}
POST   /api/approvals
POST   /api/approvals/{approval_id}/approve        (admin)
POST   /api/approvals/{approval_id}/reject         (admin)
POST   /api/approvals/{approval_id}/cancel         (admin)

GET    /api/soar/playbooks
GET    /api/soar/playbooks/{playbook_id}
GET    /api/soar/executions
GET    /api/soar/executions/{execution_id}
POST   /api/soar/executions                        (admin)
POST   /api/soar/executions/{execution_id}/cancel  (admin)
POST   /api/soar/dry-run                           (admin)

GET    /api/threat-hunts
GET    /api/threat-hunts/{hunt_id}
POST   /api/threat-hunts
POST   /api/threat-hunts/{hunt_id}/run
POST   /api/threat-hunts/{hunt_id}/cancel
GET    /api/threat-hunts/{hunt_id}/evidence
GET    /api/threat-hunts/{hunt_id}/findings
GET    /api/threat-hunts/{hunt_id}/timeline

POST   /api/soc/query

GET    /api/audit/logs                             (admin)
```

> **No `/api/policies` and no `/api/responses` exist.** Their absence is the documented V2 boundary
> ([§1](#1-architecture-at-a-glance)).

---

## Appendix B — full frontend route map

From `frontend/src/routes/index.tsx`. Only `/login` is public; `AppShell` redirects everything else
to `/login` without a token.

| Path | Page |
| --- | --- |
| `/login` | Login (the only public route) |
| `/` | redirects to `/dashboard` |
| `/dashboard` | Dashboard |
| `/incidents` | Incidents list |
| `/incidents/:correlationId` | Incident detail |
| `/detections` | Detections |
| `/detection-rules` | Detection Rules |
| `/detection-as-code` | Detection-as-Code |
| `/data-ingest` | Data Ingest |
| `/correlations` | Correlations |
| `/correlations/:correlationId` | Correlation detail |
| `/risk` | Risk |
| `/threat-intelligence` | Threat Intelligence |
| `/investigations` | Investigations |
| `/policy` | Policy (`Not available`) |
| `/responses` | Responses (`Not available`, simulation) |
| `/soar` | SOAR |
| `/threat-hunting` | Threat Hunting |
| `/incident-reports` | Incident Reports |
| `/attack-paths` | Attack Paths |
| `/attack-paths/:correlationId` | Attack Path detail |
| `/system` | System health |
| `/audit` | Audit (admin) |
| `/settings` | Settings |
| `/search` | SOC search results |
| `*` | Not found |

> The Settings panel hardcodes the label `SentinelAI · SOC Console (V1)` even though this codebase is
> V2. It is a literal in `frontend/src/pages/settings-page.tsx`, not a value derived from any API.
> Report it as a cosmetic label mismatch; do not treat it as a versioning signal.

---

## Quick reference

```bash
# infra
docker compose up -d postgres kafka

# backend
cd backend && python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env          # then set DATABASE_URL + JWT_SECRET
.venv/bin/alembic upgrade head
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# console
cd frontend && npm install && npm run dev        # http://localhost:5173

# demo
cd backend && .venv/bin/python -m app.cli demo --scenario full
cd backend && .venv/bin/python -m app.cli demo --clean   # -> drift_after_cleanup: NONE

# tests
cd backend  && .venv/bin/python -m pytest -q      # 5052 passed, 3 skipped
cd frontend && npm test                           # 132 passed
cd frontend && npm run lint && npx tsc -b --noEmit && npm run build
```