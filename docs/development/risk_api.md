Risk Assessment API (Step 11E)
=============================

Purpose
-------

Step 11E exposes the Step 11D :class:`~app.services.risk_query.RiskQueryService`
through authenticated, authorized, **read-only** FastAPI HTTP endpoints.  It is
the risk analogue of the Detection (Step 9H) and Correlation (Step 10E) APIs
and the last step of the risk-subsystem ladder (11A contract → 11B scoring →
11C persistence → 11D query → **11E API**).

Step 11E exposes read-only risk assessment retrieval through the API; it does
not calculate, modify, persist, or act on risk.

Architecture
------------

The API is a thin adapter — every route validates HTTP input, calls **one**
``RiskQueryService`` method, and returns a Step 11D read model::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> RiskQueryService (Step 11D, read-only)
        -> 11D read-model response (RiskAssessmentRecord / RiskAssessmentPage)
        -> HTTP response

The route layer **never** queries SQLAlchemy or PostgreSQL directly, never
paginates manually, never sorts, and never re-derives risk.  All retrieval,
ordering, pagination, validation, and redaction semantics are owned by the
Step 11D service and the Step 11C persistence contract.

Endpoints
---------

All endpoints require a valid JWT bearer token and one of the SOC roles
(``admin``, ``analyst``, ``ciso``).  Only ``GET`` methods are defined.

| Method | Path | Service delegation | Returns |
|--------|------|--------------------|---------|
| GET | ``/api/risk-assessments/{risk_assessment_id}`` | ``RiskQueryService.get_assessment`` | ``RiskAssessmentRecord`` |
| GET | ``/api/risk-assessments/correlation/{correlation_id}`` | ``RiskQueryService.list_assessments_for_correlation`` | ``RiskAssessmentPage`` |
| GET | ``/api/risk-assessments/recent`` | ``RiskQueryService.list_recent_assessments`` | ``list[RiskAssessmentRecord]`` |

Route ordering follows the Detection/Correlation API: the static ``/recent``
and segmented ``/correlation/{correlation_id}`` routes are registered *before*
the parameterized ``/{risk_assessment_id}`` route so ``/recent`` never
resolves as a UUID path segment.

Authentication
--------------

The existing SentinelAI JWT mechanism is reused verbatim — no second
implementation:

* ``HTTPBearer`` scheme (``app/api/dependencies.py``) plus
  ``get_current_user`` → ``app.core.security.decode_access_token``.
* No Authorization header → **401**.
* Malformed/unknown/expired token → **401** (``Invalid or expired
  authentication token``).
* Authentication is checked before any lookup; even a valid assessment id is
  rejected without a token.

RBAC
----

The existing ``require_role("admin", "analyst", "ciso")`` factory guards every
risk endpoint — the same SOC-reader model used by the Detection and
Correlation APIs.  No new roles and no client-supplied role selection:

* Allowed roles → 200/404 (successful read or controlled not-found).
* Authenticated outsider (e.g. ``viewer``) → **403** ``Insufficient
  permissions``.
* Authorization denials are audited by ``require_role`` as
  ``auth.authorization.denied`` (established behavior — unchanged).
* Successful reads are **not** audited (no read-audit convention exists in
  the project).

Request validation
------------------

* Path UUIDs validate through FastAPI path typing → **422** for malformed
  UUIDs.
* ``page >= 1``, ``page_size`` in ``[1, 200]`` (default 50), ``limit`` in
  ``[1, 200]`` (default 50) via the same ``Query(...)`` constraints the
  Detection/Correlation APIs use → **422** when violated.
* Service-level validation failures raised by the Step 11D umbrella are
  translated to **422** by the route error bridge.

Pagination
----------

Pagination is owned by 11D, never duplicated in the API:

* 1-based offset pages with database-side totals, deterministic ordering
  (``timestamp`` descending, ``risk_assessment_id`` ascending).
* ``page``/``page_size`` bounds (`MAX_PAGE_SIZE=200`) are the exact 11D
  bounds.  The correlation-scoped route passes ``page``/``page_size`` through
  unchanged.
* The recent feed is a bounded list (`limit`, default 50, max 200) and returns
  up to *limit* newest assessments in deterministic order — the API performs
  no additional sorting or re-ordering.

Response structure
------------------

Responses are the Step 11D read models (the same pattern the Detection and
Correlation APIs follow — query read models used directly as response models,
never raw ORM objects).  For one assessment: ``id``, ``risk_assessment_id``,
``correlation_id``, ``score``, ``level``, ``confidence``, ``factors``,
``evidence``, ``assessment_metadata``, ``timestamp``, ``provenance``,
``created_at``, ``updated_at``.

* ``assessment_metadata`` is the persisted form of the Step 11A
  ``metadata``; the record field names the persisted column, mirroring the
  Detection/Correlation ``result_metadata`` convention.  All metadata,
  factors, evidence, confidence, and provenance are preserved — nothing is
  silently omitted.
* A correlation-scoped page returns ``items`` + ``total`` + requested
  ``page``/``page_size``; **all** historical assessments of a correlation are
  eligible (never collapsed to one).

Error behavior
--------------

The route error bridge mirrors the Detection/Correlation ``_call_query``
pattern:

| Condition | HTTP |
|-----------|------|
| No/invalid/expired token | 401 |
| Insufficient role | 403 |
| Unknown exact-lookup id | 404 (``Risk assessment not found``) |
| Malformed UUID / invalid page / page_size / limit | 422 |
| Service validation failure (11D) | 422 |
| Sanitized query/database failure (11D) | 503 (``Risk data is unavailable``) |
| Unexpected error | 500 (``Internal server error``, centralized handler) |

No SQL statements, SQLAlchemy errors, connection strings, PostgreSQL
internals, stack traces, credentials, or secret values ever reach the client.

Audit behavior
--------------

Follows the existing project policy exactly:

* Authorization denials are audited (``auth.authorization.denied``) by the
  shared ``require_role`` dependency — no new audit code was added.
* Successful reads produce **no** audit events (no read-audit convention
  exists).
* Query failures are logged sanitized by the service and the centralized
  exception handler (endpoint, operation, ids, result counts, sanitized error
  category), never payloads.

Security
--------

* JWT bearer authentication plus role-based authorization on every route.
* The API surfaces whatever 11C/11D stored: credential-shaped values in
  metadata / factor metadata / evidence metadata were redacted (``<redacted>``)
  by the Step 11C-B persistence service before write, so responses contain the
  stored redacted form — the API is never a weaker read path.
* No secrets are logged; request/response payloads are not logged.
* Read-only contract: only ``GET``; POST/PUT/PATCH/DELETE return **405**; API
  requests never insert/update/delete rows (verified by tests and live
  PostgreSQL).

PostgreSQL integration
----------------------

Verified end-to-end against the live PostgreSQL 17 (``sentinelai``) instance:
a Step 11B assessment persisted through the real 11C
``RiskPersistenceService`` (with its Step 10C parent correlation) is retrieved
through the real 11E HTTP API with full fidelity — id, correlation id, score
(0.625), level (high), confidence, factors, evidence, metadata, timestamp, and
provenance.  Multiple historical assessments for one correlation, pagination,
the recent feed, 404/422/401, and read-only behavior were all verified, and
the seeded test data was cleaned up (parent correlations deleted; assessments
cascaded) leaving the database in its pre-run state.

No schema change: ``risk_assessments`` already exists (Step 11C-A).  The
Alembic head remains ``4a6c8d0e1f2a`` and ``alembic check`` reports no pending
operations.

Testing
-------

``tests/unit/test_risk_api.py`` (TestClient against the full app, live
PostgreSQL, real persistence path) covers:

* authentication — missing header, invalid token, **expired token**, auth
  checked before lookup;
* authorization — admin/analyst/ciso allowed, outsider 403 on every endpoint,
  denial audited, successful reads not audited;
* get-by-id — full fidelity, schema key set, factors/evidence/metadata/
  confidence/provenance preserved, 404, malformed UUID 422;
* correlation-scoped — all historical assessments returned, deterministic
  ordering, empty 200, pagination across pages, max page_size, invalid
  page/page_size;
* recent — marker-membership, multiple results, bounded limit, deterministic
  ordering, **equal-timestamp tie-break**, invalid limits;
* route ordering — ``/recent`` never resolves as ``/{risk_assessment_id}``;
* error handling — 503 safe responses with no internals leaked for every
  endpoint, service validation → 422, unexpected error → sanitized 500;
* security — secret-shaped metadata/factor-metadata/evidence-metadata
  redacted through the response, raw credentials absent, no database
  internals in responses;
* read-only — no row mutation, GET-only in OpenAPI, 405 for write methods;
* architecture — every route delegates to ``RiskQueryService`` (probe
  services) and the route module has no direct database access;
* OpenAPI contract — exact risk paths, bearer security on every operation,
  GET-only, unique operation IDs, security scheme declared.

Non-goals
---------

11E does **not** implement: risk scoring, risk recalculation, incident
creation, alert generation, MITRE mapping, AI investigation, LLM reasoning,
response/mitigation, SOAR, threat hunting, dashboards, prediction,
visualization, frontends, Kafka/RabbitMQ events, risk creation/update/delete
endpoints, or any database schema change.  Step 11E is the thin read-only
HTTP adapter over the Step 11D query service only.

Step 11E exposes read-only risk assessment retrieval through the API; it does
not calculate, modify, persist, or act on risk.