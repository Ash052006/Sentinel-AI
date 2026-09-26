Incident Memory API (Step 19)
=============================

Purpose
-------

Step 19 exposes the Step 18 :class:`~app.services.incident_memory_query.
IncidentMemoryQueryService` through authenticated, authorized, **read-only**
FastAPI HTTP endpoints.  It is the recall surface over the Step 17
``incident_memories`` persistence contract, following the exact pattern of
the Detection (Step 9H), Correlation (Step 10E), and Risk Assessment
(Step 11E) APIs.

Step 19 exposes read-only incident memory retrieval through the API; it does
not recall, search, re-extract, re-interpret, learn from, act on, or persist
memory.

Architecture
------------

The API is a thin adapter — every route validates HTTP input, calls **one**
``IncidentMemoryQueryService`` method, and returns a Step 18 read model::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> IncidentMemoryQueryService (Step 18, read-only)
        -> 18 read-model response (IncidentMemoryRecord / IncidentMemoryPage)
        -> HTTP response

The route layer **never** queries SQLAlchemy or PostgreSQL directly, never
filters in Python, never paginates manually, and never re-transforms stored
payloads.  All retrieval, ordering, pagination, validation, and the optional
``memory_type`` filter are owned by the Step 18 service/repository (a
database-side equality filter) and the Step 17 persistence contract.

Endpoints
---------

All endpoints require a valid JWT bearer token and one of the SOC roles
(``admin``, ``analyst``, ``ciso``).  Only ``GET`` methods are defined.

| Method | Path | Service delegation | Returns |
|--------|------|--------------------|---------|
| GET | ``/api/incident-memories`` | ``IncidentMemoryQueryService.list_memories`` | ``IncidentMemoryPage`` |
| GET | ``/api/incident-memories/{memory_id}`` | ``IncidentMemoryQueryService.get_memory`` | ``IncidentMemoryRecord`` |
| GET | ``/api/incident-memories/correlation/{correlation_id}`` | ``IncidentMemoryQueryService.list_memories_for_correlation`` | ``IncidentMemoryPage`` |
| GET | ``/api/incident-memories/recent`` | ``IncidentMemoryQueryService.list_recent_memories`` | ``list[IncidentMemoryRecord]`` |

The general list accepts optional ``page`` (default 1), ``page_size``
(default 50, max 200), and ``memory_type`` (a Step 16 ``MemoryType`` value;
an unknown value is rejected with 422 by FastAPI query validation).  No other
filters exist — in particular there is **no free-text, semantic, vector, or
RAG search**.

Route ordering follows the Detection/Correlation/Risk API: the collection
root ``""``, the static ``/recent``, and the segmented
``/correlation/{correlation_id}`` routes are registered *before* the
parameterized ``/{memory_id}`` route so ``/recent`` never resolves as a UUID
path segment.

Authentication
--------------

The existing SentinelAI JWT mechanism is reused verbatim — no second
implementation:

* ``HTTPBearer`` scheme (``app/api/dependencies.py``) plus
  ``get_current_user`` → ``app.core.security.decode_access_token``.
* No Authorization header → **401**.
* Malformed/unknown/expired token → **401**.
* Authentication is checked before any lookup; even a valid memory id is
  rejected without a token.

RBAC
----

The existing ``require_role("admin", "analyst", "ciso")`` factory guards every
incident memory endpoint — the same SOC-reader model used by the Detection,
Correlation, and Risk APIs.  No new roles and no client-supplied role
selection:

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
  Detection/Correlation/Risk APIs use → **422** when violated.
* ``memory_type`` validates against the Step 16 ``MemoryType`` enumeration →
  **422** for unknown values (FastAPI query validation) *before* any service
  or database work.
* Service-level validation failures raised by the Step 18 umbrella are
  translated to **422** by the route error bridge.

Pagination
----------

Pagination and ordering are owned by Step 18, never duplicated in the API:

* 1-based offset pages with database-side totals and deterministic ordering
  (``created_at`` descending, ``memory_id`` ascending).
* ``page``/``page_size`` bounds (`MAX_PAGE_SIZE=200`) are the exact Step 18
  bounds; the correlation-scoped route passes ``page``/``page_size`` through
  unchanged.
* The general-list ``memory_type`` filter is applied database-side by the
  Step 18 repository, and the page ``total`` mirrors the filtered count.
* The recent feed is a bounded list (``limit``, default 50, max 200) and
  returns up to *limit* newest memories in deterministic order — the API
  performs no additional sorting or re-ordering.

Response structure
------------------

Responses are the Step 18 read models (the same pattern the Detection,
Correlation, and Risk APIs follow — query read models used directly as
response models, never raw ORM objects).  For one memory record: ``id``,
``memory_id``, ``memory_type``, ``title``, ``summary``, ``correlation_id``,
``sources``, ``indicators``, ``entities``, ``techniques``, ``findings``,
``actions``, ``outcomes``, ``memory_metadata``, ``confidence``,
``provenance``, ``created_at``, ``updated_at``.

* ``memory_type`` and ``provenance`` are re-validated through their Step 16
  enums at the read edge; ``provenance`` is always ``recalled`` for persisted
  rows (database CHECK constraint).
* ``outcomes`` / ``memory_metadata`` are the persisted forms of the Step 16
  envelope ``outcome`` / ``metadata`` (the record field names the column,
  mirroring the Detection/Correlation/Risk read-record convention).  All
  structured content — sources, indicators, entities, techniques, findings,
  actions, outcomes, metadata — is returned verbatim as stored, deep-copied,
  never re-scanned.
* A page returns ``items`` + ``total`` + requested ``page``/``page_size``;
  **all** historical memories citing a correlation are eligible (never
  collapsed to one), even after a correlation is closed/removed (the plain
  nullable ``correlation_id`` column is deliberately **not** a foreign key).

Error behavior
--------------

The route error bridge mirrors the Detection/Correlation/Risk ``_call_query``
pattern:

| Condition | HTTP |
|-----------|------|
| No/invalid/expired token | 401 |
| Insufficient role | 403 |
| Unknown exact-lookup id | 404 (``Incident memory not found``) |
| Malformed UUID / invalid page / page_size / limit / memory_type | 422 |
| Service validation failure (18) | 422 |
| Sanitized query/database failure (18) | 503 (``Incident memory data is unavailable``) |
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
  exception handler — never payloads or raw error text.

Security
--------

* JWT bearer authentication plus role-based authorization on every route.
* The API surfaces whatever Step 17/18 stored: credential-shaped values in
  structured JSON (e.g. a nested indicator ``token``) were redacted
  (``<redacted>``) by the Step 17 persistence service *before* write, so
  responses contain the stored redacted form — the API is never a weaker read
  path.  Envelope content that was **rejected** at construction (Step 16
  secret-shaped keys such as ``authorization``/``password``/``api_key``/…)
  remains rejected — it can never be stored, so it can never be read back.
* Provenance is preserved verbatim: per-source provenance inside ``sources``
  round-trips unchanged and the record pins ``recalled``.
* No secrets are logged; request/response payloads are not logged.
* Read-only contract: only ``GET``; POST/PUT/PATCH/DELETE return **405**; API
  requests never insert/update/delete rows (verified by tests and live
  PostgreSQL).

PostgreSQL integration
----------------------

Verified end-to-end against the live PostgreSQL instance: memories persisted
through the real Step 17 ``IncidentMemoryPersistenceService`` (via Step 16
``IncidentMemory`` envelopes) are retrieved through the real Step 19 HTTP API
with full fidelity — single lookup, correlation-scoped listing, the recent
feed, deterministic ordering (``created_at`` DESC, ``memory_id`` ASC), the
general-list ``memory_type`` filter, pagination, and the 401/403/404/422/503
contract.  End-to-end redaction through the response (nested indicator
``token`` → ``<redacted>``), raw-credential absence, and read-only behavior
(all reads leave row counts unchanged) were verified, and seeded data was
cleaned up.

Schema state: no **new** migration was created.  Because this API reads the
Step 17 ``incident_memories`` table, the already-written Step 17 migration
(``4a6c8d0e1f2a -> 5b7e9f0a2c3d``) was applied to the live database, so
Alembic is now at head ``5b7e9f0a2c3d`` with no pending operations and a
single head.  ``alembic check`` reports nothing to autogenerate.

Testing
-------

``tests/unit/test_incident_memory_query.py`` — the Step 18 suite — additionally
covers the new read-only ``memory_type`` filter at the service and repository
level: narrowing round-trips, invalid filter rejected before any database
work, delegated-to-repository forwarding, and database-side filtered counting.

``tests/unit/test_incident_memory_api.py`` (TestClient against the full app,
live PostgreSQL, real persistence path) covers:

* authentication — missing header, invalid token, **expired token**, auth
  checked before lookup;
* authorization — admin/analyst/ciso allowed, outsider 403 on every endpoint,
  denial audited, successful reads not audited;
* get-by-id — full fidelity, schema key set, sources/indicators/metadata/
  confidence/provenance preserved, 404, malformed UUID 422;
* correlation-scoped — all historical memories returned, deterministic
  ordering against the persisted row instants, empty 200, pagination across
  pages, max page_size, invalid correlation UUID;
* general list — page envelope, ``memory_type`` filter narrows, filter with no
  matches returns 200 empty, invalid ``memory_type`` 422, deterministic
  pagination;
* recent — marker-membership, multiple results, bounded limit, deterministic
  ordering, **created_at tie-break by memory_id ascending**, invalid limits;
* route ordering — the collection root, ``/recent``, and
  ``/correlation/{id}`` never resolve as ``/{memory_id}``;
* error handling — 503 safe responses with no internals leaked for every
  endpoint, service validation → 422, unexpected error → sanitized 500;
* security — nested secret-shaped values stay ``<redacted>`` through the
  response, raw credentials absent, no database internals in responses, and
  secret-shaped envelope keys are still rejected at construction (never
  stored);
* read-only — no row mutation, GET-only in OpenAPI, 405 for write methods;
* architecture — every route delegates to ``IncidentMemoryQueryService``
  (probe services, including the ``memory_type`` filter pass-through) and the
  route module has no direct database access;
* OpenAPI contract — exact incident memory paths, bearer security on every
  operation, GET-only, unique operation IDs, security scheme declared.

Non-goals
---------

Step 19 does **not** implement: recall/search engines, semantic/RAG/vector
(Qdrant) retrieval, graph databases (Neo4j), AI/LLM reasoning, memory
learning or consolidation, free-text search, deduplication of memories,
creation/update/delete endpoints, alert generation, dashboards or frontends,
new authentication or authorization, new migrations, or any other pipeline
step.  Step 19 is the thin read-only HTTP adapter over the Step 18 query
service only.

Step 19 exposes read-only incident memory retrieval through the API; it does
not recall, search, re-extract, re-interpret, learn from, act on, or persist
memory.