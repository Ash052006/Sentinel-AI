Detection API Layer (Step 9H)
============================

Purpose
-------

Step 9H exposes the Step 9G :class:`~app.services.detection_query.DetectionQueryService`
as a clean, secure, **read-only** FastAPI surface over the Step 9F
persistence contract.  It is a **thin transport layer**: every route validates
its HTTP input, calls exactly one query-service method, and returns a Step 9G
read model.

The Detection API exposes persisted detection data through the Detection
Query Layer.  It does not perform detection, correlation, risk scoring, or
mutation.

Pipeline::

    DetectionAgent
        -> DetectionAnalysis
            -> DetectionPersistenceService        (Step 9F-B, writes)
                -> PostgreSQL
                    -> DetectionQueryService      (Step 9G, read-only)
                        -> Detection API          (Step 9H — this layer)
                            -> future frontend / consumers

Design principles
-----------------

* **Thin transport** — routes contain HTTP concerns only.  No route
  constructs SQL, joins, filters, paginates manually, or converts ORM rows;
  no route performs detection logic or risk/severity calculation.
* **Read-only** — only ``GET`` endpoints exist.  Detection creation remains
  owned by the DetectionAgent + DetectionPersistenceService.
* **Reuses existing security** — every endpoint requires the existing JWT
  ``HTTPBearer`` authentication dependency (``get_current_user``) and the
  existing ``require_role`` RBAC factory.  No second authentication system,
  no query-parameter/body/custom-header auth.
* **Consistent semantics** — exact lookups miss with 404; collection queries
  return 200 with an empty ``items`` list (never 404 for an empty set).
* **Event-scoped analyses** — the Step 9G contract treats an "analysis" as
  the set of ``detection_results`` / ``detection_rule_failures`` rows
  recorded for one ``event_id`` (there is no separate analysis table or
  analysis id), so the analysis paths use the event UUID as the analysis
  identity.

Endpoints
---------

All endpoints are ``GET`` and registered under the existing ``/api`` prefix
with the ``Detections`` tag.

| Method | Path | Response schema | Semantics |
|--------|------|-----------------|-----------|
| GET | ``/api/detections/{detection_id}`` | ``DetectionResultRecord`` | One persisted match by ``detection_id`` (404 if missing) |
| GET | ``/api/detections/event/{event_id}`` | ``DetectionResultPage`` | Bounded page of an event's matches (200 + empty list if none) |
| GET | ``/api/detections/rule/{rule_id}`` | ``DetectionResultPage`` | Bounded page of a rule's matches (200 + empty list if none) |
| GET | ``/api/detections/recent`` | ``list[DetectionResultRecord]`` | Newest matches across all events (bounded feed) |
| GET | ``/api/detection-analyses/{event_id}`` | ``DetectionAnalysisRecord`` | Full event-scoped analysis (results + failures); 404 if the event has neither |
| GET | ``/api/detection-analyses/{event_id}/failures`` | ``DetectionFailurePage`` | Bounded page of the event's rule/engine failures (200 + empty list if none) |

Notes on route matching: the static/segmented paths (``recent``, ``event/...``,
``rule/...``) are registered before the parameterized ``/{detection_id}``
route so ``/api/detections/recent`` can never be parsed as a UUID path segment.
Authentication
--------------

Every detection endpoint requires a valid bearer JWT through the existing
``HTTPBearer`` scheme:

* Missing or malformed request (no ``Authorization: Bearer ...`` header) →
  **401**.
* Invalid/expired JWT → **401**.

No detection endpoint accepts authentication via query parameters, request
bodies, or custom headers.

Authorization
-------------

Detection data is security telemetry.  Each endpoint guards with the
existing ``require_role("admin", "analyst", "ciso")`` dependency — the same
SOC role set the existing ``GET /api/users/security-test`` endpoint uses.

* Authenticated user with an SOC role (admin / analyst / ciso) → allowed.
* Authenticated user with any other role (or no role) → **403**
  ``{"detail": "Insufficient permissions"}``.  The denial is audited by
  ``require_role`` as ``auth.authorization.denied`` through the existing
  audit mechanism.
* No authentication at all → **401**.

There is no way for a registered user to elevate their own role through
these endpoints; they are read-only and never touch user/role data.

Request parameters
------------------

* ``detection_id``, ``event_id`` — UUID path segments typed ``uuid.UUID``.
  A malformed value is rejected by FastAPI path typing with **422** before
  any database work.
* ``rule_id`` — an application-defined identifier string.  Matched exactly;
  never lowercased or otherwise normalized.  The query service is the final
  validation boundary: empty or ``> 255`` character rule IDs are rejected
  with **422**.
* ``page`` — 1-based page number, ``>= 1`` (default 1).
* ``page_size`` — items per page, ``1..200`` (default 50).  Values outside
  the bound are rejected with **422** at the HTTP layer; the service keeps
  the same bounds as its final domain validation.
* ``limit`` (recent feed) — ``1..200`` (default 50); ``> 200`` →
  **422**.

Pagination
----------

Paginated reads use the existing 9G **bounded 1-based offset pagination**.
The response envelope (``DetectionResultPage`` / ``DetectionFailurePage``)
carries ``items``, ``total`` (the full match count, unaffected by
pagination), and the requested ``page``/``page_size``.  Every page is
deterministic:

* results: ``detected_at`` descending, then ``detection_id`` ascending;
* failures: ``failed_at`` descending, then row ``id`` ascending.

The recent feed is a bounded, unpaginated list ordered the same way
(``detected_at`` descending, ``detection_id`` ascending).

Not-found semantics
-------------------

* ``GET /api/detections/{detection_id}`` with an unknown ``detection_id`` →
  **404** ``{"detail": "Detection not found"}``.
* ``GET /api/detection-analyses/{event_id}`` when the event has neither
  results nor failures recorded → **404**
  ``{"detail": "Detection analysis not found"}``.

Empty-list semantics
--------------------

Collection queries never 404 for an empty result set:

* event with no detections → **200** ``DetectionResultPage`` with
  ``items: []``, ``total: 0``;
* rule with no detections → **200** with ``items: []``, ``total: 0``;
* event with no failures (or an unknown event) → **200**
  ``DetectionFailurePage`` with ``items: []``, ``total: 0``.
Response schemas
----------------

Routes return the existing Step 9G read models directly — never ORM models
and never arbitrary database dictionaries:

* ``DetectionResultRecord`` — persisted match: ``id``, ``event_id``,
  ``detection_id``, ``rule_id``, ``rule_type``, ``rule_version``,
  ``severity``, ``matched``, ``confidence``, ``evidence`` (structured dict),
  ``result_metadata`` (structured dict), ``detected_at``, ``provenance``,
  ``created_at``, ``updated_at``.
* ``DetectionFailureRecord`` — persisted failure: ``id``, ``event_id``,
  ``engine``, ``rule_id``, ``error_type``, ``error_message``, ``failed_at``,
  ``provenance``, ``created_at``, ``updated_at``.  Failures remain failures:
  no severity, risk, alert priority, or maliciousness is assigned.
* ``DetectionAnalysisSummary`` / ``DetectionAnalysisRecord`` — event-scoped
  aggregate (counts + time windows) with the full child record lists on the
  record view.
* ``DetectionResultPage`` / ``DetectionFailurePage`` — pagination envelopes.

Error behavior
--------------

* **422** — malformed UUIDs, invalid/oversized pagination, oversized rule
  IDs (from FastAPI path/query typing and from service-level validation
  translated by the route helper).
* **503** — sanitized database/query failures
  (``DetectionQueryError``) become ``{"detail": "Detection data is
  unavailable"}``, matching the existing ``get_db`` / health
  unavailability convention.  Raw driver/SQL text is logged server-side by
  the query service and never reaches the client.
* **500** — unexpected exceptions propagate to the existing centralized
  exception handler, which logs the traceback server-side and returns
  ``{"detail": "Internal server error"}``.

No duplicate global exception handlers were added; the route module
translates only the query service's own exception types.

Security considerations
-----------------------

* Sensitive detection telemetry is only reachable with an authenticated
  SOC-role bearer token.
* Responses are schema-validated read models; the Step 9F secret-safety
  guarantees (key-redacted evidence/metadata, bounded strings) are never
  bypassed.
* Successful reads are not logged (matching the existing convention — only
  authorization denials and failures are); the query service logs raw
  failures server-side only.

Read-only nature
----------------

* The API defines **no** ``POST``/``PUT``/``PATCH``/``DELETE`` detection
  endpoints — the OpenAPI document exposes ``get`` only for every detection
  path, and write methods return 405.
* The routes never call ``add``/``flush``/``commit``; the query service is
  read-only by contract.
* No frontend, correlation, risk scoring, or any other future SentinelAI
  functionality is added by this step.

No schema changes
-----------------

Step 9H introduces **no migration and no schema drift** — ``alembic check``
reports *"No new upgrade operations detected."*  Every query column is
covered by the existing Step 9F-A indexes.

File map
--------

| File | Purpose |
|------|---------|
| ``app/api/routes/detections.py`` | detection + detection-analyses routers (Step 9H) |
| ``app/api/router.py`` | router registration (``/detections``, ``/detection-analyses``, ``Detections`` tag) |
| ``tests/unit/test_detection_api.py`` | API behavior tests (auth, RBAC, pagination, read-only, sanitization, OpenAPI) |