Detection Query & Retrieval Layer (Step 9G)
==========================================

Purpose
-------

Step 9G adds a **read-only query layer** over the Step 9F persistence
contract.  It turns persisted ``detection_results`` /
``detection_rule_failures`` rows back into validated, consumer-safe read
models without any write surface: a future read API (Step 9I-era) will call
its service instead of touching the repository or the database.

This is a **read layer only**.  It contains:

* read-model schemas (:mod:`app.schemas.detection_query`);
* read-only methods on the existing :class:`DetectionRepository`;
* a new :class:`DetectionQueryService` with validation, safe error
  sanitization, and domain/read-model conversion.

It does **not** contain API endpoints, frontends, correlation, risk scoring,
schema changes, or any write/commit path.  The query layer adds **no new
database tables and no migration** — every query runs over the indexes
already defined by the Step 9F-A migration.

Design principles
-----------------

* **Read-only**: the service never calls ``add``/``delete``, ``flush``,
  ``commit``, or ``rollback`` on the session.  Callers own the transaction;
  if a query raises because of a real database failure, the owner of the
  session decides whether to roll that session back.
* **Domain conversion**: persistent rows become read models
  (:class:`DetectionResultRecord`, :class:`DetectionFailureRecord`); the
  authoring contracts (Step 9A/9E) are never re-emitted.
* **Validated input**: detection/event UUIDs, rule IDs (non-empty, bounded to
  255 chars), page numbers (``>= 1``), page sizes (``1..200``), and recent
  feed limits (``1..200``) are validated *before* any database work.
* **Deterministic ordering**: every list returns a stable two-key order so a
  page boundary never exposes duplicate or missing rows between calls.
* **Eager-load composition**: ``get_analysis_with_children`` issues exactly
  two bulk queries (all results, all failures) and composes them — never one
  query per child, so there is no N+1.
* **Sanitized failures**: repository/database errors surface as
  :class:`DetectionQueryError`; raw driver/SQL text is logged server-side and
  never reaches the consumer.

File map
--------

| File | Purpose |
|------|---------|
| ``app/schemas/detection_query.py`` | read models (records, analysis views, pages) |
| ``app/repositories/detection.py`` | read-only repository operations (Step 9G additions) |
| ``app/services/detection_query.py`` | ``DetectionQueryService`` + bounded pagination constants |
| ``tests/unit/test_detection_query.py`` | Step 9G behavior tests |

Pagination semantics
--------------------

Paginated reads use **bounded 1-based offset pagination**:

* ``page`` starts at 1; ``page_size`` defaults to 50 and is capped at 200.
* Every page call performs a ``count`` (for ``total``) plus a
  ``limit``/``offset`` query; ``total`` is unaffected by pagination, so
  beyond-bounds pages return empty ``items`` with the correct ``total``.
* Requests violating the bounds raise
  :class:`DetectionQueryValidationError` *before* touching the database.
* The **recent-results feed** is deliberately not paginated — it mirrors the
  threat-intel ``get_recent_lookups(limit=...)`` convention and returns a
  bounded list (default 50, capped at 200).

Ordering guarantees
-------------------

| Query | Primary key | Tie-break |
|-------|-------------|-----------|
| results for event / rule | ``detected_at DESC`` | ``detection_id ASC`` |
| recent results | ``detected_at DESC`` | ``detection_id ASC`` |
| failures for event | ``failed_at DESC`` | row ``id ASC`` |

Both tie-break columns are unique, so ordering is total and stable.

Read models
-----------

### Result record — ``DetectionResultRecord``

| Field | Notes |
|-------|-------|
| ``id`` / ``detection_id`` | row PK / Step 9A unique identity |
| ``event_id`` | originating event |
| ``rule_id`` / ``rule_type`` / ``rule_version`` | evaluated rule identity |
| ``severity`` / ``confidence`` / ``matched`` | persisted evaluation outcome |
| ``evidence`` / ``result_metadata`` | plain ``dict`` of the stored JSONB |
| ``detected_at`` | UTC tz-aware instant |
| ``provenance`` | ``DETECTED`` (CHECK-constrained) |
| ``created_at`` / ``updated_at`` | persistence timestamps |

### Failure record — ``DetectionFailureRecord``

Role-matched copy of a ``detection_rule_failures`` row (``engine``,
``rule_id``, ``error_type``, ``error_message``, ``failed_at``, ...).

### Analysis views (event-scoped)

Detection persistence has no separate analysis table — an "analysis" is the
set of result + failure rows recorded for one ``event_id``.  Two views are
provided:

* ``DetectionAnalysisSummary`` — cheap aggregate from two queries (counts +
  first/last time windows per table); ``None`` when the event has no rows.
* ``DetectionAnalysisRecord`` — extends the summary with the full
  ``results`` and ``failures`` child records (eager-loaded, no N+1).
Repository operations (Step 9G additions)
-----------------------------------------

All repository reads honour deterministic ordering and never commit.  The
existing Step 9F-B idempotency queries (``get_result_by_detection_id``,
``find_existing_failure``) are unchanged and continue to serve the write
path.

| Method | Behaviour |
|--------|-----------|
| ``get_results_for_event(event_id, *, limit, offset)`` | deterministic event-scoped results (extended with ``offset``) |
| ``get_results_for_rule(rule_id, *, limit, offset)`` | deterministic rule-scoped results (extended with ``offset``) |
| ``list_recent_results(*, limit)`` | newest matches across all events |
| ``count_results_for_event`` / ``count_results_for_rule`` | match totals (pagination ``total``) |
| ``get_results_overview`` / ``get_failures_overview`` | count + first/last time windows per event |
| ``get_failures_for_event(event_id, *, limit, offset)`` | deterministic event-scoped failures (extended with ``offset``) |
| ``count_failures_for_event`` | failure total (pagination ``total``) |

Every ``*_event``/``*_rule`` filter column and every ordering column is
backed by a Step 9F index, so no migration or new index is required.

Service API
-----------

:class:`DetectionQueryService` follows the persistence-service convention of
taking the caller-owned ``db`` session first; a ``repository_factory`` is
injected for testability::

    service = DetectionQueryService()
    record   = service.get_result(db, detection_id)
    page     = service.list_results_for_event(db, event_id, page=1, page_size=50)
    page     = service.list_results_for_rule(db, rule_id, page=1, page_size=50)
    feed     = service.list_recent_results(db, limit=50)
    page     = service.list_failures_for_analysis(db, event_id, page=1, page_size=50)
    summary  = service.get_analysis(db, event_id)              # aggregate (or None)
    view     = service.get_analysis_with_children(db, event_id) # + children (or None)

* ``get_result`` returns :class:`DetectionResultRecord | None`.
* ``list_*`` methods return page envelopes (``items`` + ``total`` + echoed
  ``page``/``page_size``).
* ``get_analysis`` / ``get_analysis_with_children`` return ``None`` when the
  event has neither results nor failures recorded.
* Timestamps read from SQLite (naive UTC) are normalized to tz-aware UTC at
  the read boundary, giving identical records on both test and production
  backends.

Error handling
--------------

* :class:`DetectionQueryValidationError` — invalid input (malformed UUIDs,
  empty/oversized rule IDs, out-of-bounds page/limit).  Raised **before**
  any database work.
* :class:`DetectionQueryError` — a repository/database failure.  Messages
  contain only safe context (e.g. the event UUID plus a fixed reason such as
  ``failed to list detection results``); the underlying exception is logged
  and preserved as ``__cause__``.  Consumers never see raw driver text, SQL,
  credentials, or tracebacks.

Read-only contract
------------------

* The repository and service contain **no** write operations for the query
  path: no ``INSERT``/``UPDATE``/``DELETE``, no ``flush``, no ``commit``.
* The service performs all reads through the repository; a session that has
  concurrently-staged (uncommitted) writes keeps them staged — the query
  layer never flushes or commits anything.
* Database errors raised by reads leave the session transaction untouched;
  the caller owns rollback decisions (mirroring the persistence service's
  transaction ownership rule, inverted for the read side).

Testing
-------

``tests/unit/test_detection_query.py`` runs against an in-memory SQLite
engine with the PostgreSQL ``JSONB`` column rendered as ``JSON`` (the same
test-only type-compiler visitor the Step 8C-B / 9F suites use).  It covers:

* round-trip reads through the real :class:`DetectionPersistenceService`;
* not-found (``None``) and empty-list behaviour;
* pagination bounds, totals, beyond-bounds pages, and invalid page/limit
  validation;
* deterministic tie-breaking on equal timestamps;
* summary and with-children analysis views (including a no-N+1 statement
  count check);
* the read-only contract — no writes on any operation, and reads never flush
  concurrently-staged pending rows;
* sanitized database errors (no raw driver/SQL text, event-id preserved).

Non-goals (explicitly out of scope for this step)
-------------------------------------------------

* No API endpoints / routes / OpenAPI exposure.
* No correlation, risk scoring, verdicts, or MITRE mapping.
* No schema changes, no Alembic migration, no new indexes.
* No write path, caching, or query statistics tracking.