Correlation Query Layer (Step 10D)
==================================

Purpose
-------

Step 10D adds a **read-only query layer** over the Step 10C persistence
contract.  It turns persisted ``correlation_results`` / ``correlation_members``
rows back into validated, consumer-safe read models with no write surface.  A
future correlation API will call its service instead of touching the repository
or the database directly.

This is a **read layer only**.  It contains:

* read-model schemas (:mod:`app.schemas.correlation_query`);
* read-only methods on the existing :class:`CorrelationRepository`;
* a new :class:`CorrelationQueryService` with validation, safe error
  sanitization, and domain/read-model conversion.

It does **not** contain API endpoints, frontends, incident/risk handling,
response, or any write/commit path.  The query layer adds **no new database
tables and no migration** — every query runs over the indexes already defined
by the Step 10C-A migration.  ``alembic check`` remains clean.

::

    Step 10D provides read-only correlation queries.  It does not create
    correlations, expose a correlation API, calculate risk, create incidents,
    map MITRE ATT&CK, or perform response.

Design principles
-----------------

* **Read-only**: the service never calls ``add``/``delete``, ``flush``,
  ``commit``, or ``rollback`` on the session.  Callers own the transaction;
  a database failure raised by a read leaves the transaction untouched and
  the session owner decides whether to roll back.
* **Contract-faithful**: read models expose persisted rows only.  The Step
  10A authoring contract is authoritative — the query layer never invents or
  re-emits computed views (e.g. aggregated ``detection_ids`` / time windows).
* **Validated input**: correlation/detection/event UUIDs, page numbers
  (``>= 1``), page sizes (``1..200``), and recent-feed limits (``1..200``)
  are validated *before* any database work.
* **Deterministic ordering**: every list returns a stable two-key order — the
  person-level ``timestamp`` descending with ``correlation_id`` ascending as
  tie-break (both columns unique, so ordering is total and page boundaries
  never drift between calls).
* **Distinct parents**: detection- and event-scoped lists return each parent
  correlation at most once (an ``IN`` subquery over ``correlation_members``),
  while a correlation's detail preserves every member reference exactly as
  persisted — including duplicates.
* **No N+1**: detail and list reads embed members via one bulk query
  (``get_members_for_correlations``) per call, never one query per
  correlation.
* **Sanitized failures**: repository/database errors surface as
  :class:`CorrelationQueryError`; raw driver/SQL text is logged server-side
  and never reaches the consumer.

File map
--------

| File | Purpose |
|------|---------|
| ``app/schemas/correlation_query.py`` | read models (``CorrelationResultRecord``, ``CorrelationMemberRecord``, ``CorrelationPage``) |
| ``app/repositories/correlation.py`` | read-only repository operations (Step 10D additions) |
| ``app/services/correlation_query.py`` | ``CorrelationQueryService`` + bounded pagination constants |
| ``tests/unit/test_correlation_query.py`` | Step 10D behavior tests |

Pagination semantics
--------------------

Paginated reads use **bounded 1-based offset pagination**:

* ``page`` starts at 1; ``page_size`` defaults to 50 and is capped at 200.
* Every page call performs a database-side ``count`` (for ``total``) plus a
  ``limit``/``offset`` query; ``total`` is unaffected by pagination, so
  beyond-bounds pages return empty ``items`` with the correct ``total``.
* Requests violating the bounds raise :class:`CorrelationQueryValidationError`
  *before* touching the database.
* The **recent-correlations feed** is deliberately not paginated — it mirrors
  the threat-intel / detection ``get_recent...`` convention and returns a
  bounded list (default 50, capped at 200).

Ordering guarantees
-------------------

| Query | Primary key | Tie-break |
|-------|-------------|-----------|
| correlations for detection | ``timestamp DESC`` | ``correlation_id ASC`` |
| correlations for event | ``timestamp DESC`` | ``correlation_id ASC`` |
| recent correlations | ``timestamp DESC`` | ``correlation_id ASC`` |
| members (detail/bulk) | ``correlation_id ASC`` | ``member_order ASC`` |

Both tie-break columns are unique, so ordering is total and stable.

Read models
-----------

Reading is **members-in-view**: a returned correlation (detail, page item, or
feed item) always carries its fully loaded members.

### Result record — ``CorrelationResultRecord``

| Field | Notes |
|-------|-------|
| ``id`` / ``correlation_id`` | row PK / Step 10A unique identity |
| ``status`` / ``confidence`` | persisted evaluation outcome (``candidate``/``active``/``closed``; confidence ``0..1`` or ``None``) |
| ``evidence`` / ``result_metadata`` | plain ``dict`` of the stored JSONB (already secret-redacted at write) |
| ``timestamp`` | Step 10A correlation timestamp, UTC tz-aware |
| ``provenance`` | ``CORRELATED`` (CHECK-constrained) |
| ``members`` | embedded ``CorrelationMemberRecord`` list, preserved order |
| ``created_at`` / ``updated_at`` | persistence timestamps |

### Member record — ``CorrelationMemberRecord``

Role-matched copy of a ``correlation_members`` row: ``detection_id`` /
``event_id`` (references, never copies of detection rows), ``timestamp``,
``member_order``.

### Page — ``CorrelationPage``

Bounded envelope with ``items``, ``total``, and echoed ``page`` / ``page_size``.

Repository operations (Step 10D additions)
------------------------------------------

All repository reads honour deterministic ordering and never commit.  The
existing Step 10C-B write methods (``add``, ``get_by_correlation_id``,
``get_members_for_correlation``) are unchanged and continue to serve the
persistence path.

| Method | Behaviour |
|--------|-----------|
| ``get_members_for_correlations(correlation_ids)`` | bulk member load for N+1-free composition |
| ``list_correlations_for_detection(detection_id, *, limit, offset)`` | distinct detection-scoped correlations |
| ``list_correlations_for_event(event_id, *, limit, offset)`` | distinct event-scoped correlations |
| ``list_recent_correlations(*, limit)`` | newest correlations across all rows |
| ``count_correlations()`` | total rows (pagination ``total``) |
| ``count_correlations_for_detection`` / ``count_correlations_for_event`` | distinct-parent counts on the database side |

Every ``*_member`` filter column and every ordering column is backed by a Step
10C-A index, so no migration or new index is required.

Service API
-----------

:class:`CorrelationQueryService` follows the persistence-service convention of
taking the caller-owned ``db`` session first; a ``repository_factory`` is
injected for testability::

    service = CorrelationQueryService()
    record  = service.get_correlation(db, correlation_id)          # detail (+ members) | None
    page    = service.list_correlations_for_detection(db, detection_id, page=1, page_size=50)
    page    = service.list_correlations_for_event(db, event_id, page=1, page_size=50)
    feed    = service.list_recent_correlations(db, limit=50)
    total   = service.count_correlations(db)
    count   = service.count_correlations_for_detection(db, detection_id)
    count   = service.count_correlations_for_event(db, event_id)

* ``get_correlation`` accepts a ``uuid.UUID`` or its 36-char string form and
  returns :class:`CorrelationResultRecord | None`.
* ``list_*`` methods return :class:`CorrelationPage` envelopes with members
  embedded (bulk-loaded, no N+1).
* Timestamps read from SQLite (naive UTC) are normalized to tz-aware UTC at
  the read boundary, giving identical records on both test and production
  backends.

Error handling
--------------

* :class:`CorrelationQueryValidationError` — invalid input (malformed UUIDs,
  out-of-bounds page/limit).  Raised **before** any database work.
* :class:`CorrelationQueryError` — a repository/database failure.  Messages
  contain only safe context (e.g. the correlation UUID plus a fixed reason
  such as ``failed to load correlation``); the underlying exception is logged
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

``tests/unit/test_correlation_query.py`` runs against an in-memory SQLite
engine with the PostgreSQL ``JSONB`` column rendered as ``JSON`` (the same
test-only type-compiler visitor the Step 10C / 9F suites use) and
``PRAGMA foreign_keys=ON`` so FK cascade/rejection behaviour matches
PostgreSQL.  It covers:

* round-trip reads through the real :class:`CorrelationPersistenceService`;
* not-found (``None``) and empty-list behaviour;
* detection- and event-scoped lists (one-to-one, one-to-many, empty, scoped
  across many detections/events) including duplicate-membership semantics;
* pagination bounds, totals, beyond-bounds pages, invalid page/limit
  validation, and deterministic tie-breaking on equal timestamps;
* database-side distinct counts (total / detection / event);
* data fidelity (confidence boundaries, evidence, metadata, provenance,
  status, timestamps, multi-member/multi-event, members embedded in every
  view) plus a no-N+1 statement-count check;
* security — the query path surfaces write-side-redacted values (token,
  auth-header, password keys) and sanitized errors containing no secrets or
  raw SQL;
* the read-only contract — no writes on any operation, and reads never flush
  concurrently-staged pending rows; returned records are independent of the
  stored rows;
* database behaviour — empty DB, multiple records, and FK-cascade deletions
  reflected immediately.

Live PostgreSQL verification
----------------------------

Beyond the SQLite suite, the query layer was exercised against the real
PostgreSQL instance with the same 35 assertions as Step 10C's live check:
persistence + idempotent re-persist, full detail round-trip (including
write-side redaction of the ``token`` metadata key), detection/event-scoped
lists with ordering, bounded recent feed, page totals with beyond-bounds
behaviour, distinct-parent counts, duplicate-member query parity, and a
run-tagged cleanup that leaves the database empty afterwards.

Regression & compatibility
--------------------------

* Target suites (10A/10B/10C/9G + 10D): 342 passed.
* Full suite: 1865 passed, 0 failed (1819 Step 10C baseline + 46 new Step 10D
  tests).
* ``alembic check``: "No new upgrade operations detected." — single head
  ``72c9d41e8b3f``, unchanged from Step 10C.
* ``python -m compileall app tests``: clean.

Non-goals (explicitly out of scope for this step)
-------------------------------------------------

* No API endpoints / routes / OpenAPI exposure (``app/api/router.py``
  untouched — no correlation endpoints exist).
* No creation of correlations — Step 10B/10C remain the only writers.
* No risk scoring, verdicts, incidents, or MITRE ATT&CK mapping.
* No response/SOAR behaviour, frontend, Kafka, OpenSearch/Qdrant/Neo4j, or
  LLM/AI integration.
* No schema changes, no Alembic migration, no new indexes, no caching or
  query statistics.