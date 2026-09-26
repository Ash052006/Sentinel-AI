Incident Memory Query Layer (Step 18)
=====================================

Purpose
-------

Step 18 adds a **read-only query layer** over the Step 17 incident memory
persistence contract.  It turns persisted ``incident_memories`` rows back
into validated, consumer-safe read models with no write surface.  A future
incident memory recall/retrieval API will call its service instead of
touching the repository or the database directly.

This is a **read layer only**.  It contains:

* read-model schemas (:mod:`app.schemas.incident_memory_query`);
* read-only methods on the existing
  :class:`IncidentMemoryRepository`;
* a new :class:`IncidentMemoryQueryService` with validation, safe error
  sanitization, and domain/read-model conversion.

It does **not** contain API endpoints, frontends, recall/retrieval
behaviour, response, or any write/commit path.  The query layer adds **no
new database tables, no new indexes, and no migration** — every query runs
over the columns already defined by the Step 17 migration (``memory_id``
is unique and indexed, ``correlation_id`` is deterministically indexed).

::

    Step 18 provides read-only incident memory queries.  It does not
    create memories, persist anything, expose a memory API, perform
    recall/retrieval, or execute response behaviour.

Design principles
-----------------

* **Read-only**: the service never calls ``add``/``delete``, ``flush``,
  ``commit``, or ``rollback`` on the session.  Callers own the transaction;
  a database failure raised by a read leaves the transaction untouched and
  the session owner decides whether to roll back.
* **Persisted view**: read models mirror the Step 17 ``incident_memories``
  columns — including the column names ``outcomes`` and
  ``memory_metadata``, which differ from the Step 16 envelope field names
  (``outcome`` / ``metadata``).  The query layer never re-emits derived or
  envelope-only fields (the envelope's own ``created_at`` is contract
  metadata and is not re-emitted here).
* **Types re-validated at the read edge**: ``memory_type`` and
  ``provenance`` are re-validated through the Step 16
  :class:`~app.schemas.incident_memory.MemoryType` / Step 14
  :class:`~app.schemas.security_event.Provenance` enums, so a corrupt raw
  column value surfaces as a controlled query failure — never as an
  unvalidated string.
* **Validated input**: memory/correlation UUIDs, page numbers (``>= 1``),
  page sizes (``1..200``), and recent-feed limits (``1..200``) are
  validated *before* any database work.
* **Deterministic ordering**: every list returns a stable two-key order —
  row ``created_at`` descending with ``memory_id`` ascending as tie-break
  (both columns effective per-row, so ordering is total and page
  boundaries never drift between calls).
* **Sanitized failures**: repository/database errors surface as
  :class:`IncidentMemoryQueryError`; raw driver/SQL text and payloads are
  logged server-side and never reach the consumer.
* **No secrets re-scan (verbatim payloads)**: the already-redacted
  structured JSONB columns are surfaced verbatim — never re-scanned.  A
  re-scan through the Step 16 secret scanners would *falsely reject* the
  legitimate ``<redacted>`` markers the Step 17 write path installed; the
  query layer only surfaces what the persistence contract already
  rejected/redacted before write.

File map
--------

| File | Purpose |
|------|---------|
| ``app/schemas/incident_memory_query.py`` | read models (``IncidentMemoryRecord``, ``IncidentMemoryPage``) |
| ``app/repositories/incident_memory.py`` | read-only repository operations (Step 18 additions) |
| ``app/services/incident_memory_query.py`` | ``IncidentMemoryQueryService`` + bounded pagination constants |
| ``tests/unit/test_incident_memory_query.py`` | Step 18 behavior tests |

Pagination semantics
--------------------

Paginated reads use **bounded 1-based offset pagination**:

* ``page`` starts at 1; ``page_size`` defaults to 50 and is capped at 200.
* Every page call performs a database-side ``count`` (for ``total``) plus a
  ``limit``/``offset`` query; ``total`` is unaffected by pagination, so
  beyond-bounds pages return empty ``items`` with the correct ``total``.
* Requests violating the bounds raise
  :class:`IncidentMemoryQueryValidationError` *before* touching the
  database.
* The **recent-memories feed** is deliberately not paginated — it mirrors
  the correlation/risk recent-feed convention and returns a bounded list
  (default 50, capped at 200).

Ordering guarantees
-------------------

| Query | Primary key | Tie-break |
|-------|-------------|-----------|
| all memories | ``created_at DESC`` | ``memory_id ASC`` |
| memories for correlation | ``created_at DESC`` | ``memory_id ASC`` |
| recent memories | ``created_at DESC`` | ``memory_id ASC`` |

Both columns are unique per row, so ordering is total and stable, and page
boundaries never drift.

Correlation scoping
-------------------

One query specialises on the Step 17 persistence semantics:
``list_memories_for_correlation`` matches the **plain, nullable
``correlation_id`` column** — deliberately **not** a foreign key (the Step
17 decision that historical recall memory must outlive the correlation
lifecycle).  Memories therefore remain retrievable after a cited
correlation is closed or removed; scoping follows the stored column,
never a join.

Read models
-----------

### Result record — ``IncidentMemoryRecord``

| Field | Notes |
|-------|-------|
| ``id`` / ``memory_id`` | row PK / Step 16 unique identity (the query key) |
| ``memory_type`` | Step 16 ``MemoryType``, re-validated through the enum at the read edge |
| ``title`` / ``summary`` | bounded Step 16 values as stored (summary is ``""`` when the envelope carried none) |
| ``correlation_id`` | plain nullable UUID (no FK), or ``None`` |
| ``sources`` / ``indicators`` / ``entities`` / ``techniques`` / ``findings`` / ``actions`` | structured ``list[dict]`` of the stored JSONB (already redacted at write), surfaced verbatim |
| ``outcomes`` / ``memory_metadata`` | structured ``dict`` of the stored JSONB (already redacted at write), surfaced verbatim |
| ``confidence`` | Step 16 bounded confidence ``0..1`` or ``None`` (CHECK-constrained) |
| ``provenance`` | ``RECALLED`` (CHECK-constrained), re-validated through the enum |
| ``created_at`` / ``updated_at`` | the row's Step 17 bookkeeping instants (UTC, tz-aware) |

The record is intentionally a **persisted view**: the columns carry the
Step 17 names (``outcomes``/``memory_metadata``) rather than the Step 16
envelope names (``outcome``/``metadata``), and the envelope's own
``created_at`` (deterministic contract metadata) is not re-emitted.

### Page — ``IncidentMemoryPage``

Bounded envelope with ``items``, ``total``, and echoed ``page`` / ``page_size``.

Repository operations (Step 18 additions)
-----------------------------------------

All repository reads honour deterministic ordering and never commit.  The
existing Step 17 methods (``add``, ``get_by_memory_id``,
``count_memories``) are unchanged and continue to serve the persistence
path.

| Method | Behaviour |
|--------|-----------|
| ``list_memories(*, limit, offset)`` | one bounded page of all memories, newest first |
| ``list_memories_for_correlation(correlation_id, *, limit, offset)`` | bounded page of memories citing the plain ``correlation_id`` column |
| ``list_recent_memories(*, limit)`` | newest memories across all rows |
| ``count_memories()`` | total rows (pagination ``total``) |
| ``count_memories_for_correlation(correlation_id)`` | citing-memory count on the database side |

Service API
-----------

:class:`IncidentMemoryQueryService` follows the persistence-service
convention of taking the caller-owned ``db`` session first; a
``repository_factory`` is injected for testability::

    service = IncidentMemoryQueryService()
    record  = service.get_memory(db, memory_id)          # detail | None
    page    = service.list_memories(db, page=1, page_size=50)
    page    = service.list_memories_for_correlation(db, correlation_id, page=1, page_size=50)
    feed    = service.list_recent_memories(db, limit=50)
    total   = service.count_memories(db)
    count   = service.count_memories_for_correlation(db, correlation_id)

* ``get_memory`` and ``list_memories_for_correlation`` accept a
  ``uuid.UUID`` or its 36-char string form.
* ``list_*`` methods return :class:`IncidentMemoryPage` envelopes.
* Timestamps read from SQLite (naive UTC) are normalized to tz-aware UTC at
  the read boundary, giving identical records on both test and production
  backends.

Error handling
--------------

* :class:`IncidentMemoryQueryValidationError` — invalid input (malformed
  UUIDs, out-of-bounds page/limit).  Raised **before** any database work.
* :class:`IncidentMemoryQueryError` — a repository/database failure (or an
  out-of-enum stored ``memory_type``/``provenance``).  Messages contain
  only safe context (e.g. the ``memory_id`` plus a fixed reason such as
  ``failed to load incident memory``); the underlying exception is logged
  and preserved as ``__cause__``.  Consumers never see raw driver text,
  SQL, credentials, payloads, or tracebacks.

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
* Returned records are deep-copied from the persisted rows, so mutating a
  record never mutates stored data.

Testing
-------

``tests/unit/test_incident_memory_query.py`` runs against an in-memory
SQLite engine with the PostgreSQL ``JSONB`` column rendered as ``JSON``
(the same test-only type-compiler visitor the Step 17 suite uses).
Deterministic listing is asserted by explicitly supplying row
``created_at`` instants (overriding the SQLAlchemy Python-side defaults)
and using letter-bearing UUIDs for tie-break checks.  It covers:

* round-trip reads through the real
  :class:`IncidentMemoryPersistenceService`, including per-source
  provenance preserved verbatim and ``summary`` normalized to ``""``;
* not-found (``None``) and empty behaviors;
* correlation-scoped lists (one-to-one, one-to-many, empty, scoped across
  many correlations, NULL ``correlation_id`` never matched);
* pagination bounds, totals, beyond-bounds pages, invalid page/limit
  validation, and deterministic tie-breaking on equal ``created_at``;
* database-side counts (total / for-correlation);
* data fidelity (confidence ``None`` and boundaries, provenance always
  ``RECALLED``, structured payloads round-tripped verbatim, timestamps
  tz-aware);
* security — the query path surfaces write-side-redacted values (e.g. a
  nested ``token`` marker) and sanitized errors containing no secrets or
  raw SQL;
* the read-only contract — no writes on any operation, reads never flush
  concurrently-staged pending rows; returned records are independent of the
  stored rows;
* database behaviour — empty DB, multiple records, and deletions reflected
  immediately.

Regression & compatibility
--------------------------

* Incident-memory suites (Step 16/17/18): 59 passed.
* Full unit suite: **3405 passed, 2 skipped, 0 errors** (previous baseline
  3360 passed / 2 skipped / 7 errors; Step 18 adds 38 tests and the Step 17
  suite's collection errors are resolved).
* Alembic state *unchanged*: heads ``5b7e9f0a2c3d``, current
  ``4a6c8d0e1f2a`` — the pre-existing "not up to date" message reflects the
  as-yet-unpromoted Step 17 migration; **Step 18 adds no migration**.
* ``python -m compileall app tests``: clean.

Non-goals (explicitly out of scope for this step)
-------------------------------------------------

* No API endpoints / routes / OpenAPI exposure (``app/api/router.py``
  untouched — no incident memory endpoints exist).
* No creation of incident memories — Step 16/17 remain the only writers.
* No recall/retrieval behaviour, no re-extraction, no reasoning about
  memory, no similarity/hunting semantics.
* No response/SOAR behaviour, frontend, Kafka, vector store/embedding
  (Qdrant), or LLM/AI integration — Step 19 (recall) owns that surface.
* No schema changes, no Alembic migration, no new indexes, no caching or
  query statistics.