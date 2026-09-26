Correlation Persistence (Step 10C)
==================================

Purpose
-------

Step 10C persists the correlation results produced by the Step 10B
``CorrelationAgent`` (itself built on the Step 10A correlation contract)
into PostgreSQL.  It is the correlation analogue of the Step 9F-B detection
persistence service and the threat-intelligence persistence service: one
schema, one repository, one transactional service, and agent wiring via an
injected side-effect sink.

Scope
-----

What Step 10C does:

* Defines two persisted entities: ``correlation_results`` (one row per
  correlation, keyed by ``correlation_id``) and ``correlation_members``
  (one lightweight reference row per member, in ``member_order``).
* Provides ``CorrelationRepository`` (staging only, never commits), the
  ``CorrelationPersistenceService`` (owns the transaction, idempotency,
  redaction, and validation), and module-level convenience wrappers.
* Wires the Correlation Agent to persistence through an injected
  ``persistence`` callback and a bound ``persist_correlations_bound``
  helper, so the agent stays a pure orchestrator.
* Ships Alembic migration ``72c9d41e8b3f`` (create correlation persistence
  tables) and a unit/integration battery plus live-PostgreSQL verification.

Step 10A contract recap
-----------------------

A Step 10A ``CorrelationResult`` carries:

* ``correlation_id`` — the unique correlation identity (idempotency key),
* ``members`` — ordered list of ``CorrelationMember`` references
  (``detection_id``, ``event_id``, ``timestamp``),
* ``status`` — ``candidate`` | ``active`` | ``closed``,
* ``confidence`` — ``0.0 .. 1.0`` or ``None``,
* ``evidence`` and ``metadata`` — structured, JSON-compatible dicts,
* ``timestamp`` — the correlation timestamp (timezone-aware),
* ``provenance`` — always ``Provenance.CORRELATED``.

Mapping to tables::

    CorrelationResult[]
        -> correlation_results      (one row per correlation, by correlation_id)
            -> correlation_members  (one reference row per member, member_order 0..n)

Data model
----------

Two models using the existing ``Base`` / ``UUIDTimestampMixin``:

### ``correlation_results`` (``CorrelationResult``)

| Column | Type | Req | Notes |
|--------|------|-----|-------|
| ``id`` | UUID (PK, mixin) | yes | auto-generated |
| ``correlation_id`` | UUID | yes | Step 10A identity; **unique** — idempotency key |
| ``status`` | Enum(CorrelationStatus) | yes | ``candidate`` \\| ``active`` \\| ``closed`` |
| ``confidence`` | Float | no | ``NULL`` or in ``[0.0, 1.0]`` — **CHECK-constrained** |
| ``evidence`` | JSONB | yes | structured, bounded; redacted |
| ``result_metadata`` | JSONB | yes | structured, bounded; redacted |
| ``timestamp`` | DateTime(tz) | yes | correlation timestamp |
| ``provenance`` | String(32) | yes | **CHECK-constrained to ``correlated``** |
| ``created_at``/``updated_at`` | DateTime(tz, mixin) | yes | |

### ``correlation_members`` (``CorrelationMember``)

| Column | Type | Req | Notes |
|--------|------|-----|-------|
| ``id`` | UUID (PK, mixin) | yes | |
| ``correlation_id`` | UUID | yes | **FK → ``correlation_results.correlation_id``, ON DELETE CASCADE** |
| ``detection_id`` | UUID | yes | referenced detection (logical FK) |
| ``event_id`` | UUID | yes | originating event (logical FK) |
| ``timestamp`` | DateTime(tz) | yes | member timestamp |
| ``member_order`` | Integer | yes | 0-based position; **UNIQUE with ``correlation_id``** |

Constraints
-----------

Enforced both at the model layer and verified live in PostgreSQL DDL:

* ``correlation_id`` UNIQUE — idempotency identity.
* ``(correlation_id, member_order)`` UNIQUE — one ordered membership per
  correlation.
* FK ``correlation_members.correlation_id → correlation_results.correlation_id``
  **ON DELETE CASCADE** — deleting a correlation removes its members.
* CHECK ``provenance = 'correlated'`` — correlation evidence can never be
  persisted under another provenance.
* CHECK ``confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)``.

No physical FK links ``detection_id``/``event_id``: SentinelAI has no
persisted ``events``/detections-by-id join tables yet, so members are
lightweight references (mirroring detection/TI ``event_id`` conventions).
Duration of a real ``events`` model, these become hard FKs unchanged.

Idempotency semantics
---------------------

* A correlation is identified by its unique ``correlation_id``.  Re-persisting
  the **same** result is a no-op (skipped, counted in ``correlations_skipped``).
* A re-correlation with a **fresh** ``correlation_id`` is a new, legitimate
  historical row.
* Same-batch duplicates of one ``correlation_id`` persist only the first and
  skip the rest.
* The service never deletes or mutates existing rows on re-persist.

Provenance and confidence guarantees
------------------------------------

* Every row is written with ``Provenance.CORRELATED``; the CHECK constraint
  blocks ``observed``/``enriched``/``reconstructed``/``detected`` at the
  database.
* Confidence is bounded by CHECK; the Step 10A schema additionally enforces
  ``ge(0.0)`` / ``le(1.0)``.

Structured-evidence rules and secret filtering
----------------------------------------------

* ``evidence``/``result_metadata`` are bounded JSONB: serialized size capped
  at ``_MAX_EVIDENCE_CHARS`` = 262 144 characters (defense in depth on top
  of the Step 10A size validators).
* Before write, structured data is recursively key-redacted: credential-
  shaped keys (``apiKey``, ``authorization``, ``password``, ``token``,
  ``cookie``, ``client_secret``, …) have their values replaced with
  ``<redacted>``, mirroring the detection and threat-intelligence services.
* Non-JSON-compatible structured data is a controlled validation failure
  (``CorrelationPersistenceValidationError``, ``... is not JSON-compatible``)
  — schema bypasses cannot crash the service or leak payloads.
* Error messages and logged details never contain credentials, raw evidence,
  payloads, or SQL text — only safe identifiers (UUIDs).

Transaction and unit-of-work
----------------------------

* One ``persist_correlations(db, results)`` call = one logical transaction:
  rows are staged, a single ``commit()`` publishes them together.
* Any failure (validation or database) rolls the unit back before a safe
  ``CorrelationPersistenceError`` propagates — no partial state is visible.
* The repository **never commits**; transaction ownership lives in the
  service.  The Caller (e.g. an API layer) supplies the ``Session``.

Flush ordering guarantee (parents before children)
--------------------------------------------------

Without a mapper ``relationship()`` between the two tables, SQLAlchemy can
emit child ``correlation_members`` INSERTs **before** their parent
``correlation_results`` row in a single unit of work — an FK violation on
FK-enforcing stores (PostgreSQL natively; SQLite under ``PRAGMA
foreign_keys=ON``).  The service therefore flushes the parent row
immediately after staging it, before adding its member references.  Every
member insert then references an already-persisted parent, all within the
same transaction.  This ordering guarantee is regression-guarded by the
unit suite (FK pragma enabled) and verified against live PostgreSQL.

Error taxonomy
--------------

* ``CorrelationPersistenceValidationError`` — the item is not a
  ``CorrelationResult``, the status is not one of ``candidate``/``active``/
  ``closed``, non-JSON-compatible structured data, or a size bound is
  exceeded.  Carries the offending ``correlation_id``.
* ``CorrelationPersistenceError`` — any other persistence failure (database
  errors, unexpected conditions); the original cause is preserved as the
  ``__cause__`` but never leaked into the message.

Repository and service roles
----------------------------

* ``CorrelationRepository.add`` stages rows; query helpers
  (``get_by_correlation_id``, ``get_members_for_correlation``) read back.
  It never opens a session and never commits.
* ``CorrelationPersistenceService`` validates, redacts, orders flushes,
  commits once, rolls back on failure, returns a frozen
  ``CorrelationPersistenceSummary`` (``correlation_ids``,
  ``correlations_created``, ``correlations_skipped``, ``member_counts``).
* ``persist_correlations(db, results)`` + ``persist_correlation(db, result)``
  are module-level convenience wrappers (default service).  The agent-side
  ``persist_correlations_bound(db_session, ...)`` is described under *Agent
  wiring*.

Agent wiring (pure orchestration)
---------------------------------

* ``CorrelationAgent.analyze(batch, *, clock=None, persistence=None)``
  computes correlations and forwards completed results to the sink.
* The agent never opens a ``Session``, never commits, never rolls back, and
  exposes no database parameter — persistence is an injected side-effect.
* ``persist_correlations_bound(db_session, ..., service=None)`` binds a
  session (and optional service) to a ``PersistenceCallback`` that persists
  each completed ``CorrelationResult`` list through the service — the
  concrete wiring between the agent and Step 10C.
* With ``persistence=None`` the agent is fully usable database-free.

Status lifecycle
----------------

Only ``candidate`` | ``active`` | ``closed`` can ever be stored.  The Step
10A schema validates the enum; the persistence service re-checks it (behind
``model_construct``-style bypasses) so no invented status reaches the
database.

Migration
---------

* Version: ``72c9d41e8b3f`` ("create correlation persistence tables"),
  ``down_revision = e2f4a6c8d1e3``, single head.
* Creates both tables with the constraints above; registered for discovery
  via ``migrations/env.py`` + model exports in ``app/models/__init__.py``.
* Verified: ``alembic current`` = ``heads`` = ``72c9d41e8b3f``, ``alembic
  check`` reports "No new upgrade operations detected.", and a
  downgrade → upgrade cycle reproduces the schema exactly.

Testing
-------

* ``tests/unit/test_correlation_persistence.py`` — service behavior on an
  in-memory SQLite engine with the PostgreSQL ``JSONB`` compiled as ``JSON``
  and **``PRAGMA foreign_keys=ON``** (FK enforcement on SQLite), covering
  mapping, idempotency (incl. same-batch duplicates), provenance/confidence
  CHECKs, FK cascade + unique constraints, redaction breadth, JSON
  round-trips, timestamp instants, single/multi-event membership, duplicate
  detection membership, confidence boundaries, oversized/non-JSON payloads,
  error secrecy, status/type validation, and input immutability.
* ``tests/unit/test_correlation_persistence_integration.py`` — full
  Step 10B agent → sink → service path, plus agent-boundary tests
  (signature has no DB parameter; source contains no ``commit()``/
  ``rollback()``/``Session(``; exclusive delegation to the injected sink;
  DB-free construction/usage).
* Live PostgreSQL verification: the persistence service, constraints, FK
  ordering, idempotency, and cascade delete were exercised and confirmed
  against a real PostgreSQL instance (see *Live-DB checks* below).

Running the tests
-----------------

.. code:: bash

    cd backend
    # unit + integration battery (SQLite-backed; no live DB required here)
    python -m pytest tests/unit/test_correlation_persistence.py \
        tests/unit/test_correlation_persistence_integration.py

    # full regression (includes live-DB API/audit batteries; requires the
    # configured PostgreSQL + a running Kafka broker for the detection/TI
    # event pipeline)
    python -m pytest -q

Migration checks
----------------

.. code:: bash

    cd backend
    python -m alembic current      # 72c9d41e8b3f (head)
    python -m alembic heads        # 72c9d41e8b3f (head)
    python -m alembic check        # No new upgrade operations detected

Live-DB checks
--------------

Against the configured PostgreSQL ``sentinelai`` database:

* persist a 2-member correlation through the service → 1 parent + 2 member
  rows (proves the parent-before-member flush ordering on a real FK);
* re-persist the same ``correlation_id`` → skipped (idempotency);
* direct-insert duplicate ``correlation_id`` → ``IntegrityError`` (UNIQUE);
* direct-insert ``provenance='observed'`` → ``IntegrityError`` (CHECK);
* direct-insert ``confidence=1.5`` → ``IntegrityError`` (CHECK);
* ``DELETE`` of the parent row cascades to its members (FK / CASCADE).

Explicit non-goals
------------------

Step 10C persists correlation results.  It does **not** expose a correlation
API, calculate risk, create incidents, map MITRE ATT&CK, or perform
response.  It also does **not** introduce a Kafka broker, OpenSearch /
Qdrant / Neo4j persistence, an ``events`` table, an AI/LLM investigation
step, or any change to Step 10A/10B correlation logic or to the
detection/threat-intelligence pipelines.

File locations
--------------

* ``backend/app/models/correlation_result.py``
* ``backend/app/models/correlation_member.py``
* ``backend/app/repositories/correlation.py``
* ``backend/app/services/correlation_persistence.py``
* ``backend/app/agents/correlation.py`` (``persistence`` wiring)
* ``backend/app/database/postgres/migrations/versions/72c9d41e8b3f_create_correlation_tables.py``
* ``backend/tests/unit/test_correlation_persistence.py``
* ``backend/tests/unit/test_correlation_persistence_integration.py``
* This document: ``docs/development/correlation_persistence.md``