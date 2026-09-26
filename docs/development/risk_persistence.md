Risk Assessment Persistence (Step 11C)
=======================================

Purpose
-------

Step 11C persists the Step 11A ``RiskAssessment`` objects produced by the
Step 11B :class:`~app.agents.risk_scoring.RiskScoringAgent` into
PostgreSQL.  It is the risk analogue of the detection (Step 9F), correlation
(Step 10C), and threat-intelligence persistence services: one schema, one
repository, one transactional service, and agent wiring via an injected
side-effect sink.

Step 11C persists risk assessments; it does not calculate, reinterpret,
query, expose, or act on risk.

Architecture
------------

The persistence path mirrors the established SentinelAI conventions exactly::

    RiskScoringAgent.analyze(correlation)      (Step 11B, pure orchestrator)
        -> [optional persistence callback]     (Step 11C-B wiring)
            -> RiskPersistenceService           (owns transaction, idempotency,
                                                 redaction, validation)
                -> RiskRepository                (staging only, never commits)
                    -> risk_assessments          (one row per assessment)

* The Step 11A ``RiskAssessment`` is the **exact** domain object passed
  through the service — the service never scores, recomputes, re-derives
  levels, or reinterprets factors/evidence.  There is no second scoring
  engine and no scoring logic anywhere in Step 11C.
* The agent stays a pure orchestrator: it builds the assessment with zero
  side effects and hands it to an injected ``persistence`` callback only if
  one was supplied.  With ``persistence=None`` the agent is fully usable
  database-free (exactly the Step 11B behavior).
* Model, repository, service, and exceptions live in dedicated modules:
  ``app/models/risk_assessment.py``, ``app/repositories/risk.py``,
  ``app/services/risk_persistence.py``.

Domain → database mapping
-------------------------

``RiskAssessment`` (Step 11A) maps one-to-one to a ``risk_assessments``
row.  **Nothing is flattened**: structured ``factors`` and ``evidence``
lists stay structured JSONB, and ``metadata`` stays a JSONB object.::

    RiskAssessment[]
        -> risk_assessments     (one row per assessment, by risk_assessment_id)

| Step 11A field  | Column             | Stored exactly |
|-----------------|--------------------|----------------|
| risk_assessment_id | risk_assessment_id | yes (UUID, unique) |
| correlation_id  | correlation_id     | yes (UUID, FK, not unique) |
| score           | score              | yes (Float, [0,1]) |
| level           | level              | yes (Enum risk_level) |
| confidence      | confidence         | yes (Float, [0,1]) |
| factors         | factors            | yes (JSONB list) |
| evidence        | evidence           | yes (JSONB list) |
| metadata        | assessment_metadata | yes (JSONB dict) |
| timestamp       | timestamp          | yes (timestamptz, indexed) |
| provenance      | provenance         | yes (String(32), CHECK) |

Factors/evidence are serialized through ``model_dump(mode="json")`` so
their internal ``detection_id``/``event_id`` UUIDs become JSON strings —
the structure is preserved, never collapsed into prose.

Database schema
---------------

One model using the existing ``Base`` / ``UUIDTimestampMixin``:

### ``risk_assessments`` (``RiskAssessment``)

| Column | Type | Req | Notes |
|--------|------|-----|-------|
| ``id`` | UUID (PK, mixin) | yes | auto-generated |
| ``risk_assessment_id`` | UUID | yes | Step 11A identity; **unique** — idempotency key |
| ``correlation_id`` | UUID | yes | Step 11A reference; **FK → ``correlation_results.correlation_id``, ON DELETE CASCADE** |
| ``score`` | Float | yes | Step 11B score in ``[0.0, 1.0]`` — **CHECK-constrained** |
| ``level`` | Enum(RiskLevel) | yes | ``low`` \\| ``medium`` \\| ``high`` \\| ``critical`` |
| ``confidence`` | Float | yes | Step 11B confidence in ``[0.0, 1.0]`` — **CHECK-constrained** |
| ``factors`` | JSONB | yes | structured, bounded; redacted |
| ``evidence`` | JSONB | yes | structured, bounded; redacted |
| ``assessment_metadata`` | JSONB | yes | structured, bounded; redacted |
| ``timestamp`` | DateTime(tz) | yes | assessment timestamp |
| ``provenance`` | String(32) | yes | **CHECK-constrained to ``risk_assessed``** |
| ``created_at``/``updated_at`` | DateTime(tz, mixin) | yes | |

Indexes: ``risk_assessment_id`` (unique), ``correlation_id``,
``timestamp``.

Idempotency semantics
---------------------

* An assessment is identified by its **unique** ``risk_assessment_id``.
  Re-persisting the same assessment is a no-op (skipped, counted in
  ``assessments_skipped``) — the existing row is never deleted or mutated.
* ``correlation_id`` is **not** unique: one correlation may legitimately
  carry several assessments over time.  Re-scoring a correlation produces a
  fresh ``risk_assessment_id`` (Step 11A identity generation) and hence a
  new, legitimate historical row.
* The service never deduplicates on ``correlation_id`` and never reorders
  or merges assessments.

Historical assessment semantics
-------------------------------

Each ``(risk_assessment_id, correlation_id, score, level, confidence,
factors, evidence, metadata, timestamp, provenance)`` set is an immutable
point-in-time record of what Step 11B concluded for that correlation at
that moment.  Persistence is append-only per ``risk_assessment_id``; no
assessment is ever updated in place, and nothing is reinterpreted when
stored.

Transaction ownership
---------------------

* One ``persist_assessment(db, assessment)`` call = one logical
  transaction: the row is staged and a single ``commit()`` publishes it;
  any failure (validation or database) rolls the unit back before a safe
  :class:`RiskPersistenceError` propagates — no partial state is visible.
* The repository **never commits**; transaction ownership lives in the
  service.  The Caller (e.g. a pipeline/API layer) supplies the ``Session``.
* Flush ordering: the parent ``correlation_results`` row is created by the
  Step 10C service in its own prior transaction (the real pipeline persists
  correlations before scoring/persisting assessments), so the FK parent
  exists at assessment-insert time — all within the normal call ordering.

Error handling
--------------

* :class:`RiskPersistenceValidationError` — the item is not a
  ``RiskAssessment``, carries a non-UUID identity/reference, a
  provenance other than ``RISK_ASSESSED``, a level outside the
  :class:`RiskLevel` enum, a naive timestamp, non-JSON-compatible
  structured content, or an exceeded size bound.  Carries the offending
  ``risk_assessment_id`` where available.
* :class:`RiskPersistenceError` — any other persistence failure (database
  errors, unexpected conditions, including the FK rejection of an unknown
  ``correlation_id``); the original cause is preserved as the ``__cause__``
  but never leaked into the message.
* Error messages and logged details never contain credentials, raw
  factors/evidence/metadata payloads, SQL text, connection strings, or
  database internals — only safe identifiers (UUIDs).  Log lines keep to
  ``risk_assessment_id``, ``correlation_id``, ``score``, ``level``, the
  operation, and the sanitized exception type.

Security / redaction
--------------------

* Before write, structured ``factors``/``evidence``/``metadata`` is
  **recursively key-redacted**: credential-shaped keys (``apiKey``,
  ``authorization``, ``password``, ``token``, ``cookie``,
  ``client_secret``, …) have their values replaced with ``<redacted>``,
  mirroring the detection, correlation, and threat-intelligence services.
* This is defense-in-depth on top of the Step 11A validators: the contract
  already rejects secret-shaped content, and the persistence boundary
  re-scans behind ``model_construct``-style bypasses.
* The source ``RiskAssessment`` object is **never mutated**: structured
  content is serialized into independent redacted copies before write.
* Errors never log credentials, payloads, or SQL text.

PostgreSQL behavior
-------------------

* ``risk_assessments.correlation_id`` is a real foreign key to
  ``correlation_results.correlation_id`` with **ON DELETE CASCADE** —
  deleting a correlation removes its assessments (Step 10C convention).
* An assessment referencing a correlation that was never persisted is
  rejected by the FK and surfaces as a sanitized :class:`RiskPersistenceError`.
* ``score``/``confidence`` are bounded by database CHECK constraints;
  ``provenance`` is CHECK-constrained to ``risk_assessed``.  All verified
  in live PostgreSQL DDL (``pg_constraint`` inspection).
* Verified live: table/indexes/FK/CHECKs present after ``alembic upgrade
  head``; a full assessment round-trips (score 0.625, level high,
  confidence 0.8, structured factors/evidence/metadata intact); idempotent
  re-persist inserts nothing; orphan correlations are rejected safely.

Testing strategy
----------------

* ``tests/unit/test_risk_persistence.py`` — service behavior on an
  in-memory SQLite engine with the PostgreSQL ``JSONB`` compiled as ``JSON``
  and **``PRAGMA foreign_keys=ON``**, covering: full-attribute mapping
  fidelity, score/confidence boundaries (0.0/1.0/middle), all four risk
  levels, provenance accept/reject, UUID identity behavior (valid,
  malformed, duplicate), idempotency plus multiple-assessments-per-
  correlation, empty/one/multiple/nested factors/evidence/metadata,
  detection_id/event_id reference preservation, secret-key redaction,
  size bounds, non-JSON failures, error secrecy, naive-timestamp rejection,
  timezone-aware round-trips, input immutability, FK parent requirement and
  cascade deletion, repository no-commit, and the module-level wrapper.
* ``tests/unit/test_risk_persistence_integration.py`` — full Step 11B
  agent → sink → service path, plus agent-boundary tests (signature has no
  database parameter; source contains no ``commit()``/``rollback()``/
  ``Session(``; the agent delegates exclusively to the injected callback;
  it constructs and works with zero database objects).
* Live-PostgreSQL verification was performed separately against the
  running database (not required by the unit suites).

Non-goals
---------

Step 11C persists risk assessments; it does not calculate, reinterpret,
query, expose, or act on risk.  It adds no scoring/query/historical
retrieval API, no frontend, no Kafka/RabbitMQ events, no incident
creation, no MITRE ATT&CK mapping, no response/SOAR, no threat hunting,
no knowledge graph, no attack prediction/path visualization, no
recalculation engine, and no new scoring policies — those belong to later
phases.