Detection Persistence Contract (Step 9F-A)
==========================================

Purpose
-------

Step 9F-A defines the **PostgreSQL persistence contract** for the detection
data produced by Step 9E.  It establishes *what* is persisted, *how* the
persisted records relate to events and rules, and the constraints, indexes,
provenance rules, and security rules that govern that persistence.

This is a **contract / database-model design step only**.  It defines the
SQLAlchemy models and their intended schema; the actual repository/service
that writes a ``DetectionAnalysis`` to PostgreSQL (Step 9F-B) is out of
scope here.  No persistence execution, no agent-to-database wiring is
implemented in this step.

Database entities
-----------------

Two SQLAlchemy models (using the existing ``Base`` and
``UUIDTimestampMixin``):

### 1. ``DetectionResult`` → ``detection_results``

A **single persisted detection match** produced by a detection evaluation
(one ``DetectionResult`` from a Step 9E ``DetectionAnalysis``).  The agent
only emits *matched* results into an analysis, so every persisted row is a
match — the ``matched`` flag must be ``true`` (enforced by a CHECK
constraint) and non-matching evaluations are represented by **no row**.

| Column | Type | Req | Notes |
|--------|------|-----|-------|
| ``id`` | UUID (PK, mixin) | yes | auto-generated |
| ``event_id`` | UUID | yes | originating event; **indexed**, logical FK (see below) |
| ``detection_id`` | UUID | yes | Step 9A ``DetectionResult.detection_id``; **unique** — the idempotency identity |
| ``rule_id`` | String(255) | yes | evaluated rule; **indexed** |
| ``rule_type`` | Enum(RuleType) | yes | reuses existing ``RuleType`` (``sigma`` \\| ``yara``) |
| ``rule_version`` | String(64) | yes | from ``DetectionMetadata.rule_version``; ``"unknown"`` when absent |
| ``severity`` | Enum(DetectionSeverity) | yes | reuses existing ``DetectionSeverity``; **indexed** |
| ``matched`` | Boolean | yes | always ``true``; **CHECK-constrained** |
| ``confidence`` | Float | yes | [0.0, 1.0]; **CHECK-constrained** |
| ``evidence`` | JSONB | yes | **structured** match evidence (safe, bounded) |
| ``result_metadata`` | JSONB | yes | safe, non-secret evaluation metadata |
| ``detected_at`` | DateTime(tz) | yes | ``DetectionResult.timestamp``; **indexed** |
| ``provenance`` | String(32) | yes | **CHECK-constrained to DETECTED** |
| ``created_at``/``updated_at`` | DateTime(tz, mixin) | yes | |

### 2. ``DetectionRuleFailure`` → ``detection_rule_failures``

A **single rule-level or engine-level detection failure** (one
``DetectionFailure`` from a Step 9E ``DetectionAnalysis``), normalised into
a row with an ``engine`` discriminator.

| Column | Type | Req | Notes |
|--------|------|-----|-------|
| ``id`` | UUID (PK, mixin) | yes | |
| ``event_id`` | UUID | yes | originating event; **indexed**, logical FK |
| ``engine`` | String(64) | yes | ``sigma`` \\| ``yara``; **indexed** |
| ``rule_id`` | String(255) | yes | failed rule, or ``"<engine>"`` for engine-level failures; **indexed** |
| ``error_type`` | String(64) | yes | machine-readable category (e.g. ``malformed_rule``) |
| ``error_message`` | Text | yes | **secret-safe**, bounded |
| ``failed_at`` | DateTime(tz) | yes | **indexed** |
| ``provenance`` | String(32) | yes | **CHECK-constrained to DETECTED** |
| ``created_at``/``updated_at`` | DateTime(tz, mixin) | yes | |

Both ``rule_type`` and ``severity`` reuse the **existing** Step 9A enums
(``RuleType``, ``DetectionSeverity``); no duplicate enums are created.

Entity relationships
--------------------

::

    SecurityEvent (event_id UUID)
          |
          |  event_id (logical FK, indexed)
          v
    DetectionResult        DetectionRuleFailure
      (one per match)        (one per rule/engine failure)

Detail:
* ``event_id`` on both tables is the UUID of the originating security event,
  stored as an **indexed UUID column (an implicit logical foreign key)**.
  SentinelAI does **not** yet persist a dedicated ``events`` table, so no
  hard SQL foreign key is created — exactly as with
  ``threat_intel_lookups.event_id``.  When an ``events`` model is introduced
  later, these columns become real foreign keys without changing meaning.
* No foreign-key column points at a ``DetectionRule`` — rules are static
  definitions held in the registry; results trace back via ``rule_id``.

Idempotency identity
--------------------

* A persisted result is identified by its unique ``detection_id``.  Re-persisting
  the *same* analysis (same ``DetectionResult`` objects) is a no-op, while a
  re-evaluation that produces a new ``detection_id`` (Step 9A auto-generates a
  UUID per evaluation) is a new, legitimate historical row.
* A persisted failure is identified by ``(event_id, engine, rule_id,
  error_type, sanitized error_message)`` — stable across re-persists of the
  same analysis (failures carry no per-evaluation timestamp).

Provenance rules
----------------

* Every persisted detection row carries ``Provenance.DETECTED``
  (``provenance = 'detected'``), enforced by a database CHECK constraint so
  detection evidence can **never** be persisted as ``observed``/``enriched``/
  ``reconstructed``.
* The existing ``Provenance`` enum is **not** altered.

Security rules
--------------

The contract **never requires** nor defines persistence of:

* API keys, authorization headers, cookies, credentials;
* raw rule source or raw event payloads as generic blobs;
* arbitrary content from ``DetectionRule.content``.

``evidence`` and ``result_metadata`` are **structured, bounded** JSONB
payloads.  ``error_message`` must stay secret-safe.  Credential-shaped keys
inside evidence/metadata are redacted by the persistence service before
write (defense in depth, mirroring the threat-intelligence service).

Mapping from DetectionAnalysis to persistence
---------------------------------------------

A ``DetectionAnalysis`` (Step 9E) maps as follows:

1. ``event_id`` → ``event_id`` on every result and failure row.
2. Each ``results[*]`` (a matched ``DetectionResult``) → a
   ``DetectionResult`` row with ``rule_id``/``rule_type``/``severity``/
   ``confidence`` from the result, ``rule_version`` from its metadata (or
   ``"unknown"``), ``evidence``/``result_metadata`` from the result's
   structured evidence/metadata (redacted), ``detected_at`` =
   ``result.timestamp``, ``provenance`` → DETECTED.
3. Each ``failures[*]`` (a ``DetectionFailure``) → a
   ``DetectionRuleFailure`` row with ``engine``, ``rule_id``, ``error_type``,
   sanitized ``error_message``, ``failed_at``, ``provenance`` → DETECTED.
4. ``DetectionAnalysisMetadata`` counters are **not** persisted as a
   separate entity; they are derivable from the rows.

This mapping is the responsibility of the Step 9F-B repository/service, and
is **not** implemented in this contract step.

Example persistence flow
------------------------

::

    DetectionAnalysis(event_id=E)
    ├── result(sigma-001, matched=true, severity=high,
    │           confidence=0.9, evidence={...})
    │     → DetectionResult(rule_id="sigma-001", rule_type="sigma",
    │                       severity="high", matched=true,
    │                       evidence={...}, provenance="detected")
    ├── result(yara-001, matched=true, severity=critical, ...)
    │     → DetectionResult(rule_id="yara-001", rule_type="yara", ...)
    └── failure(sigma, "sigma-bad", "malformed_rule", "could not parse")
          → DetectionRuleFailure(engine="sigma", rule_id="sigma-bad",
                                 error_type="malformed_rule", ...)

Explicit non-goals for Step 9F-A
--------------------------------

* **No** repository/service that writes to PostgreSQL.
* **No** wiring of the Detection Agent to the database.
* **No** change to Step 9A / 9E behavior (the agent stays a pure
  orchestrator; persistence, if any, is an injected side-effect sink).
* **No** persistent rule registry, correlation, risk scoring, MITRE
  mapping, or AI investigation.
* **No** OpenSearch / Qdrant / Neo4j persistence (PostgreSQL only).
* **No** database migration is created in this step; the models are
  registered with Alembic via ``env.py`` for future discovery, and the
  actual migration is deferred to the implementation step.  An ``events``
  table is **not** created.

File locations
--------------

* ``backend/app/models/detection_result.py``
* ``backend/app/models/detection_rule_failure.py``
* ``backend/tests/unit/test_detection_persistence_contract.py``
* This document: ``docs/development/detection_persistence_contract.md``