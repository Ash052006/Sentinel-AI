Threat Intelligence Persistence Contract (Step 8C-A)
====================================================

Purpose
-------

Step 8C-A defines the **PostgreSQL persistence contract** for the
threat-intelligence data produced by Step 8B.  It establishes *what* is
persisted, *how* the persisted records relate to events, indicators,
providers, and lookup results, and the constraints, indexes, provenance
rules, and security rules that govern that persistence.

This is a **contract / database-model design step only**.  It defines the
SQLAlchemy models and their intended schema; the actual repository/service
that writes a ``ThreatIntelligenceAnalysis`` to PostgreSQL (Step 8C-B) is
out of scope.  No persistence execution, no agent-to-database wiring, and
no downstream functionality are implemented here.

Database entities
-----------------

Two SQLAlchemy models (using the existing ``Base`` and
``UUIDTimestampMixin``):

### 1. ``ThreatIntelIndicator`` → ``threat_intel_indicators``

A **global, deduplicated** record of a normalized indicator of compromise.
It is independent of any single event, provider, or lookup.

| Column | Type | Req | Notes |
|--------|------|-----|-------|
| ``id`` | UUID (PK, mixin) | yes | auto-generated |
| ``value`` | String(2048) | yes | exact value, no URL canonicalization |
| ``indicator_type`` | Enum(IndicatorType) | yes | reuses existing ``IndicatorType`` |
| ``canonical_key`` | String(2200) | yes | Step 8A dedup key ``"{type}:{normalized}"``; **unique** |
| ``first_seen_at`` | DateTime(tz) | yes | when first encountered |
| ``last_seen_at`` | DateTime(tz) | yes | when most recently encountered |
| ``created_at`` | DateTime(tz, mixin) | yes | |
| ``updated_at`` | DateTime(tz, mixin) | yes | |

### 2. ``ThreatIntelLookup`` → ``threat_intel_lookups``

A **single, atomic provider lookup** performed for one indicator on behalf
of one security event.  A normalized design represents both outcomes —
successful result/evidence and failure — on the same row via
mutually-exclusive optional columns.

| Column | Type | Req | Notes |
|--------|------|-----|-------|
| ``id`` | UUID (PK, mixin) | yes | |
| ``event_id`` | UUID | yes | originating event; **indexed**, logical FK (see below) |
| ``indicator_id`` | UUID | yes | FK → ``threat_intel_indicators.id``, **indexed** |
| ``provider`` | String(255) | yes | **indexed** |
| ``status`` | Enum(LookupStatus) | yes | ``success`` \| ``error`` |
| ``performed_at`` | DateTime(tz) | yes | **indexed** |
| ``retryable`` | Boolean | no | failure only |
| ``error_type`` | String(64) | no | failure only (e.g. ``rate_limit``, ``timeout``) |
| ``error_message`` | Text | no | failure only, **secret-safe** |
| ``found`` | Boolean | no | success only |
| ``confidence`` | Float | no | success only, [0.0, 1.0] |
| ``result_timestamp`` | DateTime(tz) | no | success only |
| ``evidence`` | JSONB | no | success only, **structured** provider evidence |
| ``result_metadata`` | JSONB | no | success only, safe metadata |
| ``provenance`` | String(32) | yes | **CHECK-constrained to ENRICHED** |
| ``created_at``/``updated_at`` | DateTime(tz, mixin) | yes | |

``LookupStatus`` is a small enum (``success``/``error``) local to the
lookup model; it is **not** a duplicate of any existing enum.



Entity relationships
--------------------

::

    SecurityEvent (event_id UUID)
          |
          |  event_id (logical FK, indexed)
          v
    ThreatIntelIndicator  <--1:N-->  ThreatIntelLookup
      (canonical_key)               |
          provider   (String, indexed)
          status     (success | error)
          evidence   (JSONB structured payload)
          provenance (ENRICHED)

* ``ThreatIntelIndicator.lookups`` ↔ ``ThreatIntelLookup.indicator``:
  one indicator → many lookups (one per provider/event).
* Each lookup carries its result/evidence **inline** (1:1 atomic outcome),
  so no separate result table is needed while still preserving the
  ``event → indicator → provider → result`` chain.

Event relationship
------------------

``ThreatIntelLookup.event_id`` answers "which event produced this
indicator?"  SentinelAI does **not yet** persist a dedicated ``events``
table, so ``event_id`` is stored as an indexed UUID column — an implicit
**logical** foreign key — rather than a hard SQL foreign key.  When an
``events`` model is introduced in a later step, this column becomes a real
foreign key without changing its meaning.  We deliberately do **not**
create an unrelated duplicate event model.

Field definitions
-----------------

* **Indicator value / type** — ``value`` stores the indicator exactly as
  extracted (Step 8A intentionally does not normalize URLs by default).
  ``indicator_type`` reuses the existing
  ``app.services.threat_intelligence.types.IndicatorType`` (IP, DOMAIN,
  URL, HASH); no second enum is created.
* **canonical_key** — the Step 8A deterministic deduplication key
  ``"{type}:{normalized_value}"`` (domains/hashes lower-cased; IPs/URLs
  kept as-is).  It is the global-equality key for indicators.
* **Lookup execution** — ``provider``, ``status``, ``performed_at``,
  ``retryable`` capture the provider execution.
* **Failure** — ``error_type`` (machine-readable category),
  ``error_message`` (secret-safe text), ``retryable``.  These live on the
  lookup row (preferred simpler normalized design, no separate failure
  table).
* **Result / evidence** — ``found``, ``confidence``, ``result_timestamp``,
  ``evidence`` (JSONB structured payload), ``result_metadata`` (JSONB safe
  metadata).

Constraints
-----------

* ``threat_intel_indicators.canonical_key`` — **UNIQUE** and indexed.  The
  same normalized indicator/type combination cannot create uncontrolled
  duplicate indicator records.
* ``threat_intel_indicators(indicator_type, value)`` — composite **UNIQUE**
  safety net (secondary control).
* ``threat_intel_lookups.provenance`` — **CHECK** ``provenance = 'enriched'``
  (evidence can never be persisted as observed/reconstructed).

Indexes
-------

Justified indexes for the likely queries:

| Index (column) | Serves |
|----------------|--------|
| ``threat_intel_lookups.event_id`` | find TI records for an event |
| ``threat_intel_indicators.value`` | find indicators by value |
| ``threat_intel_indicators.canonical_key`` (unique) | find by type + normalized value; enforce uniqueness |
| ``threat_intel_indicators.indicator_type`` | filter by indicator category |
| ``threat_intel_lookups.indicator_id`` | find events/lookups for an indicator |
| ``threat_intel_lookups.provider`` | find results from a particular provider |
| ``threat_intel_lookups.performed_at`` | find recent provider lookups |

No excessive or un-justified indexes are added.



Provenance rules
----------------

Threat-intelligence evidence is **enrichment**.  The lookup's
``provenance`` column defaults to ``Provenance.ENRICHED.value`` and is
enforced by a database CHECK constraint so that TI evidence can **never**
be persisted as ``observed`` merely because it relates to an observed
event.  ``reconstructed`` data remains a distinct concept and is never
conflated with TI evidence; only ``enriched`` is permitted for evidence.
The existing ``Provenance`` enum is **not** altered.

Security rules
--------------

The contract **never requires** nor defines persistence of:

* API keys
* Authorization headers / cookies / credentials
* raw HTTP request or response objects
* a generic "dump everything" blob

``evidence`` is a **structured, bounded** JSONB payload (the provider's
structured non-secret result), and ``result_metadata`` holds only safe,
non-secret metadata.  ``error_message`` must stay secret-safe.  There is
no field for raw API responses.

Mapping from ThreatIntelligenceAnalysis to persistence
------------------------------------------------------

A ``ThreatIntelligenceAnalysis`` (Step 8B) maps as follows:

1. ``event_id`` → ``ThreatIntelLookup.event_id`` on every lookup.
2. Each extracted indicator → ensure a ``ThreatIntelIndicator`` row exists
   keyed by ``canonical_key`` (get-or-create), updating
   ``first_seen_at``/``last_seen_at``.
3. Each ``ProviderAssociation`` (successful) → a ``ThreatIntelLookup`` row
   with ``status = success`` and:
   * ``indicator_id`` → the indicator row,
   * ``provider`` → ``result.provider``,
   * ``found``/``confidence`` → from ``ThreatIntelResult``,
   * ``evidence`` → ``result.data`` (structured),
   * ``result_metadata`` → ``result.metadata``,
   * ``result_timestamp`` → ``result.timestamp``,
   * ``provenance`` → ENRICHED.
4. Each ``ProviderFailure`` → a ``ThreatIntelLookup`` row with
   ``status = error`` and ``provider``, ``error_type``, ``error_message``,
   ``retryable`` (plus ``indicator_id`` get-or-create).
5. ``ThreatIntelMetadata`` counters are **not** persisted as a separate
   entity; they are derivable from the lookup rows.

This mapping is the responsibility of the Step 8C-B repository, **not**
implemented here.

Example persistence flow
------------------------

::

    ThreatIntelligenceAnalysis(event_id=E)
    ├── indicator (ip, "8.8.8.8")  → get-or-create ThreatIntelIndicator
    │                                 (canonical_key "ip:8.8.8.8")
    ├── ProviderAssociation(VirusTotal, result found=true, data={...})
    │     → ThreatIntelLookup(status=success, evidence={...}, provenance=enriched)
    ├── ProviderAssociation(AbuseIPDB, result found=true, data={...})
    │     → ThreatIntelLookup(status=success, evidence={...}, provenance=enriched)
    └── ProviderFailure(OTX, error_type="timeout", retryable=true)
          → ThreatIntelLookup(status=error, error_type="timeout",
                              retryable=true, provenance=enriched)

Explicit non-goals for Step 8C-A
--------------------------------

* **No** repository/service that writes to PostgreSQL.
* **No** wiring of the Threat Intelligence Agent to the database.
* **No** change to Step 8B behavior.
* **No** detection, correlation, risk scoring, MITRE, or AI investigation.
* **No** OpenSearch / Qdrant / Neo4j persistence (PostgreSQL only).
* **No** database migration is created; the models are registered with
  Alembic via ``env.py`` for future discovery, and the actual migration is
  deferred to the implementation step.  An ``events`` table is **not**
  created (no unrelated duplicate event model).

File locations
--------------

* ``backend/app/models/threat_intel_indicator.py``
* ``backend/app/models/threat_intel_lookup.py``
* ``backend/tests/unit/test_threat_intel_persistence_contract.py``
* This document: ``docs/development/threat_intelligence_persistence_contract.md``
