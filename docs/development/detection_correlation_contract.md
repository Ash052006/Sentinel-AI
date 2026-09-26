Detection-to-Correlation Contract (Step 9I)
==========================================

Purpose
-------

Step 9I defines the **information boundary** between the completed
Detection subsystem and the future Correlation Agent.  It is a thin,
validated, JSON-compatible Pydantic contract — a transport layer for
detection information — together with a pure adapter that converts an
existing detection (the Step 9A ``DetectionResult`` authoring contract or
the Step 9G ``DetectionResultRecord`` read model) into that contract.

> **The Detection-to-Correlation Contract transports detection information
> to the future Correlation Agent. It does not perform correlation.**

The final architecture after 9I::

    DetectionAgent
          ↓
    DetectionAnalysis
          ↓
    DetectionPersistenceService
          ↓
    PostgreSQL
          ↓
    DetectionQueryService
          ↓
    DetectionAPI
          ↓
    DetectionCorrelationContract   (Step 9I — this document)
          ↓
    [Future Correlation Agent]

Detection vs. correlation
-------------------------

* **Detection** answers: *"What individual detection rules matched this
  event?"*.
* **Correlation** (future) will answer: *"Which detections/events are
  related to the same possible attack, activity sequence, entity, or
  incident?"*.

9I does **not** answer the second question.  It only defines what
information may be handed *to* the subsystem that will.  The future
Correlation Agent does not need to know about PostgreSQL table structure,
SQLAlchemy, repository implementations, persistence services, API routing,
or any other storage/infrastructure detail — it consumes
``DetectionCorrelationInput`` records.

Files
-----

| File | Purpose |
|------|---------|
| ``app/schemas/detection_correlation.py`` | ``DetectionCorrelationInput``, ``DetectionCorrelationBatch``, ``DetectionCorrelationBatchMetadata`` + the pure adapters ``to_correlation_input`` / ``to_correlation_batch`` |
| ``app/schemas/__init__.py`` | package re-exports (existing convention) |
| ``tests/unit/test_detection_correlation.py`` | Step 9I behavior tests (90 tests) |

Contract fields
---------------

``DetectionCorrelationInput`` is derived 1:1 from the existing detection
subsystem — every field has a real source and no new detection model is
created:

| Contract field | Type | Source |
|----------------|------|--------|
| ``detection_id`` | UUID | 9A ``DetectionResult.detection_id`` (persisted unique) |
| ``event_id`` | UUID | originating event UUID, preserved across both paths |
| ``timestamp`` | tz-aware ``datetime`` | 9A ``DetectionResult.timestamp`` / 9G ``DetectionResultRecord.detected_at`` |
| ``rule_id`` | ``str`` (min 1) | evaluated rule identity |
| ``rule_type`` | ``RuleType`` | ``sigma`` / ``yara`` |
| ``rule_version`` | ``str \| None`` | 9A ``DetectionMetadata.rule_version`` / 9G ``rule_version`` (``None`` when the detection carried none — the ``"unknown"`` fallback is a persistence-layer convention and is not fabricated here) |
| ``severity`` | ``DetectionSeverity`` | rule-author severity |
| ``confidence`` | ``float`` in ``[0.0, 1.0]`` | engine confidence |
| ``evidence`` | ``dict`` | 9A ``DetectionEvidence`` sections / 9G persisted evidence JSONB (structured, as-is) |
| ``metadata`` | ``dict`` | 9A ``DetectionMetadata`` fields / 9G persisted ``result_metadata`` JSONB (structured, as-is) |
| ``provenance`` | ``Provenance`` | always ``DETECTED`` (enforced) |

Traceability
------------

The contract preserves, unchanged:

* ``detection_id`` — the original detection's identity.  No new identity
  is generated for an existing detection, so correlation can always trace
  a candidate back to the detection that produced it.
* ``event_id`` — the original security event's UUID.  It is **never**
  replaced with ``correlation_id`` / ``incident_id`` / ``alert_id``; those
  belong to future layers.
* ``rule_id`` / ``rule_type`` / ``rule_version`` — exact evaluated rule
  identity.
* ``timestamp`` / ``severity`` / ``confidence`` / ``provenance`` — exact
  detection outcome values.

Provenance
----------

Detection output is **analytical/derived** information.  The contract
enforces ``Provenance.DETECTED`` on every input:

* it never converts ``DETECTED → OBSERVED`` (and rejects any input that
  pretends a detection is observed telemetry);
* the adapter preserves the ``DETECTED`` provenance exactly;
* this mirrors the Step 9F database CHECK constraint
  (``provenance = 'detected'``) and the Step 9G read model — rechecked at
  the boundary so no weakening is possible.

Evidence
--------

Detection evidence remains **structured**.  The contract transports the
existing evidence sections (``matched_conditions``, ``matched_fields``,
``rule_references``, ``detection_context`` or the persisted JSONB dict) as
a JSON-compatible ``dict``; it never flattens evidence into free-form text
and never discards it.  The contract **transports** evidence — it does
**not** decide what the evidence means.

Metadata
--------

Relevant structured detection metadata (``rule_version``,
``engine_version``, ``execution_time_ms``, ``total_rules_evaluated``,
``extra`` / persisted ``result_metadata``) is preserved as a JSON-compatible
``dict``.  The contract adds **no** risk score, threat score, incident
priority, attack stage, campaign ID, or correlation score — those do not
belong to the detection-to-correlation boundary.
Batch semantics
---------------

``DetectionCorrelationBatch`` is a **transport envelope only**:

* ``detections[]`` — the transported ``DetectionCorrelationInput`` records;
* ``metadata.record_count`` — transport bookkeeping, validated to equal
  ``len(detections)`` (a batch whose metadata disagrees with its payload is
  invalid).

The batch never:

* groups detections;
* sorts them into an attack sequence;
* calculates relationships;
* assigns correlation/incident IDs;
* creates incidents.

**Ordering** — the batch preserves the caller's input order; the adapter
never reorders.  If the caller supplies a deterministically ordered source
(such as a Step 9G ``DetectionResultPage``), the batch inherits that
deterministic order.  Chronological ordering is **not** attack-sequence
correlation, and the contract deliberately encodes no such assumption.
**Duplicates** — duplicate ``detection_id`` values are transported as-is;
the contract never silently removes or deduplicates them.

Validation
----------

Validation reuses the existing detection semantics, never weaker:

* ``confidence`` in ``[0.0, 1.0]`` (same bounds as 9A and the DB CHECK);
* timezone-aware ``timestamp`` (naive dates rejected, same rule as 9A);
* valid UUIDs for ``detection_id`` / ``event_id``;
* non-empty ``rule_id`` (``min_length=1``, same as 9A ``DetectionResult``);
* ``provenance == DETECTED`` (enforced at the boundary);
* evidence/metadata must be strictly JSON-compatible and must not contain
  credential-shaped content (``api_key``, ``authorization``, ``bearer``,
  ``secret``) — the same forbidden-pattern validation the Step 9A contract
  applies.

Immutability
------------

The contract never mutates ``DetectionResult``, ``DetectionAnalysis``, the
9G read models, evidence, or metadata.  The adapter builds an independent
representation:

* 9A path: ``DetectionEvidence`` / ``DetectionMetadata`` are dumped and
  JSON-cloned into the contract;
* 9G path: the read model's evidence / ``result_metadata`` dicts are
  JSON-cloned, so the contract shares **no mutable state** with its source.

Security
--------

* No credentials, API keys, authorization headers, bearer tokens, JWTs, or
  arbitrary objects can cross the boundary (schema-level rejection plus
  adapter defence-in-depth re-check).
* Serialization is JSON via ``model_dump_json`` — no pickle, no executable
  serialization, no arbitrary object serialization.
* The contract is an in-process boundary; it introduces no Kafka/RabbitMQ,
  no new log statements, and nothing is logged during normal conversion.

Adapter behavior
----------------

Two pure, module-level functions mirror the existing
``threat_intel_result_to_enrichment`` convention:

```python
from app.schemas.detection_correlation import (
    to_correlation_input,
    to_correlation_batch,
)

input_  = to_correlation_input(detection_result)      # 9A DetectionResult
input_  = to_correlation_input(result_record)          # 9G DetectionResultRecord
batch   = to_correlation_batch(results)                # ordered iterable
```

Both are deterministic, side-effect free, non-mutating, and perform **no**
database access (they accept already-retrieved objects) and **no**
correlation.  Rejected inputs (loud failures — never silent conversion):

* ``DetectionFailure`` / ``DetectionFailureRecord`` — failures are not
  detections (``TypeError``);
* ``DetectionAnalysis`` — a container, not a detection (``TypeError``);
* ``matched=False`` results — a non-match is not a detection
  (``ValueError``);
* any other object (``TypeError``).

Non-goals (explicitly out of scope for this step)
-------------------------------------------------

* No Correlation Agent, temporal correlation, sequence detection, event
  grouping, entity/IP/user/process correlation, attack chains, campaign
  detection, incident creation, correlation scoring, or graph traversal.
* No risk scoring, threat scoring, MITRE ATT&CK mapping, alert
  prioritization, or severity aggregation.
* No AI/LLM, embeddings, vector/graph stores.
* No Kafka/RabbitMQ.
* No API endpoints / routes / OpenAPI changes.
* No database access, no repository/persistence calls, no new tables, no
  Alembic migration (``alembic check`` reports no new upgrade operations).