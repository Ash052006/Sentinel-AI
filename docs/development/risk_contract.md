Risk Assessment Domain Contract (Step 11A)
==========================================

Purpose
-------

Step 11A defines the foundational **domain contract** for the future Risk
Scoring subsystem: the validated Pydantic representation of a single risk
assessment (``RiskAssessment``) produced over a correlated security
situation, together with its supporting controlled vocabulary
(``RiskLevel``), structured evidence (``RiskEvidence``), and named
contributors (``RiskFactor``).

Detection answers *"what individual detection rules matched this
event?"*, correlation answers *"which detections/events are related?"*,
and risk scoring answers *"how dangerous does the correlated situation
appear, and how confident is SentinelAI in that assessment?"*.  11A
defines the objects the future Risk Scoring Agent will produce.  It
**does not answer the question**.

> **Step 11A defines the Risk Assessment contract and domain model. It
> does not calculate risk, persist risk assessments, expose a risk API,
> create incidents, map MITRE ATT&CK, or perform response.**

The final architecture after 11A::

    CorrelationResult                (Step 10A)
          ↓
    [Future Risk Scoring Input]      (Risk Scoring Agent inputs)
          ↓
    11A Risk Assessment Contract     (this step — RiskAssessment)
          ↓
    [Future Risk Scoring Agent]      (Step 11B)
          ↓
    [Future Risk Persistence / Query / API]

Detection vs. correlation vs. risk
----------------------------------

* **Detection** answers *"what individual detection rules matched this
  event?"*.
* **Correlation** answers *"which detections/events are related to the
  same security activity, attack sequence, entity, or incident?"*.
* **Risk** (future) will answer *"how dangerous does the correlated
  situation appear, and how confident is SentinelAI in that
  assessment?"*.

11A does **not** answer the third question.  It defines the objects a
future risk engine will produce and consume — nothing more.

Files
-----

| File | Purpose |
|------|---------|
| ``app/schemas/risk.py`` | ``RiskLevel``, ``RiskEvidence``, ``RiskFactor``, ``RiskAssessment`` — the Step 11A contract |
| ``app/schemas/security_event.py`` | global ``Provenance`` enum — additive member ``RISK_ASSESSED = "risk_assessed"`` added |
| ``app/schemas/__init__.py`` | package re-exports (existing convention) |
| ``tests/unit/test_risk_contract.py`` | Step 11A behavior + contract-boundary tests (107 tests) |

What a risk assessment represents
---------------------------------

A ``RiskAssessment`` is the **output contract** of the future Risk
Scoring subsystem.  It represents *what a risk assessment IS* — a
structured, bounded, explainable, secret-safe evaluation of one
correlated security situation:

| Field | Semantics |
|-------|-----------|
| ``risk_assessment_id`` | UUID, auto-generated (``uuid.uuid4``) when not supplied.  Distinct from ``correlation_id``, ``detection_id``, ``event_id``, and ``incident_id``. |
| ``correlation_id`` | exact reference to the correlation being evaluated — never embedded, never regenerated |
| ``score`` | normalized risk score, bounded to ``[0.0, 1.0]`` |
| ``level`` | controlled categorical risk level (``low`` / ``medium`` / ``high`` / ``critical``) |
| ``confidence`` | how confident SentinelAI is in this assessment, bounded to ``[0.0, 1.0]`` and independent of score/level |
| ``factors`` | named contributors to the assessment (optional) |
| ``evidence`` | structured observations supporting the assessment (optional) |
| ``metadata`` | open-ended JSON-compatible, secret-free bookkeeping |
| ``timestamp`` | timezone-aware instant of the assessment |
| ``provenance`` | always ``RISK_ASSESSED`` |

Risk vs. confidence
-------------------

``score``/``level`` answer *"how dangerous does the situation appear?"*;
``confidence`` answers *"how confident is SentinelAI in this
assessment?"*.  These are **independent concepts**:

* the contract never derives one from the other;
* it contains no formula linking them (no ``score * confidence``, no
  weighted sums);
* a future engine is free to produce any combination of score and
  confidence the schema bounds permit.

Score semantics
---------------

* ``score`` is a normalized scalar bounded to ``[0.0, 1.0]`` inclusive.
* The bounds are enforced by the schema (``ge=0.0`` / ``le=1.0``);
  out-of-range scores are rejected with a ``ValidationError``.
* The score is **never calculated here** — no scoring rule, weight,
  threshold, or heuristic exists in the contract.  11A validates and
  preserves an engine-produced score; it does not produce one.

Level semantics
---------------

* ``level`` is a controlled :class:`RiskLevel` enumeration — no arbitrary
  strings.
* The ladder (``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL``) mirrors the
  categorical severity scale already established by detection severity,
  giving the system a single, comprehensible severity vocabulary.
* ``level`` is a **category**, not a score.  The contract never maps a
  numeric ``score`` to a ``level``; a precise score→level mapping is a
  scoring rule that belongs to the future Risk Scoring Agent.

Correlation reference
---------------------

A risk assessment **references** the correlation it evaluates by
``correlation_id``.  It never embeds a whole ``CorrelationResult`` (or
its members); the correlation subsystem remains the source of truth for
correlation data.  No correlation/detection object is copied into the
risk contract — the assessment is a lightweight reference plus the
engine's evaluation fields.

Identity
--------

Every risk assessment has its own stable identity:

* ``risk_assessment_id`` is auto-generated when not supplied, using
  ``uuid.uuid4``.
* It is deliberately **distinct** from ``correlation_id``,
  ``detection_id``, ``event_id``, and ``incident_id`` — a risk assessment
  is not a re-issued correlation identity.  Identity generation is
  identity generation, not risk scoring.

Timestamp
---------

* ``timestamp`` is required and must be **timezone-aware**.  Naive
  (UTC-less) timestamps are rejected.
* It records the instant the assessment was produced — descriptive
  bookkeeping, not evidence and not a verdict.

Provenance
----------

A risk assessment is a derived analytical conclusion and always carries
``Provenance.RISK_ASSESSED`` — an **additive member** of the existing
global ``Provenance`` enum (``"risk_assessed"``).  It is never labelled
observed / enriched / reconstructed / detected / correlated telemetry.
The contract **enforces** this boundary: any other provenance value is
rejected, mirroring the Step 9I / 10A boundaries that enforce
``DETECTED`` / ``CORRELATED`` respectively.  Adding one member to the
shared enum preserves all earlier provenance behavior (verified by
regression tests).

Evidence
--------

``RiskEvidence`` is one structured observation that contributed to an
assessment:

| Field | Semantics |
|-------|-----------|
| ``observation_type`` | machine-readable label (e.g. ``detection_severity``, ``correlation_confidence``, ``correlation_size``) — structured, never free-form prose, never blank |
| ``detection_id`` | optional exact reference to the detection that supplied the observation |
| ``event_id`` | optional exact reference to the source event |
| ``metadata`` | structured JSON-compatible, secret-free details |

Evidence is **structured and machine-readable** — it never requires an
LLM or free-form explanation text.  The contract defines no evidence
semantics; a future engine decides what evidence means and what an
observation contributes.

Risk factors
------------

``RiskFactor`` is a named contributor to an assessment:

| Field | Semantics |
|-------|-----------|
| ``factor_type`` | machine-readable label (e.g. ``detection_volume``, ``severity_impact``, ``correlation_extent``) — structured, never blank |
| ``contribution`` | optional numeric contribution bounded to ``[0.0, 1.0]`` when present |
| ``evidence`` | structured observations supporting the factor |
| ``metadata`` | structured JSON-compatible, secret-free details |

The schema validates and preserves factors; it **never computes them**.
Contribution values (and, more generally, what any factor means) are
produced by the future Risk Scoring Agent.

Metadata
--------

* Every structured container (assessment, factor, evidence) carries an
  optional ``metadata`` mapping.
* Metadata must be **strictly JSON-compatible** (rejects cyclic or
  non-serializable objects) and must **never contain secrets**.
* Metadata is deep-cloned on construction, so the contract never shares
  mutable state with the caller — regardless of how an object is built.
* Metadata must never encode verdicts or future-layer decisions.

Validation
----------

The contract enforces, via Pydantic validators:

* ``score`` / ``confidence`` bounded to ``[0.0, 1.0]`` inclusive;
* ``contribution`` bounded to ``[0.0, 1.0]`` inclusive when present;
* ``level`` limited to the ``RiskLevel`` members;
* ``risk_assessment_id`` / ``correlation_id`` / ``detection_id`` /
  ``event_id`` valid UUIDs;
* ``timestamp`` timezone-aware;
* ``observation_type`` / ``factor_type`` non-blank (stripped);
* ``provenance`` exactly ``RISK_ASSESSED``;
* structured payloads JSON-compatible (cyclic and non-serializable
  objects rejected), while large-but-valid structured payloads are
  accepted (no artificial caps invented and no guaranteed-order
  requirements imposed);
* unknown fields follow the project's default pydantic policy (ignored),
  matching the existing Detection/Correlation contracts.

Security
--------

* ``_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret")``
  is kept in lock-step with ``app/schemas/detection.py`` and
  ``app/schemas/correlation.py``.
* Every structured payload (assessment/factor/evidence metadata) is
  secret-screened at construction.
* Defence-in-depth: the serialized ``factors`` and ``evidence`` lists are
  re-scanned in full after per-item validation, so secret-shaped content
  cannot slip through labels.
* No field in the contract accepts credentials by design.

Immutability
------------

* The contract **never mutates its sources**: constructing a
  ``RiskAssessment`` (referencing a ``CorrelationResult``) leaves the
  correlation untouched (verified by tests).
* The contract never reorders input, generates evidence/factors, and
  never shares mutable metadata — each construction deep-clones
  structured payloads.
* ``timestamp`` exists purely as bookkeeping; it never influences score,
  level, confidence, factors, or evidence.

Dependency isolation
--------------------

``app/schemas/risk.py`` imports only the standard library, Pydantic, and
``app.schemas.security_event`` (for ``Provenance``).  It contains no
SQLAlchemy, no FastAPI, no Kafka, no repository, no service, no agent,
and no API wiring — keeping the contract safely constructible without a
database, an HTTP server, or a message bus.

Testing
-------

| Area | Coverage |
|------|----------|
| Construction/identity | valid construction, generated/preserved UUID, distinct from correlation, invalid/missing UUIDs rejected |
| Score bounds | 0.0/1.0 accepted, ``<0`` / ``>1`` rejected, required |
| Level | every member accepted, invalid values rejected, required, vocabulary matches detection severity |
| Confidence bounds | 0.0/1.0 accepted, ``<0`` / ``>1`` rejected, required, independent of score |
| Timestamp | required, naive rejected, aware accepted |
| Provenance | defaults to ``RISK_ASSESSED``, other values rejected, additive member preserved in the global enum |
| Evidence/factors/metadata | structured labels, contribution bounds, JSON-compatible, secret-free |
| Validation | invalid UUIDs, non-JSON payloads, out-of-range values, oversized-but-valid acceptance |
| Secret safety | api_key / authorization / bearer / secret rejected at every level |
| JSON compatibility | strict JSON round-trip, cyclic payloads rejected |
| Immutability | source ``CorrelationResult`` unmutated, payload unmutated, deep copies independent |
| Serialization | deterministic (explicit ids), round-trip preserves the contract |
| Equality | value equality, structural and JSON-based |
| Contract boundary | no incident / MITRE / attribution / verdict / response / LLM / scoring-engine concepts |
| Dependency isolation | source inspection: no sqlalchemy/fastapi/kafka; schema constructible with no database |
| Provenance regression | earlier ``DETECTED`` / ``CORRELATED`` boundaries unchanged |

Non-goals
---------

11A deliberately contains **none** of the following (verified by tests):

* risk formulas, weights, thresholds, heuristics, or scoring rules;
* a scoring engine / risk model of any kind (statistical, ML, LLM, or
  otherwise);
* ``score -> level`` mappings or ``score * confidence`` derivations;
* persistence or database models / migrations (Alembic head remains
  ``72c9d41e8b3f``);
* query services or an API layer;
* ``Incident``/``incident_id``/incident-severity/priority concepts;
* response / SOAR / playbook / remediation concepts;
* MITRE ATT&CK tactics/techniques or attack-stage mapping;
* threat attribution / threat-actor / campaign concepts;
* verdicts (``malicious`` / ``benign`` / ``confirmed attack``);
* AI/LLM or embedding concepts;
* OpenSearch / Qdrant / Neo4j or other future data stores;
* Kafka or message-bus changes.