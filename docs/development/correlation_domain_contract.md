Correlation Domain Contract (Step 10A)
======================================

Purpose
-------

Step 10A defines the foundational **domain contract** for the future
Correlation subsystem: the validated Pydantic representation of a single
correlation result (``CorrelationResult``), its membership references
(``CorrelationMember``), its lifecycle marker (``CorrelationStatus``), and
a pure reference-harvesting adapter (``to_correlation_members``).

> **Step 10A defines the Correlation domain contract. It does not determine
> which detections are correlated.**

The final architecture after 10A::

    DetectionCorrelationInput          (Step 9I)
          ↓
    DetectionCorrelationBatch          (Step 9I)
          ↓
    10A Correlation Domain Contract    (this step — CorrelationResult)
          ↓
    [Future Correlation Agent]
          ↓
    [Future Correlation Persistence]
          ↓
    [Future Correlation API]

Detection vs. correlation
-------------------------

* **Detection** answers: *"What individual detection rules matched this
  event?"*.
* **Correlation** (future) will answer: *"Which detections/events are
  related to the same security activity, attack sequence, entity, or
  incident?"*.

10A does **not** answer the second question.  It defines the objects a
future correlation engine will produce and consume — nothing more.

Files
-----

| File | Purpose |
|------|---------|
| ``app/schemas/correlation.py`` | ``CorrelationStatus``, ``CorrelationMember``, ``CorrelationResult`` + the pure adapter ``to_correlation_members`` |
| ``app/schemas/security_event.py`` | global ``Provenance`` enum — additive member ``CORRELATED = "correlated"`` added |
| ``app/schemas/__init__.py`` | package re-exports (existing convention) |
| ``tests/unit/test_correlation_contract.py`` | Step 10A behavior + contract-boundary tests (104 tests) |

Correlation identity
--------------------

Every correlation has its own stable identity:

| Field | Semantics |
|-------|-----------|
| ``correlation_id`` | UUID, auto-generated (``uuid.uuid4``) when not supplied.  Distinct from ``detection_id``, ``event_id``, and ``incident_id``.  Identity generation is *not* correlation logic — the contract never derives a correlation identity from detection identities. |

Correlation membership
----------------------

``CorrelationResult.members`` is a non-empty list of ``CorrelationMember``
references (``min_length=1`` — a valid completed correlation references at
least one detection).

| Member field | Semantics |
|--------------|-----------|
| ``detection_id`` | exact reference to the Step 9A ``DetectionResult`` / Step 9I ``DetectionCorrelationInput`` detection identity — never regenerated |
| ``event_id`` | exact reference to the originating ``SecurityEvent`` identity — never replaced with a correlation/incident/alert identifier |
| ``timestamp`` | the member detection's own timezone-aware evaluation timestamp |

Members are **references**, never copies of the detection record.  The
detection subsystem remains the source of truth for detection data.  The
computed views ``detection_ids`` and ``event_ids`` expose the exact values
in member order, duplicates preserved.

One event / multiple detections
-------------------------------

The model is agnostic to cardinality and supports every combination the
future engine may produce:

* one **event** → many **detections** (two members with the same
  ``event_id``);
* many **events** → many **detections**;
* one correlation for a single detection (a valid correlation still
  requires at least one member).

The contract never assumes one-detection = one-event or one-event =
one-correlation; those remain future engine decisions.

Event references
----------------

``event_ids`` (computed from members) are exact references to source
events.  They are never replaced with attack IDs, incident IDs, or
correlation IDs, and the contract never infers a relationship between two
detections merely because they share an event.

Confidence semantics
--------------------

``CorrelationResult.confidence`` is optional (``None`` when the engine
produced no numeric confidence) and bounded to ``[0.0, 1.0]`` when
present.

Correlation confidence is a **different concept** from detection
confidence:

* it describes confidence **in the correlation itself**, not in any
  member detection;
* it is never an aggregate or reinterpretation of the members' detection
  confidences (members carry no confidence);
* it is not a risk score, threat score, or priority.
Provenance
----------

Correlation is a **derived analytical result**.  Step 10A reuses the
existing global :class:`~app.schemas.security_event.Provenance` enum and
adds one new, additive member:

* ``CORRELATED = "correlated"`` — a derived analytical conclusion produced
  by a correlation evaluation; distinct from ``observed``,
  ``enriched``, ``reconstructed``, and ``detected``.

Justification for the additive change (backward-compatible):

* every ``Provenance`` value already corresponds to a pipeline stage, and
  correlation is a new analytical stage whose outputs must never be
  mislabelled as detection output (``DETECTED``) or event telemetry;
* no existing value was redefined, and no exhaustive switch on the enum
  exists in the codebase — existing consumers behave identically;
* ``security_event.py``, this document, and the tests all document the
  change, and the full backend suite re-ran with zero regressions.

``CorrelationResult.provenance`` **defaults to and is enforced as**
``CORRELATED`` — mirroring how the Step 9I boundary enforces ``DETECTED``.
The 9I detection transport contract is unchanged and still requires
``DETECTED``.

Status semantics
----------------

``CorrelationStatus`` is neutral **lifecycle bookkeeping**, deliberately
free of verdicts:

| Value | Meaning |
|-------|---------|
| ``CANDIDATE`` | proposed but not yet formally tracked or resolved (initial state) |
| ``ACTIVE`` | currently tracked; lifecycle still open |
| ``CLOSED`` | lifecycle ended — record-keeping only, carries no verdict |

The enum contains **no** ``malicious`` / ``benign`` / ``true_positive`` /
``false_positive`` values, and no confirmation/rejection semantics: those
imply downstream judgment that does not exist yet.

Temporal boundaries
-------------------

``first_seen_at`` and ``last_seen_at`` are **computed views** (the earliest
and latest member ``timestamp``).  They describe the correlated detections;
they do **not** establish correlation.  10A implements no time-window
algorithm and stores no window/gap configuration.

Evidence and metadata
---------------------

* ``evidence`` — structured JSON-compatible information supporting the
  correlation.  The contract defines **no evidence semantics**; the future
  engine decides what evidence means.  No ``same_ip`` / ``same_user`` /
  ``same_process`` / ``within-five-minutes`` rules are mandated anywhere.
* ``metadata`` — open-ended JSON-compatible metadata.  It must not smuggle
  in future-layer decisions (``risk_score``, ``attack_stage``, ``mitre``,
  ``incident_priority``, ``response_action``).

Both fields are strictly JSON-serializable, secret-screened, and stored as
independent clones.
Immutability
------------

* 10A never mutates ``DetectionCorrelationInput`` / ``DetectionCorrelationBatch``
  records or their evidence/metadata.
* evidence/metadata are deep-cloned during validation, so a
  ``CorrelationResult`` shares no mutable state with the caller's payload.
* the adapter is pure, deterministic, and side-effect free.

Validation
----------

The contract validates, rejecting (never silently repairing) invalid data:

* ``correlation_id`` is a UUID;
* ``members`` is non-empty; each member is a valid ``CorrelationMember``;
* ``detection_id`` / ``event_id`` are UUIDs at every level;
* timestamps are timezone-aware (naive datetimes are rejected);
* ``confidence`` is ``[0.0, 1.0]`` when present;
* ``evidence`` / ``metadata`` are strictly JSON-compatible;
* secret patterns are rejected;
* ``provenance`` must equal ``CORRELATED``;
* ``status`` must be a ``CorrelationStatus`` member.

Security
--------

The contract inherits the Step 9A/9I secret-safety conventions: evidence
and metadata reject credential-shaped content (``api_key``,
``authorization``, ``bearer``, ``secret``).  Members carry references only,
so no payloads travel with them.  Contracts are never logged whole by this
step.

Storage independence
--------------------

10A is storage-independent: no SQLAlchemy models, no tables, no Alembic
migrations, no repositories, no persistence services, no API endpoints, no
Kafka/RabbitMQ.  ``alembic check`` reports **no new upgrade operations**.
Correlation persistence and the Correlation API are separate future steps.

Algorithm neutrality
--------------------

The domain model is flexible enough to support multiple future
correlation strategies.  It encodes none of: time-window matching, IP
matching, user matching, process matching, attack-chain matching, graph
matching, rule similarity, or ML clustering.  Relationship types
(``SAME_IP``, ``SAME_USER``, ``ATTACK_CHAIN``, ...) are deliberately not
defined.

Adapter
-------

``to_correlation_members(inputs)`` mechanically harvests
``CorrelationMember`` references from caller-selected 9I
``DetectionCorrelationInput`` records.  The **caller** decides membership;
the adapter only extracts ``detection_id`` / ``event_id`` / ``timestamp``.
It preserves order and duplicates, deduplicates nothing, groups nothing,
and never compares fields.

Tests
-----

``tests/unit/test_correlation_contract.py`` adds **104 tests** covering
all validation rules above plus contract-boundary locks: no risk /
incident / MITRE / response / algorithm-specific fields, no correlation
methods, no relationship enum, no module imports of SQLAlchemy/FastAPI/
Kafka, and no algorithm-behaviour assumptions (no "same IP must
correlate", no "within five minutes" rules).

Full backend result: **1682 passed / 10 skipped / 0 failed** (the pre-10A
baseline was 1578 passed / 10 skipped — zero regressions).

Non-goals
---------

10A does **not** implement: the Correlation Agent, correlation algorithms,
temporal/entity grouping, attack chains, campaigns, incident creation,
risk scoring, MITRE ATT&CK, threat attribution, SOAR, LLM/embeddings,
graph databases, Kafka, PostgreSQL, FastAPI routes, frontend, or the
``CorrelationAnalysis`` / ``CorrelationFailure`` orchestration envelopes
(those belong to the future Correlation Agent step).