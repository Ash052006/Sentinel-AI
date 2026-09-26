Correlation Agent & Deterministic Correlation Engine (Step 10B)
===============================================================

Purpose
-------

Step 10B implements the **Correlation Agent** and the first
**deterministic baseline correlation strategy** for SentinelAI.  It
consumes a Step 9I ``DetectionCorrelationBatch`` and produces Step 10A
``CorrelationResult`` objects.

Detection answers *"what individual security rules matched this event?"*.
Correlation answers *"which detections/events are related?"*.

> Correlations establish deterministic relationships between detection
> records.  It does not determine whether the activity is malicious,
> assign risk, create incidents, map MITRE ATT&CK, attribute threats, or
> perform response.

Step 10A (the Correlation domain contract) is authoritative and is not
redesigned here.  Step 10B adds the agent that orchestrates a strategy
and the in-memory deterministic engine.  No persistence, no API, no
message bus, and no AI are introduced by this step.

Architecture::

    DetectionCorrelationInput[]        (Step 9I)
          ↓
    DetectionCorrelationBatch         (Step 9I)
          ↓
    CorrelationAgent                   (this step — orchestration)
          ↓
    CorrelationStrategy                (this step — strategy contract)
          ↓
    DeterministicCorrelationStrategy   (this step — baseline engine)
          ↓
    CorrelationResult[]                (Step 10A)
          ↓
    [Future Correlation Persistence]

Related steps: Step 9I (``DetectionCorrelationInput`` /
``DetectionCorrelationBatch``) and Step 10A (``CorrelationResult`` /
``CorrelationMember`` / ``CorrelationStatus``), documented in
``detection_correlation_contract.md`` and ``correlation_domain_contract.md``.

Input contract
--------------

The agent consumes exactly one object: a Step 9I
``DetectionCorrelationBatch``.  The batch is a transport envelope:

* ``detections: list[DetectionCorrelationInput]`` — the detections, in
  caller-provided order (order is transport order only; it implies no
  relationship).
* ``metadata.record_count`` — must equal ``len(detections)``.

A ``DetectionCorrelationInput`` carries: ``detection_id`` (UUID),
``event_id`` (UUID), ``timestamp`` (timezone-aware), ``rule_id``,
``rule_type`` (sigma/yara), ``rule_version`` (optional), ``severity``,
``confidence`` (bounded ``[0, 1]``), ``evidence`` (JSON dict),
``metadata`` (JSON dict), and ``provenance`` (always ``DETECTED``, enforced
by the 9I contract).

Output contract
---------------

The agent returns ``list[CorrelationResult]``.  Each result (Step 10A):

* ``correlation_id`` — generated UUID identity (Step 10A ``uuid.uuid4``
  default; identity generation is not correlation logic).
* ``members: list[CorrelationMember]`` — references (``detection_id``,
  ``event_id``, ``timestamp``), never copies of detection records.
* ``status`` — ``CorrelationStatus.CANDIDATE`` (the agent never sets
  another lifecycle state).
* ``confidence`` — ``None`` (the baseline strategy defines no numeric
  correlation confidence).
* ``evidence`` — structured, JSON-compatible, secret-safe; explains the
  grouping reason.
* ``metadata`` — ``{}`` (empty; the baseline produces no extra metadata).
* ``timestamp`` — the correlation's instant (injected ``clock`` or the
  current UTC time).
* ``provenance`` — ``Provenance.CORRELATED`` (Step 10A enforces this).

Exact baseline correlation strategy
-----------------------------------

**Same-event correlation** — the minimal deterministic rule supported by
the Step 9I/10A contracts.

Two detections correlate **if and only if** they carry the **same
``event_id``**.  Every detection whose ``event_id`` is shared by no other
input forms its own single-member correlation.

The grouping is a strict partition of the batch:

* each input belongs to exactly one group;
* members keep the batch order within each group;
* groups follow first-seen input order.

Signals used
------------

* **``event_id``** — the one and only grouping signal.  ``event_id`` is
  present in every ``DetectionCorrelationInput``, has stable semantics
  (the originating security event's UUID), cannot be fabricated by the
  agent, and is safe to compare.  This is the smallest defensible
  relationship supported by the contract.

Signals deliberately NOT used
-----------------------------

* **``rule_id`` / ``rule_type`` / ``rule_version``** — a rule firing on
  independent events is a property of the rule, not a relationship
  between detections; grouping on it would over-correlate.
* **``timestamp`` / temporal proximity** — no time window exists in the
  contract.  Two detections close in time but from different events are
  **not** correlated.  Temporal correlation is deferred future work.
* **``severity`` / ``confidence``** — never aggregated, compared, or
  reinterpreted.
* **``evidence`` / ``metadata``** — never parsed, compared, or searched
  for entity/indicator values (no heuristic extraction, no NLP).
* **``detection_id``** — identity, not a relationship.
* **Batch membership alone** — transporting records together never
  establishes a relationship.

Grouping condition
------------------

```
group(A, B)  ⇔  A.event_id == B.event_id
```

One group is emitted per distinct ``event_id`` present in the batch.

Non-grouping conditions
-----------------------

* ``event_id`` differs (regardless of rule, time, severity, confidence,
  or evidence similarity);
* the batch contains a single detection (standalone);
* inputs share rule ids, evidence text, metadata, or batch membership
  without sharing ``event_id``.

Same-event semantics
--------------------

Correlating on the same ``event_id`` means: *"these detections originate
from the same source event."*  It does **not** mean the activity is
malicious, represents an attack, or belongs to the same incident.  The
evidence explicitly preserves this distinction.

Singleton semantics
-------------------

Step 10A permits a correlation with a single member.  The baseline
strategy produces a single-member ``CorrelationResult`` (signal
``standalone_detection``) for any detection that shares its ``event_id``
with no other input.  No fabricated partner detection is invented.

Duplicate semantics
-------------------

Step 9I/10A transport duplicates as-is; the engine never silently
deduplicates and never fabricates detection ids.  Identical
``DetectionCorrelationInput`` records are grouped together (same
``event_id``) and preserved as separate members.

Ordering semantics
------------------

* Groups are ordered by first-seen input order (first occurrence of a
  distinct ``event_id`` in the batch).
* Members within a group preserve batch order exactly.
* `event_id`` grouping uses a single indexed pass (dict insertion order
  is not relied upon for output; group order derives from input order).
* Repeated analysis of identical input with an injected ``clock`` yields
  identical grouping, member order, evidence, status, and timestamp.
  Only ``correlation_id`` differs between invocations, per Step 10A's
  generated-identity semantics.

Correlation ID semantics
------------------------

Each result's ``correlation_id`` is generated per invocation by the Step
10A contract (``uuid.uuid4`` default).  Re-running analysis on the same
batch produces a new correlation id — identity generation, not
correlation logic.  Correlation ids are always distinct from detection
ids and event ids.

Evidence semantics
------------------

Evidence explains the exact deterministic reason members were grouped::

    {
        "reason": "shared_event_id",      # or "standalone_detection"
        "event_id": "...",                # the group-defining event
        "member_count": 2                 # members in this group
    }

Evidence is constructed from the group's signal and event id only.  It
never copies detection payloads, detected values, rule ids, severities,
confidences, evidence, or metadata, so it is secret-safe and
JSON-compatible by construction.

Confidence semantics
--------------------

Correlation confidence is a distinct concept from detection confidence.
The baseline strategy defines **no** numeric correlation confidence:
every result carries ``confidence=None`` (Step 10A default).  Detection
confidence is never reused, averaged, maxed, or otherwise converted into
a correlation confidence or a hidden risk score.

Provenance
----------

Every produced result carries ``Provenance.CORRELATED`` (enforced by the
Step 10A validator).  Correlation output is a derived analytical
conclusion and is never observed / enriched / reconstructed / detected.

Determinism
-----------

The same logical input produces equivalent logical output:

* grouping and member ordering are stable;
* evidence and metadata are identical;
* status (``CANDIDATE``), provenance (``CORRELATED``), confidence
  (``None``), and ``timestamp`` are identical when a ``clock`` is
  injected;
* only ``correlation_id`` varies across invocations (Step 10A identity
  semantics).

The strategy is pure: it depends on nothing outside the supplied
sequence — no time, no randomness, no external services, no state.

Input immutability
------------------

The batch, its detection records, and their evidence/metadata are never
mutated.  ``to_correlation_members`` builds independent reference
objects, and result evidence/metadata are fresh structures (the Step 10A
validators also JSON round-trip evidence/metadata).  Output never aliases
input mutable state.

Failure behavior
----------------

The agent distinguishes two controlled failure classes
(``app/services/correlation/exceptions.py``):

* ``CorrelationInputError`` — the agent received something other than a
  ``DetectionCorrelationBatch``, or a strategy received a non-``
  ``DetectionCorrelationInput`` record.  Propagated unwrapped; the
  message names the contract violation without echoing payload content.
* ``CorrelationStrategyError`` — the strategy failed unexpectedly or
  produced malformed output (non-group / empty group / non-UUID event).
  Raised with the original cause preserved through ``__cause__``; the
  message is generic.

No partially constructed ``CorrelationResult`` is ever returned: on any
failure the conversion aborts and raises instead of emitting a malformed
correlation.  Unexpected exceptions are never silently converted to
``[]``.

Security
--------

Security data is untrusted input.  The engine performs no ``eval`` /
``exec`` / subprocess / network / filesystem access.  Evidence is built
only from the group signal and event id.  Logging emits only the strategy
name, input count, and correlation count — never payloads, evidence,
tokens, or secrets.

Complexity
----------

Time ``O(n)``, space ``O(n)``, ``n`` = number of detections in the batch:
a single indexed pass groups by ``event_id`` (dict of
``event_id → group``); there are no pairwise comparisons.

Dependency injection
--------------------

``CorrelationAgent(strategy=None)`` accepts any object exposing the
``CorrelationStrategy`` interface (``name`` and ``correlate(inputs) ->
list[CorrelationGroup]``).  When ``None``, the agent uses
``DeterministicCorrelationStrategy``.  Tests inject custom/failure
strategies without touching production code.

Extensibility
-------------

New strategies (temporal, entity-based, graph-assisted, ML-assisted —
all future work) implement the same ``CorrelationStrategy`` protocol and
are injected into the agent.  The agent itself contains no grouping
logic and no knowledge of protocol internals beyond the interface.

Non-goals
---------

Step 10B implements only the baseline deterministic correlation strategy.
More advanced correlation strategies are future work.

Step 10B explicitly does **not** implement:

* correlation persistence, SQLAlchemy models, migrations, repositories;
* correlation API endpoints;
* Kafka / RabbitMQ integration;
* OpenSearch / Qdrant / Neo4j / knowledge graphs;
* incident management, risk scoring, threat scoring, MITRE ATT&CK,
  threat attribution, threat hunting, SOAR, response, mitigation, or
  attack prediction;
* LLMs, Ollama, LangGraph, embeddings, vector search, or machine
  learning;
* frontend changes.