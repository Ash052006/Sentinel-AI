Risk Scoring Agent & Deterministic Risk Scoring Engine (Step 11B)
================================================================

Purpose
-------

Step 11B implements the **Risk Scoring Agent** and the first
**deterministic baseline risk scoring engine** for SentinelAI.  It
consumes a Step 10A ``CorrelationResult`` and produces a Step 11A
``RiskAssessment``.

Detection answers *"what individual security rules matched this event?"*.
Correlation answers *"which detections/events are related?"*.  Risk
scoring answers *"how dangerous does this correlated situation appear,
and how confident is SentinelAI in that assessment?"* — for Step 11B that
answer is deliberately minimal, deterministic, and explainable.

> **Step 11B calculates deterministic risk assessments from existing
> security/correlation evidence.  It does not persist risk assessments,
> expose a risk API, create incidents, map MITRE ATT&CK, perform
> response, or use LLM/AI-generated scoring.**

Step 11A (the Risk Assessment domain contract) is authoritative and is
not redesigned here.  Step 11B adds the agent that orchestrates a scoring
strategy and the in-memory deterministic engine that produces the
assessment.  No persistence, no API, no message bus, and no AI are
introduced by this step.

Files
-----

| File | Purpose |
|------|---------|
| ``app/services/risk/exceptions.py`` | ``RiskScoringError`` / ``RiskScoringInputError`` / ``RiskScoringStrategyError`` — the Step 11B failure hierarchy |
| ``app/services/risk/engine.py`` | scoring policy constants, pure helpers, ``RiskScoringStrategy`` protocol, ``DeterministicRiskScoringEngine`` |
| ``app/services/risk/__init__.py`` | package re-exports (existing convention) |
| ``app/agents/risk_scoring.py`` | ``RiskScoringAgent`` — orchestration + input/output validation |
| ``app/agents/__init__.py`` | agent package re-export (additive) |
| ``tests/unit/test_risk_scoring.py`` | Step 11B behavior + boundary + regression tests (86 tests) |

Architecture
------------

::

    CorrelationResult                      (Step 10A)
          ↓
    RiskScoringAgent                       (this step — orchestration)
          ↓
    RiskScoringStrategy                    (this step — strategy contract)
          ↓
    DeterministicRiskScoringEngine         (this step — baseline engine)
          ↓
    RiskAssessment                         (Step 11A)
          ↓
    [Future Risk Persistence (Step 11C)]

Related steps: Step 10A (``CorrelationResult`` / ``CorrelationMember``),
documented in ``correlation_domain_contract.md``; Step 11A
(``RiskAssessment`` / ``RiskLevel`` / ``RiskEvidence`` / ``RiskFactor``),
documented in ``risk_contract.md``.

Input contract
--------------

The agent consumes exactly one object: a Step 10A ``CorrelationResult``.

* ``correlation_id`` — the correlation's UUID identity.
* ``members: list[CorrelationMember]`` — detections belonging to this
  correlation, each a reference (``detection_id``, ``event_id``,
  ``timestamp``).  The Step 10A contract guarantees at least one member
  (the engine never accepts, and never invents, an empty correlation).
* ``status`` — lifecycle bookkeeping (``candidate`` / ``active`` /
  ``closed``).  **Never** a scoring signal.
* ``confidence`` — the correlation's optional numeric confidence
  (``[0, 1]`` by contract, or ``None``).
* ``evidence`` / ``metadata`` — opaque engine artefacts.  **Never**
  parsed, compared, or scored.
* ``timestamp`` / ``provenance`` — descriptive; the scoring timestamp is
  supplied by the agent at scoring time, not read from the correlation.

Output contract
---------------

The agent returns exactly one ``RiskAssessment`` (Step 11A):

* ``risk_assessment_id`` — Step 11A-generated UUID (identity generation
  per that contract; never influences scoring).
* ``correlation_id`` — the evaluated correlation's exact id, referenced
  and never regenerated.
* ``score`` — normalized ``[0.0, 1.0]`` risk score.
* ``level`` — ``RiskLevel`` controlled category derived from the score.
* ``confidence`` — independent of the score/level, sourced only from the
  correlation's confidence.
* ``factors`` — three named, deterministic contributors.
* ``evidence`` — one structured observation per correlation member.
* ``metadata`` — JSON-compatible, secret-free scoring bookkeeping.
* ``timestamp`` — the assessment's instant (injected ``clock`` or the
  current UTC time); never a scoring input.
* ``provenance`` — ``Provenance.RISK_ASSESSED`` (Step 11A enforces this).

Scoring policy
--------------

**Cardinality scoring.**  The engine derives exactly three objective
signals from the Step 10A contract — counts that genuinely exist in every
``CorrelationResult``:

1. ``member_count`` — how many detections are linked (volume).
2. ``distinct_event_count`` — how many distinct source ``event_id``
   values the members reference (breadth).
3. ``distinct_detection_count`` — how many distinct ``detection_id``
   values the members reference (diversity).

Each signal is normalized to ``[0.0, 1.0]`` and combined with fixed,
documented weights summing to exactly ``1.0``::

    volume_n  = normalize_excess(member_count,        8)
    breadth_n = normalize_excess(distinct_event_count, 4)
    diversity_n = normalize_excess(distinct_detection_count, 4)

    score = round(clamp01(
        0.5 * volume_n + 0.3 * breadth_n + 0.2 * diversity_n
    ), 6)

* ``WEIGHT_VOLUME = 0.5``, ``WEIGHT_BREADTH = 0.3``,
  ``WEIGHT_DIVERSITY = 0.2``.
* References: ``VOLUME_REFERENCE = 8``, ``BREADTH_REFERENCE = 4``,
  ``DIVERSITY_REFERENCE = 4``.
* ``ROUND_DECIMALS = 6`` — the score and every contribution use the same
  rounding for bit-for-bit reproducibility.
* A minimal standalone correlation scores exactly ``0.0`` (LOW); a
  maximal correlation (at or above every reference) scores exactly
  ``1.0`` (CRITICAL).

Signals
-------

**Used.**  Only the three cardinality signals above.  They are chosen
because each is:

* **present** in every ``CorrelationResult`` (no fabrication);
* **objective** — a count that cannot be mistaken for an opinion;
* **derived from real security facts** — real linked detections, real
  source events, real distinct detection rules.

**Deliberately NOT used.**  The engine consumes only what Step 10A
supplies.  Anything present in other layers but absent from
``CorrelationResult`` is **never** invented, aggregated, or scored:

* **severity** — exists in ``DetectionCorrelationInput`` /
  ``DetectionResult``, but **not** in ``CorrelationResult``; scoring it
  would require fabricating data.
* **per-detection ``confidence``** — same absence; never averaged, maxed,
  or reused.
* **``rule_id`` / ``rule_type`` / ``rule_version``** — rule properties,
  present only in detection inputs, never in the correlation.
* **member / correlation ``timestamp``** — timestamps are never scoring
  inputs (temporal weighting is future work).
* **correlation ``status``** — lifecycle bookkeeping, not risk evidence.
* **correlation ``evidence`` / ``metadata`` content** — opaque engine
  artefacts, never parsed or searched (no heuristic/entity extraction, no
  NLP).
* **threat intelligence / ML / graph signals** — no external data sources
  exist in this step.

Normalization
-------------

``normalize_excess(count, reference)`` maps a count into ``[0.0, 1.0]``
by subtracting the single-element baseline and saturating at the
reference::

    normalize_excess(count, reference) =
        clamp01((count - 1) / (reference - 1))

* ``count == 1`` yields exactly ``0.0`` — a standalone detection carries
  no excess signal.
* ``count >= reference`` yields exactly ``1.0`` — the signal is saturated
  (references are not hard caps).
* The baseline subtraction is what lets the minimal correlation reach
  ``0.0`` and satisfies low-level reachability from a single detection.

Level mapping
-------------

The score is mapped to a ``RiskLevel`` by fixed, lower-inclusive
thresholds (``risk_level_for_score``):

* ``score < 0.30``                        → ``LOW``
* ``0.30 <= score < 0.55``                → ``MEDIUM``
* ``0.55 <= score < 0.75``                → ``HIGH``
* ``0.75 <= score``                       → ``CRITICAL``

Every boundary (``0.30``/``0.55``/``0.75``) is resolved by the pure,
independently-tested helper and by end-to-end reachability tests for each
level.

Confidence policy
-----------------

``confidence`` is **independent** of the score and level — a distinct
concept conceived as *"how confident is SentinelAI in this assessment?"*.

* When the correlation asserts a numeric confidence (a Step 10A field),
  it is copied through unchanged.
* When the correlation asserts none (``None``), the engine records a
  documented baseline of ``CONFIDENCE_ABSENT_BASELINE = 0.0``: it never
  invents a confidence number.
* The confidence never influences the score/level, and the score/level
  never influence the confidence.  No formula links them.

Factors
-------

Every assessment carries exactly three ``RiskFactor`` entries, in
deterministic order, each naming its signal and supplying evidence for
every real fact that contributed:

| Factor | Contribution | Evidence |
|--------|--------------|----------|
| ``member_volume`` | ``round(volume_n, 6)`` | one ``correlation_member`` observation per member |
| ``event_breadth`` | ``round(breadth_n, 6)`` | one ``distinct_event`` observation per distinct event |
| ``detection_diversity`` | ``round(diversity_n, 6)`` | one ``distinct_detection`` observation per distinct detection |

Evidence & metadata semantics
-----------------------------

Evidence is built only from member references and documented counts — it
is structured, JSON-compatible, and secret-safe by construction.  The
assessment-level evidence is one ``correlation_member`` observation per
member (member order preserved); the factor evidence reuses the same
member facts plus per-event and per-detection observations.

Evidence never copies detection payloads, detected values, rule ids,
severities, confidences, or correlation evidence/metadata content.

Assessment ``metadata`` is a deterministic, JSON-compatible, secret-free
record: the policy label (``deterministic_cardinality_risk_v1``), the
three raw counts, the three normalized values, the documented weights,
references, and level thresholds.  It contains no timestamps, identities,
or content copied from the correlation.

Determinism
-----------

The same logical correlation produces an identical assessment:

* score, level, confidence, factors, contributions, evidence, and
  metadata are identical;
* the timestamp is identical when a ``clock`` is injected (otherwise the
  current UTC time — descriptive bookkeeping, never a scoring input);
* only the Step 11A-generated ``risk_assessment_id`` varies between
  invocations (identity semantics, per the 11A contract).

The engine is pure: it depends on nothing outside the supplied
correlation — no time (for scoring), no randomness, no external services,
no state.

Input immutability
------------------

The correlation and its members are never mutated.  The assessment
references the correlation by ``correlation_id`` rather than copying it;
evidence is built into fresh ``RiskEvidence`` objects.  Output never
aliases input mutable state — appending to ``correlation.members`` after
scoring never changes a previously produced assessment.

Failure behavior
----------------

The agent distinguishes two controlled failure classes
(``app/services/risk/exceptions.py``), mirroring the Step 10B
correlation conventions:

* ``RiskScoringInputError`` — the agent received something other than a
  ``CorrelationResult``.  Propagated unwrapped; the message names the
  contract violation without echoing payload content.
* ``RiskScoringStrategyError`` — the configured strategy failed
  unexpectedly or returned a non-``RiskAssessment`` result.  Raised with
  the original cause preserved through ``__cause__``; the message is
  generic.

No partially constructed ``RiskAssessment`` is ever returned.  A
malformed strategy result is never passed through; unexpected exceptions
are never silently converted to a bogus low-risk assessment.

Security
--------

Security data is untrusted input.  The engine performs no ``eval`` /
``exec`` / subprocess / network / filesystem access.  Evidence includes
detection/event ids (references, not payloads) and documented counts
only.  Logging emits only the engine name, the correlation id, and the
score/level — never payloads, evidence, tokens, or secrets.

Complexity
----------

Time ``O(n)``, space ``O(n)``, ``n`` = number of members in the
correlation: a single pass computes the three cardinality signals; two
insertion-ordered passes derive distinct events/detections.  There are no
pairwise comparisons.

Dependency injection
--------------------

``RiskScoringAgent(engine=None)`` accepts any object exposing the
``RiskScoringStrategy`` protocol (``name`` and ``score(correlation, *,
timestamp) -> RiskAssessment``).  When ``None``, the agent uses
``DeterministicRiskScoringEngine``.  Tests inject custom/failure engines
without touching production code.  ``engine_name`` exposes the configured
strategy's name.

Non-goals
---------

Step 11B implements only the baseline deterministic cardinality engine.
More advanced scoring (severity/rule-weighted, temporal, threat-intel or
ML-assisted) is future work.

Step 11B explicitly does **not** implement:

* risk assessment persistence, SQLAlchemy models, migrations, or
  repositories (Step 11C);
* risk query or API endpoints (Steps 11D / 11E);
* Kafka / RabbitMQ integration;
* OpenSearch / Qdrant / Neo4j / knowledge graphs;
* incident management, MITRE ATT&CK mapping, threat attribution, threat
  hunting, SOAR, response, mitigation, or attack prediction;
* LLMs, Ollama, LangGraph, embeddings, vector search, or machine
  learning — no AI-generated scores;
* frontend changes.