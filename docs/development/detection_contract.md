Detection Contract (Step 9A)
============================

Overview
--------

**Detection** evaluates structured rules (Sigma, YARA) against enriched
security events and produces deterministic, auditable results.  This
document defines the **contract** for that capability (Step 9A).

It is **contract only**: it introduces the validated data models that
describe detection *rules* and detection *results*, but it does **not**
implement any rule engine (no Sigma interpreter, no YARA runtime, no
Elasticsearch DSL generation, no execution orchestration).

The models live in ``backend/app/schemas/detection.py``.

Purpose
-------

The contract provides a stable, typed schema for detection so that:

1. Rule authors can define rules without coupling to a specific engine.
2. The detection engine (a future step) can be implemented against a
   fixed input/output shape.
3. Downstream consumers (correlation, risk scoring, investigation) can
   rely on a consistent, structured result.
4. Provenance is preserved: a detection result is a *derived analytical
   conclusion* (``DETECTED``), distinct from the source event's own
   provenance (``OBSERVED``, ``ENRICHED``, etc.).
5. Results are auditable — every evaluated rule produces a result, even
   when it does **not** match.

Pipeline position::

    SecurityEvent
        → NormalizedSecurityEvent
            → EnrichedSecurityEvent
                → ThreatIntelligenceAnalysis  (Step 8)
                → DetectionResult             (Step 9A — this contract)

Responsibilities
----------------

The Detection contract:

* Defines ``DetectionRule`` — the static definition of what to evaluate.
* Defines ``DetectionResult`` — the outcome of evaluating a rule
  against one event.
* Requires **structured evidence** (matched conditions, matched fields,
  rule references, detection context) — never free-form prose and no
  raw HTTP responses.
* Requires a timezone-aware ``timestamp``.
* Carries ``severity`` (from the rule; potential impact) separately from
  ``confidence`` (engine certainty on this specific event).
* Rejects secrets anywhere in evidence or metadata.
* Constrains ``confidence`` to ``[0.0, 1.0]``.

Non-responsibilities
--------------------

The Detection contract is **not**:

* a Sigma engine,
* a YARA engine,
* an Elasticsearch DSL generator,
* a risk scorer,
* a correlation engine,
* an AI investigator, or
* a verdict engine.

It therefore defines **no** ``verdict``, **no** ``risk_score``, **no**
``alert_level``, and **no** aggregated threat score.  Severity and
confidence are properties of a single detection result, not an
aggregated verdict.

Enums
-----

``RuleType``
    ``sigma``, ``yara`` — the detection engine a rule is written for.

``DetectionSeverity``
    ``low``, ``medium``, ``high``, ``critical`` — the rule author's
    assessment of potential impact.

DetectionRule
-------------

A ``DetectionRule`` is a **static definition**; it carries no results.

* ``rule_id`` (required, non-blank) — stable unique rule identifier.
* ``name`` (required, non-blank) — human-readable name.
* ``description`` (required, non-blank) — what the rule detects.
* ``rule_type`` (required) — engine type.
* ``severity`` (required) — potential impact.
* ``enabled`` (default ``True``) — whether the engine should evaluate it.
* ``version`` (default ``"1.0.0"``) — semantic rule version.
* ``metadata`` (default) — ``DetectionMetadata``.

DetectionResult
---------------

A ``DetectionResult`` is the **derived analytical conclusion** of
evaluating one rule against one event.

* ``detection_id`` (auto-generated UUID) — unique result identifier.
* ``event_id`` (required) — the source event, preserved exactly.
* ``rule_id`` (required) — the evaluated rule, traceable to a rule.
* ``rule_type`` (required) — engine type of the evaluated rule.
* ``matched`` (required) — ``True`` = match, ``False`` = evaluated,
  did not match.
* ``severity`` (required) — from the rule.
* ``confidence`` (required, ``[0.0, 1.0]``) — engine certainty.
* ``evidence`` (default) — structured evidence.
* ``timestamp`` (required, timezone-aware) — evaluation time.
* ``metadata`` (default) — flexible evaluation metadata.
* ``provenance`` (default ``DETECTED``) — always a derived conclusion.

Structured Evidence
-------------------

``DetectionEvidence`` carries four independent, JSON-serializable
sections:

* ``matched_conditions`` — which rule conditions matched.
* ``matched_fields`` — event fields that matched.
* ``rule_references`` — related references (e.g. MITRE ATT&CK, CVE).
* ``detection_context`` — engine/rule context for the match.

Every section must be JSON-serializable; values that cannot be
serialised are rejected at the schema boundary.

Severity vs Confidence
----------------------

These two values are deliberately independent:

* ``severity`` reflects *potential impact* as assessed by the rule
  author.
* ``confidence`` reflects the engine's *certainty* that this specific
  evaluation outcome is correct.

Confidence is a required float constrained to ``[0.0, 1.0]``.

Provenance
----------

Every ``DetectionResult`` defaults to ``Provenance.DETECTED``.  This
marks the result as a derived analytical conclusion rather than a direct
observation.  The source event's own provenance is preserved on the
event record referenced by ``event_id``.

Secret-Safety
-------------

The contract rejects secrets at two levels:

1. **Schema level** — no model defines an ``api_key``,
   ``authorization``, ``token``, ``secret``, ``headers``, or
   ``raw_response`` field.
2. **Validation level** — ``evidence`` and ``metadata`` are scanned for
   the patterns ``api_key``, ``authorization``, ``bearer``, and
   ``secret`` as a defence-in-depth check.

Evidence is always structured; raw HTTP responses are never stored.

Criteria
--------

Validation criteria covered by the contract tests:

1. RuleType enum values (sigma, yara)
2. DetectionSeverity enum values (low…critical)
3. DetectionEvidence valid construction (four sections)
4. DetectionEvidence JSON serialization round-trip
5. DetectionEvidence rejects non-JSON-serializable values
6. DetectionMetadata valid construction and defaults
7. DetectionMetadata rejects negative execution_time_ms
8. DetectionRule valid construction and defaults
9. DetectionRule blank rule_id rejected
10. DetectionRule blank name rejected
11. DetectionResult valid construction with auto-generated detection_id
12. DetectionResult provenance defaults to DETECTED
13. Naive timestamp rejected
14. Confidence bounds enforcement ([0.0, 1.0])
15. Secrets in evidence rejected
16. Secrets in metadata rejected
17. Serialization round-trip for DetectionResult
18. Event ID preserved from source event (never regenerated)
19. Unique detection_id across multiple results
20. No verdict / risk_score / alert_level fields (no fabrication)
21. Structured evidence holds all four sections
22. DetectionRule serialization round-trip
23. Evidence and metadata keys are secret-safe at schema level

File Locations
--------------

* Contract models: ``backend/app/schemas/detection.py``
* Contract tests: ``backend/tests/unit/test_detection_contract.py``
* This document: ``docs/development/detection_contract.md``

Existing dependencies the contract reuses:

* ``Provenance`` from ``app.schemas.security_event``.

Consumers may import the detection schemas from ``app.schemas`` (the
package ``__init__`` re-exports ``RuleType``, ``DetectionSeverity``,
``DetectionEvidence``, ``DetectionMetadata``, ``DetectionRule``, and
``DetectionResult``) or directly from ``app.schemas.detection``.

