Detection Agent (Step 9E)
========================

Overview
--------

**Step 9E** adds the **Detection Agent** — the orchestration layer that
coordinates the existing Step 9C Sigma and Step 9D YARA detection engines
against a single :class:`NormalizedSecurityEvent` and produces one unified
:class:`DetectionAnalysis`.

The agent is an **orchestrator only**: it does **not** implement detection
logic.  Sigma rule parsing, Sigma condition evaluation, Sigma evidence
generation, YARA compilation, YARA scanning, YARA evidence generation, and
confidence calculation all remain inside their respective engines.

Architecture
------------

::

    NormalizedSecurityEvent
            |
            v
        DetectionAgent
            |
            +--------------------+
            |                    |
            v                    v
    SigmaDetectionEngine   YaraDetectionEngine
            |                    |
            +---------+----------+
                      |
                      v
            Unified Detection Analysis

File locations
--------------

* Agent: ``backend/app/agents/detection.py``
* Contract: ``backend/app/schemas/detection_agent.py``
* Tests: ``backend/tests/unit/test_detection_agent.py``
* This document: ``docs/development/detection_agent.md``

Purpose
-------

Before 9E, Sigma and YARA produced separate, engine-specific reports
(``SigmaDetectionReport`` / ``YaraDetectionReport``).  Downstream consumers
would have had to call both engines and merge their outputs themselves.
The Detection Agent performs that merge once, in a deterministic,
judgment-free way, and packages the outcome as a single
:class:`DetectionAnalysis` object.

Inputs
------

* A :class:`~app.schemas.normalized_event.NormalizedSecurityEvent`.
* A :class:`~app.services.detection.registry.DetectionRuleRegistry`
  (injected at construction time).

Outputs
-------

* A :class:`DetectionAnalysis` containing:

  * ``event_id`` — preserved from the input event.
  * ``results`` — every matched :class:`DetectionResult` from both engines.
  * ``failures`` — every rule-level and engine-level failure from both
    engines, normalised into :class:`DetectionFailure` with an ``engine``
    discriminator.
  * ``metadata`` — aggregate counts (:class:`DetectionAnalysisMetadata`).
  * ``timestamp`` — timezone-aware time of analysis.
  * ``provenance`` — always ``DETECTED``.

Orchestration flow
------------------

1. The Sigma engine is executed first: ``sigma_engine.evaluate(event)``.
   Rule selection is delegated entirely to the engine (it fetches enabled
   Sigma rules from its registry when rules are not passed explicitly).
2. The YARA engine is executed second:
   ``yara_engine.evaluate(event, yara_rules)`` where ``yara_rules`` are the
   enabled YARA rules fetched from the registry.  The YARA engine requires
   an explicit rule list (it has no registry reference of its own).
3. Engine results are concatenated (Sigma first, then YARA) and engine
   failures are normalised and concatenated in the same order.
4. A :class:`DetectionAnalysis` is assembled with deterministic aggregate
   metadata.

Sigma integration
-----------------

The agent calls ``SigmaDetectionEngine.evaluate(event)``.  It never parses
Sigma YAML, never constructs pySigma objects, never evaluates conditions,
and never builds Sigma evidence.  All of that behaviour lives in Step 9C
(``app/services/detection/sigma/``).

YARA integration
----------------

The agent calls ``YaraDetectionEngine.evaluate(event, rules)``.  It never
compiles YARA rules, never scans content bytes, never manages the compiled
rule cache, and never builds YARA evidence.  All of that behaviour lives in
Step 9D (``app/services/detection/yara/``).

Failure isolation
-----------------

Each engine executes inside its own ``try/except Exception`` block.  If an
engine raises an unexpected exception, the other engine still executes.
The unexpected exception is recorded as a structured
:class:`DetectionFailure` with ``error_type="engine_error"`` and a
secret-safe message containing only the exception class name — never the
exception arguments, never rule content, never event payloads.

Rule-level failures (``malformed_rule``, ``unsupported_feature``,
``match_error``, ``invalid_target``) reported in each engine's report are
normalised into :class:`DetectionFailure` objects with the originating
engine name.

No-match semantics
------------------

A valid rule that evaluates successfully but does not match produces **no**
result and **no** failure.  The analysis may legitimately contain:

.. code-block:: python

    results = []
    failures = []

when no enabled rules match and no execution problems occur.

Invalid-target semantics
------------------------

**INVALID TARGET != NO MATCH.**  When the YARA engine reports an invalid
target for an event without usable file content, the agent preserves that
failure (``error_type="invalid_target"``) rather than treating it as a
normal no-match.  The agent never invents a fallback target, never treats
file names, hashes, paths, process names, or command lines as content, and
never silently converts an invalid target into an empty result set.

Deterministic ordering
----------------------

Ordering is explicitly deterministic:

1. Sigma results and failures, then YARA results and failures.
2. Within each engine, rules are evaluated in the deterministic ``rule_id``
   order produced by the registry (``find_enabled_by_type`` sorts by
   ``rule_id``) / the engine's internal ordering.

Python set ordering, dictionary insertion order, randomised ordering, and
filesystem ordering are never relied upon.

Provenance
----------

* The analysis and every result carry ``Provenance.DETECTED`` — detection
  is a derived analytical conclusion.
* The input event's own provenance (``OBSERVED``, ``ENRICHED``,
  ``RECONSTRUCTED``) is never modified by the agent.
* Reconstructed input is never silently treated as observed.

Immutability
------------

The agent never mutates:

* the input :class:`NormalizedSecurityEvent` (including nested structures
  such as ``normalized_data``),
* any :class:`DetectionRule` object stored in the registry,
* any engine-owned report object.

Aggregation always creates a new output structure.

Dependency injection
--------------------

Constructor injection is used (no DI framework):

.. code-block:: python

    DetectionAgent(
        registry: DetectionRuleRegistry | None = None,
        *,
        sigma_engine: SigmaDetectionEngine | None = None,
        yara_engine: YaraDetectionEngine | None = None,
    )

When an engine is not supplied, a default instance is created.  This makes
the agent easy to unit-test with fake/mock engines (the Step 9E test suite
injects exploding fake engines to verify failure isolation).

Explicit non-responsibilities
-----------------------------

The Detection Agent does **not**:

* parse Sigma rules or evaluate Sigma conditions,
* compile or scan YARA rules,
* calculate risk scores, severity aggregation, or threat verdicts,
* map MITRE ATT&CK techniques,
* correlate events across time,
* persist results to a database (no Alembic migration, no new tables),
* expose API endpoints,
* call external services (HTTP, VirusTotal, AbuseIPDB, AlienVault OTX,
  Kafka, Redis, Qdrant, Neo4j, Ollama, or any LLM),
* execute code with ``eval``/``exec``, spawn subprocesses, or read
  arbitrary files.

It only invokes the existing detection engines and packages their outputs.