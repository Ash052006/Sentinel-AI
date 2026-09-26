Incident Memory Learning & Consolidation (Step 22)
==================================================

Purpose
-------

Step 22 adds a **deterministic, read-only consolidation** layer over the
already-persisted incident memories (Step 17 persistence, read through the
Step 18 ``IncidentMemoryQueryService``).  It distills explicit, reproducible
recurring patterns — a repeated memory type, observed indicator, technique,
mitigation action, explicit outcome status, or source-provenance relationship —
into structured :class:`IncidentMemoryLearning` records (a
:class:`IncidentMemoryLearningResult`), each carrying its historical
supporting ``memory_id`` references, a distinct-memory occurrence count,
first/last occurrence instants, support-count-derived confidence, and
deterministic policy metadata.

It is a **derived historical analysis**, never a verdict generator:

::

    Step 22 consolidates already-persisted incident memories into
    in-memory historical lessons.  It reads no live telemetry, calls no
    LLM / RAG / vector store, writes nothing to the database, exposes no
    API, mutates no memory, and changes no policy / playbook / rule /
    detection / response / threat-intel / model behaviour.

Where it sits::

    incident_memories (Step 17 persistence)
        -> IncidentMemoryQueryService   (Step 18, read-only)
            -> IncidentMemoryLearningService   (this layer, read-only)
                -> IncidentMemoryLearningResult (in-memory domain result)

Architecture boundary — query-only consumption
----------------------------------------------

The learning service composes **only** :class:`IncidentMemoryQueryService`
(the ``list_memories`` read).  It holds **no SQLAlchemy session / model /
repository dependency** and never calls ``add`` / ``delete`` / ``flush`` /
``commit`` / ``rollback``.  A caller-owned ``db`` object is passed through
verbatim to the query service exactly as the Step 18 convention requires.  A
query-service factory is injected for testability and the resolved instance
is type-checked at the last possible moment, so the boundary can never be
widened:

* corpus pages are read with a bounded page size (the Step 18
  ``MAX_PAGE_SIZE``) until ``total`` is reached;
* a query result that is internally inconsistent (wrong page, empty
  continuation page, ``len(items) != total``) is **refused**, never patched;
* a provider that is not an ``IncidentMemoryQueryService`` is refused as an
  input-validation failure.

Evidence separation — learning is not evidence
----------------------------------------------

Learning records and results are **not** ``InvestigationEvidence``.

::

    Learning results are derived historical analysis.  They are not
    current security observations and are not automatically
    InvestigationEvidence.

* The only memory identities carried are the historical
  ``supporting_memory_ids`` references; there are no ``evidence_id`` /
  ``evidence_type`` fields and no detection / correlation / risk-assessment /
  attribution identities as evidence.
* A learning record is therefore historical context for analysis — any
  decision to elevate a learning record into a live evidence chain belongs to
  an explicit, separate step, not to this one.

Design principles
-----------------

* **Explicit incident-memory fields only.**  Patterns are read strictly off
  the Step 16/18 incident-memory contract: ``memory_type``; structured
  ``indicators`` (``indicator_type`` + ``value``); ``techniques``
  (``technique_code``); ``actions`` (``action_type``); explicit ``outcomes``
  (a bounded free ``outcome_status`` string that is **never interpreted** as
  success/failure); and per-source ``sources`` provenance.  Anything the
  contract cannot express (event categories, detection rule identifiers) is
  documented out of scope and is never fabricated.
* **Canonical grouping.**  Patterns group by ``(learning_type, pattern_key)``
  with a canonical key construction; groups are enumerated in ``LearningType``
  enum order and key-sorted within each type; every ``supporting_memory_ids``
  list is ascending and duplicate-free.  No database row order, Python set
  iteration or dict insertion order is ever relied upon.
* **Determinism.**  Identical corpora produce byte-identical
  ``IncidentMemoryLearningResult`` JSON (modulo the injected
  ``uuid_factory`` / ``clock``, mirroring the Step 16 extractor convention).
* **Refuse, never truncate.**  Over-limit input — a corpus larger than
  ``MAX_LEARNING_INPUT_MEMORIES``, a group supported by more than
  ``MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES`` memories, or a result with
  more than ``MAX_LEARNING_OUTPUT_RECORDS`` records — is **rejected** with an
  ``IncidentMemoryLearningInputValidationError``, never silently trimmed.
* **Missing stays missing.**  A supporting memory without an explicit
  outcome is counted as *missing*; conflicting explicit outcome statuses are
  preserved side by side, never resolved by majority.
* **Fail-closed secret safety.**  Secret-shaped content is rejected, never
  redacted, at the schema boundary *and* at the service boundary.

Learning taxonomy
-----------------

``LearningType`` (additive, like every staged SentinelAI taxonomy) and the
exact contract field each maps to:

| | LearningType | Field read | Pattern key |
|-----------------------------|--------------------|--------------------------------------------------|
| ``recurring_memory_type``   | ``memory_type``    | ``memory_type=<value>`` |
| ``recurring_indicator``     | ``indicators[]`` — ``indicator_type`` + ``value`` | ``indicator_type=<type>|value=<value>`` |
| ``recurring_technique``     | ``techniques[]`` — ``technique_code`` | ``technique_code=<code>`` |
| ``recurring_action``        | ``actions[]`` — ``action_type`` | ``action_type=<type>`` |
| ``recurring_outcome``       | ``outcomes`` — ``outcome_status`` | ``outcome_status=<status>`` |
| ``recurring_source_provenance`` | ``sources[]`` — ``provenance`` | ``source_provenance=<provenance>`` |

The pattern **value** is always the exact consolidated string read off the
contract; the **key** is the canonical, deterministic identifier within the
learning type.  "Repeated detection / rule / event category" is folded into
the source-provenance relationship; rule identifiers and event categories
are out of scope.

Confidence
----------

Each learning record carries a support-count-derived confidence that is
**independent** from any memory / risk / detection / investigation /
attribution confidence:

::

    confidence(occurrence_count) = min(1.0, occurrence_count / 5)

* ``LEARNING_CONFIDENCE_SATURATION = 5`` — the distinct-memory occurrence
  count at which confidence saturates at 1.0.
* Monotonic, deterministic, bounded to ``[0.0, 1.0]``, derived **only** from
  explicit support.  The formula is recorded verbatim in every result's
  run metadata for explainability.
* A single occurrence is a fact, not a recurring lesson: the default
  ``min_occurrences`` is 2.

Outcome consolidation
---------------------

``LearningOutcomeInfo`` is built strictly from the Step 16 outcome contract
as persisted/queried:

* ``explicit_outcome_count`` — supporting memories with a non-empty
  ``outcomes`` payload.
* ``missing_outcome_count`` — supporting memories with no outcome.  Missing
  stays missing (never converted to a success/failure).
* ``outcome_statuses`` — the unique explicit status strings, ascending and
  duplicate-free.  The Step 16 contract leaves ``outcome_status`` a bounded
  free string; it is never interpreted as a verdict, and **conflicting
  statuses appear side by side, never majority-resolved**.
* Coherence invariants: statuses present iff at least one explicit outcome;
  ``explicit + missing == occurrence_count``.

Bounds (contract)
-----------------

| Constant | Value | Meaning |
|----------------------------------------------|--------|--------------------------------|
| ``MAX_LEARNING_PATTERN_KEY_LENGTH`` | 2048 | max serialized key length |
| ``MAX_LEARNING_PATTERN_VALUE_LENGTH`` | 512 | max pattern value / status length (mirrors the Step 16 label cap) |
| ``MAX_LEARNING_METADATA_DEPTH`` | 8 | max metadata nesting depth |
| ``MAX_LEARNING_METADATA_SERIALIZED_BYTES`` | 4096 | max metadata serialized size |
| ``MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES`` | 1000 | max supporting references per record / max ``min_occurrences`` |
| ``MAX_LEARNING_OUTPUT_RECORDS`` | 2000 | max learning records per result |

Service-side bounds: ``MAX_LEARNING_INPUT_MEMORIES = 5000`` (refused, never
truncated), ``DEFAULT_MIN_OCCURRENCES = 2``.

Provenance
----------

Every learning record is **pinned to ``Provenance.LEARNED``** — an additive
value added to the Step 14 ``Provenance`` enum for this step.  A learning
record can never masquerade as current telemetry, as an analytical verdict,
or as an original recalled memory.  Unchanged contract behaviour is
preserved: ``IncidentMemory`` continues to pin ``RECALLED``, and
``MemorySource`` rejects both ``RECALLED`` and ``LEARNED`` (sources always
retain their original provenance).

Secret safety
-------------

Fail-closed, in lock-step with the staged contracts:

* schema boundary — ``learning record metadata``, whole learning records, and
  the whole result envelope are scanned for the canonical credential-shaped
  substring set (``api_key``, ``authorization``, ``bearer``, ``secret``,
  ``password``, ``cookie``, ``session_token``, ``jwt``);
* service boundary — before assembly, every memory-derived string destined
  for output (pattern keys, pattern values, outcome statuses) is value-scanned
  for credential-shaped patterns and the substring set.

Secrets are **rejected, never redacted**.  Sanitization is the last line of
defence: the new ``IncidentMemoryLearningSafetyError`` carries a generic
message and never repeats the secret-shaped content it rejected.

Failure model
-------------

``IncidentMemoryLearningError`` is the base of a dedicated hierarchy; every
message is sanitized (no credentials, no raw memory payloads, no driver/SQL
text) and failures chain to their cause via ``__cause__`` for server-side
logging:

| Exception | Raised for |
|-----------|-----------|
| ``IncidentMemoryLearningInputValidationError`` | unusable ``clock`` / ``uuid_factory`` / ``min_occurrences``, unusable query-service factory, non-query provider, over-cap corpus / support set / output, inconsistent corpus (refuse, never truncate) |
| ``IncidentMemoryLearningQueryError`` | the underlying query service failed (sanitized, chained) |
| ``IncidentMemoryLearningStrategyError`` | any unexpected consolidation failure (chained) |
| ``IncidentMemoryLearningOutputValidationError`` | an assembled record failed contract re-validation |
| ``IncidentMemoryLearningSafetyError`` | secret-shaped content detected in assembled output |

Scope / non-goals
-----------------

* **No LLM, no RAG, no embeddings, no vector/graph store.**  The deterministic
  consolidation never imports or invokes any AI-provider or retrieval code;
  this is enforced by AST-based tests.
* **No persistence, no API, no Kafka.**  The result is an in-memory domain
  result; there are no new tables, no migrations, no endpoints, no producers.
* **No policy / playbook / rule / detection / response behaviour.**  Learning
  never generates rules, mitigations, or *current* security actions.
* **No inference from prose.**  Only explicit contract fields are read;
  nothing is invented about attackers, IPs, domains, malware, techniques,
  actions, outcomes, or verdicts.
* **Not InvestigationEvidence.**  See "Evidence separation".

Verification
------------

Targeted suite: ``pytest tests/unit/test_incident_memory_learning.py``,
covering contract, normal consolidation, outcomes, bounds/refuse, invalid
input, query failure, output re-validation, strategy failure, secret safety,
determinism, immutability, evidence separation, prompt-injection-safe data
handling, query boundary, and AST architecture isolation.

File map
--------

| File | Purpose |
|------|---------|
| ``app/schemas/incident_memory_learning.py`` | Step 22 domain contract (``LearningType``, ``LearningOutcomeInfo``, ``IncidentMemoryLearning``, ``IncidentMemoryLearningResult``, bounds) |
| ``app/services/incident_memory_learning.py`` | ``IncidentMemoryLearningService`` + policy constants + exception hierarchy + secret-safety scan |
| ``app/schemas/security_event.py`` | additive ``Provenance.LEARNED`` member (Step 22) |
| ``tests/unit/test_incident_memory_learning.py`` | Step 22 behavior tests |
| ``docs/development/incident_memory_learning.md`` | this document |