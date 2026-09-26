Natural Language SOC (Step 23)
==============================

Purpose
-------

Step 23 adds a **controlled Natural Language SOC interface**: an
authenticated SOC user (admin/analyst/ciso) asks a question in natural
language, and the system translates it into a validated, allowlisted,
read-only SOC query and returns the existing query-layer read models in a
structured envelope.

> Natural Language SOC converts user language into a validated, allowlisted,
> read-only SOC query.  It does **not** execute arbitrary natural language,
> SQL, code, or actions.  User language can never name a function, a
> table, an SQL statement, or a file; it can only influence a structured
> intent that is deterministically validated against the allowlist grammar
> before any database work.

The interface sits **above** the existing read-only query services
(Detection / Correlation / Risk / Incident Memory).  Step 23 adds **no new
query implementation, no new tables, no migration, and no write surface**.
It adds exactly **one endpoint** — ``POST /api/soc/query`` — which is
read-only with respect to SentinelAI security data.

What the LLM is and is not

The LLM's only role is **language understanding**: it converts natural
language into a structured *candidate* intent (``SOCModelIntent``).  The
candidate is **untrusted** and, like the Step 12C investigation output,
must pass strict deterministic validation before anything else.  The LLM:

* never executes queries, accesses databases or tools, or modifies state;
* never names functions, methods, SQL, shell commands, files, or actions —
  its contract enumerates exactly four resources and seven operations;
* cannot trigger any behavior outside the candidate; every subsequent step
  (strict parse, contract validation, secret scan, grammar validation,
  dispatch, formatting) is deterministic application code.

Malformed or out-of-contract model output is **rejected** — never repaired,
never partially accepted — mirroring the Step 12C philosophy.

Pipeline
--------

::

    POST /api/soc/query (JWT + require_role admin/analyst/ciso)
        -> payload validated (bounded SOCQueryRequest)
        -> SOCQueryService.query(db, text)
            -> GeminiSOCIntentParser.parse(text)      # LLM, structured output only
            -> parse_strict(raw)                      # strict JSON, no fences/prose
            -> validate_candidate(parsed)             # Pydantic SOCModelIntent, extra=forbid
            -> assert_candidate_secret_free(...)      # fail-closed credential scan
            -> validate_model_intent(candidate)       # allowlist grammar + defaults
            -> SOCQueryExecutor.execute(db, intent)   # dict dispatch -> existing query services
            -> formatter.format_response(...)         # deterministic note + semantics
        -> SOCQueryResponse (structured, read_only=True)

The parse/validate steps are strictly deterministic and the executor shares
the **same registry table** as the validator, so validation and dispatch can
never disagree (``app/services/soc/registry.py`` is the single source of
truth for ``(resource, operation)`` support).

Allowlist grammar
-----------------

Four read resources, built exclusively on existing query services:

====================  =================================
Resource              Operations
====================  =================================
``detections``        get, recent, by_event, by_rule
``correlations``      get, recent, by_event, by_detection
``risk_assessments``  get, recent, by_correlation
``incident_memories`` get, recent, by_correlation, list
====================  =================================

* ``get`` is an exact lookup by the resource's own identifier.
* ``recent`` is a bounded most-recent feed (``limit`` 1..200, default 50).
* ``by_event`` / ``by_detection`` / ``by_correlation`` / ``by_rule`` and
  ``list`` are paginated operations (``page`` / ``page_size`` 1..200,
  default 1 / 50).
* ``incident_memories.list`` also supports a native ``memory_type`` filter.
* ``risk_assessments.recent`` also supports a ``risk_level`` filter.

``incident_learning`` is intentionally **not** allowlisted: no read-only
Incident Memory Learning query service exists and Step 23 must not create a
query implementation merely for Natural Language SOC.

Filters
-------

Only two filters exist, each valid for exactly one pair:

* ``risk_level`` (low/medium/high/critical) — **only** for
  ``risk_assessments.recent``.  It is applied as a deterministic in-process
  **post-filter over the bounded recent feed** against the persisted
  ``RiskAssessmentRecord.level``.  It does not create a new database query.
* ``memory_type`` — **only** for ``incident_memories.list``, passed through
  to the existing ``IncidentMemoryQueryService.list_memories`` native
  database-side filter.

Anything else (for the wrong pair, invented filters, filters on other
operations) is rejected by the validator with a sanitized 422.  The prompt
grammar, the validator, and the executor all agree on this table; there is
no filter anyone can add by saying the word.

Bounds and rejection
--------------------

SentinelAI's "reject, never truncate" principle applies end to end:

* raw query 1..2048 characters (blank/oversized input is rejected);
* model output at most 4096 bytes (larger output is rejected);
* ``limit`` / ``page_size`` at most 200 (the exact query-service caps);
* ``rule_id`` at most 255 characters;
* at most one target identifier per intent; ``limit`` and
  ``page``/``page_size`` are mutually exclusive; ``page_size`` requires
  ``page``.

Security posture
----------------

* **Prompt injection is data, not instructions.**  The fixed grammar lives
  in ``systemInstruction``; the user text is delimited inside a
  ``<user_data>…</user_data>`` region and the system instruction warns the
  model that embedded instructions are untrusted data.
* **Fail closed.**  Malformed JSON, prose-wrapped output, multiple objects,
  out-of-contract fields, invalid enums, malformed UUIDs, unsupported
  resource/operation, invalid filters, and illegal pagination all abort the
  request (422) — nothing is repaired, redacted, or silently substituted.
* **Credential-shaped content is rejected.**  The serialized *candidate*
  intent is scanned for the shared credential vocabulary (api_key /
  authorization / bearer / secret / password / cookie / session_token /
  jwt) and rejected with a SOCSafetyError.  The raw user query is *not*
  scanned (words like "password" and "cookie" are legitimate SOC terms and
  would cause false positives).
* **Nothing sensitive is ever logged or echoed.**  User queries and raw
  Gemini prompts/responses are never logged; exceptions carry sanitized
  messages; the API response never echoes the raw user query.
* **No dynamic dispatch.**  Executors use pre-bound registry handlers keyed
  by ``(resource, operation)`` enums; there is no ``getattr`` and no
  callable name can come from model output.  The SOC core never imports
  ``fastapi``, SQLAlchemy, Kafka, Qdrant, ``app.models``, or OS/shell
  primitives (verified by AST tests).
* **Read-only by construction.**  The executor only composes existing
  ``list``/``get`` query methods; the response ``read_only`` field is pinned
  to the literal ``True``.

Error contract
--------------

============  ====================================================
HTTP status   Meaning
============  ====================================================
401           Missing/invalid JWT
403           Authenticated but not admin/analyst/ciso
422           Invalid request body, or invalid/unsafe parsed intent
503           Parser provider unavailable / misconfigured, or a
              downstream read query failed
500           Unexpected internal error (sanitized)
============  ====================================================

An exact lookup that misses returns **200** with ``found=false`` and an
empty ``items`` — the natural-language query itself succeeded; it is not an
HTTP 404.

Response contract
-----------------

``SOCQueryResponse`` distinguishes:

* ``intent`` — the validated ``SOCQueryIntent`` (resource, operation, mode,
  target, filters, pagination);
* ``metadata`` — deterministic execution metadata (mode, page/limit,
  ``applied_filters``, parser provider/model, UTC ``recorded_at``);
* ``read_only`` — pinned ``True``;
* ``found`` / ``count`` / ``total`` — outcome counts;
* ``items`` — the **serialized existing query-layer read models** (JSON-safe
  dicts), preserving their original semantics;
* ``semantics`` — deterministic labels describing what the results are
  (e.g. incident memories are labelled
  ``historical_incident_memory_not_current_observation`` so historical
  memory is never presented as a current observation);
* ``note`` — a deterministic, human-readable summary built by the
  formatter.  It is **never** generated by an LLM, never fabricates
  findings, and never claims results exist when ``found=false``.

There is deliberately **no second LLM summarizer**: introducing an LLM at
result-presentation time would recreate the very trust boundary Step 23
removes.

Testing
-------

Unit coverage ships for every executable unit:

* intent contracts (bounds, enums, extra-field rejection, Gemini schema
  mirror) — ``test_soc_intent_contract.py``;
* strict parser + candidate build + secret scan + prompt-injection boundary
  — ``test_soc_parser.py``;
* Gemini adapter (MockTransport, retry policy, error mapping, raw
  extraction) — ``test_soc_gemini.py``;
* allowlist validator (full grammar, filters, pagination) —
  ``test_soc_validator.py``;
* read-only executor (dict dispatch, exact/recent/paged, risk_level post
  filter, memory_type pass-through, sanitized failures) —
  ``test_soc_executor.py``;
* deterministic formatter — ``test_soc_formatter.py``;
* engine orchestration (bounds, lazy parser, full pipeline) —
  ``test_soc_engine.py``;
* API transport + RBAC + sanitized error mapping + real-engine wiring —
  ``test_soc_api.py``;
* architecture/AST guarantees (one POST endpoint, no exec primitives, no
  dynamic dispatch, import whitelist) — ``test_soc_architecture.py``.

Scope notes
-----------

Step 23 does **not** add: a SECOND Natural Language SOC endpoint, an SOC
write/action surface, a chat/history store, an SOC Alert/Incident response
path, arbitrary query execution, or a new audit/authorization model (it
reuses the existing JWT + ``require_role``).