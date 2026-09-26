AI Incident Report Generator (V2.20)
======================================

Purpose
-------

Step 29 adds **Ai incident report generation**: a governed, read-only
agent that composes a bounded narrative over a *persisted* correlation
and its surrounding SOC history (detections, risk assessments, incident
memories, threat hunts, approvals, SOAR executions), validates the LLM
output byte-exactly against a JSON schema contract, and persists **one
new deterministic decision row** per generation that outlives the
correlation.

> **Generation, not action.**  The report never executes policy,
> responses or SOAR, never fabricates events, attribution, timestamps or
> remediation, and never mutates any security state.  It is the *write*
> counterpart to Step 28's hunt reads — it answers "what happened for
> this correlation, bounded to what is actually recorded?".

Design principles:

* **Read-only generation.**  The service calls the LLM, validates the
  response, and writes only the ``incident_reports`` row plus audit
  events.  It cannot block, quarantine, disable, isolate, execute,
  approve, cancel or reach a provider.  Source tables stay
  byte-for-byte unchanged (comparison-tested).
* **Bounded, fail-closed.**  Every section carries an explicit cap and
  every string field a ``max_length``; a breach **raises** (Never
  truncates): the generation fails with ``REPORT_BOUND_EXCEEDED`` and a
  failed row is persisted.  Overlong LLM values are rejected, not
  truncated.
* **Availability is preserved, never collapsed.**  :class:`InputAvailability`
  keeps `PROVIDED` / `NOT_PROVIDED` / `NONE_FOUND` distinct.  A missing
  section is ``NOT_PROVIDED`` (source absent from the build context), an
  empty-but-present source is ``NONE_FOUND``, and an empty correlation
  yields ``detections: NOT_PROVIDED`` (no detection source was consulted).
  ``investigation`` / ``attribution`` / ``security_events`` are *always*
  ``NOT_PROVIDED`` — no persisted store exists, so nothing is fabricated.
  ``risk_assessment`` is ``PROVIDED`` / ``NOT_PROVIDED`` only (a risk row
  is optional by contract).
* **Catalog-citation only.**  The evidence catalog passed to the LLM is
  deterministic (the context builder's reference list).  The LLM may cite
  **only** ``reference_id`` values from that catalog; a dangling or
  invented identifier fails the whole generation with
  ``REPORT_EVIDENCE_INVALID`` (the ``findings[].evidence_references``
  surface is re-validated post-generation).
* **Secrets never cross the AI boundary.**  The serialized context is
  re-scanned before the provider call and the LLM output is re-scanned
  before persistence; credential-shaped content fails with
  ``REPORT_SECRET_DETECTED``.
* **One row per generation.**  ``report_id`` is a UNIQUE UUID; the
  correlation is an *indexed UUID logical FK with no FK constraint*, so
  the row outlives the correlation.  A failed generation persists its
  ``error_code`` / ``error_message`` with a ``NULL`` payload so the
  decision surface is fully auditable.
* **Deterministic.**  Identical persisted input produces byte-identical
  context, catalog and timeline; only ``generated_at`` and the free-text
  LLM narrative vary.

Pipeline
--------

::

  persisted correlation + SOC history (detections / risk / memories /
    hunts / approvals / soar / audit)
      -> POST /api/incident-reports/generate      (admin/analyst/ciso)
         IncidentReportService:
            audit incident_report.generated_requested
            context builder (allowlisted, availability-pinned,
              bounded, deterministic) -> IncidentReportContext
            fail closed on context errors -> REPORT_CONTEXT_UNAVAILABLE
            prompt builder -> IncidentReportPrompt
            provider call (IncidentReportGeminiClient / FakeReportLLM)
            schema validation (bounds reject, never truncate)
            evidence-citation check against the deterministic catalog
            secret safety scan on the output
            -> fleet: one succeeded | one failed row (nullable payload)
            audit .generated_succeeded | .generated_failed
      -> GET /api/incident-reports (?page=&page_size=&correlation_id=)
      -> GET /api/incident-reports/{report_id}

Backend pieces
--------------

* ``app/schemas/incident_report.py`` — the wire + model contract:
  ``InputAvailability`` / ``ReportSourceAvailability``
  (``PROVIDED|NOT_PROVIDED|NONE_FOUND``), provenance
  (``DETECTED|CORRELATED|RISK_ASSESSED|RECALLED|ENRICHED|
  APPROVAL_REVIEWED``), read models ``IncidentReportSummary`` /
  ``IncidentReportRecord`` (payload auto-validated on every read),
  ``IncidentReportGenerateRequest``, the bounded data panels
  (``IncidentFactContext``, ``IncidentReportContext``,
  ``ReportEvidenceReference``, ``SecurityEventReferenceContext``,
  ``ThreatIntelLookupContext``, ``ApprovalRequestContext``,
  ``SoarExecutionContext``, ``ThreatHuntContext``,
  ``ReportTimelineItem``, ``ReportRecordType``) and the section caps
  (``MAX_REPORT_*``).  ''_bound_string'' **rejects** (positional call
  sites) rather than truncating.
* ``app/services/reporting/context.py`` — the deterministic builder:
  correlation + members, detection results (availability-aware),
  risk assessment (``PROVIDED``/``NOT_PROVIDED`` only), incident
  memories (``RECALLED``), threat-hunt runs and SOAR executions
  presented as ``OBSERVED`` (persisted operational records with no enum
  value; decision documented here), approvals (``APPROVAL_REVIEWED``),
  a deterministic evidence catalog (``reference_id`` list) and a
  sorted timeline.  Tolerances are keyword-free; datetimes normalize
  through a tz-aware sentinel so sorting never raises.  Every source
  passes an explicit field allowlist; the builder never commits,
  rolls back, or touches an execution/policy/approval/provider path.
* ``app/services/reporting/model_output.py`` — the LLM response contract:
  ``IncidentReportModelOutput`` with strict JSON-schema parsing, the data
  panels the writer turns into the V2.20 payload, ``_validate_payload``
  (bounds reject; pydantic ``ValidationError`` escalation), and a secret
  scan.
* ``app/services/reporting/prompt.py`` — ``INCIDENT_REPORT_MODEL_JSON_SCHEMA``
  (single-candidate, no degenerate ``additionalProperties``) and
  ``IncidentReportPrompt`` (frozen dataclass wrapping an
  ``InvestigationPrompt``).
* ``app/services/reporting/llm.py`` — ``IncidentReportGeminiClient``
  reuses the Step 23 ``GeminiClient`` transport/retry/error handling,
  overriding ``_build_payload`` (the report schema above) and
  ``generate(prompt: IncidentReportPrompt)``.
* ``app/services/reporting/errors.py`` — ``ReportError`` hierarchy with
  codes: ``REPORT_NOT_FOUND``, ``CORRELATION_NOT_FOUND``, ``REPORT_INVALID``
  (validation), ``REPORT_BOUND_EXCEEDED``, ``REPORT_CONTEXT_UNAVAILABLE``,
  ``REPORT_SECRET_DETECTED``, ``REPORT_EVIDENCE_INVALID``, ``REPORT_PROVIDER_UNAVAILABLE``,
  ``REPORT_INTERNAL``.  Context/provider/unexpected LLM exceptions wrap to
  ``REPORT_PROVIDER_UNAVAILABLE``; a deliberately broken ``parse`` raises
  ``REPORT_INTERNAL``.
* ``app/services/reporting/generator.py`` — ``IncidentReportGenerator``:
  build context -> build prompt (context re-scanned for secrets) ->
  provider call -> validate -> evidence-citation check -> secret scan ->
  deterministic payload.  Secret-in-context fails before the provider;
  secret-in-output fails before persistence.
* ``app/services/reporting/service.py`` — ``IncidentReportService``:
  ``generate`` (audits ``incident_report.generated_requested`` then
  ``.generated_succeeded`` / ``.generated_failed``), ``get`` / ``list``.
  A failed generation persists the row with ``status=failed`` and its
  error; an unknown correlation raises ``CORRELATION_NOT_FOUND`` and
  writes **no** row.
* ``app/models/incident_report.py`` — ``IncidentReportRow`` (UNIQUE
  ``report_id`` uuid, ``correlation_id`` indexed no-FK, ``payload``
  JSONB nullable, ``status`` ``generated|failed``, ``title``/``model``/
  ``generated_by*``/``generated_at``, ``error_code``/``error_message``,
  ``created_at``/``updated_at``).  Migration ``8a1b2c3d4e5f`` (single
  head, applied to live Postgres).
* ``app/repositories/incident_report.py`` — ``IncidentReportRepository``:
  ``create``, ``get``, ``list`` (page/page_size + ``correlation_id``
  filter with database-side totals).
* ``app/services/reporting/__init__.py`` — public exports
  (``IncidentReportService``, ``IncidentReportGenerator``, the error
  classes).  No cli/main/action import surface.
* ``app/api/routes/incident_reports.py`` — thin transport under
  ``/api/incident-reports``: ``POST /generate`` (201), ``GET ""``,
  ``GET /{report_id}``; SOC roles admin/analyst/ciso; every viewer
  attempt is audited (``incident_report.unauthorized_attempt``, including
  reads).  ``_call_service`` maps Bound→409 (checked first),
  NotFound/CORRELATION_NOT_FOUND→404, Validation/Evidence/Secret→422,
  Context/Provider→503, Internal→500, other Exception→503.

HTTP semantics
--------------

* ``GET /api/incident-reports?page=&page_size=&correlation_id=`` — paged
  list with database-side totals, optional correlation filter.
* ``POST /api/incident-reports/generate`` — **201** with the persisted
  decision (payload for ``generated``, error surface for ``failed``).
  Unknown correlation -> **404** and NO failed row.  ``ReportBoundError``
  -> **409** (output overflows a cap; caught first).  Output that fails
  schema/evidence/secret safety -> **422** *and persists a failed row*.
  Context/provider unavailable -> **503**; unexpected failure -> **500**.
* ``GET /api/incident-reports/{report_id}`` — the record; payload
  re-validated on read; unknown id -> **404**.
* Authentication: missing/invalid token -> **401**; viewer role -> **403**
  (audited on reads too).

Frontend (dashboard)
--------------------

* ``src/types/api.ts`` — V2.20 block: ``ReportStatus`` /
  ``ReportSummary`` / ``IncidentReportRecord`` / ``IncidentReportPayload``
  (structured narrative, findings with evidence refs, evidence catalog) /
  ``IncidentReportListPage`` / ``IncidentReportGenerateRequest``.
* ``src/api/incident-reports.ts`` — typed client over the shared ``api``
  helpers (list, report, generate).
* ``src/pages/incident-reports-page.tsx`` — reports surface: generate
  form (correlation id + locked V2.20 version), reports table with
  status badges and a detail panel that renders the generated payload
  (AI narrative, findings, evidence catalog, limitations, follow-up) —
  plus an explicit "generation only" disclaimer.
* ``src/routes/index.tsx`` / ``src/layouts/sidebar.tsx`` — routed at
  ``/incident-reports``, nav entry "Incident Reports" in the Analysis
  section.
* ``src/pages/incident-reports-page.test.tsx`` — 4 tests: generated and
  failed renders, payload detail, generate form round-trip.

Tests
-----

* ``tests/unit/incident_report_test_helpers.py`` — reuse the
  threat-hunt SQLite JSONB/UUID adapters; ``a_approval`` /
  ``a_soar_execution`` (constraint-valid statuses incl. ``succeeded`` /
  ``stop_on_failure``), ``canonical_model_output()``, ``VALID_AI``,
  ``FakeReportLLM``.
* ``tests/unit/test_incident_report_contracts.py`` — 8 tests: bounds
  **reject** never truncate, provenance pins, availability preserves
  all three states, ``_validate_payload`` secret gate.
* ``tests/unit/test_incident_report_ai.py`` — 11 tests: parse strictness,
  JSON-schema shape, Gemini payload override, prompt delimiters.
* ``tests/unit/test_incident_report_generator.py`` — 13 tests:
  availability/provenance, deterministic catalog + timeline, unknown
  correlation raises, zero-write proof, dangling citation →
  ``REPORT_EVIDENCE_INVALID``, valid citation accepted, malformed output →
  validation failure, secret in output →
  ``REPORT_SECRET_DETECTED``, deterministic reports.
* ``tests/unit/test_incident_report_service.py`` — 11 tests: one row per
  call, audit trail, failed-row persistence for provider / validation /
  internal errors with a NULL payload, missing correlation no-row,
  get/list pagination, failed rows listed.
* ``tests/unit/test_incident_report_api.py`` — 8 tests, live Postgres:
  401 everywhere, viewer 403 + audit, generate 201 + payload, unknown
  correlation 404 no-row, bad ``report_version`` 422, list/get
  round-trip, missing report 404.  Rows cleaned at module teardown
  (verified count = 0 after the run).

Scope boundaries
----------------

Step 29 adds **no** execution, approval or SOAR/policy reach (the code
path is provably free of response/soar/policy/hitl/agents imports), no
fabricated events/attribution/timestamps/remediation, no truncation (all
bounds reject), no raw event ingestion, no second report row,
no scheduling or auto-generation, no chat/RAG surface, no free-text
report language, and no change to the auth system.  ``investigation`` /
``attribution`` / ``security_events`` remain ``NOT_PROVIDED`` by design,
and the ``OBSERVED`` provenance of hunt runs and SOAR executions is an
explicit, documented decision — those are operational records, not an
enum-typed security event.  The generator only *reads* persisted SOC
history and *writes* its bounded decision row plus audit events.