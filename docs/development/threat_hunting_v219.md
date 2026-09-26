Threat Hunting (V2.19)
======================

Purpose
-------

Step 28 adds **threat hunting**: governed, template-based investigation
over the SOC's *persisted* analytical history (detections, correlations,
risk assessments, threat-intel indicators/lookups, audit events).  A hunt
is a read-only, versioned query saved as a **draft**, run **exactly once**
to a terminal state, and its deterministic findings, evidence trail and
timeline are persisted for review.

> **Investigation, not action.**  Hunting never mutates security state: it
> cannot block, quarantine, disable, isolate or execute anything, and it
> cannot reach the SOAR providers.  It is the *read* counterpart to
> Steps 24–27 — it answers "has this pattern happened in our history?".

Design principles:

* **Read-only, provenance-pinned.**  Every piece of evidence carries the
  provenance of the row that produced it (``detected`` /
  ``enriched`` / ``correlated`` / ``risk_assessed`` / ``auth_anomaly`` /
  ``incident_memory``).  A hunt run leaves the source tables byte-for-byte
  unchanged (verified by a dedicated comparison test).
* **No events store.**  ``event_id`` is an *indexed UUID logical foreign
  key* over ``detection_results``, ``correlation_members`` and
  ``threat_intel_lookups`` — hunts never persist raw security events or
  their raw payloads.
* **Grammar, not DSL.**  Filters are a small, validated JSON grammar
  (14 fields / 7 ``HuntOperator`` values / ≤8 filters / IN-set ≤20 /
  value ≤2048 / window ≤720h).  There is no raw SQL, no free-text query
  language and no ``eval``/``exec`` path anywhere (scanned by tests).
* **Lifecycle is locked.**  ``DRAFT → RUNNING → COMPLETED | FAILED``, with
  ``CANCELLED`` reachable only from ``DRAFT``.  Re-running a completed
  hunt or cancelling a terminal hunt is a **409**.  A CAS guard
  (``cas_transition``) makes double-runs impossible.
* **Counts-first bounding.**  Surface cap 200 rows read per template,
  evidence ≤300, findings ≤25 (overflow folded into a summary finding
  with ``context.omitted_findings``), timeline ≤300, pages ≤200.  Cap
  breaches fail the hunt hard with ``LIMITS_EXCEEDED`` (never truncates
  silently); only findings are soft-bounded by design.
* **Deterministic identity.**  All hunt ids are UUIDv5 ``uuid5(NAMESPACE,
  f"{hunt_id}::{seed}")`` over a fixed namespace; re-running a hunt after
  a delete produces the *same* ids (idempotent, replayable).
* **Only its own tables.**  A hunt's persistence is confined to four new
  tables (rows + evidence + findings + timeline); the repository writes
  nothing else, and audit events flow only to the existing audit channel.

Pipeline
--------

::

  SOC pipeline history: detection_results / correlation_results /
    correlation_members / risk_assessments / threat_intel_lookups (+
    propagated fields on threat_intel_indicators) / audit_logs
      -> POST /api/threat-hunts                  # create draft (SOC roles)
      -> POST /api/threat-hunts/{id}/run         # run exactly once
         ThreatHuntService -> repository lookup + CAS (draft -> running)
         engine executes the hunt per template under a bounded window:
            surface scan (limit 200) -> evidence rows (limit 300)
            -> findings grouped by template key (limit 25, summary overflow)
            -> timeline rows (limit 300)
         completed | failed (validation / limit / execution errors)
      -> POST /api/threat-hunts/{id}/cancel      # drafts only
      -> GET /api/threat-hunts (?status=) | /{id}
      -> GET /api/threat-hunts/{id}/evidence | /findings | /timeline
         (paged reads, database-side totals)

Hunt templates
--------------

* ``detection_review`` — every ``detection_result`` row in the window
  (keys: detection_id, rule_id, rule_type, severity, event_id).
* ``indicator_hunt`` — ``threat_intel_lookups`` enriched against
  ``threat_intel_indicators`` (ever-seen indicators, lookups, results).
* ``multi_stage_activity`` — correlations + members with risk
  assessments surfaced (never the risk *decision* itself).
* ``authentication_anomaly`` — audit rows for sign-in /
  authentication actions in the window.
* ``incident_memory`` — incident-memory reuse (surface and findings
  labeled ``recalled``).

Backend pieces
--------------

* ``app/schemas/threat_hunting.py`` — the domain contract:
  ``ThreatHuntStatus`` (``draft | running | completed | failed |
  cancelled``), ``HuntType`` (the five templates above), ``HuntOperator``
  (``equals | not_equals | in | not_in | contains | starts_with |
  ends_with``), field/operator and per-type field tables
  (``FIELD_OPERATORS`` / ``HUNT_TYPE_FIELDS``), ``surface_allow``
  field list, ``ThreatHuntCreate`` / ``ThreatHuntFilter`` +
  serialization helpers, ``ThreatHuntSummary`` / ``ThreatHuntDetail`` /
  ``ThreatHuntEvidence`` / ``ThreatHuntFinding`` /
  ``ThreatHuntTimelineItem`` read models, ``HuntType``-aware correct
  filter validation (field membership + operator membership + IN-count +
  value length + window ordering/duration).  Secrets and control
  characters are rejected at the schema (``_SECRET_PATTERNS``,
  ``_reject_control_characters``).
* ``app/models/threat_hunt.py`` — ``ThreatHuntRow`` +
  ``ThreatHuntEvidenceRow`` + ``ThreatHuntFindingRow`` +
  ``ThreatHuntTimelineItemRow``; migration ``7a1b2c3d4e5f`` (single head,
  applied to live Postgres).  ``ThreatHuntRow`` stores the CAS guard
  (``cas_transition`` + ``cas_token``) for atomic double-run protection.
* ``app/repositories/threat_hunt.py`` — data access incl. CAS transition,
  verification of completion, page *filters* (spec-related),
  database-side totals, and JSON column writes for evidence/findings.
* ``app/services/threat_hunting/engine.py`` — the pure hunts at the
  service boundary (bounded surface, window keying, provenance pinning,
  summarization that caps findings).  All datetimes normalize through
  ``_as_utc`` so window keys are tz-deterministic.
* ``app/services/threat_hunting/service.py`` — orchestration: create,
  run, cancel, get, list, list evidence/findings/timeline; audit verbs
  ``threat_hunt.created/.executed/.completed/.failed/.cancelled``
  (including a *failure* audit written by ``_fail``), errors
  ``ThreatHuntValidationError`` / ``ThreatHuntNotFoundError`` /
  ``ThreatHuntAlreadyRunError`` / ``ThreatHuntAlreadyFailedError`` /
  ``ThreatHuntAlreadyCancelledError`` / ``HuntLimitError`` /
  ``ThreatHuntUnexpectedError`` / ``ThreatHuntExecutionError``.
* ``app/api/routes/threat_hunting.py`` — thin transport under
  ``/api/threat-hunts``; SOC roles (admin/analyst/ciso) may read, create
  and run; mutations audited; ``_call_service`` maps Validation→422,
  NotFound→404, Conflict→409 (CAS/already-run/already-failed/
  already-cancelled), Internal→500, Service→503.  Every 403 is audited
  (``threat_hunt.unauthorized_attempt``).

HTTP semantics
--------------

* ``GET /api/threat-hunts?page=&page_size=&status=`` — paged list with
  database-side totals; ``status`` filters the lifecycle state.
* ``POST /api/threat-hunts`` — **201** with the created draft (echo of
  validated filters).  Grammar violations (unknown field/operator,
  cross-field mismatch such as ``indicator_value`` on
  ``detection_review``, >8 filters, IN >20, value >2048, window >720h or
  reversed, secrets/control chars) → **422**.
* ``POST /api/threat-hunts/{id}/run`` — runs a draft exactly once;
  unknown id → **404**; re-run / terminal / non-cancelled-concurrent →
  **409**; runtime or limit failures land the hunt in ``FAILED`` with an
  ``error_code`` / ``error_message``.
* ``POST /api/threat-hunts/{id}/cancel`` — cancels a ``DRAFT`` only;
  unknown → **404**; non-draft → **409** (including already-cancelled).
* ``GET /api/threat-hunts/{id}`` and ``/evidence``, ``/findings``,
  ``/timeline`` — reads with page bounds (≤200, else **422**).
* Authentication: missing/invalid token → **401**; viewer role → **403**
  (audited everywhere, including on reads).

Frontend (dashboard)
--------------------

* ``src/types/api.ts`` — V2.19 block: ``ThreatHuntStatus`` / ``HuntType`` /
  ``ThreatHuntFilter`` / ``ThreatHuntSummary`` / ``ThreatHuntRecord`` /
  ``ThreatHuntCreateRequest`` / ``ThreatHuntEvidenceRecord`` /
  ``ThreatHuntFindingRecord`` / ``ThreatHuntTimelineItemRecord``.
* ``src/api/threat-hunting.ts`` — typed client over the shared
  ``api`` helpers (list, get, create, run, cancel, evidence, findings,
  timeline).
* ``src/pages/threat-hunting-page.tsx`` — hunts surface: create a draft
  (name / template / time window, no free-form filters), status-filtered
  hunts table with run/cancel actions on drafts, and a detail panel with
  findings / evidence / timeline tabs — plus an explicit "investigation
  only" disclaimer.
* ``src/routes/index.tsx`` / ``src/layouts/sidebar.tsx`` — routed at
  ``/threat-hunting``, nav entry "Hunting" in the Analysis section.

Tests
-----

* ``tests/unit/threat_hunt_test_helpers.py`` — ``a_detection`` /
  ``a_audit`` / ``a_correlation`` / ``a_risk`` / ``a_indicator`` /
  ``a_lookup`` / ``a_memory`` builders and the SQLite test adapters
  (``visit_JSONB`` → ``JSON``, ``visit_UUID``/``visit_uuid`` → ``CHAR(32)``)
  that keep UUID columns TEXT-affinity on SQLite; ``DetectionResult`` has
  no ``status`` column (assert on ``provenance``), indicators key on
  ``.id``, the incident-memory model class is ``IncidentMemoryRow``.
* ``tests/unit/test_threat_hunting_engine.py`` / ``_contract.py`` —
  template coverage, window keying, provenance/confidence pinning,
  deterministic ids, "returned" vs "verified" drop semantics, memory
  reuse labeled ``recalled``.
* ``tests/unit/test_threat_hunting_service.py`` — full-schema SQLite
  lifecycle: create→draft, run→completed incl. persisted evidence /
  findings / timeline, re-run → 409, cancel draft→cancelled→409, cancel
  completed → 409, unknown → 404, surface cap → ``FAILED`` +
  ``LIMITS_EXCEEDED`` + re-run refused, status/type filters, page clamp
  at 200, and audit verbs ``created/executed/completed/cancelled``.
* ``tests/unit/test_threat_hunting_architecture.py`` — no ``eval`` /
  ``exec`` / ``__import__`` / ``import_module``; no response/soar/
  policy/approval/hitl/agents imports in core+route; ``surface_allow``
  keys match the ``SURFACES`` dict; the repository writes only the 4 hunt
  tables; migration creates exactly those 4 tables and the token
  ``approval`` never appears in it.
* ``tests/unit/test_threat_hunting_security.py`` — secrets/control
  chars/IN-set/2048/120-name/721h/reversed/9-filters → ValidationError;
  SQLi-style values operate literally on ``RULE_ID`` /
  ``INDICATOR_VALUE``; findings bounded with ``omitted_findings==176`` for
  200 groups; evidence cap hard-fails (FAILED/LIMITS_EXCEEDED/audited/
  terminal); the source history is unchanged after runs; serialized pages
  leak no secrets.
* ``tests/unit/test_threat_hunt_api.py`` — live-Postgres endpoint + HTTP
  + RBAC suite (**23 tests**): 401 everywhere, all 3 SOC roles
  read/create/run, viewer 403, create→201 draft, 422 grammar/secret/
  cross-field/721h, run→completed→409, cancel semantics, paged reads,
  list + status filter, openapi surface.  Hunt rows cleaned at module
  teardown (hunt ids are String).
* ``scripts/threat_hunting_e2e.py`` — deterministic, idempotent E2E:
  seeds 3 detections + a correlation with members + a risk assessment + an
  indicator and lookup, runs ``detection_review`` / ``indicator_hunt`` /
  ``multi_stage_activity`` once, cancels a draft, and confirms the audited
  trail against live Postgres (``python scripts/threat_hunting_e2e.py``).

Scope boundaries
----------------

Step 28 adds **no** security actions, no SOAR/provider reach, no events
store, no raw SQL or DSL (`eval`/`exec` is provably absent), no
fabricated provenance or confidence, no scheduling, no auto-run, no new
auth system, and no V1 redesign.  Hunts only *read* the persisted SOC
history and *write* their own bounded artifacts plus audit events; the
findings/evidence/timeline read models are entirely derived from what the
history already records.