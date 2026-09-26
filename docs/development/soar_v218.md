SOAR Orchestration (V2.18)
==========================

Purpose
-------

Step 27 adds **SOAR orchestration**: turning an approved Step 24 policy
decision into a scripted, auditable sequence of defensive actions
(``block_ip``, ``block_domain``, ``quarantine_file``, ``disable_account``,
``terminate_session``, ``isolate_endpoint``, ``endpoint_containment``).
Everything runs against the **sandbox ``Mock*`` providers only** — no real
security product is ever touched, and the only way to reach a provider is
through the V2.16 approval workflow and the gate.

> Code, not committees.  Playbooks are **code-seeded** (``app/services/
> soar/playbooks.py``); there is no client-side playbook authoring, no
> runtime edit surface, and no free-form instruction channel.  The server
> controls what may run, against what, and in what order.

Design principles:

* **Gate everything, second-guess nothing.**  The gate re-derives the
  decision from the Step 24 record: ``ALLOWED`` executes; ``DENIED``
  records ``REJECTED / POLICY_DENIED`` with **zero steps** (provable no
  provider was invoked); ``REQUIRES_APPROVAL`` executes **only** through
  the existing V2.16 approval grant (checked via the verifier seam), stays
  ``pending`` when no grant is offered, and is rejected when a grant is
  unsatisfiable.
* **Provenance is pinned.**  The policy decision wire model *always*
  carries ``Provenance.POLICY_DECIDED`` (schema-enforced), so a forged or
  non-policy payload is rejected as ``POLICY_INVALID`` before anything
  runs.
* **Remember by content.**  An execution is content-addressed: the
  idempotency key is a SHA-256 over the canonical (playbook, target,
  decision, approval, response, correlation) tuple with the playbook
  version folded in, and the ``execution_id`` is a UUIDv5 over that key.
  Replaying the same body re-returns the stored execution; exactly one row
  is ever persisted.  Only *executed* runs are deduplicated — ``pending`` /
  ``rejected`` projections are no-op records that are never stored, so a
  resolved approval can later produce a real run.
* **Deterministic, structural order.**  Steps are executed in declared
  order with ``start_sibling``/``requires``-style edges validated eagerly;
  a provider failure under ``stop_on_failure`` halts the run (``failed`` /
  ``partial``), and ``retries_attempted`` is recorded on step records
  (including successes that needed retries).
* **Workers are verbs, not nouns.**  Each step names a provider adapter by
  ``provider_id`` plus arguments; adapters are thin pure functions over a
  provider contract.  No adapter owns state or policy.

Pipeline
--------

::

  PolicyDecision (Step 24)  [ALLOWED | DENIED | REQUIRES_APPROVAL, POLICY_DECIDED]
      -> POST /api/soar/executions          # execute (admin / analyst / ciso)
      -> POST /api/soar/dry-run             # projected run, persists nothing
         SoarService -> gate (re-derive decision, approval, target)
           ALLOWED      -> engine.run(playbook)  -> steps via Mock* providers
           DENIED       -> rejected / POLICY_DENIED (no step executes)
           REQUIRES_APPROVAL
             no approval_id      -> pending / APPROVAL_NOT_GIVEN (recorded,
                                    nothing executes)
             grant via V2.16 verifier (unsatisfied) -> rejected / verifier code
             grant satisfied     -> engine.run(...) (approval-bearing key)
         idempotency SHA-256(canonical content + playbook version)
           -> UUIDv5 execution_id   (replay returns stored execution)
         SoarExecutionRow + SoarStepExecutionRow persisted (not for dry-runs)
      -> GET /api/soar/playbooks | /api/soar/playbooks/{id}   # read-only
      -> GET /api/soar/executions | /api/soar/executions/{id}
      -> POST /api/soar/executions/{id}/cancel                # admin only

Backend pieces
--------------

* ``app/schemas/soar.py`` — the domain contract: ``SoarExecutionStatus``
  (``pending | running | succeeded | failed | partial | cancelled |
  rejected``), ``SoarStepStatus``, ``SoarPlaybookDefinition`` /
  ``SoarPlaybookVersion`` / ``SoarStepDefinition`` (code-seeded, with a
  validator that rejects empty or unanchored step lists), ``SoarExecution``
  / ``SoarStepExecution`` read models, ``SoarExecutionRequest`` (decision +
  target + optional approval id + response id + playbook id) with the
  decision provenance pinned to ``POLICY_DECIDED``.
* ``app/models/soar_execution.py`` / ``soar_step_execution.py`` / ``soar_
  playbook.py`` / ``soar_playbook_version.py`` — persistent rows (``*Row``
  classes), including ``approval_id`` as a *reference* to the existing
  V2.16 ``approval_requests`` grant; migration ``6a1b2c3d4e5f`` (single
  head, applied to live Postgres).
* ``app/repositories/soar.py`` — data access incl. idempotency lookup and
  paged reads (database-side total).
* ``app/services/soar/playbooks.py`` — the fixed registry of 7 code-seeded
  playbooks with version pinning; ``app/services/soar/registry.py`` /
  ``validator.py`` — registry guards + eager step validation.
* ``app/services/soar/providers.py`` — the **sandbox provider contract**:
  ``firewall`` / ``dns`` / ``edr`` / ``identity`` / ``endpoint``
  Mock* adapters return deterministic, argument-echoing results and are
  *provably* the only adapters (architecture test scans every provider
  adapter against an allow-list).
* ``app/services/soar/gate.py`` — the pure re-checks: ``POLICY_DENIED``,
  ``POLICY_INVALID`` (provenance), ``POLICY_REQUIRES_APPROVAL``,
  ``ACTION_MISMATCH``, ``TARGET_INVALID``, plus V2.16 verifier codes
  (``APPROVAL_NOT_GIVEN`` / ``APPROVAL_UNKNOWN`` / ``APPROVAL_NOT_APPROVED`` /
  ``APPROVAL_EXPIRED`` / ``APPROVAL_REVOKED`` / ``APPROVAL_MISMATCH``).
* ``app/services/soar/engine.py`` — ordered step execution,
  ``stop_on_failure`` halting, bounded retries with ``retries_attempted``
  recorded on every step record (including successes), pending projections
  never persisted.
* ``app/services/soar/hashing.py`` — canonical-JSON content hashing
  (SHA-256 idempotency key, UUIDv5 execution id, playbook-version folding).
* ``app/services/soar/service.py`` — orchestration: execute, dry-run,
  cancel, list/get playbooks and executions; errors
  ``SoarValidationError`` / ``SoarNotFoundError`` / ``SoarConflictError`` /
  ``SoarServiceError`` / ``SoarInternalError``.
* ``app/api/routes/soar.py`` — thin transport under ``/api/soar``; reads
  for admin/analyst/ciso, mutations (execute, dry-run, cancel) admin-only;
  ``_call_service`` maps Validation→422, NotFound→404, Conflict→409,
  Internal→500, Service→503.  Every 403 is audited
  (``soar.unauthorized_attempt``).

HTTP semantics
--------------

* ``GET /api/soar/playbooks`` — paged list of the code-registered set
  (read-only; newest active version each).
* ``GET /api/soar/playbooks/{playbook_id}`` — one playbook; unknown → **404**.
* ``POST /api/soar/executions`` — **200** with the execution record on
  success/suspended/rejected (never 201; execution state is the answer).
  Non-``POLICY_DECIDED`` provenance or an unvalidatable decision → **422**;
  re-submitting an executed body re-returns the stored execution.
* ``POST /api/soar/dry-run`` — projected run (``simulated=true``),
  persists nothing.
* ``POST /api/soar/executions/{id}/cancel`` — cancels a pending/suspended
  run; unknown id → **404**; cancelling an executed run is a no-op **200**.
* ``GET /api/soar/executions?page=&page_size=&status=&playbook_id=`` and
  ``GET /api/soar/executions/{id}`` — reads.
* Authentication: missing/invalid token → **401**; non-admin mutation →
  **403** (audited); analyst/ciso reads allowed.

Frontend (dashboard)
--------------------

* ``src/types/api.ts`` — ``SoarExecution*`` / ``SoarStep`` /
  ``SoarPlaybook*`` types.
* ``src/api/soar.ts`` — typed client backed by the shared ``buildUrl`` /
  ``request`` helpers (execute, dry-run, list/get playbooks, list/get/cancel
  executions).
* ``src/pages/soar-page.tsx`` — orchestrations surface: run a playbook
  against a target with an approval grant, dry-run preview, execution
  history with status chips, and cancel for admin users.
* ``src/routes/index.tsx`` / ``src/layouts/sidebar.tsx`` — SOAR page and
  nav entry.

Tests
-----

* ``tests/unit/soar_test_helpers.py`` — canonical ``a_decision`` /
  ``a_request`` builders, ``StubApprovalVerifier``, and the SQLite test
  adapters (``visit_JSONB`` → ``JSON``, ``visit_UUID``/``visit_uuid`` →
  ``CHAR(32)``) that keep ``UUID(as_uuid=True)`` columns TEXT-affinity on
  SQLite (the default NUMERIC affinity corrupts bare ``UUID`` values).
* ``tests/unit/test_soar_playbooks.py`` / ``test_soar_providers.py`` /
  ``test_soar_hashing.py`` — version pinning, registry guards, adapter
  allow-listing, canonical content hashing, provider-only sandbox contract.
* ``tests/unit/test_soar_gate.py`` — the full refusal matrix
  (DENIED / provenance / approval-missing / approval-unsatisfied /
  action-mismatch / target-invalid) proves no provider can be reached;
  allowed approvals execute exactly once.
* ``tests/unit/test_soar_engine.py`` — ordered execution, halt semantics,
  retries+``retries_attempted``, idempotency (including
  different-approval-differs and approval-bearing key reuse), pending
  projections never stored.
* ``tests/unit/test_soar_service.py`` — full-schema SQLite lifecycle
  (execute / dry-run purity / cancel / reads / RBAC error mapping).
* ``tests/unit/test_soar_api.py`` — live-Postgres endpoint + HTTP + RBAC
  suite (28 tests), with execution rows cleaned at module teardown.
* ``tests/unit/test_soar_architecture.py`` — network-boundary and layering
  rules (no policy/approval internals in the SOAR surface, ``soar`` token
  absent from the policy/response networks, exec-primitive scans).
* ``tests/integration/test_soar_e2e.py`` — scenarios A–E against the live
  API: (A) full sanctioned run, (B) denied never executes, (C) pending →
  cancel (+ idempotent cancel), (D) identical submission persists once, (E)
  dry-run persists nothing + playbook endpoints are GET-only + the Step 25
  Response service still exposes no API surface.
* Updated boundary tests: ``test_response_architecture.py`` carves out the
  dedicated ``/api/soar`` domain API only; ``test_approval_architecture.py``
  permits the SOAR migration's *reference* to ``approval_requests`` while
  still forbidding any approval table creation.

Scope boundaries
----------------

Step 27 adds **no** real security actions, no client-side playbook
authoring, no runtime instruction channel, no auto-approval, no scheduler,
no new auth system, no network egress from providers (sandbox-only
adapters), and no V1 redesign.  Everything that executes still flows
through an approved Step 24 decision, and every provider invoked is a
``Mock*`` sandbox adapter.