Human-in-the-Loop Approval Workflow (V2.16)
=============================================

Purpose
-------

Step 26 adds the **Human-in-the-Loop (HITL) approval workflow**: an
authenticated SOC operator (admin / analyst / ciso) reviews a
``REQUIRES_APPROVAL`` policy decision and grants or refuses it, with a
mandatory accountability comment.  The grant authorizes — and **only**
authorizes — the existing Step 25 Response layer, which re-checks everything
at its own gate before simulating an action.

> Approval == authorization, not execution.  ``APPROVED`` means a human
> granted the underlying policy decision; it never creates or executes a
> response action.  The response layer's own ``response_status``
> (``executed`` / ``failed`` / ``skipped`` / ``rejected``) is recorded as a
> *separate* field, so nobody can confuse "approved" with "done".

Design principles:

* **Human decision, never machine.**  The workflow is structured
  bookkeeping: no LLM, no agent, no model ever decides an approval, who may
  approve, or why.  No auto-approval, no approval scoring, no free-form
  instruction channel.
* **Roles, not bodies.**  The actor's identity and role come from the
  existing trusted identity store (JWT ``HTTPBearer`` + ``User``).  The HTTP
  body carries only the decision, target, optional note, and resolution
  comment — never a role, an action, or an authorization claim.
* **One lifecycle per decision.**  ``approval_id`` is a deterministic
  UUIDv5 over the (decision, action, target, requester) tuple and
  ``policy_decision_id`` is unique, so a resolved decision can never be
  re-opened or double-executed.
* **Closed state vocabulary.**  ``pending → approved | rejected | expired |
  cancelled``.  Terminal states never transition; ``approved`` is idempotent
  and never re-executes.
* **Approval is layered over the existing pipeline.**  The action is
  **inherited** from the Step 24 decision (never client-supplied), the
  target is validated by the existing Step 25 validator, and an ``APPROVED``
  grant re-submits the *same* decision + grant to the Response executor —
  nothing bypasses the response gate.

Pipeline
--------

::

    PolicyDecision (Step 24)  REQUIRES_APPROVAL
        -> POST /api/approvals                      # create_request
            -> ApprovalRequestCreate (validated, secret-free)
            -> ApprovalService.create_request (transactional)
                -> ApprovalRecord (pending, TTL 24h, provenance approval_reviewed)
        -> GET /api/approvals/recent | /api/approvals   # reads
        -> POST /api/approvals/{id}/approve         # authorize ONLY
            -> conditional UPDATE ... WHERE status='pending'  (one winner)
            -> rebuild PolicyDecision from JSONB -> validate target
            -> ResponseRequest(approval_id, ...)
            -> ResponseMitigationService.execute(db, request, approval_verifier)
                -> approval verifier re-checks grant (locked, read-only)
                -> Step 25 gate still requires ALLOWED + matching request
                -> MockResponseProvider simulates -> response_status recorded
        -> POST /api/approvals/{id}/reject|cancel   # human refusal / withdrawal
        -> (expiry) lazy via _reconcile, no scheduler

Backend pieces
--------------

* ``app/schemas/approval.py`` — the domain contract: ``ApprovalStatus``
  (five members), ``ApprovalRequestCreate`` (decision + target + optional
  note; action inherited), ``ApprovalDecisionInput`` (required comment),
  ``ApprovalRecord`` (read model), ``ApprovalPage``.  All strings are
  control-character-free, JSON-compatible, and secret-scanned; timestamps
  must be timezone-aware; ``provenance`` is pinned to
  ``APPROVAL_REVIEWED``.
* ``app/models/approval_request.py`` + migration ``a1b2c3d4e5f6`` — the
  ``approval_requests`` table with ``UNIQUE(policy_decision_id)`` and CHECK
  constraints written with portable ``length(...)`` (works on both
  PostgreSQL and SQLite test schemas).
* ``app/repositories/approval.py`` — data access incl. the concurrency-safe
  ``resolve_pending`` conditional ``UPDATE ... WHERE status='pending' AND
  expires_at > now``.
* ``app/services/approval/service.py`` — orchestration: create, list page /
  recent, get, approve (conditional commit → decision rebuild → response
  handoff → status recording), reject, cancel, lazy expiry.  Service errors
  ``ApprovalValidationError`` / ``ApprovalNotFoundError`` /
  ``ApprovalConflictError`` / ``ApprovalServiceError``.
* ``app/services/response/approval_gate.py`` — a **pure contract** the
  approval service implements: codes ``APPROVAL_NOT_GIVEN``,
  ``APPROVAL_UNKNOWN``, ``APPROVAL_NOT_APPROVED``, ``APPROVAL_EXPIRED``,
  ``APPROVAL_REVOKED``, ``APPROVAL_MISMATCH``.  The Response executor also
  verifies a grant via ``ResponseExecutor(approval_verifier=...)``; without a
  verifier a REQUIRES_APPROVAL request is rejected immediately.
* ``app/api/routes/approvals.py`` — thin transport: every route calls one
  service method and returns a read model.  Reuses ``bearer_scheme`` /
  ``get_current_user`` / ``get_db`` plus a small ``_require_soc_role``
  dependency that requires admin/analyst/ciso and audits every denial as
  ``approval.unauthorized_attempt``.

HTTP semantics
--------------

* ``POST /api/approvals`` — create (201).  Non-``REQUIRES_APPROVAL``
  decision, malformed/unvalidatable target → **422**.  Re-create while
  pending/approved → **200** idempotent.  Re-create after resolution **409**.
* ``GET /api/approvals/recent?limit=&status=`` — newest-first bounded feed
  (default 50, max 200).
* ``GET /api/approvals?page=&page_size=&status=`` — paged list with a
  database-side total (page_size max 200).
* ``GET /api/approvals/{id}`` — single record; unknown → **404**.
* ``POST /api/approvals/{id}/approve|reject|cancel`` — body
  ``{"comment": ...}`` required (missing/blank → **422**); unknown id →
  **404**; resolving a non-pending request → **409**; approve-on-approved is
  idempotent **200**.
* Authentication: missing/invalid token → **401**; non-SOC role → **403**
  ("Insufficient permissions", audited).

Frontend (dashboard)
--------------------

* ``src/types/api.ts`` — ``approval_reviewed`` added to ``Provenance``;
  ``ResponseActionType``, ``ApprovalStatus``, ``ApprovalRecord``,
  ``ApprovalDecisionInput``, ``Page<ApprovalRecord>``.
* ``src/api/approvals.ts`` — ``approvalsApi.list/recent/get/approve/reject/
  cancel`` using the shared ``buildUrl``/``request`` client.
* ``src/pages/dashboard/dashboard-data.tsx`` — a ``pending`` approvals query
  (bounded, max 10) that is **enabled only for admin/analyst/ciso** roles
  read from the auth store.
* ``src/pages/dashboard/panels.tsx`` — ``PendingApprovalsPanel``: compact
  table of pending authorizations with inline, comment-required
  Approve/Reject confirmation (first ``useMutation`` in the codebase;
  invalidates the pending feed on success).  Approval clicks never claim
  "executed" — the footer states that approval authorizes only and the
  response layer records its own ``response_status``.
* ``src/pages/dashboard-page.tsx`` — panel placed in the right-hand column
  beside Response & policy / System health.

Tests
-----

* ``tests/unit/test_approval_contract.py`` — schema validation: safe
  defaults, secret/control-character rejection, timezone awareness,
  provenance pinning, extra=forbid.
* ``tests/unit/test_approval_service.py`` — state machine, TTL/cancellation
  (via injected clock), conflict semantics, idempotent approve (never
  re-executes), reject/expire/cancel never execute, page/recent limits.
* ``tests/unit/test_approval_api.py`` — endpoint shapes, HTTP status
  mapping, pagination, RBAC (401/403/405), audit calls.
* ``tests/unit/test_approval_security.py`` — unauthorized-role denial,
  resolution actor recording, replay-suppression (approved → approved returns
  the stored record), response hand-off executes exactly once via the mock
  provider.
* ``tests/unit/test_approval_architecture.py`` — network-boundary and
  layering rules (no policy-service import in routes, no decision/approval
  endpoint in the policy router, migration uses portable SQL).
* Updated contract/architecture tests: Provenance length 13, tail
  ``APPROVAL_REVIEWED``; response contract tail ``APPROVAL_REVIEWED``.
* Frontend ``dashboard-page.test.tsx`` — SOC-role gate, feed rendering,
  comment-required approve/reject flows (incl. inline error surface), empty
  state.

Scope boundaries
----------------

Step 26 adds **no** new auth system, no LLM/agent decision-making, no
auto-approval, no real security actions, no SOAR/hunting/attack-viz, and no
V1 redesign.  The response layer stays the only executor and V2.16 executes
against the simulated ``MockResponseProvider`` only.