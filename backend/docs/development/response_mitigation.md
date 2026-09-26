# Response & Mitigation — Step 25

**Location:** `app/services/response/` · **Contract:** `app/schemas/response.py`

## 1. Purpose

The Response & Mitigation layer is SentinelAI Version 1's **execution
layer**.  It answers one deterministic question for an action that the
Step 24 Policy Decision Engine has already judged:

> *How is this permitted action safely executed — and what happened?*

The pipeline now reaches a full loop:

| Layer | Question |
| --- | --- |
| Detection | *what matched?* |
| Correlation | *what is related?* |
| Risk Assessment | *how dangerous?* |
| Investigation / Attribution | *what happened and who may be responsible?* |
| Policy Decision (Step 24) | *may this proposed action proceed?* |
| **Response & Mitigation (this step)** | *how is a permitted action executed, and what happened?* |

## 2. Response ≠ Policy, Response ≠ System Mutation

Two invariants frame the whole step:

1. **The response layer never judges.** It re-verifies, and only
   executes, what an `ALLOWED` Step 24 `PolicyDecision` already
   permitted.  A `DENIED`,
   `REQUIRES_APPROVAL`, malformed, or mismatched decision is refused
   with an auditable `REJECTED` result **before any provider is
   called** — the layer enforces this independently, never trusting the
   caller's belief.
2. **The response layer never touches real systems in this step.**
   `MockResponseProvider` simulates the six actions deterministically and
   provably modifies nothing: no host, no firewall, no account, no file,
   no endpoint, no subprocess, no OS API, no network, no filesystem.
   Real integrations (EDR / IAM / SOAR / cloud security APIs) belong to
   future SOAR scope and must implement the same `ResponseProvider`
   interface.

## 3. Design Principles

1. **Policy gate first.** Order in `ResponseExecutor.execute`:
   request coercion → decision verification (`POLICY_DECIDED`
   provenance) → policy state (`ALLOWED`
   now proceeds; `DENIED` / `REQUIRES_APPROVAL` /
   unknown → `REJECTED`) → request/decision integrity (decision id,
   correlation id, action type) → per-action target validation →
   content-derived response identity → idempotency suppression →
   provider resolution → execution → normalization.
2. **Deterministic.** Same request + same decision + same clock ⇒ a
   byte-identical `ResponseResult`, including a UUIDv5 `response_id` and
   a SHA-256 idempotency key both derived from `policy_decision_id +
   action_type + target`.  No randomness anywhere.
3. **Idempotent.** Identical already-processed content suppresses
   duplicate execution and returns the stored deterministic record (by
   copy — callers can never corrupt internal state).  Capacity is
   bounded by `RESPONSE_MAX_PROCESSED_KEYS`; exhaustion fails closed
   with a provisioning error.
4. **Fail closed, never fake success.** Malformed decisions/requests,
   unsupported actions, and invalid targets are `REJECTED` or refuse;
   provider failure is `FAILED`; nothing ever converts a failure into an
   `EXECUTED`.
5. **Structured targets, closed vocabulary.** `ResponseActionType` is
   **imported** from the Step 24 contract — one shared type, drift
   impossible.  Targets are validated *per action* purely structurally
   (pure `ipaddress` parsing / regex): no DNS, no filesystem, no
   command interpretation, no URLs.
6. **Secret-safe & audit-friendly.** Every record is fetched from the
   shared secret scan; messages/error codes are sanitized templates that
   never echo raw targets, payloads, or exception internals.
7. **No persistence, no API, no LLM, no SOAR.** Step 25 adds no
   migration and no route (the OpenAPI contract contains no response
   path); determinism/idempotency live in an in-memory content-derived
   store injected into the executor.

## 4. Vocabulary

| Enum | Members | Notes |
| --- | --- | --- |
| `ResponseActionType` | `block_ip`, `block_domain`, `quarantine_file`, `disable_account`, `terminate_session`, `isolate_endpoint` | imported from Step 24 |
| `ResponseExecutionStatus` | `executed`, `failed`, `skipped`, `rejected` | `skipped` reserved for future duplicate/approval flows |

`Provenance.RESPONSE_EXECUTED` (12th, additive member) is pinned on every
`ResponseResult`.

## 5. Layer Components

| Module | Role |
| --- | --- |
| `errors.py` | sanitized exception hierarchy |
| `contracts.py` | re-exports the shared Step 24 + Step 25 vocabulary |
| `providers.py` | `ResponseProvider` ABC + deterministic `MockResponseProvider` |
| `registry.py` | explicit action→provider map; duplicates rejected; deterministic lookup |
| `validator.py` | per-action target validation, canonicalization, idempotency keys |
| `executor.py` | the policy gate + safe orchestration (the heart of the step) |
| `service.py` | `ResponseMitigationService` facade |

## 6. Result Semantics

| Situation | `execution_status` | `error_code` |
| --- | --- | --- |
| `ALLOWED` + provider success | `EXECUTED` | — |
| `ALLOWED` + provider raised `ResponseProviderError` | `FAILED` | `PROVIDER_ERROR` |
| `ALLOWED` + provider raised unexpectedly | `FAILED` | `PROVIDER_FAILURE` |
| decision `DENIED` | `REJECTED` | `POLICY_DENIED` |
| decision `REQUIRES_APPROVAL` | `REJECTED` | `POLICY_REQUIRES_APPROVAL` |
| malformed / unverifiable decision | `REJECTED` | `POLICY_INVALID` |
| decision id / correlation / action mismatch | `REJECTED` | `POLICY_DECISION_MISMATCH` / `CORRELATION_MISMATCH` / `ACTION_MISMATCH` |
| invalid target for the action | `REJECTED` | `TARGET_INVALID` |
| non-canonical (spoofed) `response_id` | `REJECTED` | `RESPONSE_ID_MISMATCH` |
| no registered provider | `REJECTED` | `PROVIDER_UNSUPPORTED` |

## 7. Security & Scope Guards

* AST-enforced: no `eval`/`exec`/`compile`/`__import__`/`getattr`
  dispatch/`globals`/`locals`/`vars`, no `subprocess`/`os`, no
  `open()`/filesystem, no socket/httpx/requests/urllib, no
  `sqlalchemy`/`kafka`/`qdrant`/`app.models`, no Gemini, no `time.sleep`.
* The package imports policy **schemas** (shared vocabulary) but never
  the policy **service** — it cannot re-judge or override a decision.
* The provider registry never constructs providers from data; names and
  actions are code constants only.
* Next-steps (`HITL`, `SOAR`) are **not** implemented.