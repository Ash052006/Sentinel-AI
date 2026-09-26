# Policy Decision Engine — Step 24

**Location:** `app/services/policy/` · **Contract:** `app/schemas/policy_decision.py`

## 1. Purpose

The Policy Decision Engine is SentinelAI Version 1's **decision layer**.
It answers one deterministic question for a *proposed* security response
action:

> *May this proposed response action proceed — and if so, under which
> rule, with what explanation?*

The pipeline already knows:

| Layer | Question |
| --- | --- |
| Detection | *what matched?* |
| Correlation | *what is related?* |
| Risk Assessment | *how dangerous?* |
| Investigation / Attribution | *what happened and who may be responsible?* |
| **Policy Decision (this step)** | *may this proposed action proceed?* |

The decision is **never** an instruction to act.  A future Response &
Mitigation layer is *not* part of this step.

## 2. Policy Decision ≠ Response Execution

This is the central invariant of the step:

* Constructing/returning a `PolicyDecision` **never** executes anything.
* The engine has **no** transport, **no** LLM call, **no** DB or ORM, **no**
  filesystem or OS access, **no** shell, and **no** network primitive.
* The engine can never reach a host, account, file, or device, and the
  closed `ResponseActionType` enumeration contains **no free-form action**,
  no function name, no SQL, and no shell string.
* There is **no** SOAR / HITL / response service in this step, and no API
  route was added (the OpenAPI contract contains no policy path).

## 3. Design Principles

1. **Decides only.** A pure, read-only evaluator over declarative data.
2. **Deterministic.** Same input + same rule set + same clock ⇒ a
   byte-identical decision, including a UUIDv5 identity derived from the
   decision content.  No randomness anywhere.
3. **Fail closed.** Missing requirements → `DENIED`.  Missing confidence is
   a failing value, never a passing one.  No rule covering the action →
   `DENIED` under the documented `POLICY-NO-COVERAGE` sentinel.
4. **First applicable rule wins.** Rules are totally ordered by
   `(priority, policy_rule_id)`; insertion order is irrelevant.
5. **Structured explanation.** `reason` is a fixed template; the evaluation
   trace (`metadata.evaluation`) records candidate rules, per-gate results,
   and the decision path.  No free-form AI text.
6. **Evidence references, never fabrications.** Evidence only *references*
   legitimate existing identifiers (correlation / detection / risk
   assessment / investigation / attribution / incident memory) and
   preserves their original `source_provenance` verbatim.
7. **Secret-safe.** Metadata, rules, and evidence are JSON-compatible,
   bounded, cloned, and scanned for credential-shaped content at the
   contract boundary (mirroring Step 11A).

## 4. Scope

**In scope (delivered):**

* `PolicyInput` / `PolicyRule` / `PolicyDecision` / `PolicyEvidence`
  contracts + `ResponseActionType` / `PolicyDecisionStatus` /
  `PolicyEvidenceType` enums.
* Additive `Provenance.POLICY_DECIDED` value.
* `PolicyRuleRegistry` (immutable, deterministic snapshot; rejects
  duplicate rule ids).
* `PolicyDecisionEngine` (all gates, fail-closed, no-coverage sentinel).
* Default baseline policy `sentinelai-default-policy-v1` (six rules,
  one per action).
* Test suite (contract / rules / engine / integration / architecture).

**Explicitly out of scope (NOT delivered — future steps):**

* Response execution, SOAR, HITL workflow. ✅ none
* Any API route / OpenAPI surface. ✅ none
* Persistence / migrations / models. ✅ none
* LLM usage, message bus, external systems. ✅ none
* Arbitrary code / SQL / function-name execution. ✅ none

## 5. Contract Overview

### 5.1 `ResponseActionType`

Closed six-member vocabulary: `block_ip`, `block_domain`, `quarantine_file`,
`disable_account`, `terminate_session`, `isolate_endpoint`.  No custom or
free-form actions exist; an unsupported value is rejected at validation.

### 5.2 `PolicyInput`

Structured evaluation context (extra fields rejected):

* `correlation_id` — UUID reference to the correlation in question.
* `requested_action` — proposed action (closed enum).
* `risk_level` — `RiskLevel` (low/medium/high/critical), from Risk Assessment.
* `risk_score` — optional `[0.0, 1.0]`, carried for explanation.
* `confidence` — optional `[0.0, 1.0]`; `None` means unavailable and treats
  any confidence gate as **failing** (fail closed).
* `attribution_status` — optional attribution context.
* `investigation_available`, `evidence_available` — structured availability
  flags (never the investigation/evidence text itself).
* `evidence_references` — bounded (≤ 16) references to existing items.
* `metadata` — JSON-compatible, secret-free bookkeeping (cloned).
* `timestamp` — timezone-aware.

### 5.3 `PolicyRule`

Pure declarative data (extra fields rejected):

* `policy_rule_id` — `^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$`, ≤ 64.
* `action_type` — governing action (`None` = cross-cutting rule; not used by
  the default policy but supported).
* `minimum_risk_level`, `minimum_confidence` — applicability floors.
* `require_evidence`, `require_investigation`, `require_attribution` —
  boolean requirements.
* `requires_approval` — rule always demands human authorization.
* `approval_above_risk_level` — elevated-risk escalation (must be ≥
  `minimum_risk_level`; an escalation below the floor is rejected as
  conflicting configuration).
* `enabled`, `priority` (≥ 0), `description` (≤ 500), `metadata`.
* `enabled=False` rules are kept for audit but ignored by the engine.

### 5.4 `PolicyDecision`

The auditable output:

* `policy_decision_id` — UUIDv5 over canonical decision content (deterministic).
* `decision` — `allowed` / `denied` / `requires_approval`.
* `reason` — deterministic, template-built explanation (never LLM text).
* `requires_approval` — `True` exactly when decision is `requires_approval`.
* `evidence` — preserved references (cloned, never relabelled).
* `metadata.evaluation` — `{candidates, selected_rule, gate_results, decision_path}`.
* `provenance` — pinned to `Provenance.POLICY_DECIDED` (additive value;
  any other value is rejected by the validator).

## 6. Decision States

| State | Meaning |
| --- | --- |
| `allowed` | An applicable rule's conditions all passed; the action is permitted **by policy** (still never executed by this step). |
| `denied` | At least one required condition failed (with the specific gate in the trace); or no rule governs the action. |
| `requires_approval` | Conditions passed but the rule (or an elevated risk level) demands explicit human authorization before any future response layer may act. |

## 7. Default Policy (`sentinelai-default-policy-v1`)

**Important:** these thresholds are SentinelAI's *initial demonstrative
policy* — documented as this project's explicit, deterministic defaults.
They are **not** universal cybersecurity best practice.

Six rules, all `priority=10`, all `require_evidence=True`, covering every
action exactly once:

| Rule | Action | Min risk | Min conf | Investigation | Attribution | Approval |
| --- | --- | --- | --- | --- | --- | --- |
| `POLICY-BLOCK-IP-001` | block_ip | low | 0.50 | – | – | above high |
| `POLICY-BLOCK-DOMAIN-001` | block_domain | low | 0.60 | – | – | above high |
| `POLICY-TERMINATE-SESSION-001` | terminate_session | low | 0.60 | – | – | above high |
| `POLICY-QUARANTINE-FILE-001` | quarantine_file | medium | 0.70 | – | – | always |
| `POLICY-DISABLE-ACCOUNT-001` | disable_account | medium | 0.70 | required | – | always |
| `POLICY-ISOLATE-ENDPOINT-001` | isolate_endpoint | high | 0.70 | – | required | always |

Net effect:

* Low-risk actions with equal-or-lower risk and adequate confidence are
  `allowed` up to medium risk; at high/critical risk they escalate to
  `requires_approval` (``approval_above_risk_level=high``, inclusive).
* High-impact actions (quarantine, disable account, isolate endpoint)
  always require human authorization when eligible, and add further
  requirements (investigation / attribution).

## 8. Evaluation (Gate Order)

Fixed, auditable, single-source-of-truth gate order:

1. `evidence` — if the rule requires evidence and `evidence_available` is false.
2. `risk_floor` — if `risk_level` ranks below `minimum_risk_level`.
3. `confidence` — if the rule sets a minimum and the input confidence is
   missing or below it.
4. `investigation` — if the rule requires investigation and none is reported.
5. `attribution` — if the rule requires attribution and the status is
   missing or unsupported (`attributed` / `partially_supported`).

When every gate passes, the rule's approval behaviour decides.  The first
rule (in `(priority, rule_id)` order) whose gates all pass decides; if none
passes, the highest-precedence candidate's first failing gate explains the
denial.  If the registry has no rule for the action → `DENIED` with
`policy_rule_id="POLICY-NO-COVERAGE"` and `decision_path="denied:no_coverage"`.

## 9. Determinism & Identity

* The engine takes an optional injectable UTC `clock`; decisions use it
  verbatim (no ``now()`` inside).
* Metric/explanation rendering uses fixed precision formatting, so reason
  strings are stable.
* `policy_decision_id` = `uuid5(POLICY_DECISION_NAMESPACE, canonical_json)`
  where the canonical JSON is sorted-key, compact, string-typed content
  (correlation id, action, decision, rule id, reason, risk level/score,
  confidence, timestamp).  Identical (input, rules, clock) ⇒ identical id.

## 10. Fail-Closed Behaviour

| Situation | Outcome |
| --- | --- |
| Confidence unavailable under a minimum-confidence rule | `denied` |
| Confidence below the minimum | `denied` |
| Risk below the rule's floor | `denied` |
| Evidence required but not available | `denied` |
| Investigation required but not available | `denied` |
| Attribution required but missing/unsupported | `denied` |
| No enabled rule governs the action | `denied` (sentinel) |
| Out-of-bounds / malformed input | `PolicyInputValidationError` (sanitized) |
| Inner engine defect | `PolicyInternalError` (sanitized, chained cause) |

Sanitized exceptions never echo caller values, identifiers, secrets, or
evaluation context.

## 11. Registry

* `PolicyRuleRegistry(rules)` builds an immutable `(priority, rule_id)`
  sorted **deep copy snapshot** — callers mutating their own rule objects
  afterwards cannot change what the engine evaluates.
* Duplicate `policy_rule_id` → `PolicyRuleConfigurationError`.
* Non-`PolicyRule` entries → `PolicyRuleConfigurationError`.
* `rules_for(action)` returns enabled rules (specific action or
  `action_type=None` cross-cutting), deterministic order.
* `DEFAULT_REGISTRY` is the canonical default.

## 12. Architecture & Isolation

Implemented package: `app/services/policy/`

* `errors.py` — sanitized exception hierarchy.
* `contracts.py` — schema re-exports.
* `rules.py` — default policy data (single source of truth for thresholds).
* `registry.py` — registry + `DEFAULT_REGISTRY` + no-coverage sentinel.
* `engine.py` — `PolicyDecisionEngine`, gate evaluation, traces, IDs.
* `__init__.py` — public surface.

Static isolation guarantees (enforced by `test_policy_architecture.py` via
AST/source inspection):

* No `eval`/`exec`/`compile`/`__import__`/`globals`/`locals`/`vars`.
* No `getattr(` / `__getattribute__` dynamic dispatch.
* Imports whitelisted: stdlib, `pydantic`, and `app` only.  **Forbidden:**
  `fastapi`, `sqlalchemy`, `kafka`, `qdrant`, `subprocess`, `socket`,
  `httpx`, `requests`, `urllib`, `app.models`, `app.agents`, `app.main`,
  `pickle`, Gemini SDKs.
* No filesystem / OS / shell primitives.
* No `app.services.response`, HITL, or SOAR imports; no action-runner
  functions (`_block`, `_quarantine`, `_disable`, `_isolate`, `_execute`).
* No API route added (OpenAPI contains no policy/decision/approval path).

## 13. Provenance

`Provenance.POLICY_DECIDED = "policy_decided"` was added **additively** at
the end of the enum in `app/schemas/security_event.py`; all prior values
are untouched (the full suite confirms no other consumer breaks).  Any
`PolicyDecision` whose `provenance` is not `POLICY_DECIDED` is rejected.

Evidence `source_provenance` is preserved verbatim — a risk assessment
reference stays `risk_assessed`, a historical incident memory stays
`recalled`, etc.  Nothing is relabelled as a policy decision and a recalled
memory reference is never upgraded to current evidence.

## 14. Versioned API & Compatibility

* Decision ids are stable UUIDv5, so re-evaluating the same content reuses
  the same identity.
* The decision surface is additive: all fields retain their documented
  meaning; no field is repurposed.
* `DEFAULT_POLICY_RULES` changes are docs-first: thresholds are captured in
  `rules.py` and mirrored in this document.

## 15. Test Summary

`tests/unit/test_policy_*.py`:

* `test_policy_contract.py` — enums, bounds, provenance additivity,
  secret-safety, cloning, rule-conflict rejection, provenance pinning.
* `test_policy_rules.py` — default policy composition, registry validation,
  deterministic ordering, cross-cutting rules, sentinel.
* `test_policy_engine.py` — all decision states, boundaries, gate order,
  first-applicable precedence, no-coverage sentinel, byte-level
  determinism, immutability, explainability, input coercion.
* `test_policy_integration.py` — RiskAssessment / InvestigationResult /
  AttributionAssessment → `PolicyInput` → `PolicyDecision` flows with real
  contracts, provenance preservation, end-to-end determinism, gate-order
  interaction.
* `test_policy_architecture.py` — AST/source isolation, import whitelists,
  OpenAPI no-policy-path, no response surface.

**One pre-existing test was corrected:** `tests/unit/test_incident_memory
_contract.py` asserted `len(Provenance) == 10`; the Step 24 additive enum
value makes the correct count `11`.  This is a minimal, test-only,
documented correction (no production behavior change) permitted by the
FIX GATE.