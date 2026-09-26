"""Deterministic Policy Decision Engine — Step 24.

Evaluates declarative :class:`~app.schemas.policy_decision.PolicyRule`
data over a structured :class:`~app.schemas.policy_decision.PolicyInput`
and produces an auditable :class:`~app.schemas.policy_decision.
PolicyDecision` — ``ALLOWED`` / ``DENIED`` / ``REQUIRES_APPROVAL``.

Hard guarantees:

* **Decides only.** This engine never executes an action, never contacts
  a host/account/file/network device, never calls SOAR, never emits a
  command, never touches a network, never imports at runtime, and never
  invokes an LLM.  There is no "response" surface anywhere in it.
* **Deterministic.** Same input + same rule set + same clock -> a
  byte-identical decision (including the derived ``policy_decision_id``,
  which is a UUIDv5 over the canonical decision content — no randomness).
* **Fail closed.** Every missing requirement yields ``DENIED``; an action
  with no governing rule yields ``DENIED`` under the documented
  ``POLICY-NO-COVERAGE`` sentinel.  Confidence that is *unavailable* is
  treated as a failing value, never as a passing one.
* **First applicable rule wins.** Rules are considered in the total order
  ``(priority, policy_rule_id)``; the first rule whose *conditions* all
  pass decides.  If none passes, the highest-precedence rule's first
  failing gate explains the denial (always non-empty — if the first rule
  passed it would have decided).
* **Structured explanation.** ``reason`` is a fixed template and
  ``metadata.evaluation`` is a deterministic trace (candidate rule ids,
  per-gate results, decision path).  No free-form AI text.

Gate order (fixed, auditable, documented):

1. ``evidence``      — if the rule requires evidence and none is available.
2. ``risk_floor``    — if risk level is below the rule's minimum.
3. ``confidence``    — if the rule sets a minimum confidence and the input
                      confidence is missing or below it.
4. ``investigation`` — if the rule requires investigation context and none
                      is reported.
5. ``attribution``   — if the rule requires supported attribution and the
                      status is missing or unsupported.

When every gate passes, the rule's approval behaviour decides:
``requires_approval``, or an elevated-risk escalation
(``approval_above_risk_level``), or ``ALLOWED``.

Institution note: the default thresholds live in
:mod:`app.services.policy.rules` and are SentinelAI's *initial
demonstrative policy*, not universal security best practice.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Callable

from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    PolicyInput,
    PolicyRule,
    ResponseActionType,
    risk_rank,
)
from app.schemas.threat_attribution import AttributionStatus
from app.services.policy.errors import PolicyInputValidationError, PolicyInternalError
from app.services.policy.identity import (
    derive_policy_decision_id,
    policy_decision_id_content,
)
from app.services.policy.registry import (
    DEFAULT_REGISTRY,
    NO_COVERAGE_RULE_ID,
    PolicyRuleRegistry,
)
from app.services.policy.rules import POLICY_NAME

#: Attribution statuses the engine treats as "supported" for rules that
#: declare ``require_attribution=True``.  Deterministic, documented, fixed.
SUPPORTED_ATTRIBUTION_STATUSES = frozenset(
    {
        AttributionStatus.ATTRIBUTED,
        AttributionStatus.PARTIALLY_SUPPORTED,
    }
)

#: Fixed gate order (single source of truth for the evaluation trace).
_GATE_NAMES: tuple[str, ...] = (
    "evidence",
    "risk_floor",
    "confidence",
    "investigation",
    "attribution",
)


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(value: float) -> str:
    """Stable, deterministic float rendering for explanations."""
    return f"{value:.2f}"


def _attribution_satisfied(status: AttributionStatus | None) -> bool:
    return status in SUPPORTED_ATTRIBUTION_STATUSES


def _first_failing_gate(
    rule: PolicyRule, inp: PolicyInput
) -> str | None:
    """Return the first 'gate (by fixed order) the input fails for *rule*,
    or None when the rule is fully applicable."""
    if rule.require_evidence and not inp.evidence_available:
        return "evidence"
    if risk_rank(inp.risk_level) < risk_rank(rule.minimum_risk_level):
        return "risk_floor"
    if rule.minimum_confidence is not None and (
        inp.confidence is None or inp.confidence < rule.minimum_confidence
    ):
        return "confidence"
    if rule.require_investigation and not inp.investigation_available:
        return "investigation"
    if rule.require_attribution and not _attribution_satisfied(
        inp.attribution_status
    ):
        return "attribution"
    return None


def _gate_results(
    rule: PolicyRule, inp: PolicyInput, failing: str | None
) -> list[dict[str, Any]]:
    """Deterministic per-gate trace for the deciding/explaining rule."""
    results: list[dict[str, Any]] = []
    for gate in _GATE_NAMES:
        if gate == "evidence":
            required = rule.require_evidence
            passed = not required or inp.evidence_available
        elif gate == "risk_floor":
            required = True
            passed = (
                risk_rank(inp.risk_level) >= risk_rank(rule.minimum_risk_level)
            )
        elif gate == "confidence":
            required = rule.minimum_confidence is not None
            passed = (
                not required
                or (inp.confidence is not None and inp.confidence >= rule.minimum_confidence)
            )
        elif gate == "investigation":
            required = rule.require_investigation
            passed = not required or inp.investigation_available
        else:  # attribution
            required = rule.require_attribution
            passed = not required or _attribution_satisfied(inp.attribution_status)
        if failing == gate:
            passed = False
        results.append(
            {"gate": gate, "required": required, "passed": bool(passed)}
        )
    return results


def _deny_reason(gate: str, rule: PolicyRule, inp: PolicyInput) -> str:
    action = inp.requested_action.value
    if gate == "evidence":
        return (
            f"Requested action {action} is denied under policy "
            f"{rule.policy_rule_id}: evidence availability is required "
            "and was not provided."
        )
    if gate == "risk_floor":
        return (
            f"Requested action {action} is denied under policy "
            f"{rule.policy_rule_id}: risk level {inp.risk_level.value} is "
            f"below the required minimum {rule.minimum_risk_level.value}."
        )
    if gate == "confidence":
        if inp.confidence is None:
            return (
                f"Requested action {action} is denied under policy "
                f"{rule.policy_rule_id}: confidence is unavailable and "
                f"a minimum of {_fmt(rule.minimum_confidence or 0.0)} is "
                "required."
            )
        return (
            f"Requested action {action} is denied under policy "
            f"{rule.policy_rule_id}: confidence {_fmt(inp.confidence)} is "
            f"below the required minimum "
            f"{_fmt(rule.minimum_confidence or 0.0)}."
        )
    if gate == "investigation":
        return (
            f"Requested action {action} is denied under policy "
            f"{rule.policy_rule_id}: a completed investigation is "
            "required and was not provided."
        )
    # attribution
    if inp.attribution_status is None:
        return (
            f"Requested action {action} is denied under policy "
            f"{rule.policy_rule_id}: supported attribution is required "
            "and was not provided."
        )
    supported = ", ".join(
        sorted(status.value for status in SUPPORTED_ATTRIBUTION_STATUSES)
    )
    return (
        f"Requested action {action} is denied under policy "
        f"{rule.policy_rule_id}: attribution status "
        f"{inp.attribution_status.value} is not a supported attribution "
        f"(supported: {supported})."
    )


def _approval_reason(
    rule: PolicyRule, inp: PolicyInput, *, elevated: bool
) -> str:
    action = inp.requested_action.value
    if elevated:
        assert rule.approval_above_risk_level is not None
        return (
            f"Requested action {action} requires human authorization "
            f"under policy {rule.policy_rule_id} because risk level "
            f"{inp.risk_level.value} is at or above "
            f"{rule.approval_above_risk_level.value}."
        )
    return (
        f"Requested action {action} requires human authorization under "
        f"policy {rule.policy_rule_id}."
    )


def _allowed_reason(rule: PolicyRule, inp: PolicyInput) -> str:
    base = (
        f"Requested action {inp.requested_action.value} is allowed under "
        f"policy {rule.policy_rule_id}: risk level "
        f"{inp.risk_level.value} meets or exceeds "
        f"{rule.minimum_risk_level.value}"
    )
    if rule.minimum_confidence is not None and inp.confidence is not None:
        base += (
            f" and confidence {_fmt(inp.confidence)} meets or exceeds "
            f"{_fmt(rule.minimum_confidence)}"
        )
    return base + "."


def _no_coverage_reason(inp: PolicyInput) -> str:
    return (
        f"Requested action {inp.requested_action.value} is denied: no "
        "enabled policy rule covers this action."
    )


class PolicyDecisionEngine:
    """Deterministic policy evaluator.

    Args:
        registry: Optional :class:`PolicyRuleRegistry`.  Defaults to the
            canonical default registry.
        clock: Overridable UTC clock for the decision timestamp (fixed in
            tests to make serialization byte-deterministic).
    """

    def __init__(
        self,
        *,
        registry: PolicyRuleRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry: PolicyRuleRegistry = (
            registry if registry is not None else DEFAULT_REGISTRY
        )
        self._clock: Callable[[], datetime] = clock or _default_now

    @property
    def registry(self) -> PolicyRuleRegistry:
        return self._registry

    # -- Public entry point ---------------------------------------------------

    def decide(
        self,
        policy_input: PolicyInput | Mapping[str, Any],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> PolicyDecision:
        """Evaluate one structured policy input and return a decision.

        Args:
            policy_input: A validated :class:`PolicyInput` or a plain
                mapping (validated here; failures raise
                :class:`PolicyInputValidationError` without echoing caller
                values).
            clock: Optional per-call UTC clock override.

        Raises:
            PolicyInputValidationError: structurally invalid input or an
                unsupported action (defense-in-depth; the contract itself
                rejects these at construction).
            PolicyInternalError: the clock returned a naive timestamp.
        """
        inp = self._coerce_input(policy_input)
        action = inp.requested_action
        if not isinstance(action, ResponseActionType):
            raise PolicyInputValidationError(
                "the requested action must be a supported response action"
            )

        now = (clock or self._clock)()
        if now.tzinfo is None or now.utcoffset() is None:
            raise PolicyInternalError(
                "the policy clock must return a timezone-aware timestamp"
            )

        candidates = self._registry.rules_for(action)

        # Fail closed: no rule governs the action.
        if not candidates:
            return self._no_coverage_decision(inp, now)

        for rule in candidates:
            failing = _first_failing_gate(rule, inp)
            if failing is None:
                return self._applicable_decision(rule, inp, now)

        # No rule applicable: the highest-precedence candidate's first
        # failing gate explains the denial (that rule failed by
        # construction, so `failing` is guaranteed non-None).
        explaining = candidates[0]
        failing = _first_failing_gate(explaining, inp)
        return self._denied_decision(explaining, inp, failing, now)

    @staticmethod
    def _coerce_input(policy_input: Any) -> PolicyInput:
        if isinstance(policy_input, PolicyInput):
            return policy_input
        if isinstance(policy_input, Mapping):
            try:
                return PolicyInput.model_validate(policy_input)
            except Exception as exc:  # noqa: BLE001 - sanitized, never echoed
                raise PolicyInputValidationError(
                    "policy input failed validation"
                ) from exc
        raise PolicyInputValidationError(
            "policy input must be a PolicyInput instance or a mapping"
        )

    # -- Decision assembly ----------------------------------------------------

    def _no_coverage_decision(self, inp: PolicyInput, now: datetime) -> PolicyDecision:
        return self._assemble(
            inp=inp,
            rule_id=NO_COVERAGE_RULE_ID,
            decided=None,
            decision=PolicyDecisionStatus.DENIED,
            decision_path="denied:no_coverage",
            reason=_no_coverage_reason(inp),
            requireds=False,
            now=now,
        )

    def _denied_decision(
        self,
        rule: PolicyRule,
        inp: PolicyInput,
        failing: str,
        now: datetime,
    ) -> PolicyDecision:
        assert failing is not None
        return self._assemble(
            inp=inp,
            rule_id=rule.policy_rule_id,
            decided=rule,
            decision=PolicyDecisionStatus.DENIED,
            decision_path=f"denied:{failing}",
            reason=_deny_reason(failing, rule, inp),
            requireds=True,
            now=now,
        )

    def _applicable_decision(
        self, rule: PolicyRule, inp: PolicyInput, now: datetime
    ) -> PolicyDecision:
        elevated = (
            rule.requires_approval is False
            and rule.approval_above_risk_level is not None
            and risk_rank(inp.risk_level)
            >= risk_rank(rule.approval_above_risk_level)
        )
        if rule.requires_approval or elevated:
            decision = PolicyDecisionStatus.REQUIRES_APPROVAL
            decision_path = (
                "requires_approval_elevated_risk"
                if elevated
                else "requires_approval"
            )
            reason = _approval_reason(rule, inp, elevated=elevated)
        else:
            decision = PolicyDecisionStatus.ALLOWED
            decision_path = "allowed"
            reason = _allowed_reason(rule, inp)
        return self._assemble(
            inp=inp,
            rule_id=rule.policy_rule_id,
            decided=rule,
            decision=decision,
            decision_path=decision_path,
            reason=reason,
            requireds=True,
            now=now,
        )

    def _assemble(
        self,
        *,
        inp: PolicyInput,
        rule_id: str,
        decided: PolicyRule | None,
        decision: PolicyDecisionStatus,
        decision_path: str,
        reason: str,
        requireds: bool,
        now: datetime,
    ) -> PolicyDecision:
        candidates = [r.policy_rule_id for r in self._registry.rules_for(inp.requested_action)]
        if requireds:
            explaining = decided
            assert explaining is not None
            gate_results = _gate_results(
                explaining,
                inp,
                failing=(
                    decision_path.removeprefix("denied:")
                    if decision_path.startswith("denied:")
                    else None
                ),
            )
        else:
            gate_results = []

        metadata: dict[str, Any] = {
            "policy": POLICY_NAME,
            "input": json.loads(json.dumps(inp.metadata)),
            "evaluation": {
                "candidates": candidates,
                "selected_rule": rule_id if decided is not None else None,
                "gate_results": gate_results,
                "decision_path": decision_path,
            },
        }

        evidence = [
            item.model_validate(item.model_dump(mode="json"))
            for item in inp.evidence_references
        ]

        content = policy_decision_id_content(
            correlation_id=inp.correlation_id,
            requested_action=inp.requested_action,
            decision=decision,
            policy_rule_id=rule_id,
            reason=reason,
            risk_level=inp.risk_level,
            risk_score=inp.risk_score,
            confidence=inp.confidence,
            timestamp=now,
        )

        return PolicyDecision(
            policy_decision_id=derive_policy_decision_id(content),
            correlation_id=inp.correlation_id,
            requested_action=inp.requested_action,
            decision=decision,
            reason=reason,
            policy_rule_id=rule_id,
            risk_level=inp.risk_level,
            risk_score=inp.risk_score,
            confidence=inp.confidence,
            requires_approval=(decision is PolicyDecisionStatus.REQUIRES_APPROVAL),
            evidence=evidence,
            metadata=metadata,
            timestamp=now,
        )


__all__ = [
    "PolicyDecisionEngine",
    "SUPPORTED_ATTRIBUTION_STATUSES",
]