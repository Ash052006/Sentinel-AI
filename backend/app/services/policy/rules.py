"""SentinelAI default baseline policy — Step 24.

A small, explicit, deterministic policy that demonstrates all three
outcomes (``ALLOWED`` / ``DENIED`` / ``REQUIRES_APPROVAL``) over the six
closed :class:`~app.schemas.policy_decision.ResponseActionType` values.

**Important.** These rules are SentinelAI's *initial demonstrative
policy* — the exact thresholds below are this project's explicit,
deterministic defaults, documented here as the single source of truth.
They are **not** claimed to be universal cybersecurity best practice.
They exist so the engine has a defensible, auditable baseline until real
organizational policy is supplied.

The rules are pure declarative data: no code, no expressions, no
callables.  Evaluation is fixed engine logic in
:mod:`app.services.policy.engine`.

Evaluation summary (full gate order is documented in the engine):

* every action requires evidence availability (``require_evidence=True``
  is the fail-closed default);
* a low-risk/low-confidence situation never passes:
  * risk below the floor -> DENIED (action not warranted);
  * confidence below the minimum (or unavailable) -> DENIED;
* high-impact actions (quarantine, disable account, isolate endpoint)
  always require human authorization when they *do* pass;
* elevated risk on a normally-allowable action escalates it to
  REQUIRES_APPROVAL (``approval_above_risk_level=HIGH``);
* otherwise (appropriate risk, sufficient confidence, proper context,
  non-escalated) -> ALLOWED.
"""

from __future__ import annotations

from app.schemas.policy_decision import PolicyRule, ResponseActionType
from app.schemas.risk import RiskLevel

#: Stable identity of the default policy, recorded in decision metadata.
POLICY_NAME = "sentinelai-default-policy-v1"

#: The default baseline policy, in deterministic order.  One rule per
#: action (all priority 10; action scopes are disjoint so precedence
#: between them is irrelevant — determinism tests exercise overlapping
#: custom rule sets separately).
#:
#: Rule semantics (documented, exact, deterministic):
#
#: * ``POLICY-BLOCK-IP-001``          — allow at low/medium risk, escalate
#:   to approval at high risk or above; confidence >= 0.50.
#: * ``POLICY-BLOCK-DOMAIN-001``      — allow at low/medium risk, escalate
#:   to approval at high risk or above; confidence >= 0.60.
#: * ``POLICY-QUARANTINE-FILE-001``   — high-impact; requires approval
#:   whenever eligible; risk floor medium; confidence >= 0.70.
#: * ``POLICY-DISABLE-ACCOUNT-001``   — high-impact; requires a completed
#:   investigation and approval; risk floor medium; confidence >= 0.70.
#: * ``POLICY-TERMINATE-SESSION-001`` — allow at low/medium risk, escalate
#:   to approval at high risk or above; confidence >= 0.60.
#: * ``POLICY-ISOLATE-ENDPOINT-001``  — high-impact; requires supported
#:   attribution and approval; risk floor high; confidence >= 0.70.
DEFAULT_POLICY_RULES: tuple[PolicyRule, ...] = (
    PolicyRule(
        policy_rule_id="POLICY-BLOCK-IP-001",
        action_type=ResponseActionType.BLOCK_IP,
        minimum_risk_level=RiskLevel.LOW,
        minimum_confidence=0.5,
        require_evidence=True,
        require_investigation=False,
        require_attribution=False,
        requires_approval=False,
        approval_above_risk_level=RiskLevel.HIGH,
        enabled=True,
        priority=10,
        description=(
            "SentinelAI demonstrative policy: block_ip is allowed at "
            "low/medium risk with evidence and confidence >= 0.50; "
            "elevated (high/critical) risk escalates to human approval."
        ),
    ),
    PolicyRule(
        policy_rule_id="POLICY-BLOCK-DOMAIN-001",
        action_type=ResponseActionType.BLOCK_DOMAIN,
        minimum_risk_level=RiskLevel.LOW,
        minimum_confidence=0.6,
        require_evidence=True,
        require_investigation=False,
        require_attribution=False,
        requires_approval=False,
        approval_above_risk_level=RiskLevel.HIGH,
        enabled=True,
        priority=10,
        description=(
            "SentinelAI demonstrative policy: block_domain is allowed at "
            "low/medium risk with evidence and confidence >= 0.60; "
            "elevated (high/critical) risk escalates to human approval."
        ),
    ),
    PolicyRule(
        policy_rule_id="POLICY-QUARANTINE-FILE-001",
        action_type=ResponseActionType.QUARANTINE_FILE,
        minimum_risk_level=RiskLevel.MEDIUM,
        minimum_confidence=0.7,
        require_evidence=True,
        require_investigation=False,
        require_attribution=False,
        requires_approval=True,
        approval_above_risk_level=None,
        enabled=True,
        priority=10,
        description=(
            "SentinelAI demonstrative policy: quarantine_file is a "
            "high-impact action — eligible only at medium+ risk with "
            "evidence and confidence >= 0.70, and always requires human "
            "approval."
        ),
    ),
    PolicyRule(
        policy_rule_id="POLICY-DISABLE-ACCOUNT-001",
        action_type=ResponseActionType.DISABLE_ACCOUNT,
        minimum_risk_level=RiskLevel.MEDIUM,
        minimum_confidence=0.7,
        require_evidence=True,
        require_investigation=True,
        require_attribution=False,
        requires_approval=True,
        approval_above_risk_level=None,
        enabled=True,
        priority=10,
        description=(
            "SentinelAI demonstrative policy: disable_account is a "
            "high-impact action that additionally requires a completed "
            "AI investigation — eligible only at medium+ risk with "
            "evidence, investigation context, and confidence >= 0.70, "
            "and always requires human approval."
        ),
    ),
    PolicyRule(
        policy_rule_id="POLICY-TERMINATE-SESSION-001",
        action_type=ResponseActionType.TERMINATE_SESSION,
        minimum_risk_level=RiskLevel.LOW,
        minimum_confidence=0.6,
        require_evidence=True,
        require_investigation=False,
        require_attribution=False,
        requires_approval=False,
        approval_above_risk_level=RiskLevel.HIGH,
        enabled=True,
        priority=10,
        description=(
            "SentinelAI demonstrative policy: terminate_session is "
            "allowed at low/medium risk with evidence and confidence "
            ">= 0.60; elevated (high/critical) risk escalates to human "
            "approval."
        ),
    ),
    PolicyRule(
        policy_rule_id="POLICY-ISOLATE-ENDPOINT-001",
        action_type=ResponseActionType.ISOLATE_ENDPOINT,
        minimum_risk_level=RiskLevel.HIGH,
        minimum_confidence=0.7,
        require_evidence=True,
        require_investigation=False,
        require_attribution=True,
        requires_approval=True,
        approval_above_risk_level=None,
        enabled=True,
        priority=10,
        description=(
            "SentinelAI demonstrative policy: isolate_endpoint is the "
            "most impactful action — eligible only at high+ risk with "
            "evidence, supported attribution, and confidence >= 0.70, "
            "and always requires human approval."
        ),
    ),
)


def rule_ids() -> tuple[str, ...]:
    """All default rule ids in deterministic declaration order."""
    return tuple(rule.policy_rule_id for rule in DEFAULT_POLICY_RULES)


__all__ = [
    "DEFAULT_POLICY_RULES",
    "POLICY_NAME",
    "rule_ids",
]