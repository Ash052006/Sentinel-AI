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

#: Enterprise Tier-1/Tier-2 specialized security policies with higher priority (5).
ENTERPRISE_POLICY_RULES: tuple[PolicyRule, ...] = (
    PolicyRule(
        policy_rule_id="POLICY-EMERGENCY-CONTAINMENT-001",
        action_type=ResponseActionType.ISOLATE_ENDPOINT,
        minimum_risk_level=RiskLevel.CRITICAL,
        minimum_confidence=0.85,
        require_evidence=True,
        require_investigation=False,
        require_attribution=False,
        requires_approval=True,
        approval_above_risk_level=None,
        enabled=True,
        priority=5,
        description=(
            "Emergency Ransomware & Threat Containment: rapid endpoint isolation "
            "for critical risk incidents with confidence >= 0.85; human-in-the-loop "
            "authorization required."
        ),
    ),
    PolicyRule(
        policy_rule_id="POLICY-C2-IMMEDIATE-BLOCK-001",
        action_type=ResponseActionType.BLOCK_IP,
        minimum_risk_level=RiskLevel.LOW,
        minimum_confidence=0.85,
        require_evidence=True,
        require_investigation=False,
        require_attribution=False,
        requires_approval=False,
        approval_above_risk_level=RiskLevel.HIGH,
        enabled=True,
        priority=5,
        description=(
            "Automated Perimeter Defense: immediate blocking of confirmed "
            "command-and-control IP addresses with confidence >= 0.85."
        ),
    ),
    PolicyRule(
        policy_rule_id="POLICY-CREDENTIAL-THEFT-DISABLE-001",
        action_type=ResponseActionType.DISABLE_ACCOUNT,
        minimum_risk_level=RiskLevel.HIGH,
        minimum_confidence=0.75,
        require_evidence=True,
        require_investigation=True,
        require_attribution=False,
        requires_approval=True,
        approval_above_risk_level=None,
        enabled=True,
        priority=5,
        description=(
            "Compromised Account Containment: account disablement upon verified "
            "credential theft or LSASS memory dumping with completed investigation."
        ),
    ),
    PolicyRule(
        policy_rule_id="POLICY-PHISHING-DOMAIN-SINKHOLE-001",
        action_type=ResponseActionType.BLOCK_DOMAIN,
        minimum_risk_level=RiskLevel.LOW,
        minimum_confidence=0.80,
        require_evidence=True,
        require_investigation=False,
        require_attribution=False,
        requires_approval=False,
        approval_above_risk_level=RiskLevel.HIGH,
        enabled=True,
        priority=5,
        description=(
            "Automated Threat Infrastructure Takedown: DNS blocking of confirmed "
            "phishing and malware delivery domains with confidence >= 0.80."
        ),
    ),
    PolicyRule(
        policy_rule_id="POLICY-ROGUE-SESSION-TERMINATE-001",
        action_type=ResponseActionType.TERMINATE_SESSION,
        minimum_risk_level=RiskLevel.MEDIUM,
        minimum_confidence=0.70,
        require_evidence=True,
        require_investigation=False,
        require_attribution=False,
        requires_approval=False,
        approval_above_risk_level=RiskLevel.HIGH,
        enabled=True,
        priority=5,
        description=(
            "Zero Trust Session Governance: automated session termination for "
            "unauthorized administrative access or remote shells."
        ),
    ),
    PolicyRule(
        policy_rule_id="POLICY-MALWARE-ACTIVE-QUARANTINE-001",
        action_type=ResponseActionType.QUARANTINE_FILE,
        minimum_risk_level=RiskLevel.MEDIUM,
        minimum_confidence=0.80,
        require_evidence=True,
        require_investigation=False,
        require_attribution=False,
        requires_approval=True,
        approval_above_risk_level=None,
        enabled=True,
        priority=5,
        description=(
            "Malicious Payload Quarantine: isolation of detected dropped executables, "
            "reverse shell binaries, and web shells with confidence >= 0.80."
        ),
    ),
)

ALL_POLICY_RULES: tuple[PolicyRule, ...] = ENTERPRISE_POLICY_RULES + DEFAULT_POLICY_RULES


def rule_ids() -> tuple[str, ...]:
    """All default rule ids in deterministic declaration order."""
    return tuple(rule.policy_rule_id for rule in DEFAULT_POLICY_RULES)


def all_rule_ids() -> tuple[str, ...]:
    """All policy rule ids including enterprise policies."""
    return tuple(rule.policy_rule_id for rule in ALL_POLICY_RULES)


__all__ = [
    "ALL_POLICY_RULES",
    "DEFAULT_POLICY_RULES",
    "ENTERPRISE_POLICY_RULES",
    "POLICY_NAME",
    "all_rule_ids",
    "rule_ids",
]