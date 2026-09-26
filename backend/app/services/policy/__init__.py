"""SentinelAI Policy Decision Engine (Step 24).

Public surface: :class:`PolicyDecisionEngine`, the registry +
default policy, and the domain contracts.  This layer **decides only** —
it never executes an action, never touches a network, never invokes an LLM.
"""

from __future__ import annotations

from app.services.policy.contracts import (
    POLICY_DECISION_NAMESPACE,
    POLICY_MAX_EVIDENCE_REFERENCES,
    POLICY_MAX_ROLE_LENGTH,
    POLICY_MAX_RULE_ID_LENGTH,
    PolicyDecision,
    PolicyDecisionStatus,
    PolicyEvidence,
    PolicyEvidenceType,
    PolicyInput,
    PolicyRule,
    ResponseActionType,
    RiskLevel,
    risk_rank,
)
from app.services.policy.engine import PolicyDecisionEngine
from app.services.policy.errors import (
    PolicyError,
    PolicyEvaluationError,
    PolicyInputValidationError,
    PolicyInternalError,
    PolicyRuleConfigurationError,
)
from app.services.policy.registry import (
    DEFAULT_REGISTRY,
    NO_COVERAGE_RULE_ID,
    PolicyRuleRegistry,
)
from app.services.policy.rules import DEFAULT_POLICY_RULES, POLICY_NAME

__all__ = [
    "DEFAULT_POLICY_RULES",
    "DEFAULT_REGISTRY",
    "NO_COVERAGE_RULE_ID",
    "POLICY_DECISION_NAMESPACE",
    "POLICY_MAX_EVIDENCE_REFERENCES",
    "POLICY_MAX_ROLE_LENGTH",
    "POLICY_MAX_RULE_ID_LENGTH",
    "POLICY_NAME",
    "PolicyDecision",
    "PolicyDecisionEngine",
    "PolicyDecisionStatus",
    "PolicyError",
    "PolicyEvaluationError",
    "PolicyEvidence",
    "PolicyEvidenceType",
    "PolicyInput",
    "PolicyInputValidationError",
    "PolicyInternalError",
    "PolicyRule",
    "PolicyRuleConfigurationError",
    "PolicyRuleRegistry",
    "ResponseActionType",
    "RiskLevel",
    "risk_rank",
]