"""Default baseline policy + registry tests (Step 24).

Covers ``app.services.policy.rules`` (the six documented default rules)
and ``app.services.policy.registry`` (deterministic ordering, duplicate
rejection, action filtering, cross-cutting rules, no-coverage sentinel).
"""

from __future__ import annotations

import pytest

from app.services.policy.errors import PolicyRuleConfigurationError
from app.services.policy.registry import (
    DEFAULT_REGISTRY,
    NO_COVERAGE_RULE_ID,
    PolicyRuleRegistry,
)
from app.services.policy.rules import DEFAULT_POLICY_RULES, POLICY_NAME, rule_ids
from app.schemas.policy_decision import (
    PolicyRule,
    ResponseActionType,
)
from app.schemas.risk import RiskLevel


def _rule(policy_rule_id: str, **overrides) -> PolicyRule:
    data = {
        "policy_rule_id": policy_rule_id,
        "action_type": ResponseActionType.BLOCK_IP,
        "minimum_risk_level": RiskLevel.LOW,
        "minimum_confidence": 0.5,
        "require_evidence": True,
        "require_investigation": False,
        "require_attribution": False,
        "requires_approval": False,
        "approval_above_risk_level": None,
        "enabled": True,
        "priority": 10,
        "description": f"rule {policy_rule_id}",
        "metadata": {},
    }
    data.update(overrides)
    return PolicyRule.model_validate(data)


# ---------------------------------------------------------------------------
# 1. Default baseline policy
# ---------------------------------------------------------------------------


class TestDefaultPolicy:
    def test_name(self):
        assert POLICY_NAME == "sentinelai-default-policy-v1"

    def test_six_rules_two_per_action_types(self):
        assert len(DEFAULT_POLICY_RULES) == 6

    def test_covers_every_action_once(self):
        actions = [rule.action_type for rule in DEFAULT_POLICY_RULES]
        assert actions == list(ResponseActionType)
        assert len(set(actions)) == len(ResponseActionType)

    def test_ids_are_unique_and_uppercase(self):
        ids = rule_ids()
        assert len(ids) == len(set(ids))
        for rule_id in ids:
            assert rule_id == rule_id.upper()

    def test_all_rules_require_evidence(self):
        for rule in DEFAULT_POLICY_RULES:
            assert rule.require_evidence is True

    def test_high_impact_rules_require_approval(self):
        by_action = {r.action_type: r for r in DEFAULT_POLICY_RULES}
        assert by_action[ResponseActionType.QUARANTINE_FILE].requires_approval
        assert by_action[ResponseActionType.DISABLE_ACCOUNT].requires_approval
        assert by_action[ResponseActionType.ISOLATE_ENDPOINT].requires_approval

    def test_disable_account_requires_investigation(self):
        rule = next(r for r in DEFAULT_POLICY_RULES if r.action_type is ResponseActionType.DISABLE_ACCOUNT)
        assert rule.require_investigation is True

    def test_isolate_endpoint_requires_attribution_and_high_floor(self):
        rule = next(r for r in DEFAULT_POLICY_RULES if r.action_type is ResponseActionType.ISOLATE_ENDPOINT)
        assert rule.require_attribution is True
        assert rule.minimum_risk_level is RiskLevel.HIGH

    def test_low_impact_rules_escalate_above_high(self):
        for name in (
            "POLICY-BLOCK-IP-001",
            "POLICY-BLOCK-DOMAIN-001",
            "POLICY-TERMINATE-SESSION-001",
        ):
            rule = next(r for r in DEFAULT_POLICY_RULES if r.policy_rule_id == name)
            assert rule.approval_above_risk_level is RiskLevel.HIGH

    def test_descriptions_documented(self):
        for rule in DEFAULT_POLICY_RULES:
            assert len(rule.description) >= 20
            assert "SentinelAI demonstrative policy" in rule.description


# ---------------------------------------------------------------------------
# 2. Registry construction and validation
# ---------------------------------------------------------------------------


class TestRegistryValidation:
    def test_empty_registry(self):
        registry = PolicyRuleRegistry([])
        assert registry.rule_count == 0
        assert registry.rule_ids() == ()

    def test_duplicate_rule_id_rejected(self):
        rules = [
            _rule("DUPE-001"),
            _rule("DUPE-001"),
        ]
        with pytest.raises(PolicyRuleConfigurationError):
            PolicyRuleRegistry(rules)

    def test_non_rule_rejected(self):
        with pytest.raises(PolicyRuleConfigurationError):
            PolicyRuleRegistry(["not-a-rule"])  # type: ignore[list-item]

    def test_default_registry_has_all_rules(self):
        assert DEFAULT_REGISTRY.rule_count == 6
        assert len(DEFAULT_REGISTRY.rule_ids()) == 6

    def test_get_missing_returns_none(self):
        assert DEFAULT_REGISTRY.get("NOPE-999") is None

    def test_get_returns_rule(self):
        rule = DEFAULT_REGISTRY.get("POLICY-BLOCK-IP-001")
        assert rule is not None
        assert rule.action_type is ResponseActionType.BLOCK_IP


# ---------------------------------------------------------------------------
# 3. Deterministic ordering
# ---------------------------------------------------------------------------


class TestOrdering:
    def test_priority_ascending_then_id(self):
        rules = [
            _rule("ZED-001", priority=20),
            _rule("ALPHA-001", priority=10),
            _rule("BETA-001", priority=10),
        ]
        registry = PolicyRuleRegistry(rules)
        assert registry.rule_ids() == ("ALPHA-001", "BETA-001", "ZED-001")

    def test_insertion_order_irrelevant(self):
        a = [_rule("ONE-001", priority=2), _rule("TWO-001", priority=1)]
        b = [_rule("TWO-001", priority=1), _rule("ONE-001", priority=2)]
        ra, rb = PolicyRuleRegistry(a), PolicyRuleRegistry(b)
        assert ra.rule_ids() == rb.rule_ids() == ("TWO-001", "ONE-001")

    def test_rules_for_is_sorted_and_enabled_only(self):
        disabled = _rule("DISABLED-001", priority=1, enabled=False)
        enabled = _rule("ENABLED-001", priority=10)
        other_action = _rule("OTHER-001", action_type=ResponseActionType.BLOCK_DOMAIN)
        registry = PolicyRuleRegistry([other_action, enabled, disabled])
        assert registry.rules_for(ResponseActionType.BLOCK_IP) == (enabled,)

    def test_cross_cutting_rule_applies_to_all(self):
        cross = _rule("CROSS-001", action_type=None, priority=1)
        scoped = _rule("SCOPED-001", action_type=ResponseActionType.BLOCK_IP, priority=10)
        registry = PolicyRuleRegistry([scoped, cross])
        assert registry.rules_for(ResponseActionType.BLOCK_IP) == (cross, scoped)
        assert [r.policy_rule_id for r in registry.rules_for(ResponseActionType.BLOCK_DOMAIN)] == ["CROSS-001"]


# ---------------------------------------------------------------------------
# 4. Sentinel
# ---------------------------------------------------------------------------


class TestSentinel:
    def test_no_coverage_sentinel(self):
        assert NO_COVERAGE_RULE_ID == "POLICY-NO-COVERAGE"

    def test_registry_never_mutates_snapshot(self):
        original = [_rule("KEEP-001")]
        registry = PolicyRuleRegistry(original)
        original.append(_rule("DROP-001"))
        assert registry.rule_ids() == ("KEEP-001",)