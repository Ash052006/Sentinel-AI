"""Policy decision engine tests (Step 24).

Deterministic evaluation behaviour of
:class:`app.services.policy.engine.PolicyDecisionEngine` over the
default baseline policy: gate order, fail-closed denials, approval
escalation, no-coverage sentinel, first-applicable rule precedence,
byte-level determinism, immutability, and structured explainability.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.policy_decision import (
    POLICY_MAX_EVIDENCE_REFERENCES,
    PolicyDecision,
    PolicyDecisionStatus,
    PolicyEvidence,
    PolicyEvidenceType,
    PolicyInput,
    PolicyRule,
    ResponseActionType,
)
from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance
from app.schemas.threat_attribution import AttributionStatus
from app.services.policy import (
    NO_COVERAGE_RULE_ID,
    POLICY_NAME,
    PolicyDecisionEngine,
    PolicyInputValidationError,
    PolicyRuleRegistry,
)

TZ = timezone.utc
NOW = datetime(2025, 7, 17, 8, 0, 0, tzinfo=TZ)
FIXED = datetime(2025, 7, 17, 12, 0, 0, tzinfo=TZ)


def _fixed_engine() -> PolicyDecisionEngine:
    return PolicyDecisionEngine(clock=lambda: FIXED)


def _data(**overrides) -> dict:
    data = {
        "correlation_id": str(uuid.uuid4()),
        "requested_action": ResponseActionType.BLOCK_IP.value,
        "risk_level": RiskLevel.LOW.value,
        "risk_score": 0.3,
        "confidence": 0.9,
        "attribution_status": None,
        "investigation_available": False,
        "evidence_available": True,
        "evidence_references": [],
        "metadata": {"source": "unit-test"},
        "timestamp": NOW.isoformat(),
    }
    data.update(overrides)
    return data


def _decide(**overrides) -> PolicyDecision:
    return _fixed_engine().decide(_data(**overrides))


def _custom_engine(rules, **overrides) -> PolicyDecision:
    return PolicyDecisionEngine(
        registry=PolicyRuleRegistry(rules), clock=lambda: FIXED
    )


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
# 1. ALLOWED / DENIED / REQUIRES_APPROVAL (all three)
# ---------------------------------------------------------------------------


class TestDecisionStates:
    def test_allowed_default_policy(self):
        d = _decide()
        assert d.decision is PolicyDecisionStatus.ALLOWED
        assert d.requires_approval is False
        assert d.policy_rule_id == "POLICY-BLOCK-IP-001"
        assert d.metadata["evaluation"]["decision_path"] == "allowed"

    def test_denied_no_evidence(self):
        d = _decide(evidence_available=False)
        assert d.decision is PolicyDecisionStatus.DENIED
        assert d.requires_approval is False
        assert d.metadata["evaluation"]["decision_path"] == "denied:evidence"
        assert d.policy_rule_id == "POLICY-BLOCK-IP-001"

    def test_denied_low_confidence(self):
        d = _decide(confidence=0.4)
        assert d.decision is PolicyDecisionStatus.DENIED
        assert d.metadata["evaluation"]["decision_path"] == "denied:confidence"

    def test_denied_missing_confidence_fails_closed(self):
        d = _decide(confidence=None)
        assert d.decision is PolicyDecisionStatus.DENIED
        assert d.metadata["evaluation"]["decision_path"] == "denied:confidence"

    def test_denied_risk_floor_quarantine(self):
        d = _decide(
            requested_action=ResponseActionType.QUARANTINE_FILE.value,
            risk_level=RiskLevel.LOW.value,
            confidence=0.9,
        )
        assert d.decision is PolicyDecisionStatus.DENIED
        assert d.metadata["evaluation"]["decision_path"] == "denied:risk_floor"

    def test_denied_investigation_missing(self):
        d = _decide(
            requested_action=ResponseActionType.DISABLE_ACCOUNT.value,
            risk_level=RiskLevel.MEDIUM.value,
            confidence=0.9,
            investigation_available=False,
        )
        assert d.decision is PolicyDecisionStatus.DENIED
        assert d.metadata["evaluation"]["decision_path"] == "denied:investigation"

    def test_denied_attribution_missing(self):
        d = _decide(
            requested_action=ResponseActionType.ISOLATE_ENDPOINT.value,
            risk_level=RiskLevel.HIGH.value,
            confidence=0.9,
            attribution_status=None,
        )
        assert d.decision is PolicyDecisionStatus.DENIED
        assert d.metadata["evaluation"]["decision_path"] == "denied:attribution"

    def test_denied_attribution_unsupported(self):
        d = _decide(
            requested_action=ResponseActionType.ISOLATE_ENDPOINT.value,
            risk_level=RiskLevel.HIGH.value,
            confidence=0.9,
            attribution_status=AttributionStatus.UNATTRIBUTED.value,
        )
        assert d.decision is PolicyDecisionStatus.DENIED
        assert d.metadata["evaluation"]["decision_path"] == "denied:attribution"

    def test_requires_approval_high_impact_actions(self):
        for action, kw in (
            (
                ResponseActionType.QUARANTINE_FILE,
                {"risk_level": RiskLevel.MEDIUM.value},
            ),
            (
                ResponseActionType.DISABLE_ACCOUNT,
                {"risk_level": RiskLevel.MEDIUM.value, "investigation_available": True},
            ),
            (
                ResponseActionType.ISOLATE_ENDPOINT,
                {"risk_level": RiskLevel.HIGH.value, "attribution_status": "attributed"},
            ),
        ):
            d = _decide(requested_action=action.value, confidence=0.9, **kw)
            assert d.decision is PolicyDecisionStatus.REQUIRES_APPROVAL, action
            assert d.requires_approval is True

    def test_requires_approval_elevated_risk(self):
        d = _decide(risk_level=RiskLevel.HIGH.value)
        assert d.decision is PolicyDecisionStatus.REQUIRES_APPROVAL
        assert (
            d.metadata["evaluation"]["decision_path"]
            == "requires_approval_elevated_risk"
        )

    def test_supported_attribution_statuses_pass_gate(self):
        for status in (
            AttributionStatus.ATTRIBUTED.value,
            AttributionStatus.PARTIALLY_SUPPORTED.value,
        ):
            d = _decide(
                requested_action=ResponseActionType.ISOLATE_ENDPOINT.value,
                risk_level=RiskLevel.HIGH.value,
                confidence=0.9,
                attribution_status=status,
            )
            assert d.decision is PolicyDecisionStatus.REQUIRES_APPROVAL


# ---------------------------------------------------------------------------
# 2. Boundaries
# ---------------------------------------------------------------------------


class TestBoundaries:
    def test_confidence_exactly_at_minimum_passes(self):
        d = _decide(confidence=0.5)
        assert d.decision is PolicyDecisionStatus.ALLOWED

    def test_confidence_just_below_minimum_fails(self):
        d = _decide(confidence=0.499999)
        assert d.decision is PolicyDecisionStatus.DENIED

    def test_confidence_maximum(self):
        assert _decide(confidence=1.0).decision is PolicyDecisionStatus.ALLOWED
        assert (
            _decide(requested_action=ResponseActionType.QUARANTINE_FILE.value,
                    risk_level=RiskLevel.MEDIUM.value, confidence=1.0).decision
            is PolicyDecisionStatus.REQUIRES_APPROVAL
        )

    def test_risk_floor_exactly_at_minimum_passes(self):
        d = _decide(
            requested_action=ResponseActionType.QUARANTINE_FILE.value,
            risk_level=RiskLevel.MEDIUM.value,
            confidence=0.9,
        )
        assert d.decision is PolicyDecisionStatus.REQUIRES_APPROVAL

    def test_escalation_threshold_is_inclusive(self):
        # approval_above_risk_level=HIGH: HIGH and CRITICAL escalate.
        for level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            d = _decide(risk_level=level.value)
            assert d.decision is PolicyDecisionStatus.REQUIRES_APPROVAL

    def test_below_escalation_threshold_stays_allowed(self):
        for level in (RiskLevel.LOW, RiskLevel.MEDIUM):
            d = _decide(risk_level=level.value, confidence=0.9)
            assert d.decision is PolicyDecisionStatus.ALLOWED

    def test_risk_score_bounds_via_engine(self):
        # Out-of-range values are rejected at contract coercion (fail closed).
        with pytest.raises(PolicyInputValidationError):
            _decide(risk_score=1.7)
        with pytest.raises(PolicyInputValidationError):
            _decide(risk_score=-0.5)

    def test_empty_evidence_list_is_permitted(self):
        d = _decide(evidence_available=True, evidence_references=[])
        assert d.decision is PolicyDecisionStatus.ALLOWED
        assert d.evidence == []

    def test_max_evidence_references_accepted(self):
        refs = [
            {
                "evidence_type": PolicyEvidenceType.RISK_ASSESSMENT.value,
                "reference_id": str(uuid.uuid4()),
                "role": "supporting_risk",
                "source_provenance": Provenance.RISK_ASSESSED.value,
                "metadata": {},
            }
            for _ in range(POLICY_MAX_EVIDENCE_REFERENCES)
        ]
        d = _decide(evidence_references=refs)
        assert len(d.evidence) == POLICY_MAX_EVIDENCE_REFERENCES

    def test_over_max_evidence_references_rejected(self):
        refs = [
            {
                "evidence_type": PolicyEvidenceType.RISK_ASSESSMENT.value,
                "reference_id": str(uuid.uuid4()),
                "role": "supporting_risk",
                "metadata": {},
            }
            for _ in range(POLICY_MAX_EVIDENCE_REFERENCES + 1)
        ]
        with pytest.raises(PolicyInputValidationError):
            _decide(evidence_references=refs)


# ---------------------------------------------------------------------------
# 3. Multiple applicable rules — first-applicable precedence
# ---------------------------------------------------------------------------


class TestFirstApplicablePrecedence:
    def test_lowest_priority_value_decides(self):
        high_precedence = _rule(
            "PREC-HIGH",
            priority=1,
            minimum_confidence=0.95,
            requires_approval=True,
        )
        low_precedence = _rule(
            "PREC-LOW",
            priority=99,
            minimum_confidence=0.1,
            requires_approval=False,
        )
        # confidence=0.95 satisfies both rules; priority=1 wins.
        d = _custom_engine([low_precedence, high_precedence]).decide(
            _data(confidence=0.95)
        )
        assert d.policy_rule_id == "PREC-HIGH"
        assert d.decision is PolicyDecisionStatus.REQUIRES_APPROVAL

    def test_first_rule_failing_gates_falls_through_to_next(self):
        strict = _rule(
            "STRICT-001",
            priority=1,
            minimum_confidence=0.95,
            requires_approval=True,
        )
        permissive = _rule("PERMISSIVE-001", priority=99, requires_approval=False)
        # confidence=0.6 fails STRICT (0.95); PERMISSIVE applies -> ALLOWED.
        d = _custom_engine([strict, permissive]).decide(_data(confidence=0.6))
        assert d.policy_rule_id == "PERMISSIVE-001"
        assert d.decision is PolicyDecisionStatus.ALLOWED

    def test_no_rule_applicable_uses_highest_precedence_gate(self):
        strict = _rule("STRICT-001", priority=1, require_evidence=True)
        looser = _rule("LOOSER-001", priority=99, minimum_confidence=0.99)
        # No evidence: STRICT fails its first gate (evidence).
        d = _custom_engine([strict, looser]).decide(_data(evidence_available=False))
        assert d.decision is PolicyDecisionStatus.DENIED
        assert d.policy_rule_id == "STRICT-001"
        assert d.metadata["evaluation"]["decision_path"] == "denied:evidence"

    def test_all_default_rules_same_priority_no_interference(self):
        # All six default rules share priority 10 but disjoint actions;
        # an isolation request must still consult the isolation rule.
        d = _decide(
            requested_action=ResponseActionType.ISOLATE_ENDPOINT.value,
            risk_level=RiskLevel.HIGH.value,
            confidence=0.9,
            attribution_status="attributed",
        )
        assert d.policy_rule_id == "POLICY-ISOLATE-ENDPOINT-001"


# ---------------------------------------------------------------------------
# 4. Fail-closed sentinel — no coverage
# ---------------------------------------------------------------------------


class TestNoCoverage:
    def test_empty_registry_denies_with_sentinel(self):
        d = _custom_engine([]).decide(_data(risk_level=RiskLevel.CRITICAL.value))
        assert d.decision is PolicyDecisionStatus.DENIED
        assert d.policy_rule_id == NO_COVERAGE_RULE_ID
        assert d.metadata["evaluation"]["decision_path"] == "denied:no_coverage"
        assert d.metadata["evaluation"]["candidates"] == []
        assert d.metadata["evaluation"]["selected_rule"] is None

    def test_action_outside_policy_denies(self):
        # Registry only covers block_ip; a terminate_session request has
        # no coverage -> deny.
        d = _custom_engine([_rule("ONLY-BLOCK-IP-001")]).decide(
            _data(
                requested_action=ResponseActionType.TERMINATE_SESSION.value,
                risk_level=RiskLevel.HIGH.value,
            )
        )
        assert d.decision is PolicyDecisionStatus.DENIED
        assert d.policy_rule_id == NO_COVERAGE_RULE_ID


# ---------------------------------------------------------------------------
# 5. Gate order (fixed, auditable)
# ---------------------------------------------------------------------------


class TestGateOrder:
    def test_evidence_gate_precedes_risk_floor(self):
        # Fails BOTH evidence (False) and risk floor (quarantine@LOW):
        # the first gate in fixed order must decide.
        d = _decide(
            requested_action=ResponseActionType.QUARANTINE_FILE.value,
            risk_level=RiskLevel.LOW.value,
            confidence=0.9,
            evidence_available=False,
        )
        assert d.metadata["evaluation"]["decision_path"] == "denied:evidence"

    def test_risk_floor_precedes_confidence(self):
        d = _decide(
            requested_action=ResponseActionType.QUARANTINE_FILE.value,
            risk_level=RiskLevel.LOW.value,
            confidence=0.1,
        )
        assert d.metadata["evaluation"]["decision_path"] == "denied:risk_floor"

    def test_confidence_precedes_investigation(self):
        d = _decide(
            requested_action=ResponseActionType.DISABLE_ACCOUNT.value,
            risk_level=RiskLevel.MEDIUM.value,
            confidence=0.1,
            investigation_available=False,
        )
        assert d.metadata["evaluation"]["decision_path"] == "denied:confidence"

    def test_investigation_precedes_attribution(self):
        d = _decide(
            requested_action=ResponseActionType.ISOLATE_ENDPOINT.value,
            risk_level=RiskLevel.HIGH.value,
            confidence=0.9,
            investigation_available=False,
            attribution_status=None,
        )
        # isolate_endpoint does not require investigation; attribution gate decides.
        assert d.metadata["evaluation"]["decision_path"] == "denied:attribution"

    def test_gate_results_trace_is_structured(self):
        d = _decide()
        gates = d.metadata["evaluation"]["gate_results"]
        assert [g["gate"] for g in gates] == [
            "evidence",
            "risk_floor",
            "confidence",
            "investigation",
            "attribution",
        ]
        assert all(g["passed"] is True for g in gates)

    def test_gate_results_mark_failing_gate(self):
        d = _decide(evidence_available=False)
        gates = d.metadata["evaluation"]["gate_results"]
        evidence_gate = next(g for g in gates if g["gate"] == "evidence")
        assert evidence_gate["required"] is True
        assert evidence_gate["passed"] is False
        risk_floor = next(g for g in gates if g["gate"] == "risk_floor")
        assert risk_floor["passed"] is True


# ---------------------------------------------------------------------------
# 6. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_input_same_clock_identical_dump(self):
        payload = _data()
        d1 = _fixed_engine().decide(payload)
        d2 = _fixed_engine().decide(payload)
        assert d1.model_dump(mode="json") == d2.model_dump(mode="json")
        assert d1.policy_decision_id == d2.policy_decision_id

    def test_decision_id_is_uuid5_derived_not_random(self):
        payload = _data()
        d1 = _fixed_engine().decide(payload)
        d2 = _fixed_engine().decide(payload)
        assert d1.policy_decision_id.version == 5
        assert d1.policy_decision_id == d2.policy_decision_id

    def test_different_input_different_id(self):
        d1 = _decide()
        d2 = _decide(confidence=0.7)
        assert d1.policy_decision_id != d2.policy_decision_id

    def test_different_clock_different_id(self):
        payload = _data()
        d1 = PolicyDecisionEngine(clock=lambda: FIXED).decide(payload)
        d2 = PolicyDecisionEngine(
            clock=lambda: datetime(2025, 7, 18, 12, 0, 0, tzinfo=TZ)
        ).decide(payload)
        assert d1.policy_decision_id != d2.policy_decision_id

    def test_timestamp_uses_clock(self):
        assert _decide().timestamp == FIXED

    def test_evidence_source_provenance_preserved_verbatim(self):
        ref_id = uuid.uuid4()
        d = _decide(
            evidence_references=[
                {
                    "evidence_type": PolicyEvidenceType.INCIDENT_MEMORY.value,
                    "reference_id": str(ref_id),
                    "role": "historical_memory",
                    "source_provenance": Provenance.RECALLED.value,
                    "metadata": {},
                }
            ]
        )
        assert d.evidence[0].source_provenance is Provenance.RECALLED
        assert d.evidence[0].reference_id == ref_id
        assert d.provenance is Provenance.POLICY_DECIDED


# ---------------------------------------------------------------------------
# 7. Immutability — engine never mutates its inputs
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_input_not_mutated(self):
        payload = _data(metadata={"k": "v"})
        before = {k: repr(v) for k, v in payload.items()}
        _fixed_engine().decide(payload)
        after = {k: repr(v) for k, v in payload.items()}
        assert before == after

    def test_decision_evidence_not_aliased_to_input(self):
        refs = [
            {
                "evidence_type": PolicyEvidenceType.DETECTION.value,
                "reference_id": str(uuid.uuid4()),
                "role": "primary_detection",
                "source_provenance": Provenance.DETECTED.value,
                "metadata": {"a": 1},
            }
        ]
        d = _decide(evidence_references=refs)
        assert isinstance(d.evidence[0], PolicyEvidence)
        # Mutating the decision must not affect the caller's payload.
        d.evidence[0].metadata["a"] = 999
        assert refs[0]["metadata"] == {"a": 1}

    def test_decision_metadata_is_cloned(self):
        payload = _data(metadata={"source": "unit-test"})
        d = _fixed_engine().decide(payload)
        d.metadata["source"] = "mutated"
        assert payload["metadata"]["source"] == "unit-test"

    def test_registry_snapshot_not_affected_by_rule_mutation(self):
        rule = _rule("SNAPSHOT-001")
        registry = PolicyRuleRegistry([rule])
        dumped = rule.model_dump(mode="json")
        # Even if a caller mutates its original rule object, the registry
        # stores its own validated copy semantics via model dumps.
        rule.description = "changed"
        stored = registry.get("SNAPSHOT-001")
        assert stored is not None
        assert stored.model_dump(mode="json") != rule.model_dump(mode="json")
        assert dumped["description"] == "rule SNAPSHOT-001"


# ---------------------------------------------------------------------------
# 8. Explainability — deterministic templates
# ---------------------------------------------------------------------------


class TestExplainability:
    def test_allowed_reason_names_rule_and_thresholds(self):
        d = _decide()
        assert d.reason == (
            "Requested action block_ip is allowed under policy "
            "POLICY-BLOCK-IP-001: risk level low meets or exceeds low "
            "and confidence 0.90 meets or exceeds 0.50."
        )
        assert d.policy_rule_id == "POLICY-BLOCK-IP-001"
        assert d.reason == d.reason.strip()

    def test_elevated_approval_reason(self):
        d = _decide(risk_level=RiskLevel.HIGH.value)
        assert d.reason == (
            "Requested action block_ip requires human authorization under "
            "policy POLICY-BLOCK-IP-001 because risk level high is at or "
            "above high."
        )

    def test_approval_reason_by_rule(self):
        d = _decide(
            requested_action=ResponseActionType.QUARANTINE_FILE.value,
            risk_level=RiskLevel.MEDIUM.value,
            confidence=0.9,
        )
        assert d.reason == (
            "Requested action quarantine_file requires human "
            "authorization under policy POLICY-QUARANTINE-FILE-001."
        )

    def test_denied_evidence_reason(self):
        d = _decide(evidence_available=False)
        assert d.reason == (
            "Requested action block_ip is denied under policy "
            "POLICY-BLOCK-IP-001: evidence availability is required and "
            "was not provided."
        )

    def test_denied_confidence_reason(self):
        d = _decide(confidence=0.1)
        assert d.reason == (
            "Requested action block_ip is denied under policy "
            "POLICY-BLOCK-IP-001: confidence 0.10 is below the required "
            "minimum 0.50."
        )

    def test_no_coverage_reason(self):
        d = _custom_engine([]).decide(_data())
        assert d.reason == (
            "Requested action block_ip is denied: no enabled policy rule "
            "covers this action."
        )

    def test_evaluation_metadata_trace(self):
        d = _decide()
        evaluation = d.metadata["evaluation"]
        assert d.metadata["policy"] == POLICY_NAME
        assert evaluation["candidates"] == ["POLICY-BLOCK-IP-001"]
        assert evaluation["selected_rule"] == "POLICY-BLOCK-IP-001"
        assert evaluation["decision_path"] == "allowed"

    def test_input_metadata_carried_into_decision(self):
        d = _decide(metadata={"analyst": "unit-test"})
        assert d.metadata["input"] == {"analyst": "unit-test"}

    def test_no_freeform_ai_text_in_reason(self):
        for d in (
            _decide(),
            _decide(evidence_available=False),
            _decide(requested_action=ResponseActionType.QUARANTINE_FILE.value,
                    risk_level=RiskLevel.MEDIUM.value, confidence=0.9),
        ):
            assert len(d.reason) <= 500
            assert d.reason


# ---------------------------------------------------------------------------
# 9. Input coercion & validation at the engine boundary
# ---------------------------------------------------------------------------


class TestInputCoercion:
    def test_accepts_prebuilt_policy_input(self):
        inp = PolicyInput.model_validate(_data())
        d = _fixed_engine().decide(inp)
        assert d.decision is PolicyDecisionStatus.ALLOWED

    def test_accepts_mapping(self):
        d = _fixed_engine().decide(_data())
        assert d.decision is PolicyDecisionStatus.ALLOWED

    def test_invalid_mapping_raises_sanitized_error(self):
        with pytest.raises(PolicyInputValidationError) as excinfo:
            _fixed_engine().decide({"correlation_id": "not-a-uuid"})
        assert "failed validation" in str(excinfo.value)
        assert "not-a-uuid" not in str(excinfo.value)

    def test_unsupported_action_raises_sanitized_error(self):
        with pytest.raises(PolicyInputValidationError):
            _decide(requested_action="deploy_to_production")

    def test_non_mapping_non_input_raises(self):
        with pytest.raises(PolicyInputValidationError):
            _fixed_engine().decide("block_ip")  # type: ignore[arg-type]

    def test_unknown_fields_in_mapping_rejected(self):
        with pytest.raises(PolicyInputValidationError):
            _decide(extra_channel="smuggled")

    def test_naive_timestamp_in_mapping_rejected(self):
        payload = _data(timestamp=datetime(2025, 7, 17, 8, 0, 0).isoformat())
        with pytest.raises(PolicyInputValidationError):
            _fixed_engine().decide(payload)