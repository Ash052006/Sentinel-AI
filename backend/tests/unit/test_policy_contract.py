"""Policy Decision domain contract tests (Step 24).

Covers the contract file ``app/schemas/policy_decision.py``: enum
vocabulary, additive provenance (``POLICY_DECIDED``), structured bounds,
requested-action closure, secret-safety, timezone awareness, cloning of
caller-owned payloads, rule configuration conflict rejection, and the
pinned policy decision provenance.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.policy_decision import (
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
    risk_rank,
)
from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance
from app.schemas.threat_attribution import AttributionStatus

TZ = timezone.utc
NOW = datetime(2025, 7, 17, 8, 0, 0, tzinfo=TZ)


def _evidence(reference_id: uuid.UUID, **overrides) -> PolicyEvidence:
    data = {
        "evidence_type": PolicyEvidenceType.CORRELATION,
        "reference_id": reference_id,
        "role": "primary_correlation",
        "source_provenance": Provenance.CORRELATED,
        "metadata": {"weight": 1},
    }
    data.update(overrides)
    return PolicyEvidence.model_validate(data)


def _input(**overrides) -> PolicyInput:
    data = {
        "correlation_id": uuid.uuid4(),
        "requested_action": ResponseActionType.BLOCK_IP,
        "risk_level": RiskLevel.LOW,
        "risk_score": 0.3,
        "confidence": 0.9,
        "attribution_status": None,
        "investigation_available": False,
        "evidence_available": True,
        "evidence_references": [],
        "metadata": {"source": "unit-test"},
        "timestamp": NOW,
    }
    data.update(overrides)
    return PolicyInput.model_validate(data)


def _rule(**overrides) -> PolicyRule:
    data = {
        "policy_rule_id": "TEST-RULE-001",
        "action_type": ResponseActionType.BLOCK_IP,
        "minimum_risk_level": RiskLevel.LOW,
        "minimum_confidence": 0.5,
        "require_evidence": True,
        "require_investigation": False,
        "require_attribution": False,
        "requires_approval": False,
        "approval_above_risk_level": RiskLevel.HIGH,
        "enabled": True,
        "priority": 10,
        "description": "test rule",
        "metadata": {},
    }
    data.update(overrides)
    return PolicyRule.model_validate(data)


# ---------------------------------------------------------------------------
# 1. Enumerations
# ---------------------------------------------------------------------------


class TestEnumerations:
    def test_decision_status_values(self):
        assert PolicyDecisionStatus.ALLOWED.value == "allowed"
        assert PolicyDecisionStatus.DENIED.value == "denied"
        assert PolicyDecisionStatus.REQUIRES_APPROVAL.value == "requires_approval"
        assert len(PolicyDecisionStatus) == 3

    def test_action_vocabulary_closed(self):
        assert len(ResponseActionType) == 6
        assert {a.value for a in ResponseActionType} == {
            "block_ip",
            "block_domain",
            "quarantine_file",
            "disable_account",
            "terminate_session",
            "isolate_endpoint",
        }
        with pytest.raises(ValueError):
            ResponseActionType("run_python")

    def test_evidence_type_vocabulary(self):
        assert len(PolicyEvidenceType) == 6
        assert {e.value for e in PolicyEvidenceType} == {
            "correlation",
            "detection",
            "risk_assessment",
            "investigation",
            "attribution",
            "incident_memory",
        }


# ---------------------------------------------------------------------------
# 2. risk_rank total order
# ---------------------------------------------------------------------------


class TestRiskRank:
    def test_ordinal_mapping(self):
        assert risk_rank(RiskLevel.LOW) == 0
        assert risk_rank(RiskLevel.MEDIUM) == 1
        assert risk_rank(RiskLevel.HIGH) == 2
        assert risk_rank(RiskLevel.CRITICAL) == 3

    def test_total_order(self):
        order = [
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ]
        ranks = [risk_rank(level) for level in order]
        assert ranks == sorted(ranks)
        assert len(set(ranks)) == 4


# ---------------------------------------------------------------------------
# 3. Provenance: additive POLICY_DECIDED, prior values intact
# ---------------------------------------------------------------------------


class TestProvenance:
    def test_policy_decided_added_additively(self):
        assert Provenance.POLICY_DECIDED.value == "policy_decided"
        assert len(Provenance) == 13
        assert list(Provenance)[-1] is Provenance.APPROVAL_REVIEWED

    def test_prior_values_intact(self):
        for expected, actual in (
            ("observed", Provenance.OBSERVED),
            ("enriched", Provenance.ENRICHED),
            ("reconstructed", Provenance.RECONSTRUCTED),
            ("detected", Provenance.DETECTED),
            ("correlated", Provenance.CORRELATED),
            ("risk_assessed", Provenance.RISK_ASSESSED),
            ("ai_generated", Provenance.AI_GENERATED),
            ("attribution_assessed", Provenance.ATTRIBUTION_ASSESSED),
            ("recalled", Provenance.RECALLED),
            ("learned", Provenance.LEARNED),
        ):
            assert actual.value == expected


# ---------------------------------------------------------------------------
# 4. Policy evidence
# ---------------------------------------------------------------------------


class TestPolicyEvidence:
    def test_valid(self):
        ev = _evidence(uuid.uuid4())
        assert ev.evidence_type is PolicyEvidenceType.CORRELATION
        assert ev.source_provenance is Provenance.CORRELATED

    def test_blank_role_rejected(self):
        with pytest.raises(ValidationError):
            _evidence(uuid.uuid4(), role="   ")

    def test_role_length_bounded(self):
        too_long = "x" * (POLICY_MAX_ROLE_LENGTH + 1)
        with pytest.raises(ValidationError):
            _evidence(uuid.uuid4(), role=too_long)

    def test_secret_rejected_in_metadata(self):
        with pytest.raises(ValidationError):
            _evidence(uuid.uuid4(), metadata={"credential": "bearer xyz"})

    def test_non_json_metadata_rejected(self):
        with pytest.raises(ValidationError):
            _evidence(uuid.uuid4(), metadata={"bad": object()})

    def test_metadata_cloned(self):
        m = {"weight": 1}
        ev = _evidence(uuid.uuid4(), metadata=m)
        m["weight"] = 999
        assert ev.metadata == {"weight": 1}


# ---------------------------------------------------------------------------
# 5. Policy input
# ---------------------------------------------------------------------------


class TestPolicyInput:
    def test_unknown_fields_rejected(self):
        with pytest.raises(ValidationError):
            _input(extra_channel="ignored?")

    def test_score_bounds(self):
        with pytest.raises(ValidationError):
            _input(risk_score=1.5)
        with pytest.raises(ValidationError):
            _input(risk_score=-0.1)
        with pytest.raises(ValidationError):
            _input(confidence=1.1)
        with pytest.raises(ValidationError):
            _input(confidence=-0.01)
        _input(risk_score=0.0, confidence=1.0)

    def test_naive_timestamp_rejected(self):
        with pytest.raises(ValidationError):
            _input(timestamp=datetime(2025, 7, 17, 8, 0, 0))

    def test_evidence_reference_bounds(self):
        refs = [_evidence(uuid.uuid4()) for _ in range(POLICY_MAX_EVIDENCE_REFERENCES)]
        _input(evidence_references=refs)
        with pytest.raises(ValidationError):
            _input(
                evidence_references=[
                    *_refs(), *_refs(), _evidence(uuid.uuid4())
                ]
            )

    def test_evidence_secrets_rejected(self):
        with pytest.raises(ValidationError):
            _input(
                evidence_references=[
                    _evidence(uuid.uuid4(), metadata={"api_key": "sk-123"})
                ]
            )

    def test_metadata_secrets_rejected(self):
        with pytest.raises(ValidationError):
            _input(metadata={"auth": "secret-token-1"})

    def test_metadata_cloned(self):
        m = {"source": "unit-test"}
        inp = _input(metadata=m)
        m["tampered"] = True
        assert "tampered" not in inp.metadata
        assert inp.metadata == {"source": "unit-test"}

    def test_defaults(self):
        inp = _input(confidence=None)
        assert inp.confidence is None
        assert inp.investigation_available is False
        assert inp.evidence_available is True
        assert inp.attribution_status is None
        assert inp.evidence_references == []
        assert inp.timestamp.tzinfo is not None


def _refs() -> list[PolicyEvidence]:
    return [_evidence(uuid.uuid4()) for _ in range(POLICY_MAX_EVIDENCE_REFERENCES)]


# ---------------------------------------------------------------------------
# 6. Policy rule
# ---------------------------------------------------------------------------


class TestPolicyRule:
    def test_valid(self):
        rule = _rule()
        assert rule.policy_rule_id == "TEST-RULE-001"
        assert rule.enabled is True

    def test_rule_id_pattern(self):
        for bad in (
            "lower-rule-001",
            "RULE 001",
            "RULE_UNDERSCORE",
            "1RULE-001",
            "RULE-001*",
        ):
            with pytest.raises(ValidationError):
                _rule(policy_rule_id=bad)
        _rule(policy_rule_id="POLICY-BLOCK-IP-001")
        _rule(policy_rule_id="ABC")

    def test_rule_id_length_bounded(self):
        with pytest.raises(ValidationError):
            _rule(policy_rule_id="R" * (POLICY_MAX_RULE_ID_LENGTH + 1))

    def test_confidence_bounds(self):
        with pytest.raises(ValidationError):
            _rule(minimum_confidence=1.5)
        with pytest.raises(ValidationError):
            _rule(minimum_confidence=-0.1)

    def test_blank_description_rejected(self):
        with pytest.raises(ValidationError):
            _rule(description="   ")

    def test_escalation_below_floor_rejected(self):
        with pytest.raises(ValidationError):
            _rule(
                minimum_risk_level=RiskLevel.HIGH,
                approval_above_risk_level=RiskLevel.MEDIUM,
            )

    def test_escalation_at_or_above_floor_accepted(self):
        _rule(
            minimum_risk_level=RiskLevel.HIGH,
            approval_above_risk_level=RiskLevel.HIGH,
        )
        _rule(
            minimum_risk_level=RiskLevel.LOW,
            approval_above_risk_level=RiskLevel.HIGH,
        )

    def test_cross_cutting_action_none_accepted(self):
        rule = _rule(action_type=None)
        assert rule.action_type is None

    def test_negative_priority_rejected(self):
        with pytest.raises(ValidationError):
            _rule(priority=-1)


# ---------------------------------------------------------------------------
# 7. Policy decision
# ---------------------------------------------------------------------------


class TestPolicyDecision:
    def _decision(self, **overrides) -> PolicyDecision:
        data = {
            "policy_decision_id": uuid.uuid5(
                POLICY_DECISION_NAMESPACE, "deterministic-test"
            ),
            "correlation_id": uuid.uuid4(),
            "requested_action": ResponseActionType.BLOCK_IP,
            "decision": PolicyDecisionStatus.ALLOWED,
            "reason": "Requested action block_ip is allowed under policy TEST-RULE-001.",
            "policy_rule_id": "TEST-RULE-001",
            "risk_level": RiskLevel.LOW,
            "risk_score": 0.3,
            "confidence": 0.9,
            "requires_approval": False,
            "evidence": [],
            "metadata": {},
            "timestamp": NOW,
        }
        data.update(overrides)
        return PolicyDecision.model_validate(data)

    def test_default_provenance_is_policy_decided(self):
        decision = self._decision()
        assert decision.provenance is Provenance.POLICY_DECIDED

    def test_non_policy_provenance_rejected(self):
        with pytest.raises(ValidationError):
            self._decision(provenance=Provenance.CORRELATED)
        with pytest.raises(ValidationError):
            self._decision(provenance=Provenance.RECALLED)

    def test_requires_approval_tracks_decision(self):
        approved = self._decision(
            decision=PolicyDecisionStatus.REQUIRES_APPROVAL,
            requires_approval=True,
        )
        assert approved.requires_approval is True
        denied = self._decision(
            decision=PolicyDecisionStatus.DENIED,
            requires_approval=False,
        )
        assert denied.requires_approval is False

    def test_naive_timestamp_rejected(self):
        with pytest.raises(ValidationError):
            self._decision(timestamp=datetime(2025, 7, 17, 8, 0, 0))

    def test_reason_non_blank_and_bounded(self):
        with pytest.raises(ValidationError):
            self._decision(reason="   ")
        with pytest.raises(ValidationError):
            self._decision(reason="x" * 501)

    def test_evidence_secrets_rejected(self):
        with pytest.raises(ValidationError):
            self._decision(evidence=[_evidence(uuid.uuid4(), metadata={"secret": "x"})])

    def test_metadata_secrets_rejected(self):
        with pytest.raises(ValidationError):
            self._decision(metadata={"token": "authorization-code"})

    def test_metadata_cloned(self):
        m = {"trace": "unit-test"}
        decision = self._decision(metadata=m)
        m["tampered"] = True
        assert "tampered" not in decision.metadata


# ---------------------------------------------------------------------------
# 8. Contract constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_namespace_is_fixed(self):
        assert str(POLICY_DECISION_NAMESPACE) == "6f1e0f4a-2c41-4a4d-9f0b-1d2e3a4b5c6d"

    def test_bounds_positive(self):
        assert POLICY_MAX_EVIDENCE_REFERENCES == 16
        assert POLICY_MAX_ROLE_LENGTH == 64
        assert POLICY_MAX_RULE_ID_LENGTH == 64