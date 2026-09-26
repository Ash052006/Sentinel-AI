"""Policy engine integration tests — existing pipeline outputs (Step 24).

Builds genuine RiskAssessment / InvestigationResult / AttributionAssessment
instances from the existing Step 11A / 12A / 12B-ish contracts, maps their
fields into :class:`PolicyInput` deterministically (through an adapter
convention documented in the Step 24 doctrine — no fake-AI, no mocking of
external subsystems), and asserts the resulting decisions.  Evidence
references are real identifiers, and their source provenance is preserved
verbatim (a risk assessment stays ``risk_assessed``; a historical memory
stays ``recalled`` and is never relabelled).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.schemas.investigation import InvestigationResult
from app.schemas.policy_decision import (
    POLICY_DECISION_NAMESPACE,
    PolicyDecision,
    PolicyDecisionStatus,
    PolicyEvidence,
    PolicyEvidenceType,
    PolicyInput,
    ResponseActionType,
)
from app.schemas.risk import RiskAssessment, RiskEvidence, RiskFactor, RiskLevel
from app.schemas.security_event import Provenance
from app.schemas.threat_attribution import AttributionAssessment, AttributionStatus
from app.services.policy import PolicyDecisionEngine, PolicyRuleRegistry
from app.services.policy.rules import DEFAULT_POLICY_RULES

TZ = timezone.utc
NOW = datetime(2025, 7, 17, 8, 0, 0, tzinfo=TZ)
FIXED = datetime(2025, 7, 17, 12, 0, 0, tzinfo=TZ)


def _risk_assessment(correlation_id: uuid.UUID, *, level: RiskLevel, score: float) -> RiskAssessment:
    detection_id = uuid.uuid5(POLICY_DECISION_NAMESPACE, "det-fixture")
    return RiskAssessment(
        risk_assessment_id=uuid.uuid5(POLICY_DECISION_NAMESPACE, "risk-fixture"),
        correlation_id=correlation_id,
        level=level,
        score=score,
        confidence=0.9,
        factors=[
            RiskFactor(
                factor_type="severity_impact",
                contribution=score,
                evidence=[
                    RiskEvidence(
                        observation_type="detection_severity",
                        detection_id=detection_id,
                        metadata={},
                    )
                ],
                metadata={},
            )
        ],
        evidence=[
            RiskEvidence(
                observation_type="detection_severity",
                detection_id=detection_id,
                metadata={},
            )
        ],
        provenance=Provenance.RISK_ASSESSED,
        timestamp=NOW,
        metadata={"source": "integration-fixture"},
    )


def _build_risk_assessment_to_input(
    ra: RiskAssessment, *, action: ResponseActionType
) -> PolicyInput:
    """Adapter convention: map a Step 11A output into policy input."""
    return PolicyInput(
        correlation_id=ra.correlation_id,
        requested_action=action,
        risk_level=ra.level,
        risk_score=ra.score,
        confidence=ra.confidence,
        evidence_available=True,
        evidence_references=[
            PolicyEvidence(
                evidence_type=PolicyEvidenceType.RISK_ASSESSMENT,
                reference_id=ra.risk_assessment_id,
                role="primary_risk_assessment",
                source_provenance=ra.provenance,
                metadata={},
            ),
            PolicyEvidence(
                evidence_type=PolicyEvidenceType.DETECTION,
                reference_id=ra.evidence[0].detection_id,
                role="supporting_detection",
                source_provenance=Provenance.DETECTED,
                metadata={},
            ),
        ],
        metadata={"adapter": "risk_assessment_to_policy_input@v1"},
        timestamp=NOW,
    )


def _build_investigation_to_input(
    investigation: InvestigationResult,
    /,
    *,
    action: ResponseActionType,
    attribution_status: AttributionStatus | None = None,
) -> PolicyInput:
    return PolicyInput(
        correlation_id=investigation.correlation_id,
        requested_action=action,
        risk_level=RiskLevel.MEDIUM,
        risk_score=0.7,
        confidence=investigation.confidence,
        attribution_status=attribution_status,
        investigation_available=True,
        evidence_available=True,
        evidence_references=[
            PolicyEvidence(
                evidence_type=PolicyEvidenceType.INVESTIGATION,
                reference_id=investigation.investigation_id,
                role="completed_investigation",
                source_provenance=investigation.provenance,
                metadata={},
            )
        ],
        metadata={"adapter": "investigation_to_policy_input@v1"},
        timestamp=NOW,
    )


def _engine() -> PolicyDecisionEngine:
    return PolicyDecisionEngine(registry=PolicyRuleRegistry(DEFAULT_POLICY_RULES), clock=lambda: FIXED)


class TestRiskAssessmentFlow:
    def test_low_risk_block_ip_allows(self):
        cid = uuid.uuid4()
        ra = _risk_assessment(cid, level=RiskLevel.LOW, score=0.3)
        decision = _engine().decide(
            _build_risk_assessment_to_input(ra, action=ResponseActionType.BLOCK_IP)
        )
        assert decision.decision is PolicyDecisionStatus.ALLOWED
        assert decision.policy_rule_id == "POLICY-BLOCK-IP-001"
        assert decision.correlation_id == cid
        assert decision.risk_level is RiskLevel.LOW
        assert decision.risk_score == 0.3
        assert decision.provenance is Provenance.POLICY_DECIDED

    def test_critical_risk_block_domain_escalates_to_approval(self):
        cid = uuid.uuid4()
        ra = _risk_assessment(cid, level=RiskLevel.CRITICAL, score=0.95)
        decision = _engine().decide(
            _build_risk_assessment_to_input(ra, action=ResponseActionType.BLOCK_DOMAIN)
        )
        assert decision.decision is PolicyDecisionStatus.REQUIRES_APPROVAL
        assert decision.policy_rule_id == "POLICY-BLOCK-DOMAIN-001"
        assert (
            decision.metadata["evaluation"]["decision_path"]
            == "requires_approval_elevated_risk"
        )

    def test_evidence_provenance_preserved_and_not_relabelled(self):
        cid = uuid.uuid4()
        ra = _risk_assessment(cid, level=RiskLevel.LOW, score=0.2)
        decision = _engine().decide(
            _build_risk_assessment_to_input(ra, action=ResponseActionType.BLOCK_IP)
        )
        types = [ev.evidence_type for ev in decision.evidence]
        assert PolicyEvidenceType.RISK_ASSESSMENT in types
        assert PolicyEvidenceType.DETECTION in types
        # Risk-assessment reference keeps its original provenance.
        ra_evidence = next(
            ev for ev in decision.evidence if ev.evidence_type is PolicyEvidenceType.RISK_ASSESSMENT
        )
        assert ra_evidence.source_provenance is Provenance.RISK_ASSESSED
        detection_evidence = next(
            ev for ev in decision.evidence if ev.evidence_type is PolicyEvidenceType.DETECTION
        )
        assert detection_evidence.source_provenance is Provenance.DETECTED
        # No evidence is ever relabelled as a policy decision.
        assert all(
            ev.source_provenance is not Provenance.POLICY_DECIDED
            for ev in decision.evidence
        )

    def test_decision_is_reference_only(self):
        cid = uuid.uuid4()
        ra = _risk_assessment(cid, level=RiskLevel.LOW, score=0.2)
        decision = _engine().decide(
            _build_risk_assessment_to_input(ra, action=ResponseActionType.BLOCK_IP)
        )
        assert isinstance(decision, PolicyDecision)
        assert decision.requested_action is ResponseActionType.BLOCK_IP


# ---------------------------------------------------------------------------
# Investigation context flow
# ---------------------------------------------------------------------------


def _investigation(cid: uuid.UUID) -> InvestigationResult:
    return InvestigationResult(
        investigation_id=uuid.uuid5(POLICY_DECISION_NAMESPACE, "investigation-fixture"),
        correlation_id=cid,
        risk_assessment_id=uuid.uuid5(POLICY_DECISION_NAMESPACE, "risk-fixture"),
        confidence=0.85,
        observations=[],
        findings=[],
        evidence=[],
        provenance=Provenance.AI_GENERATED,
        timestamp=NOW,
        metadata={},
    )


class TestInvestigationFlow:
    def test_disable_account_with_investigation_requires_approval(self):
        cid = uuid.uuid4()
        investigation = _investigation(cid)
        decision = _engine().decide(
            _build_investigation_to_input(
                investigation, action=ResponseActionType.DISABLE_ACCOUNT
            )
        )
        assert decision.decision is PolicyDecisionStatus.REQUIRES_APPROVAL
        assert decision.policy_rule_id == "POLICY-DISABLE-ACCOUNT-001"

    def test_investigation_reference_provenance_carried(self):
        cid = uuid.uuid4()
        investigation = _investigation(cid)
        decision = _engine().decide(
            _build_investigation_to_input(
                investigation, action=ResponseActionType.DISABLE_ACCOUNT
            )
        )
        inv_evidence = next(
            ev for ev in decision.evidence if ev.evidence_type is PolicyEvidenceType.INVESTIGATION
        )
        assert inv_evidence.source_provenance is Provenance.AI_GENERATED
        assert inv_evidence.reference_id == investigation.investigation_id


class TestAttributionFlow:
    def _attribution(self, cid: uuid.UUID, status: AttributionStatus) -> AttributionAssessment:
        return AttributionAssessment(
            attribution_assessment_id=uuid.uuid5(POLICY_DECISION_NAMESPACE, "attribution-fixture"),
            correlation_id=cid,
            status=status,
            hypotheses=[],
            evidence=[],
            provenance=Provenance.ATTRIBUTION_ASSESSED,
            timestamp=NOW,
            metadata={},
        )

    def test_supported_attribution_enables_high_impact_rule(self):
        cid = uuid.uuid4()
        attribution = self._attribution(cid, AttributionStatus.ATTRIBUTED)
        # Isolate endpoint requires supported attribution + approval.
        inp = PolicyInput(
            correlation_id=cid,
            requested_action=ResponseActionType.ISOLATE_ENDPOINT,
            risk_level=RiskLevel.HIGH,
            risk_score=0.9,
            confidence=0.9,
            attribution_status=attribution.status,
            evidence_available=True,
            evidence_references=[
                PolicyEvidence(
                    evidence_type=PolicyEvidenceType.ATTRIBUTION,
                    reference_id=attribution.attribution_assessment_id,
                    role="primary_attribution",
                    source_provenance=attribution.provenance,
                    metadata={},
                )
            ],
            metadata={"adapter": "attribution_to_policy_input@v1"},
            timestamp=NOW,
        )
        decision = _engine().decide(inp)
        assert decision.decision is PolicyDecisionStatus.REQUIRES_APPROVAL
        assert decision.policy_rule_id == "POLICY-ISOLATE-ENDPOINT-001"
        attr_evidence = next(
            ev for ev in decision.evidence if ev.evidence_type is PolicyEvidenceType.ATTRIBUTION
        )
        assert attr_evidence.source_provenance is Provenance.ATTRIBUTION_ASSESSED


class TestEndToEndChains:
    def test_full_chain_deterministic(self):
        cid = uuid.uuid4()
        ra = _risk_assessment(cid, level=RiskLevel.LOW, score=0.3)
        inp = _build_risk_assessment_to_input(ra, action=ResponseActionType.BLOCK_IP)
        d1 = _engine().decide(inp)
        d2 = _engine().decide(inp)
        assert d1.model_dump(mode="json") == d2.model_dump(mode="json")
        assert d1.policy_decision_id == d2.policy_decision_id

    def test_chain_within_pipeline_order_uses_risk_first(self):
        # Even when investigation and attribution context both exist, the
        # fixed gate order (evidence -> risk -> confidence -> investigation
        # -> attribution) means risk decides an isolate_endpoint at LOW.
        cid = uuid.uuid4()
        attribution = AttributionAssessment(
            attribution_assessment_id=uuid.uuid5(POLICY_DECISION_NAMESPACE, "attr2"),
            correlation_id=cid,
            status=AttributionStatus.PARTIALLY_SUPPORTED,
            hypotheses=[],
            evidence=[],
            provenance=Provenance.ATTRIBUTION_ASSESSED,
            timestamp=NOW,
            metadata={},
        )
        inp = PolicyInput(
            correlation_id=cid,
            requested_action=ResponseActionType.ISOLATE_ENDPOINT,
            risk_level=RiskLevel.LOW,
            risk_score=0.2,
            confidence=0.9,
            attribution_status=attribution.status,
            investigation_available=True,
            evidence_available=True,
            metadata={},
            timestamp=NOW,
        )
        decision = _engine().decide(inp)
        assert decision.decision is PolicyDecisionStatus.DENIED
        assert decision.metadata["evaluation"]["decision_path"] == "denied:risk_floor"