"""End-to-end policy -> response integration tests (Step 25).

Builds a genuine Step 11A :class:`RiskAssessment`, maps it into a Step 24
:class:`PolicyInput` via the documented adapter convention, lets the
Step 24 :class:`PolicyDecisionEngine` reach a deterministic decision, and
hands the authorized decision to :class:`ResponseMitigationService`:

    RiskAssessment -> PolicyInput -> PolicyDecisionEngine -> PolicyDecision
        -> ResponseRequest -> ResponseMitigationService
            -> ResponseProvider (mock) -> ResponseResult

Guarantees exercised here:

* ALLOWED decision  -> the response executes through the mock provider;
* REQUIRES_APPROVAL -> the response is REJECTED and no provider is
  called, proving the layer enforces the policy gate independently of
  whatever the caller believed;
* the integration is deterministic (fixed engine clock + fixed service
  clock) and fully off-host.

No external systems, no API calls, no database, no shell, no filesystem.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.schemas.policy_decision import (
    POLICY_DECISION_NAMESPACE,
    PolicyDecisionStatus,
    PolicyEvidence,
    PolicyEvidenceType,
    PolicyInput,
    ResponseActionType,
)
from app.schemas.response import ResponseExecutionStatus, ResponseRequest
from app.schemas.risk import RiskAssessment, RiskEvidence, RiskFactor, RiskLevel
from app.schemas.security_event import Provenance
from app.services.policy import PolicyDecisionEngine, PolicyRuleRegistry
from app.services.policy.rules import DEFAULT_POLICY_RULES
from app.services.response import ResponseMitigationService
from app.services.response.providers import ResponseProvider
from app.services.response.registry import ResponseProviderRegistry
from app.schemas.response import ResponseResult

TZ = timezone.utc
NOW = datetime(2025, 8, 1, 9, 0, 0, tzinfo=TZ)
FIXED = datetime(2025, 8, 1, 12, 0, 0, tzinfo=TZ)


def _risk_assessment(correlation_id: uuid.UUID, *, level: RiskLevel, score: float) -> RiskAssessment:
    detection_id = uuid.uuid5(POLICY_DECISION_NAMESPACE, "response-int-det")
    return RiskAssessment(
        risk_assessment_id=uuid.uuid5(POLICY_DECISION_NAMESPACE, "response-int-risk"),
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
        metadata={"source": "response-integration"},
    )


def _to_policy_input(
    ra: RiskAssessment, *, action: ResponseActionType
) -> PolicyInput:
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
        metadata={"adapter": "response_integration@v1"},
        timestamp=NOW,
    )


def _engine() -> PolicyDecisionEngine:
    return PolicyDecisionEngine(
        registry=PolicyRuleRegistry(DEFAULT_POLICY_RULES), clock=lambda: FIXED
    )


class WatchProvider(ResponseProvider):
    """Deterministic mock provider that records invocations."""

    name = "watch"
    supported_actions = frozenset(ResponseActionType)

    def __init__(self) -> None:
        self.call_count = 0

    def execute(self, request: ResponseRequest, *, clock=None) -> ResponseResult:
        self.call_count += 1
        now = (clock() if clock is not None else datetime.now(timezone.utc))
        return ResponseResult(
            response_id=request.response_id,
            policy_decision_id=request.policy_decision_id,
            correlation_id=request.correlation_id,
            action_type=request.action_type,
            execution_status=ResponseExecutionStatus.EXECUTED,
            target=request.target,
            provider=self.name,
            started_at=now,
            completed_at=now,
            message="Simulated block_ip execution",
            error_code=None,
            metadata={},
            timestamp=now,
        )


def _service(provider: WatchProvider) -> ResponseMitigationService:
    return ResponseMitigationService(
        registry=ResponseProviderRegistry((provider,)),
        clock=lambda: FIXED,
    )


class TestEndToEnd:
    def test_risk_to_policy_to_response_allowed(self) -> None:
        provider = WatchProvider()
        service = _service(provider)
        correlation_id = uuid.uuid4()
        risk = _risk_assessment(correlation_id, level=RiskLevel.LOW, score=0.3)
        decision = _engine().decide(
            _to_policy_input(risk, action=ResponseActionType.BLOCK_IP)
        )
        assert decision.decision is PolicyDecisionStatus.ALLOWED
        assert decision.policy_rule_id == "POLICY-BLOCK-IP-001"

        request = ResponseRequest(
            response_id=service.derive_response_id(
                policy_decision_id=decision.policy_decision_id,
                action=ResponseActionType.BLOCK_IP,
                target="10.0.0.5",
            ),
            policy_decision_id=decision.policy_decision_id,
            correlation_id=correlation_id,
            action_type=ResponseActionType.BLOCK_IP,
            target="10.0.0.5",
        )
        result = service.execute(request, decision)

        assert result.execution_status is ResponseExecutionStatus.EXECUTED
        assert result.error_code is None
        assert result.provider == "watch"
        assert result.target == "10.0.0.5"
        assert result.response_id == request.response_id
        assert result.correlation_id == correlation_id
        assert result.provenance is Provenance.RESPONSE_EXECUTED
        assert provider.call_count == 1

        # Idempotent retry: same record, provider not re-invoked.
        again = service.execute(request, decision)
        assert again == result
        assert provider.call_count == 1

    def test_critical_approval_never_reaches_provider(self) -> None:
        provider = WatchProvider()
        service = _service(provider)
        correlation_id = uuid.uuid4()
        risk = _risk_assessment(
            correlation_id, level=RiskLevel.CRITICAL, score=0.95
        )
        decision = _engine().decide(
            _to_policy_input(risk, action=ResponseActionType.BLOCK_DOMAIN)
        )
        assert decision.decision is PolicyDecisionStatus.REQUIRES_APPROVAL
        assert decision.requires_approval is True

        request = ResponseRequest(
            response_id=service.derive_response_id(
                policy_decision_id=decision.policy_decision_id,
                action=ResponseActionType.BLOCK_DOMAIN,
                target="evil.example.com",
            ),
            policy_decision_id=decision.policy_decision_id,
            correlation_id=correlation_id,
            action_type=ResponseActionType.BLOCK_DOMAIN,
            target="evil.example.com",
        )
        result = service.execute(request, decision)

        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "POLICY_REQUIRES_APPROVAL"
        assert result.provider is None
        assert provider.call_count == 0  # provably uninvoked

    def test_denied_decision_never_reaches_provider(self) -> None:
        provider = WatchProvider()
        service = _service(provider)
        correlation_id = uuid.uuid4()
        risk = _risk_assessment(correlation_id, level=RiskLevel.LOW, score=0.3)
        decision = _engine().decide(
            _to_policy_input(risk, action=ResponseActionType.DISABLE_ACCOUNT)
        )
        # Low-risk account disable is denied by the default policy.
        assert decision.decision is PolicyDecisionStatus.DENIED

        request = ResponseRequest(
            response_id=service.derive_response_id(
                policy_decision_id=decision.policy_decision_id,
                action=ResponseActionType.DISABLE_ACCOUNT,
                target="alice@corp",
            ),
            policy_decision_id=decision.policy_decision_id,
            correlation_id=correlation_id,
            action_type=ResponseActionType.DISABLE_ACCOUNT,
            target="alice@corp",
        )
        result = service.execute(request, decision)

        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "POLICY_DENIED"
        assert result.provider is None
        assert provider.call_count == 0

    def test_full_chain_is_deterministic(self) -> None:
        correlation_id = uuid.uuid4()
        risk = _risk_assessment(correlation_id, level=RiskLevel.MEDIUM, score=0.5)
        decision_a = _engine().decide(
            _to_policy_input(risk, action=ResponseActionType.BLOCK_DOMAIN)
        )
        decision_b = _engine().decide(
            _to_policy_input(risk, action=ResponseActionType.BLOCK_DOMAIN)
        )
        assert decision_a == decision_b

        service_a = _service(WatchProvider())
        service_b = _service(WatchProvider())
        request_a = ResponseRequest(
            response_id=service_a.derive_response_id(
                policy_decision_id=decision_a.policy_decision_id,
                action=ResponseActionType.BLOCK_DOMAIN,
                target="evil.example.com",
            ),
            policy_decision_id=decision_a.policy_decision_id,
            correlation_id=correlation_id,
            action_type=ResponseActionType.BLOCK_DOMAIN,
            target="evil.example.com",
        )
        request_b = ResponseRequest(
            response_id=service_b.derive_response_id(
                policy_decision_id=decision_b.policy_decision_id,
                action=ResponseActionType.BLOCK_DOMAIN,
                target="evil.example.com",
            ),
            policy_decision_id=decision_b.policy_decision_id,
            correlation_id=correlation_id,
            action_type=ResponseActionType.BLOCK_DOMAIN,
            target="evil.example.com",
        )
        result_a = service_a.execute(request_a, decision_a)
        result_b = service_b.execute(request_b, decision_b)
        assert result_a.execution_status is ResponseExecutionStatus.EXECUTED
        assert result_a == result_b