"""Evidence-grounded Explainability service + provider factory tests.

These are deterministic unit tests: no database, no network, no provider key.
Read sources are injected fakes and the AI narrative runs through a scripted
``InvestigationLLMClient`` (the shared "mock LLM" pattern), so the whole suite
exercises the real pipelines without a live model.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.agents.investigation.agent import InvestigationAgent
from app.agents.investigation.exceptions import InvestigationConfigurationError
from app.agents.investigation.llm_client import InvestigationLLMClient
from app.agents.investigation.prompt import InvestigationPrompt
from app.agents.investigation.provider import (
    InvestigationProviderConfigurationError,
    build_investigation_agent,
    build_investigation_llm_client,
)
from app.schemas.correlation import CorrelationStatus
from app.schemas.correlation_query import (
    CorrelationMemberRecord,
    CorrelationResultRecord,
)
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.detection_query import DetectionResultRecord
from app.schemas.explainability import (
    DimensionCoverage,
    ExplanationDimension,
    ExplanationStatus,
)
from app.schemas.investigation_context import _evidence_id
from app.schemas.risk import RiskLevel
from app.schemas.risk_query import RiskAssessmentRecord
from app.schemas.security_event import Provenance
from app.services.explainability import (
    ExplainabilityBoundError,
    ExplainabilityContextError,
    ExplainabilityError,
    ExplainabilityNotFoundError,
    ExplainabilityService,
    ExplainabilitySources,
    ExplainabilityValidationError,
)


@pytest.fixture(scope="session", autouse=True)
def _test_database():
    """Shadow the DB-creating session fixture: these tests use no database.

    The explanation service is exercised entirely through injected fake read
    sources and a scripted LLM client, so no schema is required.  Overriding
    the conftest fixtures here keeps the suite hermetic (and independent of the
    migrations graph) without weakening any DB-backed test elsewhere.
    """
    yield


@pytest.fixture(scope="session", autouse=True)
def _shipped_detection_rules():
    """Shadow the rule-deploying session fixture: no database is used here."""
    yield


_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_CREATED_AT = datetime(2025, 8, 2, 0, 0, 0, tzinfo=timezone.utc)
_CORRELATION_ID = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_RISK_ID = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
_DETECTION_1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
_EVENT_1 = uuid.UUID("44444444-4444-4444-4444-444444444444")
_APPROVAL_ID = uuid.UUID("55555555-5555-5555-5555-555555555555")
_EXECUTION_ID = uuid.UUID("66666666-6666-6666-6666-666666666666")


# ---------------------------------------------------------------------------
# Record factories
# ---------------------------------------------------------------------------


def _correlation_record(**overrides) -> CorrelationResultRecord:
    payload: dict = {
        "id": uuid.uuid4(),
        "correlation_id": _CORRELATION_ID,
        "status": CorrelationStatus.ACTIVE,
        "confidence": 0.85,
        "evidence": {"basis": "explicit-membership"},
        "result_metadata": {"source": "unit-test"},
        "timestamp": _FIXED_TS,
        "provenance": Provenance.CORRELATED,
        "members": [
            CorrelationMemberRecord(
                id=uuid.uuid4(),
                correlation_id=_CORRELATION_ID,
                detection_id=_DETECTION_1,
                event_id=_EVENT_1,
                timestamp=_FIXED_TS,
                member_order=0,
                created_at=_CREATED_AT,
                updated_at=_CREATED_AT,
            )
        ],
        "created_at": _CREATED_AT,
        "updated_at": _CREATED_AT,
    }
    payload.update(overrides)
    return CorrelationResultRecord(**payload)


def _detection_record(**overrides) -> DetectionResultRecord:
    payload: dict = {
        "id": uuid.uuid4(),
        "event_id": _EVENT_1,
        "detection_id": _DETECTION_1,
        "rule_id": "sigma_rule_1",
        "rule_type": RuleType.SIGMA,
        "rule_version": "1.0",
        "severity": DetectionSeverity.HIGH,
        "matched": True,
        "confidence": 0.9,
        "evidence": {"matched_fields": ["command_line"]},
        "result_metadata": {"engine": "sigma"},
        "detected_at": _FIXED_TS,
        "provenance": Provenance.DETECTED,
        "created_at": _CREATED_AT,
        "updated_at": _CREATED_AT,
    }
    payload.update(overrides)
    return DetectionResultRecord(**payload)


def _risk_record(**overrides) -> RiskAssessmentRecord:
    payload: dict = {
        "id": uuid.uuid4(),
        "risk_assessment_id": _RISK_ID,
        "correlation_id": _CORRELATION_ID,
        "score": 0.72,
        "level": RiskLevel.HIGH,
        "confidence": 0.9,
        "factors": [
            {"factor_type": "detection_severity", "contribution": 0.6, "evidence": []}
        ],
        "evidence": [],
        "assessment_metadata": {"engine": "risk"},
        "timestamp": _FIXED_TS,
        "provenance": Provenance.RISK_ASSESSED,
        "created_at": _CREATED_AT,
        "updated_at": _CREATED_AT,
    }
    payload.update(overrides)
    return RiskAssessmentRecord(**payload)


# ---------------------------------------------------------------------------
# Fake read sources
# ---------------------------------------------------------------------------


class _FakeCorrelationService:
    def __init__(self, record):
        self._record = record

    def get_correlation(self, db, correlation_id):
        return self._record


class _FakeDetectionService:
    def __init__(self, records):
        self._records = {r.detection_id: r for r in records}

    def get_result(self, db, detection_id):
        return self._records.get(detection_id)


class _FakeRiskService:
    def __init__(self, record):
        self._record = record

    def list_assessments_for_correlation(self, db, correlation_id, *, page, page_size):
        items = [self._record] if self._record is not None else []
        return SimpleNamespace(items=items, total=len(items), page=page, page_size=page_size)


class _FakeMemoryService:
    def list_memories_for_correlation(self, db, correlation_id, *, page, page_size):
        return SimpleNamespace(items=[], total=0, page=page, page_size=page_size)


def _approval_row():
    return SimpleNamespace(
        approval_id=_APPROVAL_ID,
        action_type="block_host",
        target="host-1",
        status="approved",
        policy_rule_id="policy.critical.host",
    )


def _soar_row():
    return SimpleNamespace(
        execution_id=_EXECUTION_ID,
        playbook_id="isolate_host",
        primary_action="isolate_host",
        target="host-1",
        status="completed",
        simulated=True,
    )


class _FakeRepo:
    def __init__(self, rows):
        self._rows = rows

    def list_for_correlation(self, correlation_id, *, limit=None):
        return list(self._rows)


def _sources(
    *,
    correlation=None,
    detections=None,
    risk="default",
    approvals=(),
    soar=(),
    agent_factory=None,
) -> ExplainabilitySources:
    return ExplainabilitySources(
        correlation_service=_FakeCorrelationService(
            _correlation_record() if correlation is None else correlation
        ),
        detection_service=_FakeDetectionService(
            [_detection_record()] if detections is None else detections
        ),
        risk_service=_FakeRiskService(_risk_record() if risk == "default" else risk),
        memory_service=_FakeMemoryService(),
        approval_repository_factory=lambda db: _FakeRepo(list(approvals)),
        soar_repository_factory=lambda db: _FakeRepo(list(soar)),
        agent_factory=agent_factory,
    )


# ---------------------------------------------------------------------------
# Scripted LLM client
# ---------------------------------------------------------------------------


class ScriptedLLMClient(InvestigationLLMClient):
    provider_name = "scripted"
    model_name = "scripted-1"

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def generate(self, prompt: InvestigationPrompt) -> str:
        return json.dumps(self._payload)


def _agent_with_payload(payload: dict) -> InvestigationAgent:
    return InvestigationAgent(
        llm_client=ScriptedLLMClient(payload),
        investigation_id_factory=lambda: uuid.UUID(
            "12345678-1234-1234-1234-123456789abc"
        ),
        result_timestamp_factory=lambda: _FIXED_TS,
    )


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def test_provider_factory_rejects_unknown_provider():
    with pytest.raises(InvestigationProviderConfigurationError):
        build_investigation_llm_client("does-not-exist")


def test_provider_factory_known_providers():
    from app.agents.investigation.provider import _PROVIDER_CLIENTS

    assert set(_PROVIDER_CLIENTS) == {"gemini", "groq"}


def test_build_agent_honours_injected_client():
    fake = ScriptedLLMClient({"findings": [], "observations": []})
    agent = build_investigation_agent("groq", llm_client=fake)
    assert agent.provider_name == "scripted"


# ---------------------------------------------------------------------------
# Deterministic explanation
# ---------------------------------------------------------------------------


def test_deterministic_explanation_dimensions():
    service = ExplainabilityService(_sources())
    result = service.explain_correlation(None, _CORRELATION_ID, use_ai=False)

    assert result.status is ExplanationStatus.INSUFFICIENT_EVIDENCE
    by_dim = {d.dimension: d for d in result.dimensions}

    assert set(by_dim) == {
        ExplanationDimension.DETECTION,
        ExplanationDimension.CORRELATION,
        ExplanationDimension.RISK,
        ExplanationDimension.MITRE,
        ExplanationDimension.POLICY,
        ExplanationDimension.RESPONSE,
        ExplanationDimension.AUDIT,
    }

    assert by_dim[ExplanationDimension.CORRELATION].coverage is DimensionCoverage.GROUNDED
    assert by_dim[ExplanationDimension.DETECTION].coverage is DimensionCoverage.GROUNDED
    assert by_dim[ExplanationDimension.RISK].coverage is DimensionCoverage.GROUNDED
    # MITRE / audit have no persisted source: flagged, never invented.
    assert by_dim[ExplanationDimension.MITRE].coverage is DimensionCoverage.UNAVAILABLE
    assert by_dim[ExplanationDimension.AUDIT].coverage is DimensionCoverage.UNAVAILABLE
    assert by_dim[ExplanationDimension.MITRE].unavailable_reason
    # No approvals/SOAR -> response none_found, policy unavailable.
    assert by_dim[ExplanationDimension.RESPONSE].coverage is DimensionCoverage.NONE_FOUND
    assert by_dim[ExplanationDimension.POLICY].coverage is DimensionCoverage.UNAVAILABLE


def test_deterministic_claims_reference_real_evidence():
    service = ExplainabilityService(_sources())
    result = service.explain_correlation(None, _CORRELATION_ID, use_ai=False)

    known = {e.evidence_id for e in result.evidence}
    assert known  # context evidence was produced
    for dim in result.dimensions:
        for claim in dim.claims:
            for eid in claim.evidence_ids:
                assert eid in known


def test_sections_flag_unavailable_reasons_in_limitations():
    service = ExplainabilityService(_sources())
    result = service.explain_correlation(None, _CORRELATION_ID, use_ai=False)
    assert any("mitre:" in line for line in result.limitations)
    assert any("audit:" in line for line in result.limitations)


def test_grounded_response_and_policy_from_approvals_and_soar():
    service = ExplainabilityService(
        _sources(approvals=[_approval_row()], soar=[_soar_row()])
    )
    result = service.explain_correlation(None, _CORRELATION_ID, use_ai=False)
    by_dim = {d.dimension: d for d in result.dimensions}

    response = by_dim[ExplanationDimension.RESPONSE]
    assert response.coverage is DimensionCoverage.GROUNDED
    assert _APPROVAL_ID in response.reference_ids
    assert _EXECUTION_ID in response.reference_ids

    policy = by_dim[ExplanationDimension.POLICY]
    assert policy.coverage is DimensionCoverage.GROUNDED
    assert "policy.critical.host" in " ".join(c.text for c in policy.claims)


def test_missing_correlation_raises_not_found():
    sources = _sources()
    sources.correlation_service = _FakeCorrelationService(None)
    service = ExplainabilityService(sources)
    with pytest.raises(ExplainabilityNotFoundError):
        service.explain_correlation(None, _CORRELATION_ID)


def test_detection_none_found_when_unresolved():
    service = ExplainabilityService(_sources(detections=[]))
    result = service.explain_correlation(None, _CORRELATION_ID, use_ai=False)
    by_dim = {d.dimension: d for d in result.dimensions}
    assert by_dim[ExplanationDimension.DETECTION].coverage is DimensionCoverage.NONE_FOUND


def test_risk_none_found_when_absent():
    service = ExplainabilityService(_sources(risk=None))
    result = service.explain_correlation(None, _CORRELATION_ID, use_ai=False)
    by_dim = {d.dimension: d for d in result.dimensions}
    assert by_dim[ExplanationDimension.RISK].coverage is DimensionCoverage.NONE_FOUND


# ---------------------------------------------------------------------------
# AI narrative
# ---------------------------------------------------------------------------


def _correlation_evidence_id() -> uuid.UUID:
    return _evidence_id(f"correlated|correlation|{_CORRELATION_ID}")


def test_ai_narrative_is_grounded_and_provenance_pinned():
    evidence_id = _correlation_evidence_id()
    payload = {
        "findings": [
            {
                "finding_type": "activity_pattern",
                "title": "Correlated activity",
                "summary": "Multiple detections share the same event.",
                "confidence": 0.7,
                "evidence_ids": [str(evidence_id)],
            }
        ],
        "observations": [
            {
                "observation_type": "ai_reasoning",
                "observation_text": "The detections co-occur on one event.",
            }
        ],
    }
    service = ExplainabilityService(
        _sources(agent_factory=lambda: _agent_with_payload(payload))
    )
    result = service.explain_correlation(None, _CORRELATION_ID, use_ai=True)

    assert result.status is ExplanationStatus.EXPLAINED
    assert result.ai_provider == "scripted"
    assert result.ai_model == "scripted-1"
    assert len(result.narrative) == 1
    assert result.narrative[0].provenance is Provenance.AI_GENERATED
    assert result.narrative[0].evidence_ids == [evidence_id]
    assert result.unsupported_claims == []
    assert result.provenance is Provenance.AI_GENERATED


def test_ungrounded_ai_finding_is_flagged_not_presented_as_grounded():
    payload = {
        "findings": [
            {
                "finding_type": "escalation",
                "title": "Unsupported escalation",
                "confidence": 0.4,
                "evidence_ids": [],
            }
        ],
        "observations": [],
    }
    service = ExplainabilityService(
        _sources(agent_factory=lambda: _agent_with_payload(payload))
    )
    result = service.explain_correlation(None, _CORRELATION_ID, use_ai=True)
    assert result.status is ExplanationStatus.EXPLAINED
    assert result.unsupported_claims == ["Unsupported escalation"]


def test_ai_provider_failure_degrades_gracefully():
    def _boom():
        raise InvestigationConfigurationError("no key")

    service = ExplainabilityService(_sources(agent_factory=_boom))
    result = service.explain_correlation(None, _CORRELATION_ID, use_ai=True)

    assert result.status is ExplanationStatus.AI_UNAVAILABLE
    assert result.narrative == []
    # Deterministic dimensions survive the AI outage.
    by_dim = {d.dimension: d for d in result.dimensions}
    assert by_dim[ExplanationDimension.CORRELATION].coverage is DimensionCoverage.GROUNDED
    assert any("provider" in line.lower() for line in result.limitations)


def test_use_ai_false_never_calls_agent():
    called = {"n": 0}

    def _factory():
        called["n"] += 1
        return _agent_with_payload({"findings": [], "observations": []})

    service = ExplainabilityService(_sources(agent_factory=_factory))
    service.explain_correlation(None, _CORRELATION_ID, use_ai=False)
    assert called["n"] == 0


# ---------------------------------------------------------------------------
# Route transport (pure, no database)
# ---------------------------------------------------------------------------


from fastapi import HTTPException  # noqa: E402

from app.api.routes import investigations as investigations_route  # noqa: E402
from app.schemas.explainability import ExplanationRequest  # noqa: E402


def _http_status(excinfo) -> int:
    assert isinstance(excinfo.value, HTTPException)
    return excinfo.value.status_code


def test_call_service_maps_not_found_to_404():
    with pytest.raises(HTTPException) as exc:
        investigations_route._call_service(
            lambda: (_ for _ in ()).throw(
                ExplainabilityNotFoundError(_CORRELATION_ID)
            )
        )
    assert _http_status(exc) == 404


def test_call_service_maps_validation_to_422():
    with pytest.raises(HTTPException) as exc:
        investigations_route._call_service(
            lambda: (_ for _ in ()).throw(
                ExplainabilityValidationError("bad id")
            )
        )
    assert _http_status(exc) == 422


def test_call_service_maps_bound_to_409():
    with pytest.raises(HTTPException) as exc:
        investigations_route._call_service(
            lambda: (_ for _ in ()).throw(ExplainabilityBoundError("too many"))
        )
    assert _http_status(exc) == 409


def test_call_service_maps_context_to_503_without_leaking_detail():
    with pytest.raises(HTTPException) as exc:
        investigations_route._call_service(
            lambda: (_ for _ in ()).throw(
                ExplainabilityContextError("row 123 unparseable")
            )
        )
    assert _http_status(exc) == 503
    assert "row 123" not in str(exc.value.detail)


def test_call_service_maps_base_error_to_422_and_unexpected_to_503():
    with pytest.raises(HTTPException) as exc:
        investigations_route._call_service(
            lambda: (_ for _ in ()).throw(ExplainabilityError("boom"))
        )
    assert _http_status(exc) == 422

    with pytest.raises(HTTPException) as exc:
        investigations_route._call_service(
            lambda: (_ for _ in ()).throw(RuntimeError("db down"))
        )
    assert _http_status(exc) == 503


class _StubService:
    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error
        self.calls = []

    def explain_correlation(self, db, correlation_id, *, use_ai):
        self.calls.append((correlation_id, use_ai))
        if self._error is not None:
            raise self._error
        return self._result


def test_get_handler_forces_deterministic(monkeypatch):
    sentinel = _correlation_evidence_id()  # any object; transport passthrough
    stub = _StubService(result=sentinel)
    monkeypatch.setattr(investigations_route, "_get_service", lambda: stub)

    out = investigations_route.explain_correlation_deterministic(
        _CORRELATION_ID, db=None, current_user=None
    )
    assert out is sentinel
    assert stub.calls == [(_CORRELATION_ID, False)]


def test_post_handler_honours_use_ai_flag(monkeypatch):
    stub = _StubService(result="ok")
    monkeypatch.setattr(investigations_route, "_get_service", lambda: stub)

    investigations_route.explain_correlation_with_ai(
        _CORRELATION_ID,
        payload=ExplanationRequest(use_ai=False),
        db=None,
        current_user=None,
    )
    assert stub.calls[-1] == (_CORRELATION_ID, False)

    investigations_route.explain_correlation_with_ai(
        _CORRELATION_ID, payload=None, db=None, current_user=None
    )
    assert stub.calls[-1] == (_CORRELATION_ID, True)
