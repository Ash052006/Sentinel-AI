"""Step 13 — InvestigationAgent knowledge-dispatch tests.

The agent accepts an optional ``InvestigationKnowledgeContext`` alongside
the 12B context: it forwards it to the prompt builder, and the resulting
Gemini request carries a separate knowledge part.  Knowledge is reference
material only — it never becomes evidence on the result.
"""

import json
import uuid
from datetime import datetime, timezone

import pytest

from app.agents.investigation.agent import InvestigationAgent
from app.agents.investigation.exceptions import InvestigationContextError
from app.agents.investigation.llm_client import InvestigationLLMClient
from app.agents.investigation.prompt import (
    KNOWLEDGE_DATA_START,
    InvestigationPromptBuilder,
)
from app.schemas.correlation import CorrelationStatus
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.investigation import InvestigationEvidence
from app.schemas.investigation_context import (
    ContextInputAvailability,
    CorrelationContext,
    DetectionContext,
    InputAvailability,
    InvestigationContext,
)
from app.schemas.security_event import Provenance
from tests.unit.knowledge_test_helpers import (
    KNOWLEDGE_IDS,
    make_item,
    make_knowledge_context,
)

_TS = datetime(2025, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
_EVIDENCE_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")
_INVESTIGATION_ID = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
_CORRELATION_ID = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_DETECTION_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _context():
    return InvestigationContext(
        investigation_id=_INVESTIGATION_ID,
        context_created_at=_TS,
        input_availability=ContextInputAvailability(
            correlation=InputAvailability.PROVIDED,
            detections=InputAvailability.PROVIDED,
        ),
        correlation=CorrelationContext(
            correlation_id=_CORRELATION_ID,
            status=CorrelationStatus.ACTIVE,
            confidence=0.85,
            members=[],
            evidence={},
            timestamp=_TS,
        ),
        detections=[
            DetectionContext(
                detection_id=_DETECTION_ID,
                event_id=uuid.UUID("44444444-4444-4444-4444-444444444444"),
                rule_id="sigma-001",
                rule_type=RuleType.SIGMA,
                severity=DetectionSeverity.HIGH,
                confidence=0.9,
                evidence={"matched": True},
                metadata={"engine": "sigma"},
                timestamp=_TS,
            )
        ],
        evidence=[
            InvestigationEvidence(
                evidence_id=_EVIDENCE_ID,
                evidence_type="detection_result",
                provenance=Provenance.DETECTED,
                detection_id=_DETECTION_ID,
            )
        ],
    )


def _agent(output: dict):
    """Build an agent with a stubbed LLM client that returns *output*."""

    class Stub(InvestigationLLMClient):
        provider_name = "stub"
        model_name = None

        def __init__(self):
            self.received: list = []

        def generate(self, prompt) -> str:
            self.received.append(prompt)
            return json.dumps(output)

    stub = Stub()
    agent = InvestigationAgent(
        llm_client=stub,
        investigation_id_factory=lambda: _INVESTIGATION_ID,
        result_timestamp_factory=lambda: _TS,
    )
    return agent, stub


def _empty_output() -> dict:
    return {"findings": [], "observations": []}


def test_agent_accepts_valid_knowledge_context():
    ctx = _context()
    knowledge = make_knowledge_context(items=[make_item()], top_k=1)
    agent, stub = _agent(_empty_output())
    result = agent.investigate(ctx, knowledge_context=knowledge)
    assert result.findings == []
    assert result.observations == []
    prompt = stub.received[0]
    assert prompt.knowledge_content
    assert KNOWLEDGE_DATA_START in prompt.knowledge_content


def test_agent_defaults_to_no_knowledge():
    agent, stub = _agent(_empty_output())
    result = agent.investigate(_context())
    assert result.findings == []
    assert stub.received[0].knowledge_content == ""


def test_agent_rejects_wrong_knowledge_type():
    agent, _ = _agent(_empty_output())
    with pytest.raises(InvestigationContextError):
        agent.investigate(_context(), knowledge_context={"items": []})  # type: ignore[arg-type]
    with pytest.raises(InvestigationContextError):
        agent.investigate(_context(), knowledge_context="json")  # type: ignore[arg-type]


def test_knowledge_never_becomes_evidence_on_result():
    from app.agents.investigation.prompt import KNOWLEDGE_DATA_START

    ctx = _context()
    knowledge = make_knowledge_context(
        items=[
            make_item(
                knowledge_id=KNOWLEDGE_IDS[0],
                content="a retrieved attack-pattern reference",
            )
        ],
        top_k=1,
    )
    agent, stub = _agent(_empty_output())
    result = agent.investigate(ctx, knowledge_context=knowledge)
    # The result's evidence is exactly the context's evidence — the retrieved
    # knowledge object never maps into an InvestigationEvidence.
    assert [e.evidence_id for e in result.evidence] == [_EVIDENCE_ID]
    # The result never mentions the knowledge id.
    assert str(KNOWLEDGE_IDS[0]) not in result.model_dump_json()
    assert KNOWLEDGE_DATA_START in stub.received[0].knowledge_content


def test_gemini_payload_splits_knowledge_into_own_part():
    builder = InvestigationPromptBuilder()
    knowledge = make_knowledge_context(items=[make_item()], top_k=1)
    prompt = builder.build(_context(), knowledge_context=knowledge)
    # Direct request-shape check through the real GeminiClient payload path.
    import app.agents.investigation.gemini as gemini_mod

    import httpx

    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=_gemini_ok()))
    gclient = gemini_mod.GeminiClient(
        api_key="test-key",
        model="gemini-test",
        http_client=httpx.Client(transport=transport),
    )
    payload = gclient._build_payload(prompt)
    parts = payload["contents"][0]["parts"]
    assert len(parts) == 2
    assert parts[0]["text"] == prompt.content
    assert parts[1]["text"] == prompt.knowledge_content
    assert KNOWLEDGE_DATA_START in parts[1]["text"]


def _gemini_ok():
    return {
        "candidates": [
            {
                "finishReason": "STOP",
                "content": {"parts": [{"text": '{"findings": [], "observations": []}'}]},
            }
        ]
    }