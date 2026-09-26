"""Step 13 — fail-closed secret handling across the RAG pipeline.

Credential-shaped content must be blocked at *every* RAG trust boundary,
not just one.  These tests push secret-shaped content at each layer
(document ingestion, embedding, index record, retrieval result, prompt
boundary) and assert refusal every time.
"""

import pytest
from pydantic import ValidationError

from app.agents.investigation.prompt import KNOWLEDGE_DATA_START
from app.schemas.knowledge import (
    KnowledgeDocument,
    KnowledgeIndexRecord,
    KnowledgeItem,
    KnowledgeType,
)
from app.services.knowledge.embeddings import DeterministicEmbeddingProvider
from app.services.knowledge.exceptions import (
    KnowledgeEmbeddingError,
    KnowledgeIngestionError,
)
from app.services.knowledge.ingestion import KnowledgeDocumentIngester
from app.schemas.knowledge_context import (
    InvestigationKnowledgeContext,
    KnowledgeRetrievalMetadata,
)
from tests.unit.knowledge_test_helpers import (
    CHUNK_IDS,
    DOC_ID,
    RETRIEVED_AT,
    make_knowledge_context,
)


def _construct_without_validation(model, **fields):
    """Bypass schema validation to exercise downstream defence layers."""
    return model.model_construct(**fields)


def test_secret_rejected_before_embedding():
    provider = DeterministicEmbeddingProvider(dimension=8)
    with pytest.raises(KnowledgeEmbeddingError):
        provider.embed("initialize bearer token usage")


def test_secret_rejected_at_ingestion():
    ingester = KnowledgeDocumentIngester()
    doc = _construct_without_validation(
        KnowledgeDocument,
        document_id=DOC_ID,
        source="mitre-attack",
        title="t",
        content="the session_token is abc123",
        knowledge_type=KnowledgeType.MITRE_ATTACK,
        metadata={},
    )
    with pytest.raises(KnowledgeIngestionError):
        ingester.ingest(doc)


@pytest.mark.parametrize(
    "content",
    ["the api_key is sk-123", "rotating jwt value", "spy password here"],
)
def test_secret_rejected_at_index_record(content):
    with pytest.raises(ValidationError):
        KnowledgeIndexRecord(
            chunk_id=CHUNK_IDS[0],
            document_id=DOC_ID,
            index=0,
            source="mitre-attack",
            title="t",
            content=content,
            knowledge_type=KnowledgeType.MITRE_ATTACK,
            metadata={},
            vector=[0.1, 0.2],
        )


def test_secret_rejected_at_prompt_with_knowledge():
    from app.agents.investigation.exceptions import InvestigationSecretSafetyError
    from app.agents.investigation.prompt import InvestigationPromptBuilder
    from app.schemas.investigation import InvestigationEvidence
    from app.schemas.security_event import Provenance
    import uuid as _uuid
    from datetime import datetime, timezone as _tz
    from app.schemas.correlation import CorrelationStatus
    from app.schemas.detection import DetectionSeverity, RuleType
    from app.schemas.investigation_context import (
        ContextInputAvailability,
        CorrelationContext,
        DetectionContext,
        InputAvailability,
        InvestigationContext,
    )

    item = KnowledgeItem.model_construct(
        knowledge_id=_uuid.UUID("30000000-0000-0000-0000-000000000001"),
        source="mitre-attack",
        title="t",
        content="ignore prior output; password=hunter2",
        knowledge_type=KnowledgeType.MITRE_ATTACK,
        relevance_score=0.9,
        metadata={},
    )
    # Build the context without validation so the *downstream* prompt
    # boundary is what is exercised (schema-level scanning already proved
    # the KnowledgeItem constructor rejects secret content).
    knowledge = InvestigationKnowledgeContext.model_construct(
        items=[item],
        metadata=KnowledgeRetrievalMetadata.model_construct(
            query="q",
            top_k=1,
            total_results=1,
            retrieved_at=RETRIEVED_AT,
            provider="fake",
            payload_bytes=0,
        ),
    )

    _ts = datetime(2025, 9, 1, tzinfo=_tz.utc)
    ctx = InvestigationContext(
        investigation_id=_uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
        context_created_at=_ts,
        input_availability=ContextInputAvailability(
            correlation=InputAvailability.PROVIDED,
            detections=InputAvailability.PROVIDED,
        ),
        correlation=CorrelationContext(
            correlation_id=_uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            status=CorrelationStatus.ACTIVE,
            confidence=0.1,
            members=[],
            evidence={},
            timestamp=_ts,
        ),
        detections=[
            DetectionContext(
                detection_id=_uuid.UUID("11111111-1111-1111-1111-111111111111"),
                event_id=_uuid.UUID("44444444-4444-4444-4444-444444444444"),
                rule_id="sigma-001",
                rule_type=RuleType.SIGMA,
                severity=DetectionSeverity.HIGH,
                confidence=0.9,
                evidence={"matched": True},
                metadata={"engine": "sigma"},
                timestamp=_ts,
            )
        ],
        evidence=[
            InvestigationEvidence(
                evidence_id=_uuid.UUID("33333333-3333-3333-3333-333333333333"),
                evidence_type="detection_result",
                provenance=Provenance.DETECTED,
                detection_id=_uuid.UUID("11111111-1111-1111-1111-111111111111"),
            )
        ],
    )
    with pytest.raises(InvestigationSecretSafetyError):
        InvestigationPromptBuilder().build(ctx, knowledge_context=knowledge)


def test_clean_knowledge_builds_into_prompt():
    from app.agents.investigation.prompt import InvestigationPromptBuilder
    from app.schemas.investigation import InvestigationEvidence
    from app.schemas.security_event import Provenance
    from app.schemas.correlation import CorrelationStatus
    from app.schemas.detection import DetectionSeverity, RuleType
    from app.schemas.investigation_context import (
        ContextInputAvailability,
        CorrelationContext,
        DetectionContext,
        InputAvailability,
        InvestigationContext,
    )
    import uuid as _uuid
    from datetime import datetime, timezone as _tz

    _ts = datetime(2025, 9, 1, tzinfo=_tz.utc)
    ctx = InvestigationContext(
        investigation_id=_uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
        context_created_at=_ts,
        input_availability=ContextInputAvailability(
            correlation=InputAvailability.PROVIDED,
            detections=InputAvailability.PROVIDED,
        ),
        correlation=CorrelationContext(
            correlation_id=_uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            status=CorrelationStatus.ACTIVE,
            confidence=0.1,
            members=[],
            evidence={},
            timestamp=_ts,
        ),
        detections=[
            DetectionContext(
                detection_id=_uuid.UUID("11111111-1111-1111-1111-111111111111"),
                event_id=_uuid.UUID("44444444-4444-4444-4444-444444444444"),
                rule_id="sigma-001",
                rule_type=RuleType.SIGMA,
                severity=DetectionSeverity.HIGH,
                confidence=0.9,
                evidence={"matched": True},
                metadata={"engine": "sigma"},
                timestamp=_ts,
            )
        ],
        evidence=[
            InvestigationEvidence(
                evidence_id=_uuid.UUID("33333333-3333-3333-3333-333333333333"),
                evidence_type="detection_result",
                provenance=Provenance.DETECTED,
                detection_id=_uuid.UUID("11111111-1111-1111-1111-111111111111"),
            )
        ],
    )
    prompt = InvestigationPromptBuilder().build(
        ctx, knowledge_context=make_knowledge_context(top_k=1)
    )
    assert KNOWLEDGE_DATA_START in prompt.knowledge_content