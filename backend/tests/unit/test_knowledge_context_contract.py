"""Step 13 — Investigation Knowledge Context contract tests.

Covers ``KnowledgeRetrievalMetadata`` and ``InvestigationKnowledgeContext``:
the pinned ``is_background_reference`` flag, coherence invariants
(``total_results == len(items)``, items never exceed ``top_k``, payload
bound), timezone-awareness of ``retrieved_at``, and the defensive builder
(whole-payload secret scan + byte bound).
"""

import uuid
from datetime import datetime

import pytest
from pydantic import ValidationError

from app.schemas.knowledge import KnowledgeItem, KnowledgeType
from app.schemas.knowledge_context import (
    MAX_KNOWLEDGE_ITEMS,
    MAX_KNOWLEDGE_QUERY_LENGTH,
    MAX_RAG_CONTEXT_PAYLOAD_BYTES,
    MAX_RETRIEVAL_TOP_K,
    InvestigationKnowledgeContext,
    KnowledgeRetrievalMetadata,
    build_investigation_knowledge_context,
)
from app.services.knowledge.exceptions import KnowledgeSafetyError
from tests.unit.knowledge_test_helpers import (
    KNOWLEDGE_IDS,
    RETRIEVED_AT,
    make_item,
    make_knowledge_context,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_bounds_are_as_documented():
    assert MAX_KNOWLEDGE_QUERY_LENGTH == 4096
    assert MAX_RETRIEVAL_TOP_K == 10
    assert MAX_KNOWLEDGE_ITEMS == 50
    assert MAX_RAG_CONTEXT_PAYLOAD_BYTES == 128 * 1024


# ---------------------------------------------------------------------------
# KnowledgeRetrievalMetadata
# ---------------------------------------------------------------------------


def test_metadata_requires_query_top_k_total_provider():
    with pytest.raises(ValidationError):
        KnowledgeRetrievalMetadata(retrieved_at=RETRIEVED_AT)  # type: ignore[call-arg]


def test_metadata_naive_retrieved_at_rejected():
    with pytest.raises(ValidationError):
        KnowledgeRetrievalMetadata(
            query="q",
            top_k=3,
            total_results=0,
            retrieved_at=datetime(2025, 9, 1),  # naive
            provider="fake",
            payload_bytes=0,
        )


def test_metadata_top_k_bounds():
    with pytest.raises(ValidationError):
        KnowledgeRetrievalMetadata(
            query="q",
            top_k=MAX_RETRIEVAL_TOP_K + 1,
            total_results=0,
            retrieved_at=RETRIEVED_AT,
            provider="fake",
            payload_bytes=0,
        )


# ---------------------------------------------------------------------------
# InvestigationKnowledgeContext
# ---------------------------------------------------------------------------


def test_context_is_background_reference_pinned_true():
    for ctx in (
        make_knowledge_context(items=[]),
        make_knowledge_context(items=[make_item()]),
    ):
        assert ctx.is_background_reference is True


def test_context_payload_bytes_present():
    ctx = make_knowledge_context(items=[make_item()])
    assert ctx.metadata.payload_bytes >= 0


def test_context_items_never_exceed_top_k():
    items = [make_item(knowledge_id=KNOWLEDGE_IDS[i]) for i in range(5)]
    with pytest.raises(ValidationError):
        InvestigationKnowledgeContext(
            items=items,
            metadata=KnowledgeRetrievalMetadata(
                query="q",
                top_k=2,
                knowledge_types=[],
                total_results=5,
                retrieved_at=RETRIEVED_AT,
                provider="fake",
                payload_bytes=0,
            ),
        )


def test_context_total_results_must_match_items():
    with pytest.raises(ValidationError):
        InvestigationKnowledgeContext(
            items=[make_item()],
            metadata=KnowledgeRetrievalMetadata(
                query="q",
                top_k=5,
                total_results=0,
                retrieved_at=RETRIEVED_AT,
                provider="fake",
                payload_bytes=0,
            ),
        )


def test_context_items_bound():
    many = [make_item(knowledge_id=uuid.uuid4()) for _ in range(MAX_KNOWLEDGE_ITEMS + 1)]
    with pytest.raises(ValidationError):
        InvestigationKnowledgeContext(
            items=many,
            metadata=KnowledgeRetrievalMetadata(
                query="q",
                top_k=MAX_RETRIEVAL_TOP_K,
                total_results=len(many),
                retrieved_at=RETRIEVED_AT,
                provider="fake",
                payload_bytes=0,
            ),
        )


def test_context_never_contains_evidence_types():
    # The knowledge context is typed as KnowledgeItem records only; an
    # InvestigationEvidence can never be injected at the schema level.
    ctx = make_knowledge_context()
    assert all(not hasattr(item, "provenance") for item in ctx.items)
    assert all(not hasattr(item, "evidence_id") for item in ctx.items)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def test_builder_produces_coherent_context():
    items = [
        make_item(knowledge_id=KNOWLEDGE_IDS[0], relevance_score=0.9),
        make_item(knowledge_id=KNOWLEDGE_IDS[1], relevance_score=0.4),
    ]
    ctx = build_investigation_knowledge_context(
        items=items,
        query="initial access",
        top_k=3,
        knowledge_types=[KnowledgeType.MITRE_ATTACK],
        retrieved_at=RETRIEVED_AT,
        provider="fake",
    )
    assert ctx.metadata.total_results == 2
    assert ctx.metadata.payload_bytes > 0
    assert ctx.metadata.knowledge_types == [KnowledgeType.MITRE_ATTACK]
    assert ctx.items == items
    assert ctx.is_background_reference is True


def _unvalidated_item(content: str) -> KnowledgeItem:
    """Build a KnowledgeItem while bypassing schema validation.

    Legitimate for testing the builder's defence-in-depth whole-payload scan:
    valid schemas can no longer carry secrets, so the boundary check is
    exercised with a constructed artifact.
    """
    return KnowledgeItem.model_construct(
        knowledge_id=KNOWLEDGE_IDS[0],
        source="mitre-attack",
        title="Knowledge",
        content=content,
        knowledge_type=KnowledgeType.MITRE_ATTACK,
        relevance_score=0.9,
        metadata={},
    )


def test_builder_rejects_secret_shaped_item():
    item = _unvalidated_item("rotating bearer token for authentication plumbing")
    with pytest.raises(ValueError):
        build_investigation_knowledge_context(
            items=[item],
            query="q",
            top_k=3,
            knowledge_types=None,
            retrieved_at=RETRIEVED_AT,
            provider="fake",
        )


def test_builder_safety_error_is_a_value_error():
    item = _unvalidated_item("the api_key value must never be carried")
    with pytest.raises(KnowledgeSafetyError):
        build_investigation_knowledge_context(
            items=[item],
            query="q",
            top_k=3,
            knowledge_types=None,
            retrieved_at=RETRIEVED_AT,
            provider="fake",
        )


def test_payload_bound_is_unreachable_by_valid_items():
    # Defence-in-depth sanity: the schema bounds (top_k <= 10, item content
    # <= 8000) keep even a maximally-populated context inside the 128 KiB
    # payload bound, so the guard exists as a hard ceiling rather than being
    # the effective limiter.
    big_content = "x" * 8000
    items = [
        make_item(knowledge_id=KNOWLEDGE_IDS[i % 5], content=big_content)
        for i in range(10)
    ]
    ctx = build_investigation_knowledge_context(
        items=items,
        query="q" * 4096,
        top_k=10,
        knowledge_types=None,
        retrieved_at=RETRIEVED_AT,
        provider="f",
    )
    assert ctx.metadata.payload_bytes <= MAX_RAG_CONTEXT_PAYLOAD_BYTES


def test_builder_empty_items_ok():
    ctx = build_investigation_knowledge_context(
        items=[],
        query="nothing found",
        top_k=3,
        knowledge_types=None,
        retrieved_at=RETRIEVED_AT,
        provider="fake",
    )
    assert ctx.items == []
    assert ctx.metadata.total_results == 0