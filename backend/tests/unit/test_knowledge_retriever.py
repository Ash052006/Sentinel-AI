"""Step 13 — InvestigationKnowledgeRetriever tests.

Covers the read-side facade: query validation and bounds, top-k bounds,
knowledge-type filter validation, deterministic (re)ordering, the embedding
call, store result-contract enforcement, metadata bookkeeping, timestamps,
and the final context construction.
"""

from datetime import datetime, timezone

import pytest

from app.schemas.knowledge import KnowledgeType
from app.services.knowledge.exceptions import KnowledgeRetrievalError
from app.services.knowledge.retriever import (
    InvestigationKnowledgeRetriever,
)
from tests.unit.knowledge_test_helpers import (
    KNOWLEDGE_IDS,
    RETRIEVED_AT,
    RecordingKnowledgeVectorStore,
    make_item,
)


def _retriever(
    store: RecordingKnowledgeVectorStore | None = None,
    items: list | None = None,
    **kw,
):
    store = store or RecordingKnowledgeVectorStore(items=items)
    kw.setdefault("default_top_k", 3)
    return InvestigationKnowledgeRetriever(vector_store=store, **kw)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_retriever_requires_vector_store():
    with pytest.raises(KnowledgeRetrievalError):
        InvestigationKnowledgeRetriever(vector_store="nope")  # type: ignore[arg-type]


@pytest.mark.parametrize("top_k", [0, -1, 3.5, True, 11])
def test_retriever_rejects_bad_default_top_k(top_k):
    with pytest.raises(KnowledgeRetrievalError):
        _retriever(default_top_k=top_k)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Query validation and bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_query", ["", "   ", "\n\t", 42, None, ["q"]])
def test_retrieve_rejects_invalid_queries(bad_query):
    retriever = _retriever(items=[])
    with pytest.raises((KnowledgeRetrievalError, TypeError)):
        retriever.retrieve(bad_query)  # type: ignore[arg-type]


def test_retrieve_rejects_oversized_query():
    from app.schemas.knowledge_context import MAX_KNOWLEDGE_QUERY_LENGTH

    retriever = _retriever(items=[])
    with pytest.raises(KnowledgeRetrievalError):
        retriever.retrieve("q" * (MAX_KNOWLEDGE_QUERY_LENGTH + 1))


@pytest.mark.parametrize("top_k", [0, -2, 2.5, True, 11])
def test_retrieve_rejects_bad_top_k(top_k):
    retriever = _retriever(items=[])
    with pytest.raises((KnowledgeRetrievalError, TypeError)):
        retriever.retrieve("initial access", top_k=top_k)  # type: ignore[arg-type]


def test_retrieve_rejects_non_enum_filters():
    retriever = _retriever(items=[])
    with pytest.raises(KnowledgeRetrievalError):
        retriever.retrieve("q", knowledge_types=["sigma"])  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# Result contract & determinism
# ---------------------------------------------------------------------------


def test_retrieve_orders_deterministically_by_descending_score():
    items = [
        make_item(knowledge_id=KNOWLEDGE_IDS[1], relevance_score=0.4),
        make_item(knowledge_id=KNOWLEDGE_IDS[0], relevance_score=0.9),
        make_item(knowledge_id=KNOWLEDGE_IDS[2], relevance_score=0.9),
    ]
    retriever = _retriever(items=items)
    ctx = retriever.retrieve("technique", top_k=3, retrieved_at=RETRIEVED_AT)
    assert [i.knowledge_id for i in ctx.items] == [
        KNOWLEDGE_IDS[0],
        KNOWLEDGE_IDS[2],
        KNOWLEDGE_IDS[1],
    ]
    # Same query -> byte-identical context (stable ids) and identical order.
    again = retriever.retrieve("technique", top_k=3, retrieved_at=RETRIEVED_AT)
    assert ctx.model_dump_json() == again.model_dump_json()


def test_retrieve_metadata_bookkeeping():
    items = [
        make_item(knowledge_id=KNOWLEDGE_IDS[0], relevance_score=0.9)
    ]
    retriever = _retriever(items=items, default_top_k=2)
    ctx = retriever.retrieve(
        "technique",
        knowledge_types=[KnowledgeType.MITRE_ATTACK],
        retrieved_at=RETRIEVED_AT,
    )
    assert ctx.metadata.total_results == 1
    assert ctx.metadata.top_k == 2
    assert ctx.metadata.knowledge_types == [KnowledgeType.MITRE_ATTACK]
    assert ctx.metadata.retrieved_at == RETRIEVED_AT
    assert ctx.metadata.provider == "fake"
    assert ctx.is_background_reference is True


def test_retrieve_uses_provider_store_name():
    store = RecordingKnowledgeVectorStore(
        items=[make_item()], store_name="qdrant"
    )
    retriever = _retriever(store=store)
    ctx = retriever.retrieve("q")
    assert ctx.metadata.provider == "qdrant"


def test_retrieve_defaults_top_k_from_config():
    retriever = _retriever(items=[make_item()], default_top_k=1)
    ctx = retriever.retrieve("q")
    assert ctx.metadata.top_k == 1


def test_retrieve_rejects_store_overfull_result():
    class GreedyStore(RecordingKnowledgeVectorStore):
        def search(self, vector, *, limit, knowledge_types=None):
            super().search(vector, limit=limit, knowledge_types=knowledge_types)
            return [make_item(knowledge_id=KNOWLEDGE_IDS[i]) for i in range(5)]

    retriever = _retriever(store=GreedyStore())
    with pytest.raises(KnowledgeRetrievalError):
        retriever.retrieve("q", top_k=2)


def test_retrieve_rejects_naive_retrieved_at():
    items = [make_item()]
    retriever = _retriever(items=items)
    naive = datetime(2025, 9, 1)
    with pytest.raises(KnowledgeRetrievalError):
        retriever.retrieve("q", retrieved_at=naive)


def test_retrieve_empty_result_is_valid():
    retriever = _retriever(items=[])
    ctx = retriever.retrieve("unknown", top_k=3)
    assert ctx.items == []
    assert ctx.metadata.total_results == 0


def test_retrieve_uses_embedding_provider_for_query():
    from app.services.knowledge.embeddings import DeterministicEmbeddingProvider

    store = RecordingKnowledgeVectorStore(items=[])
    retriever = _retriever(store=store, embedding_provider=DeterministicEmbeddingProvider(dimension=16))
    retriever.retrieve("initial access technique", top_k=2)
    assert len(store.searches) == 1
    assert len(store.searches[0]["vector"]) == 16


def test_retrieved_content_is_never_modified():
    store = RecordingKnowledgeVectorStore(
        items=[make_item(content="verbatim original content", relevance_score=0.5)]
    )
    retriever = _retriever(store=store)
    ctx = retriever.retrieve("q")
    assert ctx.items[0].content == "verbatim original content"