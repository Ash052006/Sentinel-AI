"""Step 13 — live Qdrant integration smoke test.

Opt-in (``-m rag_integration``) and only meaningful when a Qdrant endpoint
is configured; skipped by default so the normal suite stays offline.  The
offline deterministic embedding provider is used end-to-end.
"""

import os
import uuid

import pytest

from app.schemas.knowledge import KnowledgeType
from app.services.knowledge.embeddings import DeterministicEmbeddingProvider
from app.services.knowledge.qdrant_store import QdrantKnowledgeVectorStore
from app.services.knowledge.retriever import (
    InvestigationKnowledgeRetriever,
)
from app.schemas.knowledge import KnowledgeIndexRecord
from tests.unit.knowledge_test_helpers import DOC_ID


@pytest.mark.rag_integration
@pytest.mark.skipif(
    os.environ.get("QDRANT_URL") is None,
    reason="QDRANT_URL not set",
)
def test_live_qdrant_roundtrip():
    """Upsert -> search -> retrieve against a real Qdrant instance."""
    from qdrant_client import QdrantClient

    collection = f"sentinelai_rag_live_{uuid.uuid4().hex[:8]}"
    client = QdrantClient(url=os.environ["QDRANT_URL"])
    store = QdrantKnowledgeVectorStore(
        collection=collection,
        qdrant_client=client,
        dimension=16,
    )
    provider = DeterministicEmbeddingProvider(dimension=16)
    try:
        records = []
        for idx, (title, content) in enumerate(
            [("Initial access", "credential dumping technique"),
             ("Persistence", "registry run key persistence")]
        ):
            vector = provider.embed(content)
            records.append(
                KnowledgeIndexRecord(
                    chunk_id=uuid.UUID(f"90000000-0000-0000-0000-{idx:012d}"),
                    document_id=DOC_ID,
                    index=idx,
                    source="live-test",
                    title=title,
                    content=content,
                    knowledge_type=KnowledgeType.ATTACK_PATTERN,
                    metadata={},
                    vector=vector,
                )
            )
        assert store.upsert(records) == 2

        retriever = InvestigationKnowledgeRetriever(
            vector_store=store,
            embedding_provider=provider,
        )
        ctx = retriever.retrieve("credential dumping", top_k=2)
        assert 1 <= ctx.metadata.total_results <= 2
        assert ctx.is_background_reference is True
        assert ctx.metadata.provider == "qdrant"
    finally:
        try:
            client.delete_collection(collection_name=collection)
        except Exception:  # pragma: no cover - cleanup best effort
            pass