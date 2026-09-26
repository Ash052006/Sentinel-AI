"""Shared fixtures/helpers for the Step 13 Knowledge & RAG test modules.

Not collected by pytest (``python_files = test_*.py``), so it is safe to
import from any ``tests/unit/test_knowledge_*.py`` file.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from app.schemas.knowledge import (
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeIndexRecord,
    KnowledgeItem,
    KnowledgeType,
)
from app.schemas.knowledge_context import (
    KnowledgeRetrievalMetadata,
    InvestigationKnowledgeContext,
)
from app.services.knowledge.vector_store import (
    KnowledgeVectorStore,
    _InputContract,
)

#: Fixed, deterministic timezone-aware timestamps.
TS = datetime(2025, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
RETRIEVED_AT = datetime(2025, 9, 1, 12, 5, 0, tzinfo=timezone.utc)

DOC_ID = uuid.UUID("10000000-0000-0000-0000-000000000000")
CHUNK_IDS = [
    uuid.UUID(f"20000000-0000-0000-0000-{i:012d}") for i in range(1, 6)
]
KNOWLEDGE_IDS = [
    uuid.UUID(f"30000000-0000-0000-0000-{i:012d}") for i in range(1, 6)
]


def make_document(
    *,
    document_id: uuid.UUID = DOC_ID,
    source: str = "mitre-attack",
    title: str = "Technique knowledge",
    content: str = "Known technique: initial access via credential dumping.",
    knowledge_type: KnowledgeType = KnowledgeType.MITRE_ATTACK,
    metadata: dict[str, Any] | None = None,
) -> KnowledgeDocument:
    return KnowledgeDocument(
        document_id=document_id,
        source=source,
        title=title,
        content=content,
        knowledge_type=knowledge_type,
        metadata=metadata or {},
    )


def make_chunk(
    *,
    chunk_id: uuid.UUID | None = None,
    document_id: uuid.UUID = DOC_ID,
    index: int = 0,
    source: str = "mitre-attack",
    title: str = "Technique knowledge",
    content: str = "Known technique: initial access via credential dumping.",
    knowledge_type: KnowledgeType = KnowledgeType.MITRE_ATTACK,
    metadata: dict[str, Any] | None = None,
) -> KnowledgeChunk:
    return KnowledgeChunk(
        chunk_id=chunk_id or CHUNK_IDS[0],
        document_id=document_id,
        index=index,
        source=source,
        title=title,
        content=content,
        knowledge_type=knowledge_type,
        metadata=metadata or {},
    )


def make_item(
    *,
    knowledge_id: uuid.UUID | None = None,
    source: str = "mitre-attack",
    title: str = "Technique knowledge",
    content: str = "Known technique: initial access via credential dumping.",
    knowledge_type: KnowledgeType = KnowledgeType.MITRE_ATTACK,
    relevance_score: float = 0.9,
    metadata: dict[str, Any] | None = None,
) -> KnowledgeItem:
    return KnowledgeItem(
        knowledge_id=knowledge_id or KNOWLEDGE_IDS[0],
        source=source,
        title=title,
        content=content,
        knowledge_type=knowledge_type,
        relevance_score=relevance_score,
        metadata=metadata or {},
    )


def make_index_record(
    *,
    chunk_id: uuid.UUID | None = None,
    document_id: uuid.UUID = DOC_ID,
    index: int = 0,
    source: str = "mitre-attack",
    title: str = "Technique knowledge",
    content: str = "Known technique: initial access via credential dumping.",
    knowledge_type: KnowledgeType = KnowledgeType.MITRE_ATTACK,
    metadata: dict[str, Any] | None = None,
    vector: list[float] | None = None,
) -> KnowledgeIndexRecord:
    return KnowledgeIndexRecord(
        chunk_id=chunk_id or CHUNK_IDS[0],
        document_id=document_id,
        index=index,
        source=source,
        title=title,
        content=content,
        knowledge_type=knowledge_type,
        metadata=metadata or {},
        vector=vector if vector is not None else [0.1, 0.2, 0.3],
    )


def make_knowledge_context(
    *,
    items: list[KnowledgeItem] | None = None,
    query: str = "initial access technique",
    top_k: int = 5,
    knowledge_types: list[KnowledgeType] | None = None,
    retrieved_at: datetime = RETRIEVED_AT,
    provider: str = "fake",
) -> InvestigationKnowledgeContext:
    if top_k < 1:
        raise ValueError("top_k must be >= 1")
    chosen = list(items) if items is not None else [
        make_item(knowledge_id=KNOWLEDGE_IDS[i % len(KNOWLEDGE_IDS)])
        for i in range(top_k)
    ]
    return InvestigationKnowledgeContext(
        items=chosen,
        metadata=KnowledgeRetrievalMetadata(
            query=query,
            top_k=top_k,
            knowledge_types=list(knowledge_types or []),
            total_results=len(chosen),
            retrieved_at=retrieved_at,
            provider=provider,
            payload_bytes=0,
        ),
    )


class RecordingKnowledgeVectorStore(KnowledgeVectorStore):
    """In-memory fake store that records search calls for assertions."""

    store_display_name = "fake"

    def __init__(
        self,
        *,
        items: list[KnowledgeItem] | None = None,
        store_name: str | None = None,
    ) -> None:
        self._items = list(items or [])
        self.store_display_name = store_name or "fake"
        self.upserted: list[KnowledgeIndexRecord] = []
        self.searches: list[dict[str, Any]] = []

    @property
    def store_name(self) -> str:
        return self.store_display_name

    def upsert(self, records: Any) -> int:
        self.upserted.extend(records)
        return len(records)

    def search(self, vector: Any, *, limit: int, knowledge_types=None) -> list[KnowledgeItem]:
        _InputContract.check_search_inputs(vector, limit, knowledge_types)
        self.searches.append(
            {
                "vector": list(vector),
                "limit": limit,
                "knowledge_types": tuple(knowledge_types) if knowledge_types else None,
            }
        )
        return list(self._items)


def deterministic_uuids(factory_prefix: str) -> Callable[[], uuid.UUID]:
    """Return an id factory producing a stable sequence of UUIDs.

    *factory_prefix* must be at most 8 hex characters; it is left-padded to a
    full 32-character UUID followed by an incrementing counter.
    """
    prefix = ((factory_prefix or "40000000")[:8]).ljust(8, "0")
    counter = 0

    def _next() -> uuid.UUID:
        nonlocal counter
        counter += 1
        return uuid.UUID(f"{prefix}{counter:024d}")

    return _next