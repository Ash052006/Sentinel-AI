"""Investigation Knowledge Context contract — Step 13.

A validated representation of the **retrieved security knowledge** supplied
to the Step 12C AI Investigation Agent as background reference material.

The contract makes the evidence / knowledge separation structurally explicit:

* ``InvestigationKnowledgeContext`` contains only :class:`KnowledgeItem`
  records — never ``InvestigationEvidence``.
* ``is_background_reference`` is pinned to ``True`` by the schema, so the
  object permanently communicates that this information was retrieved as
  background knowledge, and that intent cannot be silently reclassified.
* Knowledge items carry a ``knowledge_type`` and a ``source``; they carry no
  security-event provenance and no evidence identity, so retrieved knowledge
  can never masquerade as observed evidence.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator, model_validator
from typing_extensions import Literal

from app.schemas.knowledge import (
    MAX_KNOWLEDGE_ITEMS,
    MAX_KNOWLEDGE_SOURCE_LENGTH,
    KnowledgeItem,
    KnowledgeType,
)

#: Maximum number of retrieved knowledge items a context may hold.
MAX_RETRIEVAL_TOP_K = 10

#: Maximum serialized size of a complete InvestigationKnowledgeContext
#: (all items plus metadata): 128 KiB.
MAX_RAG_CONTEXT_PAYLOAD_BYTES = 128 * 1024

#: Maximum length of a retrieval query string.
MAX_KNOWLEDGE_QUERY_LENGTH = 4096


class KnowledgeRetrievalMetadata(BaseModel):
    """Bookkeeping metadata describing how the knowledge was retrieved.

    ``provider`` is a stable, non-secret identifier of the vector store
    implementation (e.g. ``qdrant``); it never contains connection details
    or credentials.
    """

    query: str = Field(
        ...,
        max_length=MAX_KNOWLEDGE_QUERY_LENGTH,
        description="The query text this retrieval was performed for.",
    )
    top_k: int = Field(
        ...,
        ge=1,
        le=MAX_RETRIEVAL_TOP_K,
        description="The number of items requested.",
    )
    knowledge_types: list[KnowledgeType] = Field(
        default_factory=list,
        description="Optional knowledge-type filters applied.",
    )
    total_results: int = Field(
        ...,
        ge=0,
        description="The number of items actually retrieved.",
    )
    retrieved_at: datetime = Field(
        ...,
        description="When the retrieval was performed (timezone-aware UTC).",
    )
    provider: str = Field(
        ...,
        max_length=MAX_KNOWLEDGE_SOURCE_LENGTH,
        description="Stable vector-store provider identifier (any one).",
    )
    payload_bytes: int = Field(
        ...,
        ge=0,
        description="Serialized size in bytes of the full retrieved payload.",
    )

    @field_validator("retrieved_at")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "retrieved_at must be timezone-aware; naive timestamps are "
                "not accepted"
            )
        return v


class InvestigationKnowledgeContext(BaseModel):
    """Retrieved security knowledge supplied to the investigation agent.

    Clear message to every consumer: this information was retrieved as
    background knowledge and is **never** treated as observed security
    evidence.
    """

    is_background_reference: Literal[True] = Field(
        default=True,
        description=(
            "Pinned True: this object is background reference material by "
            "construction and can never be reclassified as observed evidence."
        ),
    )
    items: list[KnowledgeItem] = Field(
        default_factory=list,
        description=(
            "Retrieved knowledge items in deterministic relevance order.  "
            "Each item is background reference material only."
        ),
    )
    metadata: KnowledgeRetrievalMetadata = Field(
        ...,
        description="Bookkeeping metadata about the retrieval.",
    )

    @field_validator("items")
    @classmethod
    def _items_bounded(cls, v: list[KnowledgeItem]) -> list[KnowledgeItem]:
        if len(v) > MAX_KNOWLEDGE_ITEMS:
            raise ValueError(
                f"retrieved knowledge items exceed MAX_KNOWLEDGE_ITEMS="
                f"{MAX_KNOWLEDGE_ITEMS} (got {len(v)})"
            )
        return v

    @model_validator(mode="after")
    def _coherent(self) -> "InvestigationKnowledgeContext":
        if self.metadata.total_results != len(self.items):
            raise ValueError(
                f"metadata.total_results={self.metadata.total_results} does "
                f"not equal the number of retrieved items ({len(self.items)})"
            )
        if len(self.items) > self.metadata.top_k:
            raise ValueError(
                f"retrieved {len(self.items)} items but top_k was "
                f"{self.metadata.top_k}; a retrieval must never exceed its "
                "requested bound"
            )
        try:
            serialized = self.model_dump_json()
        except Exception:  # pragma: no cover - defensive
            return self
        size = len(serialized.encode("utf-8"))
        if size > MAX_RAG_CONTEXT_PAYLOAD_BYTES:
            raise ValueError(
                f"InvestigationKnowledgeContext exceeds MAX_RAG_CONTEXT_"
                f"PAYLOAD_BYTES={MAX_RAG_CONTEXT_PAYLOAD_BYTES} "
                f"(serialized size {size})"
            )
        return self


def build_investigation_knowledge_context(
    *,
    items: list[KnowledgeItem],
    query: str,
    top_k: int,
    knowledge_types: list[KnowledgeType] | None,
    retrieved_at: datetime,
    provider: str,
) -> InvestigationKnowledgeContext:
    """Assemble a validated, coherent InvestigationKnowledgeContext.

    Performs a final whole-payload secret scan (defence-in-depth before the
    prompt boundary) and enforces the total-payload bound.

    Args:
        items: Retrieved knowledge items (already deterministically ordered).
        query: The retrieval query text.
        top_k: The requested item count.
        knowledge_types: Optional knowledge-type filters that were applied.
        retrieved_at: Timezone-aware retrieval timestamp.
        provider: Stable vector-store provider identifier.
    """
    from app.services.knowledge.safety import assert_knowledge_safe

    for item in items:
        assert_knowledge_safe(item.model_dump_json(), "retrieved knowledge item")

    pending = InvestigationKnowledgeContext(
        items=list(items),
        metadata=KnowledgeRetrievalMetadata(
            query=query,
            top_k=top_k,
            knowledge_types=list(knowledge_types or []),
            total_results=len(items),
            retrieved_at=retrieved_at,
            provider=provider,
            payload_bytes=0,
        ),
    )

    payload = pending.model_dump_json()
    payload_bytes = len(payload.encode("utf-8"))
    assert_knowledge_safe(payload, "investigation knowledge context")
    if payload_bytes > MAX_RAG_CONTEXT_PAYLOAD_BYTES:
        raise ValueError(
            "InvestigationKnowledgeContext payload exceeds "
            f"MAX_RAG_CONTEXT_PAYLOAD_BYTES={MAX_RAG_CONTEXT_PAYLOAD_BYTES} "
            f"(serialized {payload_bytes} bytes)"
        )

    return pending.model_copy(
        update={
            "metadata": pending.metadata.model_copy(
                update={"payload_bytes": payload_bytes}
            )
        }
    )