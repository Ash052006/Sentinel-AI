"""Investigation knowledge retrieval — Step 13.

``InvestigationKnowledgeRetriever`` is the read-side facade of the RAG
layer: it takes a bounded, validated query and returns a bounded,
deterministically-ordered :class:`InvestigationKnowledgeContext` that the
Step 12C prompt builder can hand to Gemini **as reference material only**.

Guarantees:

* query and result counts are bounded and validated;
* the embedding provider rescans the query (fail closed);
* retrieved items are re-ordered deterministically
  ``(-relevance_score, str(knowledge_id))`` so identical stores always
  produce byte-identical output;
* the final payload is secret-scanned and size-bounded again;
* retrieval never fabricates, rewrites, or re-scores content — it only
  re-orders what the store returned within the score contract.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Sequence

from app.core.config import settings
from app.schemas.knowledge import KnowledgeItem, KnowledgeType
from app.schemas.knowledge_context import (
    MAX_KNOWLEDGE_QUERY_LENGTH,
    MAX_RETRIEVAL_TOP_K,
    InvestigationKnowledgeContext,
    build_investigation_knowledge_context,
)
from app.services.knowledge.embeddings import (
    EmbeddingProvider,
    create_embedding_provider,
)
from app.services.knowledge.exceptions import KnowledgeRetrievalError
from app.services.knowledge.vector_store import KnowledgeVectorStore


class InvestigationKnowledgeRetriever:
    """Bounded, deterministic retrieval of investigation background knowledge."""

    def __init__(
        self,
        *,
        vector_store: KnowledgeVectorStore,
        embedding_provider: EmbeddingProvider | None = None,
        default_top_k: int | None = None,
        retrieved_at_factory: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(vector_store, KnowledgeVectorStore):
            raise KnowledgeRetrievalError(
                "retriever requires a KnowledgeVectorStore instance; "
                f"received {type(vector_store).__name__}"
            )
        self._vector_store = vector_store
        self._embedding_provider = (
            embedding_provider or create_embedding_provider()
        )
        self._default_top_k = (
            default_top_k if default_top_k is not None else settings.rag_default_top_k
        )
        if (
            isinstance(self._default_top_k, bool)
            or not isinstance(self._default_top_k, int)
            or not 1 <= self._default_top_k <= MAX_RETRIEVAL_TOP_K
        ):
            raise KnowledgeRetrievalError(
                f"default_top_k must be within [1, MAX_RETRIEVAL_TOP_K="
                f"{MAX_RETRIEVAL_TOP_K}]"
            )
        self._retrieved_at_factory = retrieved_at_factory or _default_retrieved_at

    @property
    def vector_store(self) -> KnowledgeVectorStore:
        return self._vector_store

    def retrieve(
        self,
        query: str,
        *,
        top_k: int | None = None,
        knowledge_types: Sequence[KnowledgeType] | None = None,
        retrieved_at: datetime | None = None,
    ) -> InvestigationKnowledgeContext:
        """Retrieve bounded background knowledge for *query*.

        Raises:
            KnowledgeRetrievalError: for invalid, unbounded, or empty
                queries; for out-of-contract store responses; or when the
                final payload would exceed its bound.
        """
        if not isinstance(query, str):
            raise KnowledgeRetrievalError(
                "retrieval query must be text"
            )
        stripped = query.strip()
        if not stripped:
            raise KnowledgeRetrievalError(
                "retrieval query must not be blank"
            )
        if len(stripped) > MAX_KNOWLEDGE_QUERY_LENGTH:
            raise KnowledgeRetrievalError(
                f"retrieval query exceeds MAX_KNOWLEDGE_QUERY_LENGTH="
                f"{MAX_KNOWLEDGE_QUERY_LENGTH}"
            )

        resolved_top_k = top_k if top_k is not None else self._default_top_k
        if (
            isinstance(resolved_top_k, bool)
            or not isinstance(resolved_top_k, int)
            or not 1 <= resolved_top_k <= MAX_RETRIEVAL_TOP_K
        ):
            raise KnowledgeRetrievalError(
                f"top_k must be within [1, MAX_RETRIEVAL_TOP_K="
                f"{MAX_RETRIEVAL_TOP_K}]; got {resolved_top_k!r}"
            )

        resolved_types: tuple[KnowledgeType, ...] | None = None
        if knowledge_types is not None:
            if isinstance(knowledge_types, (str, KnowledgeType)):
                raise KnowledgeRetrievalError(
                    "knowledge_types must be a sequence of KnowledgeType"
                )
            resolved_types = tuple(knowledge_types)
            for kt in resolved_types:
                if not isinstance(kt, KnowledgeType):
                    raise KnowledgeRetrievalError(
                        "knowledge_types entries must be KnowledgeType members; "
                        f"received {type(kt).__name__}"
                    )

        vector = self._embedding_provider.embed(stripped)
        try:
            items = self._vector_store.search(
                vector,
                limit=resolved_top_k,
                knowledge_types=resolved_types,
            )
        except Exception as exc:
            raise KnowledgeRetrievalError(
                "knowledge retrieval from the vector store failed"
            ) from exc

        if not isinstance(items, list) or len(items) > resolved_top_k:
            raise KnowledgeRetrievalError(
                "the vector store violated the bounded result contract"
            )

        ordered = self._deterministic_order(items)
        when = retrieved_at if retrieved_at is not None else self._retrieved_at_factory()
        if not isinstance(when, datetime) or when.tzinfo is None:
            raise KnowledgeRetrievalError(
                "retrieved_at must be a timezone-aware datetime"
            )
        if when.tzinfo is None or when.tzinfo.utcoffset(when) is None:
            when = when.astimezone(timezone.utc)

        try:
            context = build_investigation_knowledge_context(
                items=ordered,
                query=stripped,
                top_k=resolved_top_k,
                knowledge_types=resolved_types,
                retrieved_at=when,
                provider=self._vector_store.store_name,
            )
        except ValueError as exc:
            raise KnowledgeRetrievalError(
                "retrieved knowledge failed the final context validations"
            ) from exc
        return context

    @staticmethod
    def _deterministic_order(items: list[KnowledgeItem]) -> list[KnowledgeItem]:
        ordered = list(items)
        ordered.sort(
            key=lambda item: (
                -item.relevance_score,
                str(item.knowledge_id),
            )
        )
        return ordered


def _default_retrieved_at() -> datetime:
    return datetime.now(timezone.utc)