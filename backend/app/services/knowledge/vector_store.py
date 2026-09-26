"""Vector-store abstraction — Step 13.

``KnowledgeVectorStore`` is the only seam through which knowledge vectors
are stored and searched.  Nothing in the investigation layer talks to Qdrant
(or any backend) directly; concrete stores map validated records to their
backend and rebuild backend results back into
:class:`~app.schemas.knowledge.KnowledgeItem` values.

The search contract is strict on purpose:

* vectors must be validated (finite, non-empty);
* ``limit`` is bounded to ``[1, MAX_RETRIEVAL_TOP_K]``;
* ``knowledge_types`` filters, when supplied, must be real
  ``KnowledgeType`` members;
* results must be returned inside the score contract ``[-1.0, 1.0]``;
* malformed backend payloads and out-of-contract results fail closed
  (never silently dropped or coerced).
"""

from __future__ import annotations

import abc
from typing import Sequence

from app.schemas.knowledge import (
    KnowledgeIndexRecord,
    KnowledgeItem,
    KnowledgeType,
)
from app.schemas.knowledge_context import MAX_RETRIEVAL_TOP_K
from app.services.knowledge.embeddings import validate_embedding_vector
from app.services.knowledge.exceptions import KnowledgeVectorStoreError


class KnowledgeVectorStore(abc.ABC):
    """Storage/search boundary for knowledge index records."""

    @property
    @abc.abstractmethod
    def store_name(self) -> str:
        """Stable provider identifier surfaced in retrieval metadata."""

    @abc.abstractmethod
    def upsert(self, records: Sequence[KnowledgeIndexRecord]) -> int:
        """Store validated index records; return the number stored."""

    @abc.abstractmethod
    def search(
        self,
        vector: Sequence[float],
        *,
        limit: int,
        knowledge_types: Sequence[KnowledgeType] | None = None,
    ) -> list[KnowledgeItem]:
        """Vector search bounded by *limit* and optional type filters."""


class _InputContract:
    """Shared input validation used by concrete stores."""

    @staticmethod
    def check_search_inputs(
        vector: Sequence[float],
        limit: int,
        knowledge_types: Sequence[KnowledgeType] | None,
    ) -> None:
        try:
            validate_embedding_vector(vector)
        except Exception as exc:
            raise KnowledgeVectorStoreError(
                "search vector is outside the embedding contract"
            ) from exc
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise KnowledgeVectorStoreError("search limit must be an integer")
        if not 1 <= limit <= MAX_RETRIEVAL_TOP_K:
            raise KnowledgeVectorStoreError(
                f"search limit must be within [1, MAX_RETRIEVAL_TOP_K="
                f"{MAX_RETRIEVAL_TOP_K}]; got {limit}"
            )
        if knowledge_types is not None:
            if isinstance(knowledge_types, (str, KnowledgeType)):
                raise KnowledgeVectorStoreError(
                    "knowledge_types must be a sequence of KnowledgeType"
                )
            for kt in knowledge_types:
                if not isinstance(kt, KnowledgeType):
                    raise KnowledgeVectorStoreError(
                        "knowledge_types entries must be KnowledgeType members; "
                        f"received {type(kt).__name__}"
                    )