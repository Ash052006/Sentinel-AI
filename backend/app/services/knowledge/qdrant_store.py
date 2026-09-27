"""Qdrant-backed KnowledgeVectorStore — Step 13.

Wraps the Qdrant client behind :class:`KnowledgeVectorStore` so the
investigation layer never touches Qdrant directly.  The wrapper:

* creates its Qdrant client lazily (the module imports fine without
  ``qdrant-client`` installed);
* auto-creates the collection with the cosine contract if it does not yet
  exist;
* validates every input record, rebuilt item, and score against the
  knowledge contract; any violation fails closed with a sanitized
  :class:`KnowledgeVectorStoreError` (payloads, vectors, and credentials
  never appear in messages).

Qdrant credentials are resolved from settings at construction and are only
ever handed to the Qdrant client; they are never logged or echoed.
"""

from __future__ import annotations

import uuid
from typing import Any, Sequence

from pydantic import BaseModel, ValidationError

from app.core.config import settings
from app.schemas.knowledge import (
    KnowledgeIndexRecord,
    KnowledgeItem,
    KnowledgeType,
)
from app.services.knowledge.exceptions import KnowledgeVectorStoreError
from app.services.knowledge.vector_store import (
    KnowledgeVectorStore,
    _InputContract,
)


class QdrantKnowledgeVectorStore(KnowledgeVectorStore):
    """Knowledge store backed by a Qdrant collection with cosine distance."""

    _store_name = "qdrant"

    def __init__(
        self,
        *,
        dimension: int | None = None,
        collection: str | None = None,
        url: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
        qdrant_client: Any | None = None,
    ) -> None:
        self._dimension = dimension if dimension is not None else settings.embedding_dimension
        self._collection = (
            collection if collection is not None else settings.qdrant_collection
        )
        self._url = url if url is not None else settings.qdrant_url
        self._api_key = api_key if api_key is not None else settings.qdrant_api_key
        self._timeout = (
            timeout if timeout is not None else settings.qdrant_timeout_seconds
        )
        self._external_client = qdrant_client
        self._client: Any | None = None

        if isinstance(self._dimension, bool) or not isinstance(self._dimension, int) or self._dimension < 1:
            raise KnowledgeVectorStoreError(
                "qdrant store requires a positive integer embedding dimension"
            )
        if self._collection is None or not str(self._collection).strip():
            raise KnowledgeVectorStoreError(
                "qdrant store requires a non-blank collection name"
            )
        if (
            isinstance(self._timeout, bool)
            or not isinstance(self._timeout, (int, float))
            or not self._timeout > 0
        ):
            raise KnowledgeVectorStoreError(
                "qdrant store requires a positive numeric timeout"
            )
        self._collection = str(self._collection).strip()

    @property
    def store_name(self) -> str:
        return self._store_name

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def collection(self) -> str:
        return self._collection

    def _resolve_client(self) -> Any:
        if self._external_client is not None:
            return self._external_client
        if self._client is None:
            from qdrant_client import QdrantClient  # lazy: keep import optional

            self._client = QdrantClient(
                url=self._url or None,
                api_key=self._api_key or None,
                timeout=self._timeout,
            )
        return self._client

    def _ensure_collection(self, client: Any) -> None:
        from qdrant_client.http import models as qdrant_models

        try:
            client.get_collection(collection_name=self._collection)
        except Exception:
            try:
                client.create_collection(
                    collection_name=self._collection,
                    vectors_config=qdrant_models.VectorParams(
                        size=self._dimension,
                        distance=qdrant_models.Distance.COSINE,
                    ),
                )
            except Exception as exc:
                raise KnowledgeVectorStoreError(
                    "qdrant collection could not be prepared"
                ) from exc

    def upsert(self, records: Sequence[KnowledgeIndexRecord]) -> int:
        if not isinstance(records, (list, tuple)):
            raise KnowledgeVectorStoreError(
                "upsert expects a sequence of KnowledgeIndexRecord values"
            )
        validated: list[KnowledgeIndexRecord] = []
        for record in records:
            if not isinstance(record, BaseModel) or not isinstance(
                record, KnowledgeIndexRecord
            ):
                raise KnowledgeVectorStoreError(
                    "upsert entries must be validated KnowledgeIndexRecord values"
                )
            validated.append(record)
        if not validated:
            return 0

        from qdrant_client.models import PointStruct

        client = self._resolve_client()
        self._ensure_collection(client)
        points = [
            PointStruct(
                id=str(record.chunk_id),
                vector=list(record.vector),
                payload={
                    "document_id": str(record.document_id),
                    "index": record.index,
                    "source": record.source,
                    "title": record.title,
                    "content": record.content,
                    "knowledge_type": record.knowledge_type.value,
                    "metadata": record.metadata,
                },
            )
            for record in validated
        ]
        try:
            client.upsert(
                collection_name=self._collection, points=points
            )
        except Exception as exc:
            raise KnowledgeVectorStoreError(
                "qdrant upsert failed"
            ) from exc
        return len(validated)

    def search(
        self,
        vector,
        *,
        limit: int,
        knowledge_types: Sequence[KnowledgeType] | None = None,
    ) -> list[KnowledgeItem]:
        _InputContract.check_search_inputs(vector, limit, knowledge_types)
        from qdrant_client.http import models as qdrant_models

        client = self._resolve_client()
        self._ensure_collection(client)

        query_filter: Any = None
        if knowledge_types:
            query_filter = qdrant_models.Filter(
                should=[
                    qdrant_models.FieldCondition(
                        key="knowledge_type",
                        match=qdrant_models.MatchValue(value=kt.value),
                    )
                    for kt in knowledge_types
                ]
            )

        try:
            response = client.query_points(
                collection_name=self._collection,
                query=list(vector),
                limit=limit,
                query_filter=query_filter,
                with_payload=True,
            )
            hits = response.points
        except Exception as exc:
            raise KnowledgeVectorStoreError(
                "qdrant search failed"
            ) from exc

        items: list[KnowledgeItem] = []
        for hit in hits:
            payload = getattr(hit, "payload", None)
            if not isinstance(payload, dict):
                raise KnowledgeVectorStoreError(
                    "qdrant returned a hit without a payload"
                )
            items.append(self._rebuild_item(hit, payload))
        return items

    @staticmethod
    def _rebuild_item(hit: Any, payload: dict[str, Any]) -> KnowledgeItem:
        chunk_id = getattr(hit, "id", None)
        if chunk_id is None:
            raise KnowledgeVectorStoreError(
                "qdrant returned a hit without an identity"
            )
        score = getattr(hit, "score", None)
        try:
            if not isinstance(score, (int, float)) or isinstance(score, bool):
                raise ValueError("score must be numeric")
            item = KnowledgeItem(
                knowledge_id=uuid.UUID(str(chunk_id)),
                source=str(payload.get("source", "")),
                title=str(payload.get("title", "")),
                content=str(payload.get("content", "")),
                knowledge_type=KnowledgeType(payload.get("knowledge_type")),
                relevance_score=float(score),
                metadata=payload.get("metadata", {})
                if isinstance(payload.get("metadata", {}), dict)
                else {},
            )
        except (ValueError, ValidationError, TypeError, KeyError) as exc:
            raise KnowledgeVectorStoreError(
                "qdrant returned a payload outside the knowledge contract"
            ) from exc
        return item