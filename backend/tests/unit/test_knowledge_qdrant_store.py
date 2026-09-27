"""Step 13 — QdrantKnowledgeVectorStore tests.

Exercises the Qdrant wrapper against a fake client so no network is needed:
payload mapping on upsert, hit rebuilding on search, collection
auto-creation, knowledge-type filter construction, strict input validation,
and fail-closed behaviour on out-of-contract hits (bad scores, missing
payloads, malformed ids).  Also verifies the store resolves sane
configuration.
"""

from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas.knowledge import KnowledgeType
from app.services.knowledge.exceptions import KnowledgeVectorStoreError
from app.services.knowledge.qdrant_store import QdrantKnowledgeVectorStore
from tests.unit.knowledge_test_helpers import (
    CHUNK_IDS,
    DOC_ID,
    KNOWLEDGE_IDS,
    make_index_record,
    make_item,
)


class FakeQdrantClient:
    def __init__(self, *, hits: list[Any] | None = None, exists: bool = False) -> None:
        self.hits = hits or []
        self.exists = exists
        self.created: bool = False
        self.create_kwargs: dict[str, Any] | None = None
        self.upsert_kwargs: dict[str, Any] | None = None
        self.query_points_kwargs: dict[str, Any] | None = None

    def get_collection(self, collection_name: str) -> Any:
        if not self.exists:
            raise ValueError("collection not found")
        return SimpleNamespace(name=collection_name)

    def create_collection(self, **kwargs: Any) -> None:
        self.created = True
        self.create_kwargs = kwargs

    def upsert(self, **kwargs: Any) -> None:
        self.upsert_kwargs = kwargs

    def query_points(self, **kwargs: Any) -> Any:
        self.query_points_kwargs = kwargs
        return SimpleNamespace(points=self.hits)


def _store(fake: FakeQdrantClient, **kw) -> QdrantKnowledgeVectorStore:
    kw.setdefault("dimension", 4)
    kw.setdefault("collection", "sentinelai_knowledge_test")
    kw.setdefault("timeout", 5.0)
    kw.setdefault("url", "http://localhost:6333")
    kw.setdefault("qdrant_client", fake)
    return QdrantKnowledgeVectorStore(**kw)


def _hit(chunk_index: int, score: float = 0.8) -> SimpleNamespace:
    return SimpleNamespace(
        id=str(CHUNK_IDS[chunk_index]),
        score=score,
        payload={
            "document_id": str(DOC_ID),
            "index": chunk_index,
            "source": "mitre-attack",
            "title": "Technique knowledge",
            "content": "Known technique: initial access.",
            "knowledge_type": KnowledgeType.MITRE_ATTACK.value,
            "metadata": {},
        },
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_config_resolves_positively():
    fake = FakeQdrantClient()
    store = _store(fake)
    assert store.dimension == 4
    assert store.collection == "sentinelai_knowledge_test"
    assert store.store_name == "qdrant"


@pytest.mark.parametrize(
    "dimension", [0, -2, True, 2.5]
)
def test_invalid_dimension_rejected(dimension):
    with pytest.raises(KnowledgeVectorStoreError):
        QdrantKnowledgeVectorStore(
            dimension=dimension, collection="c", timeout=5.0
        )


@pytest.mark.parametrize("collection", ["", "   "])
def test_blank_collection_rejected(collection):
    with pytest.raises(KnowledgeVectorStoreError):
        QdrantKnowledgeVectorStore(
            dimension=4, collection=collection, timeout=5.0
        )


@pytest.mark.parametrize("timeout", [0, -1, 0.0])
def test_invalid_timeout_rejected(timeout):
    with pytest.raises(KnowledgeVectorStoreError):
        QdrantKnowledgeVectorStore(
            dimension=4, collection="c", timeout=timeout
        )


# ---------------------------------------------------------------------------
# Collection auto-creation
# ---------------------------------------------------------------------------


def test_collection_auto_created_when_missing():
    fake = FakeQdrantClient(exists=False)
    store = _store(fake)
    store.upsert([make_index_record()])
    assert fake.created is True
    assert fake.create_kwargs["vectors_config"].size == 4


def test_collection_not_recreated_when_exists():
    fake = FakeQdrantClient(exists=True)
    store = _store(fake)
    store.upsert([make_index_record()])
    assert fake.created is False


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------


def test_upsert_returns_stored_count():
    fake = FakeQdrantClient()
    store = _store(fake)
    records = [make_index_record(chunk_id=CHUNK_IDS[i]) for i in range(3)]
    assert store.upsert(records) == 3
    points = fake.upsert_kwargs["points"]
    assert len(points) == 3
    assert str(points[0].id) == str(CHUNK_IDS[0])
    assert points[0].payload["knowledge_type"] == KnowledgeType.MITRE_ATTACK.value
    assert points[0].payload["document_id"] == str(DOC_ID)


def test_upsert_empty_sequence_is_noop():
    fake = FakeQdrantClient()
    store = _store(fake)
    assert store.upsert([]) == 0
    assert fake.upsert_kwargs is None


def test_upsert_rejects_non_records():
    fake = FakeQdrantClient()
    store = _store(fake)
    with pytest.raises(KnowledgeVectorStoreError):
        store.upsert(["not-a-record"])  # type: ignore[list-item]
    with pytest.raises(KnowledgeVectorStoreError):
        store.upsert("nope")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


def test_search_rebuilds_items():
    fake = FakeQdrantClient(hits=[_hit(0, 0.9), _hit(1, 0.4)])
    store = _store(fake)
    items = store.search([0.1, 0.2, 0.3, 0.4], limit=2)
    assert len(items) == 2
    assert items[0].knowledge_id == CHUNK_IDS[0]
    assert items[0].relevance_score == 0.9
    assert items[1].relevance_score == 0.4
    assert fake.query_points_kwargs["limit"] == 2


def test_search_passes_knowledge_type_filter():
    fake = FakeQdrantClient(hits=[])
    store = _store(fake)
    store.search(
        [0.1, 0.2, 0.3, 0.4],
        limit=3,
        knowledge_types=[KnowledgeType.MITRE_ATTACK, KnowledgeType.CVE],
    )
    filters = fake.query_points_kwargs["query_filter"]
    assert filters.should[0].key == "knowledge_type"
    assert filters.should[0].match.value == KnowledgeType.MITRE_ATTACK.value


@pytest.mark.parametrize("score", [1.5, -1.5, float("nan"), float("inf")])
def test_search_fails_closed_on_out_of_contract_score(score):
    hit = _hit(0, score)
    fake = FakeQdrantClient(hits=[hit])
    store = _store(fake)
    with pytest.raises(KnowledgeVectorStoreError):
        store.search([0.1, 0.2, 0.3, 0.4], limit=2)


def test_search_fails_closed_on_missing_payload():
    fake = FakeQdrantClient(
        hits=[SimpleNamespace(id="x", score=0.9, payload=None)]
    )
    store = _store(fake)
    with pytest.raises(KnowledgeVectorStoreError):
        store.search([0.1, 0.2, 0.3, 0.4], limit=2)


def test_search_fails_closed_on_malformed_payload():
    fake = FakeQdrantClient(
        hits=[SimpleNamespace(id="nope-not-a-uuid", score=0.9, payload={})]
    )
    store = _store(fake)
    with pytest.raises(KnowledgeVectorStoreError):
        store.search([0.1, 0.2, 0.3, 0.4], limit=2)


def test_search_fails_closed_when_backend_raises():
    class ExplodingClient(FakeQdrantClient):
        def query_points(self, **kwargs):
            raise RuntimeError("backend exploded")

    store = _store(ExplodingClient())
    with pytest.raises(KnowledgeVectorStoreError):
        store.search([0.1, 0.2, 0.3, 0.4], limit=2)


def test_search_validates_limits_via_shared_contract():
    fake = FakeQdrantClient(exists=True)
    store = _store(fake)
    with pytest.raises(KnowledgeVectorStoreError):
        store.search([0.1, 0.2, 0.3, 0.4], limit=0)