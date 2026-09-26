"""Step 13 — KnowledgeVectorStore contract tests.

Verifies the storage/search abstraction through a recording fake: the
``store_name`` identifier, bounded search input validation (vector, limit,
knowledge types), and the strict result-contract enforcement the retriever
relies on.
"""

import pytest

from app.schemas.knowledge import KnowledgeType
from app.schemas.knowledge_context import MAX_RETRIEVAL_TOP_K
from app.services.knowledge.exceptions import KnowledgeVectorStoreError
from app.services.knowledge.vector_store import (
    KnowledgeVectorStore,
    _InputContract,
)
from tests.unit.knowledge_test_helpers import (
    KNOWLEDGE_IDS,
    RecordingKnowledgeVectorStore,
    make_item,
)


def test_store_name_is_required_identifier():
    store = RecordingKnowledgeVectorStore(store_name="fake-store")
    assert store.store_name == "fake-store"


def test_knowledge_vector_store_is_abstract():
    with pytest.raises(TypeError):
        KnowledgeVectorStore()  # type: ignore[abstract]


def test_search_input_contract_rejects_bad_vector():
    store = RecordingKnowledgeVectorStore()
    for bad in ([], [float("nan")], [float("inf")], ["x"]):
        with pytest.raises((KnowledgeVectorStoreError, TypeError)):
            store.search(bad, limit=3)


@pytest.mark.parametrize("bad_limit", [0, -1, MAX_RETRIEVAL_TOP_K + 1, 2.5, True])
def test_search_input_contract_rejects_bad_limit(bad_limit):
    store = RecordingKnowledgeVectorStore()
    with pytest.raises((KnowledgeVectorStoreError, TypeError)):
        store.search([0.1, 0.2], limit=bad_limit)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_types",
    [("mitre-attack",), ("sigma", 42)],
)
def test_search_input_contract_rejects_non_enum_filters(bad_types):
    store = RecordingKnowledgeVectorStore()
    with pytest.raises(KnowledgeVectorStoreError):
        store.search([0.1, 0.2], limit=3, knowledge_types=bad_types)  # type: ignore[arg-type]


def test_search_input_contract_rejects_scalar_filters():
    store = RecordingKnowledgeVectorStore()
    with pytest.raises(KnowledgeVectorStoreError):
        store.search([0.1, 0.2], limit=3, knowledge_types=KnowledgeType.SIGMA)  # type: ignore[arg-type]


def test_search_returns_items_in_store_order():
    items = [
        make_item(knowledge_id=KNOWLEDGE_IDS[0], relevance_score=0.7),
        make_item(knowledge_id=KNOWLEDGE_IDS[1], relevance_score=0.9),
    ]
    store = RecordingKnowledgeVectorStore(items=items)
    result = store.search([0.1, 0.2], limit=3)
    assert result == items


def test_input_contract_direct_check(monkeypatch):
    # The shared helper is usable by all concrete stores.
    from app.services.knowledge.vector_store import _InputContract

    _InputContract.check_search_inputs(
        [0.1, 0.2], 3, [KnowledgeType.CVE]
    )
    with pytest.raises(KnowledgeVectorStoreError):
        _InputContract.check_search_inputs([0.1], 0, None)