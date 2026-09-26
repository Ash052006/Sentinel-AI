"""Step 13 — Knowledge schema contract tests.

Covers the strict, bounded, secret-safe knowledge contracts: the shared
bounds, ``KnowledgeType``, ``KnowledgeDocument``, ``KnowledgeChunk``,
``KnowledgeItem``, and ``KnowledgeIndexRecord`` — including blank/oversized
content, metadata depth/size bounds, vector validity, score bounds, and
refuse-to-carry secret behaviour at every layer.
"""

import math
import uuid

import pytest
from pydantic import ValidationError

from app.schemas.knowledge import (
    MAX_CHUNKS_PER_DOCUMENT,
    MAX_CHUNK_CONTENT_LENGTH,
    MAX_KNOWLEDGE_DOCUMENT_CONTENT_LENGTH,
    MAX_KNOWLEDGE_METADATA_DEPTH,
    MAX_KNOWLEDGE_METADATA_SERIALIZED_BYTES,
    MAX_KNOWLEDGE_SOURCE_LENGTH,
    MAX_KNOWLEDGE_TITLE_LENGTH,
    KnowledgeBoundError,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeIndexRecord,
    KnowledgeItem,
    KnowledgeType,
    KnowledgeValidationError,
)
from tests.unit.knowledge_test_helpers import (
    CHUNK_IDS,
    DOC_ID,
    KNOWLEDGE_IDS,
    make_chunk,
    make_document,
    make_index_record,
    make_item,
)

# ---------------------------------------------------------------------------
# KnowledgeType
# ---------------------------------------------------------------------------


def test_knowledge_type_enum_is_bounded_enum():
    assert issubclass(KnowledgeType, str)
    assert KnowledgeType.MITRE_ATTACK == "mitre_attack"
    assert len(KnowledgeType) == 8


def test_knowledge_type_rejects_arbitrary_strings():
    with pytest.raises(ValueError):
        KnowledgeType("whatever-free-form")
    with pytest.raises(ValueError):
        KnowledgeType(None)


# ---------------------------------------------------------------------------
# KnowledgeDocument
# ---------------------------------------------------------------------------


def test_document_requires_all_fields():
    with pytest.raises(ValidationError):
        KnowledgeDocument()  # type: ignore[call-arg]


def test_document_blank_source_rejected():
    with pytest.raises(ValidationError):
        make_document(source="   ")


def test_document_oversized_source_rejected():
    with pytest.raises(ValidationError, match="exceeds its bound"):
        make_document(source="x" * (MAX_KNOWLEDGE_SOURCE_LENGTH + 1))


def test_document_oversized_title_rejected():
    with pytest.raises(ValidationError, match="exceeds its bound"):
        make_document(title="x" * (MAX_KNOWLEDGE_TITLE_LENGTH + 1))


def test_document_blank_content_rejected():
    with pytest.raises(ValidationError):
        make_document(content="\n\t ")


def test_document_oversized_content_rejected_never_truncated():
    with pytest.raises(ValidationError, match="MAX_KNOWLEDGE_DOCUMENT_CONTENT_LENGTH"):
        make_document(content="x" * (MAX_KNOWLEDGE_DOCUMENT_CONTENT_LENGTH + 1))


def _too_deep_metadata() -> dict:
    """A metadata payload nested beyond the documented MAX_DEPTH=8."""
    root: dict = {}
    node = root
    for i in range(9):
        child: dict = {}
        node[str(i)] = child
        node = child
    return root


def _too_big_metadata() -> dict:
    return {"x": "y" * MAX_KNOWLEDGE_METADATA_SERIALIZED_BYTES}


@pytest.mark.parametrize(
    "bad_metadata",
    [_too_deep_metadata(), _too_big_metadata()],
)
def test_document_metadata_bounds(bad_metadata):
    with pytest.raises(ValidationError, match="exceeds"):
        make_document(metadata=bad_metadata)


def test_document_metadata_non_json_rejected():
    with pytest.raises(ValidationError):
        make_document(metadata={"blob": object()})


@pytest.mark.parametrize(
    "secret",
    [
        {"api_key": "sk-live"},
        {"note": "contains password=hunter2"},
        {"deep": {"jwt": "eyJ"}},
        {"session_token": "abc"},
        {"cookie": "yes"},
        {"authorization": "frob"},
        {"bearer": "x"},
        {"secret": "y"},
    ],
)
def test_document_refuses_secret_shaped_metadata(secret):
    with pytest.raises(ValidationError):
        make_document(metadata=secret)


@pytest.mark.parametrize(
    "content",
    [
        "plain security vocabulary can be ordinary log content",
        "credential rotation telemetry is data, not instructions",
    ],
)
def test_document_plain_keyword_content_is_data(content):
    # The refuse-to-carry rule protects credential-shaped *values*; plain
    # security vocabulary remains legitimate knowledge data.
    doc = make_document(content=content)
    assert doc.content == content


# ---------------------------------------------------------------------------
# KnowledgeChunk
# ---------------------------------------------------------------------------


def test_chunk_requires_all_fields():
    with pytest.raises(ValidationError):
        KnowledgeChunk()  # type: ignore[call-arg]


def test_chunk_content_bound_rejects():
    with pytest.raises(ValidationError, match="MAX_CHUNK_CONTENT_LENGTH"):
        make_chunk(content="x" * (MAX_CHUNK_CONTENT_LENGTH + 1))


def test_chunk_blank_content_rejected():
    with pytest.raises(ValidationError):
        make_chunk(content="   ")


def test_chunk_preserves_document_identity():
    chunk = make_chunk(chunk_id=CHUNK_IDS[2], document_id=DOC_ID, index=3)
    assert chunk.chunk_id == CHUNK_IDS[2]
    assert chunk.document_id == DOC_ID
    assert chunk.index == 3


def test_chunk_metadata_bounds():
    with pytest.raises(ValidationError, match="exceeds"):
        make_chunk(metadata={"x": "y" * MAX_KNOWLEDGE_METADATA_SERIALIZED_BYTES})


def test_chunk_refuses_secrets():
    with pytest.raises(ValidationError):
        make_chunk(content="the api_key is sk-live-1234")


# ---------------------------------------------------------------------------
# KnowledgeItem
# ---------------------------------------------------------------------------


def test_item_requires_all_fields():
    with pytest.raises(ValidationError):
        KnowledgeItem()  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "score",
    [1.5, -1.5, math.nan, math.inf, -math.inf, "high"],
)
def test_item_relevance_score_bound(score):
    with pytest.raises((ValidationError, TypeError)):
        make_item(relevance_score=score)


@pytest.mark.parametrize("score", [-1.0, 0.0, 0.5, 1.0])
def test_item_relevance_score_inside_contract(score):
    item = make_item(relevance_score=score)
    assert item.relevance_score == score


def test_item_content_bound_rejects():
    with pytest.raises(ValidationError, match="MAX_CHUNK_CONTENT_LENGTH"):
        make_item(content="x" * (MAX_CHUNK_CONTENT_LENGTH + 1))


def test_item_refuses_secrets():
    with pytest.raises(ValidationError):
        make_item(content="rotating bearer token abc")


def test_item_knowledge_id_distinct_from_evidence():
    item = make_item(knowledge_id=KNOWLEDGE_IDS[0])
    assert item.knowledge_id != DOC_ID


# ---------------------------------------------------------------------------
# KnowledgeIndexRecord
# ---------------------------------------------------------------------------


def test_index_record_requires_all_fields():
    with pytest.raises(ValidationError):
        KnowledgeIndexRecord()  # type: ignore[call-arg]


def test_index_record_empty_vector_rejected():
    with pytest.raises(ValidationError):
        make_index_record(vector=[])


@pytest.mark.parametrize(
    "bad_vector",
    [
        [0.1, math.nan, 0.3],
        [0.1, math.inf],
        [0.1, "x"],
        [0.1, 0.2, None],
    ],
)
def test_index_record_vector_must_be_finite_numbers(bad_vector):
    with pytest.raises((ValidationError, TypeError)):
        make_index_record(vector=bad_vector)


def test_index_record_coerces_numbers_to_floats():
    record = make_index_record(vector=[1, 2, 3])
    assert record.vector == [1.0, 2.0, 3.0]


def test_index_record_refuses_secrets():
    with pytest.raises(ValidationError):
        make_index_record(content="session_token=abc123")


def test_index_record_negative_index_rejected():
    with pytest.raises(ValidationError):
        make_index_record(index=-1)


# ---------------------------------------------------------------------------
# Shared error hierarchy
# ---------------------------------------------------------------------------


def test_error_hierarchy():
    assert issubclass(KnowledgeBoundError, KnowledgeValidationError)
    assert issubclass(KnowledgeValidationError, ValueError)
    assert KnowledgeBoundError("x")  # instantiable
    assert KnowledgeValidationError("y")


def test_bounds_are_explicit_positive_integers():
    assert MAX_CHUNKS_PER_DOCUMENT == 10_000
    assert MAX_CHUNK_CONTENT_LENGTH == 8000
    assert MAX_KNOWLEDGE_METADATA_DEPTH == 8
    assert MAX_KNOWLEDGE_METADATA_SERIALIZED_BYTES == 4 * 1024
    assert MAX_KNOWLEDGE_SOURCE_LENGTH == 256
    assert MAX_KNOWLEDGE_TITLE_LENGTH == 512
    assert MAX_KNOWLEDGE_DOCUMENT_CONTENT_LENGTH == 1_000_000
    assert all(v > 0 for v in (MAX_CHUNKS_PER_DOCUMENT, MAX_CHUNK_CONTENT_LENGTH))


def test_immutable_by_convention_metadata():
    metadata = {"source": "internal"}
    doc = make_document(metadata=metadata)
    metadata["source"] = "mutated"
    assert doc.metadata == {"source": "internal"}