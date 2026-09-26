"""Step 13 — Knowledge chunking tests.

Covers the deterministic ``KnowledgeChunker``: identical input/config ->
identical output, no content loss, no empty chunks, strict chunk-size and
overlap bounds, config validation, aggregate bound protection, no infinite
loop on pathological inputs, and the fact that content is never interpreted.
"""

import pytest

from app.schemas.knowledge import (
    MAX_CHUNK_CONTENT_LENGTH,
    MAX_CHUNKS_PER_DOCUMENT,
    KnowledgeChunk,
)
from app.services.knowledge.chunking import (
    DEFAULT_CHUNK_OVERLAP,
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    KnowledgeChunker,
    chunk_documents,
)
from app.services.knowledge.exceptions import KnowledgeChunkingError
from tests.unit.knowledge_test_helpers import (
    DOC_ID,
    deterministic_uuids,
    make_document,
)

SIZE = 50
OVERLAP = 10


def _chunker(**kw) -> KnowledgeChunker:
    kw.setdefault("chunk_size", SIZE)
    kw.setdefault("chunk_overlap", OVERLAP)
    kw.setdefault("chunk_id_factory", deterministic_uuids("400000"))
    return KnowledgeChunker(**kw)


def _document(text: str, **kw):
    return make_document(content=text, title="Chunking doc", **kw)


def _reconstruct(chunks: list[KnowledgeChunk]) -> str:
    """Build the min/overlap-aware doc text each chunk covers."""
    return "".join(chunk.content for chunk in chunks)


def _is_subsequence(text: str, full: str) -> bool:
    """True when *text* appears as a subsequence of *full* (no loss)."""
    iterator = iter(full)
    return all(char in iterator for char in text)


# ---------------------------------------------------------------------------
# Basics
# ---------------------------------------------------------------------------


def test_single_short_document_one_chunk():
    chunks = _chunker().chunk(_document("short text"))
    assert len(chunks) == 1
    assert chunks[0].content == "short text"
    assert chunks[0].index == 0
    assert chunks[0].document_id == DOC_ID


def test_chunk_preserves_identity_fields():
    chunks = _chunker().chunk(_document("ab " * 100, source="cve-feed"))
    first = chunks[0]
    assert first.source == "cve-feed"
    assert first.document_id == DOC_ID
    assert first.knowledge_type.value  # preserves validated type


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_repeated_chunking_is_identical():
    doc = _document("word " * 500)
    a = _chunker().chunk(doc)
    b = _chunker().chunk(doc)
    assert [c.content for c in a] == [c.content for c in b]
    assert a == b


def test_deterministic_across_identical_documents():
    d1 = _document("word " * 500)
    d2 = _document("word " * 500)
    assert _chunker().chunk(d1) == _chunker().chunk(d2)


# ---------------------------------------------------------------------------
# Bounds and no-loss
# ---------------------------------------------------------------------------


def test_no_chunk_exceeds_chunk_size():
    text = "alpha beta gamma delta epsilon zeta eta theta " * 200
    for chunk in _chunker().chunk(_document(text)):
        assert len(chunk.content) <= SIZE


def test_content_not_lost_across_chunks():
    text = "alpha beta gamma delta epsilon zeta eta theta " * 200
    chunks = _chunker().chunk(_document(text))
    # With overlap, windows duplicate trailing text but must never lose a
    # single character of the document: the document is a subsequence.
    assert _is_subsequence(text, _reconstruct(chunks))


def test_no_empty_chunks():
    text = "alpha beta gamma delta epsilon zeta eta theta " * 200
    for chunk in _chunker().chunk(_document(text)):
        assert chunk.content  # non-empty
        assert chunk.content.strip()


def test_whole_document_preserved_byte_for_byte():
    # With overlap=0, contiguous windows reconstruct the exact document.
    text = "alpha beta gamma delta epsilon zeta eta theta " * 30
    chunker = _chunker(chunk_overlap=0)
    chunks = chunker.chunk(_document(text))
    assert _reconstruct(chunks) == text


def test_overlap_reorders_nothing():
    text = "alpha beta gamma delta epsilon zeta eta theta " * 30
    chunks = _chunker().chunk(_document(text))
    assert chunks[0].index == 0
    for i in range(1, len(chunks)):
        assert chunks[i].index == chunks[i - 1].index + 1


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def test_defaults_are_documented():
    c = KnowledgeChunker()
    assert c.chunk_size == DEFAULT_CHUNK_SIZE == 4000
    assert c.chunk_overlap == DEFAULT_CHUNK_OVERLAP == 200


def test_chunk_size_bounds():
    assert MAX_CHUNK_SIZE == MAX_CHUNK_CONTENT_LENGTH
    with pytest.raises(KnowledgeChunkingError):
        KnowledgeChunker(chunk_size=0)
    with pytest.raises(KnowledgeChunkingError):
        KnowledgeChunker(chunk_size=MAX_CHUNK_CONTENT_LENGTH + 1)
    with pytest.raises(TypeError):
        KnowledgeChunker(chunk_size=2.5)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        KnowledgeChunker(chunk_size=True)  # type: ignore[arg-type]


def test_chunk_overlap_bounds():
    with pytest.raises(KnowledgeChunkingError):
        KnowledgeChunker(chunk_size=50, chunk_overlap=50)
    with pytest.raises(KnowledgeChunkingError):
        KnowledgeChunker(chunk_size=50, chunk_overlap=51)
    with pytest.raises(TypeError):
        KnowledgeChunker(chunk_size=50, chunk_overlap=True)  # type: ignore[arg-type]


def test_invalid_input_type():
    with pytest.raises(KnowledgeChunkingError):
        _chunker().chunk("not-a-document")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Pathological input terminates
# ---------------------------------------------------------------------------


def test_unbroken_token_is_hard_split_deterministically():
    # A run of non-space characters longer than chunk_size is hard split;
    # the split must still terminate, keep chunks non-empty, and stay bounded.
    text = "x" * (SIZE * 3 + 7)
    chunks = _chunker().chunk(_document(text))
    assert chunks
    for chunk in chunks:
        assert 0 < len(chunk.content) <= SIZE
    # Whole token is still fully covered even when split mid-word.
    assert _is_subsequence(text, _reconstruct(chunks))


def test_no_infinite_loop_on_large_document():
    text = ("a b c " * 10000)
    chunks = _chunker().chunk(_document(text))
    assert len(chunks) < 10000
    # Every chunk advanced the position (implicit: loop terminated).


def test_max_chunks_per_document_guard():
    # A configuration with a tiny size and a document at the max bound must
    # refuse to exceed MAX_CHUNKS_PER_DOCUMENT rather than continue forever.
    chunker = KnowledgeChunker(
        chunk_size=1,
        chunk_overlap=0,
        chunk_id_factory=deterministic_uuids("400001"),
    )
    doc = _document("ab" * MAX_CHUNKS_PER_DOCUMENT)
    with pytest.raises(KnowledgeChunkingError):
        chunker.chunk(doc)


def test_chunking_never_evaluates_content():
    # Content that *looks* like code or an instruction is preserved as text.
    doc = _document("print('owned'); os.system('id')")
    chunks = _chunker().chunk(doc)
    assert len(chunks) == 1
    assert "print('owned')" in chunks[0].content
    assert "os.system" in chunks[0].content


# ---------------------------------------------------------------------------
# Bulk chunking
# ---------------------------------------------------------------------------


def test_bulk_chunk_documents_shares_chunker():
    docs = [_document("alpha beta " * 50), _document("gamma delta " * 100)]
    all_chunks = chunk_documents(docs, chunker=_chunker())
    assert len(all_chunks) == len(
        _chunker().chunk(docs[0])
    ) + len(_chunker().chunk(docs[1]))
    assert all(isinstance(c, KnowledgeChunk) for c in all_chunks)