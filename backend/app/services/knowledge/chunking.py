"""Deterministic knowledge chunking — Step 13.

Splits a trusted knowledge document into bounded, overlapping chunks that
preserve the source identity and never lose content:

* **Deterministic** — identical text + identical configuration produce
  byte-identical chunks (chunk *identities* come from an injectable
  factory).  No random splitting, no current-time influence.
* **Bounded** — every chunk content is at most ``chunk_size`` characters;
  configured sizes and the total chunk count are validated up front.
* **No content loss / no empty chunks** — chunk boundaries cut on the last
  whitespace of the window and re-include the trailing separator so the
  concatenation of chunks covers the whole document; each chunk is
  non-empty and advances by at least one character, which also guarantees
  termination (plus an explicit chunk-count bound as defence-in-depth).
* **No interpretation** — content is plain text and is never evaluated,
  executed, or parsed as an interpreted artifact.
"""

from __future__ import annotations

import uuid
from typing import Callable, Sequence

from app.schemas.knowledge import (
    MAX_CHUNKS_PER_DOCUMENT,
    MAX_CHUNK_CONTENT_LENGTH,
    KnowledgeBoundError,
    KnowledgeChunk,
    KnowledgeDocument,
)
from app.services.knowledge.exceptions import (
    KnowledgeChunkingError,
)

#: Default chunk size (characters) when not configured.
DEFAULT_CHUNK_SIZE = 4000

#: Default overlap between consecutive chunks (characters).
DEFAULT_CHUNK_OVERLAP = 200

#: Maximum configurable chunk size: never above the schema content bound.
MAX_CHUNK_SIZE = MAX_CHUNK_CONTENT_LENGTH

#: Maximum configurable overlap: always strictly below ``chunk_size``.
MAX_CHUNK_OVERLAP = 1000


def _last_whitespace_end(text: str, start: int, end: int) -> int:
    """Return the position just after the last whitespace in ``[start, end)``.

    Returns ``end`` when there is no whitespace (the window is cut at its
    end; mid-word splitting is the deterministic fallback for an unbroken
    run of non-space characters).
    """
    for i in range(end - 1, start - 1, -1):
        if text[i].isspace():
            return i + 1
    return end


class KnowledgeChunker:
    """Deterministic, bounded chunker producing ``KnowledgeChunk`` records."""

    def __init__(
        self,
        *,
        chunk_size: int | None = None,
        chunk_overlap: int | None = None,
        chunk_id_factory: Callable[[], uuid.UUID] | None = None,
    ) -> None:
        self.chunk_size = chunk_size if chunk_size is not None else DEFAULT_CHUNK_SIZE
        self.chunk_overlap = (
            chunk_overlap if chunk_overlap is not None else DEFAULT_CHUNK_OVERLAP
        )
        self._chunk_id_factory = chunk_id_factory or uuid.uuid4

        if not isinstance(self.chunk_size, int) or isinstance(self.chunk_size, bool):
            raise TypeError("chunk_size must be a positive integer")
        if not 1 <= self.chunk_size <= MAX_CHUNK_SIZE:
            raise KnowledgeChunkingError(
                f"chunk_size must be in [1, MAX_CHUNK_SIZE={MAX_CHUNK_SIZE}]; "
                f"got {self.chunk_size}"
            )
        if not isinstance(self.chunk_overlap, int) or isinstance(self.chunk_overlap, bool):
            raise TypeError("chunk_overlap must be a non-negative integer")
        if not 0 <= self.chunk_overlap < self.chunk_size:
            raise KnowledgeChunkingError(
                "chunk_overlap must be in [0, chunk_size); overlapping more "
                "than the whole chunk would break the bound contract"
            )
        if self.chunk_overlap > MAX_CHUNK_OVERLAP:
            raise KnowledgeChunkingError(
                f"chunk_overlap exceeds MAX_CHUNK_OVERLAP={MAX_CHUNK_OVERLAP}"
            )

    def chunk(
        self, document: KnowledgeDocument
    ) -> list[KnowledgeChunk]:
        """Split *document* into deterministic, bounded chunks.

        Raises:
            KnowledgeChunkingError: on invalid input or when the chunk-count
                bound would be exceeded.
        """
        if not isinstance(document, KnowledgeDocument):
            raise KnowledgeChunkingError(
                "chunking requires a validated KnowledgeDocument input; "
                f"received {type(document).__name__}"
            )
        text = document.content
        chunks = self._split_text(
            text,
            document_id=document.document_id,
            source=document.source,
            title=document.title,
            knowledge_type=document.knowledge_type,
            metadata=document.metadata,
        )
        return chunks

    def _split_text(
        self,
        text: str,
        *,
        document_id: uuid.UUID,
        source: str,
        title: str,
        knowledge_type,
        metadata: dict,
    ) -> list[KnowledgeChunk]:
        size = self.chunk_size
        overlap = self.chunk_overlap
        n = len(text)
        if n == 0:
            raise KnowledgeChunkingError(
                "a knowledge document with empty content cannot be chunked"
            )

        result: list[KnowledgeChunk] = []
        pos = 0
        index = 0
        while pos < n:
            end = min(pos + size, n)
            if pos + size >= n:
                # Final window: take the whole remainder so a short tail is
                # never trimmed for word boundaries.
                cut = n
            else:
                cut = _last_whitespace_end(text, pos, end)
            content = text[pos:cut]

            result.append(
                KnowledgeChunk(
                    chunk_id=self._chunk_id_factory(),
                    document_id=document_id,
                    index=index,
                    source=source,
                    title=title,
                    content=content,
                    knowledge_type=knowledge_type,
                    metadata=metadata,
                )
            )
            index += 1
            if index > MAX_CHUNKS_PER_DOCUMENT:
                raise KnowledgeChunkingError(
                    f"chunking exceeded MAX_CHUNKS_PER_DOCUMENT="
                    f"{MAX_CHUNKS_PER_DOCUMENT}; refusing to continue"
                )

            if cut == n:
                break

            nxt = cut - overlap
            if nxt <= pos:
                # Degenerate short window: the overlap cannot be honoured
                # without stalling; advance deterministically past this chunk.
                nxt = cut
            pos = nxt
        return result


def chunk_documents(
    documents: Sequence[KnowledgeDocument],
    *,
    chunker: KnowledgeChunker | None = None,
) -> list[KnowledgeChunk]:
    """Convenience: chunk many documents with one shared chunker."""
    chunker = chunker or KnowledgeChunker()
    out: list[KnowledgeChunk] = []
    for document in documents:
        out.extend(chunker.chunk(document))
    if len(out) > MAX_CHUNKS_PER_DOCUMENT * len(documents):
        raise KnowledgeBoundError(
            "aggregate chunk count exceeded its bound during bulk chunking"
        )
    return out