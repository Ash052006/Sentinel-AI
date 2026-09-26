"""Knowledge ingestion — Step 13.

Accepts only explicitly supplied, already-validated
:class:`~app.schemas.knowledge.KnowledgeDocument` objects.  There is no
arbitrary web scraping, URL fetching, or external ingestion: documents reach
this layer through a controlled, human- or import-script-supplied path.

The ingester re-scans the document at this trust boundary (fail closed),
delegates splitting to the deterministic chunker, and returns chunks that
carry the document's source identity.  Content is plain text and is never
evaluated or executed here.
"""

from __future__ import annotations

from app.schemas.knowledge import KnowledgeChunk, KnowledgeDocument
from app.services.knowledge.chunking import KnowledgeChunker, KnowledgeChunkingError
from app.services.knowledge.exceptions import (
    KnowledgeIngestionError,
    KnowledgeSafetyError,
)
from app.services.knowledge.safety import assert_knowledge_safe


class KnowledgeDocumentIngester:
    """Validates and deterministically chunks a supplied knowledge document."""

    def __init__(self, *, chunker: KnowledgeChunker | None = None) -> None:
        self.chunker = chunker or KnowledgeChunker()

    def ingest(self, document: KnowledgeDocument) -> list[KnowledgeChunk]:
        """Split *document* into validated knowledge chunks.

        Raises:
            KnowledgeIngestionError: for any non-``KnowledgeDocument`` input,
                secret-shaped content, or chunking failure.  The error message
                never contains document content.
        """
        if not isinstance(document, KnowledgeDocument):
            raise KnowledgeIngestionError(
                "ingestion requires a validated KnowledgeDocument input; "
                f"received {type(document).__name__}"
            )
        try:
            assert_knowledge_safe(
                document.model_dump_json(), "knowledge document"
            )
        except KnowledgeSafetyError as exc:
            raise KnowledgeIngestionError(
                "ingestion rejected the supplied document (secret-shaped "
                "content detected)"
            ) from exc
        try:
            chunks = self.chunker.chunk(document)
        except (KnowledgeChunkingError, ValueError) as exc:
            raise KnowledgeIngestionError(
                "ingestion rejected the supplied document (chunking failed)"
            ) from exc
        return list(chunks)