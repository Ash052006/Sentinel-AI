"""Investigation Knowledge & RAG Layer services (Step 13).

Packaging note: nothing in this package imports ``qdrant-client`` at module
scope.  The Qdrant store imports the client lazily inside methods, so the
RAG layer (and the whole dependency-isolation test surface) imports fine in
any environment.
"""

from __future__ import annotations

from app.services.knowledge.chunking import (
    DEFAULT_CHUNK_OVERLAP,
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_OVERLAP,
    MAX_CHUNK_SIZE,
    KnowledgeChunker,
    chunk_documents,
)
from app.services.knowledge.embeddings import (
    DeterministicEmbeddingProvider,
    EmbeddingProvider,
    create_embedding_provider,
    validate_embedding_vector,
)
from app.services.knowledge.exceptions import (
    KnowledgeChunkingError,
    KnowledgeConfigError,
    KnowledgeEmbeddingError,
    KnowledgeIngestionError,
    KnowledgeLayerError,
    KnowledgeRetrievalError,
    KnowledgeSafetyError,
    KnowledgeVectorStoreError,
)
from app.services.knowledge.ingestion import KnowledgeDocumentIngester
from app.services.knowledge.qdrant_store import QdrantKnowledgeVectorStore
from app.services.knowledge.retriever import InvestigationKnowledgeRetriever
from app.services.knowledge.vector_store import KnowledgeVectorStore

__all__ = [
    "DEFAULT_CHUNK_OVERLAP",
    "DEFAULT_CHUNK_SIZE",
    "MAX_CHUNK_OVERLAP",
    "MAX_CHUNK_SIZE",
    "KnowledgeChunker",
    "chunk_documents",
    "DeterministicEmbeddingProvider",
    "EmbeddingProvider",
    "create_embedding_provider",
    "validate_embedding_vector",
    "KnowledgeChunkingError",
    "KnowledgeConfigError",
    "KnowledgeEmbeddingError",
    "KnowledgeIngestionError",
    "KnowledgeLayerError",
    "KnowledgeRetrievalError",
    "KnowledgeSafetyError",
    "KnowledgeVectorStoreError",
    "KnowledgeDocumentIngester",
    "QdrantKnowledgeVectorStore",
    "InvestigationKnowledgeRetriever",
    "KnowledgeVectorStore",
]