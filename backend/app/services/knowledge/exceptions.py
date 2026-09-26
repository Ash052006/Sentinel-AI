"""Operational error hierarchy for the Knowledge & RAG layer (Step 13).

Schema-level validation errors live in
``app/schemas/knowledge.py`` (``KnowledgeValidationError`` /
``KnowledgeBoundError``).  This module defines the operational errors raised
by the ingestion, chunking, embedding, vector-store, and retrieval services.
All messages are sanitized: they never carry document content, embeddings,
vectors, connection details, or credentials.  Causes are chained internally.
"""

from __future__ import annotations


class KnowledgeLayerError(Exception):
    """Base error for the Knowledge & RAG layer."""


class KnowledgeConfigError(KnowledgeLayerError):
    """Missing or invalid configuration (embedding provider, vector store)."""


class KnowledgeIngestionError(KnowledgeLayerError):
    """A knowledge document could not be ingested safely."""


class KnowledgeChunkingError(KnowledgeLayerError):
    """A document could not be split deterministically within its bounds."""


class KnowledgeEmbeddingError(KnowledgeLayerError):
    """An embedding could not be produced or validated."""


class KnowledgeVectorStoreError(KnowledgeLayerError):
    """A vector-store operation failed or returned an invalid response."""


class KnowledgeRetrievalError(KnowledgeLayerError):
    """A retrieval request was invalid, unbounded, or failed."""


class KnowledgeSafetyError(KnowledgeLayerError, ValueError):
    """Credential-shaped content was detected in knowledge data (fail closed).

    Subclasses both ``KnowledgeLayerError`` and ``ValueError`` so both the
    schema-validation paths and the service paths can catch and reclassify
    it deterministically.
    """