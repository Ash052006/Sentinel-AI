"""Knowledge contracts for the Investigation Knowledge & RAG Layer (Step 13).

Defines the strict, bounded, secret-safe representation of **retrieved
security knowledge** used by the AI Investigation Agent (Step 12C).

The layer's single most important rule is the **evidence / knowledge
separation**::

    ACTUAL EVIDENCE     = what SentinelAI observed or received from
                          authoritative sources (InvestigationEvidence).
    RAG KNOWLEDGE       = background reference material retrieved from a
                          knowledge base (KnowledgeItem).
    AI INVESTIGATION    = Gemini's reasoning over the supplied evidence and
                          retrieved knowledge (InvestigationResult).

This module deliberately does **not** reuse ``InvestigationEvidence`` for
knowledge and does **not** attach security-event provenance (``OBSERVED``,
``DETECTED``, ``CORRELATED``, ``RISK_ASSESSED``) or ``AI_GENERATED``
provenance to knowledge.  Retrieved knowledge is classified by an explicit
:class:`KnowledgeType` and a human-readable ``source`` only.

Design principles (mirroring the existing SentinelAI contracts — Step 9A
detection, Step 12B investigation context):

* **Allowlisting** — documents, chunks, and items carry only the fields this
  layer needs; no free-form serialization of arbitrary objects.
* **Bounded** — explicit constants bound string lengths, list sizes, payload
  sizes, and total RAG payload size.  Bounds **reject** rather than silently
  truncate security knowledge.
* **Secret-safe** — the repository refuse-to-carry pattern
  (``api_key``/``authorization``/``bearer``/``secret`` plus the credential
  families ``password``/``cookie``/``session_token``/``jwt``) is applied to
  every knowledge artifact at construction.
* **Immutable-by-convention** — validators return independent JSON clones;
  consumers never share mutable mappings with sources.
* **Dependency-light** — stdlib + Pydantic only.  No SQLAlchemy, FastAPI,
  Kafka, HTTP clients, Qdrant, or AI frameworks.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Bounds — explicit, documented, conservative limits for the RAG layer.
# ---------------------------------------------------------------------------

#: Maximum length of a knowledge source identifier (e.g. ``mitre-attack``,
#: ``sigma-hunting``, ``internal-soc``).  Refused, not truncated.
MAX_KNOWLEDGE_SOURCE_LENGTH = 256

#: Maximum length of a knowledge title / heading.
MAX_KNOWLEDGE_TITLE_LENGTH = 512

#: Maximum length of one chunk's content (an indexed unit).  Chunking splits
#: larger documents deterministically so no single chunk exceeds this.
MAX_CHUNK_CONTENT_LENGTH = 8000

#: Maximum length of an ingested document's full content.  Documents larger
#: than this are **rejected** (never silently truncated).
MAX_KNOWLEDGE_DOCUMENT_CONTENT_LENGTH = 1_000_000

#: Maximum serialized size of a knowledge metadata payload: 4 KiB.
MAX_KNOWLEDGE_METADATA_SERIALIZED_BYTES = 4 * 1024

#: Maximum container nesting depth for a metadata payload.
MAX_KNOWLEDGE_METADATA_DEPTH = 8

#: Maximum number of chunks produced from a single document.
MAX_CHUNKS_PER_DOCUMENT = 10_000

#: Maximum number of knowledge items an InvestigationKnowledgeContext may
#: hold (a retrieval is further bounded by ``MAX_RETRIEVAL_TOP_K``).
MAX_KNOWLEDGE_ITEMS = 50


# ---------------------------------------------------------------------------
# Knowledge-schema errors (deterministic, sanitized).
# ---------------------------------------------------------------------------


class KnowledgeValidationError(ValueError):
    """Base error for knowledge contract validation."""


class KnowledgeBoundError(KnowledgeValidationError):
    """A documented knowledge bound was exceeded; the artifact was refused."""


# ---------------------------------------------------------------------------
# Knowledge type — explicit, bounded, extensible-by-edit enum.
# ---------------------------------------------------------------------------


class KnowledgeType(str, Enum):
    """The bounded taxonomy of retrievable security knowledge.

    Adding a category is a deliberate code-level change (extensible without
    allowing arbitrary free-form strings): the enum is validated at every
    contract boundary, so an unknown string can never masquerade as a known
    knowledge type.
    """

    MITRE_ATTACK = "mitre_attack"
    SIGMA = "sigma"
    YARA = "yara"
    CVE = "cve"
    MALWARE = "malware"
    ATTACK_PATTERN = "attack_pattern"
    SECURITY_DOCUMENTATION = "security_documentation"
    INTERNAL_SECURITY_KNOWLEDGE = "internal_security_knowledge"


# ---------------------------------------------------------------------------
# Secret-safety helpers (lock-step with the Step 12B / Step 12C sets).
# ---------------------------------------------------------------------------

#: Forbidden credential-shaped strings, kept in lock-step with
#: ``app/schemas/investigation_context.py`` and
#: ``app/agents/investigation/_safety.py``.
_SECRET_PATTERNS = (
    "api_key",
    "authorization",
    "bearer",
    "secret",
    "password",
    "cookie",
    "session_token",
    "jwt",
)


def _assert_json_compatible(value: Any, field: str) -> None:
    """Raise ValueError when *value* is not strictly JSON-serializable."""
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{field} must be JSON-compatible: {exc}"
        ) from exc


def _assert_no_secrets(value: Any, field: str) -> None:
    """Raise ValueError when *value* contains common secret patterns."""
    serialized = json.dumps(value).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"{field} must not contain secrets ('{pattern}' detected)"
            )


def _json_clone(value: dict[str, Any]) -> dict[str, Any]:
    """Return an independent, JSON-compatible deep copy of *value*."""
    return json.loads(json.dumps(value))


def _container_depth(value: Any) -> int:
    """Measure the deepest container-nesting chain (root counts as depth 1)."""
    if isinstance(value, dict):
        return 1 + max(
            (_container_depth(child) for child in value.values()),
            default=0,
        )
    if isinstance(value, (list, tuple)):
        return 1 + max(
            (_container_depth(child) for child in value),
            default=0,
        )
    return 0


def _validate_control_payload(
    value: dict[str, Any], field: str
) -> dict[str, Any]:
    """Validate a structured payload and return an independent clone."""
    _assert_json_compatible(value, field)
    _assert_no_secrets(value, field)
    depth = _container_depth(value)
    if depth > MAX_KNOWLEDGE_METADATA_DEPTH:
        raise KnowledgeBoundError(
            f"{field} exceeds MAX_KNOWLEDGE_METADATA_DEPTH="
            f"{MAX_KNOWLEDGE_METADATA_DEPTH} (nesting depth {depth})"
        )
    size = len(json.dumps(value).encode("utf-8"))
    if size > MAX_KNOWLEDGE_METADATA_SERIALIZED_BYTES:
        raise KnowledgeBoundError(
            f"{field} exceeds MAX_KNOWLEDGE_METADATA_SERIALIZED_BYTES="
            f"{MAX_KNOWLEDGE_METADATA_SERIALIZED_BYTES} "
            f"(serialized size {size})"
        )
    return _json_clone(value)


def _bound_string(value: str, field: str, max_length: int) -> str:
    """Enforce a string bound without mutating the value."""
    if not value.strip():
        raise ValueError(f"{field} must not be blank")
    if len(value) > max_length:
        raise KnowledgeBoundError(
            f"{field} exceeds its bound of {max_length} (length {len(value)})"
        )
    return value


def _ensure_timezone_aware(value: datetime, field: str) -> None:
    """Reject naive (timezone-unaware) timestamps."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(
            f"{field} must be timezone-aware; naive timestamps are not accepted"
        )


# ---------------------------------------------------------------------------
# KnowledgeDocument — trusted ingestion input.
# ---------------------------------------------------------------------------


class KnowledgeDocument(BaseModel):
    """One trusted, application-supplied security knowledge document.

    A document is **data**, never code and never instructions: ingestion
    never evaluates, executes, or parses content as an interpreted artifact.
    The document records its origin so the layer always knows where a piece
    of knowledge came from.
    """

    document_id: uuid.UUID = Field(
        ...,
        description="Identity of the document, preserved exactly.",
    )
    source: str = Field(
        ...,
        description=(
            "Coarse origin of the knowledge, e.g. 'mitre-attack', "
            "'sigma-hunting', 'cve-feed', 'internal-soc'.  Recorded so the "
            "layers know where knowledge came from."
        ),
    )
    title: str = Field(
        ...,
        description="Human-readable heading of the document.",
    )
    content: str = Field(
        ...,
        description=(
            "Plain-text knowledge content.  Never evaluated or executed; "
            "treated strictly as data."
        ),
    )
    knowledge_type: KnowledgeType = Field(
        ...,
        description="Bounded knowledge category.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured source metadata (e.g. 'ingested_at', 'version').  "
            "Must be JSON-compatible and secret-free."
        ),
    )

    @field_validator("source")
    @classmethod
    def _source_bounded(cls, v: str) -> str:
        return _bound_string(v, "knowledge source", MAX_KNOWLEDGE_SOURCE_LENGTH)

    @field_validator("title")
    @classmethod
    def _title_bounded(cls, v: str) -> str:
        return _bound_string(v, "knowledge title", MAX_KNOWLEDGE_TITLE_LENGTH)

    @field_validator("content")
    @classmethod
    def _content_bounded(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("knowledge content must not be blank")
        if len(v) > MAX_KNOWLEDGE_DOCUMENT_CONTENT_LENGTH:
            raise KnowledgeBoundError(
                f"knowledge content exceeds MAX_KNOWLEDGE_DOCUMENT_"
                f"CONTENT_LENGTH={MAX_KNOWLEDGE_DOCUMENT_CONTENT_LENGTH} "
                f"(length {len(v)})"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "knowledge metadata")

    @model_validator(mode="after")
    def _document_secret_free(self) -> "KnowledgeDocument":
        # Defence-in-depth: the whole document serialization must be
        # secret-free so credential-shaped content can never be ingested.
        try:
            serialized = self.model_dump_json()
        except Exception:  # pragma: no cover - defensive
            return self
        _assert_no_secrets(serialized, "knowledge document")
        return self


# ---------------------------------------------------------------------------
# KnowledgeChunk — the indexed unit produced by deterministic chunking.
# ---------------------------------------------------------------------------


class KnowledgeChunk(BaseModel):
    """One deterministic, bounded slice of a knowledge document.

    Chunks preserve the source identity (``document_id``), the position
    (``index``), and the source metadata so retrieved content can always be
    traced back to its origin.  A chunk is the unit stored in the vector
    store and later retrieved.
    """

    chunk_id: uuid.UUID = Field(
        ...,
        description="Identity of the chunk (stable across retrievals).",
    )
    document_id: uuid.UUID = Field(
        ...,
        description="Identity of the source document.",
    )
    index: int = Field(
        ...,
        ge=0,
        description="Zero-based position of the chunk within its document.",
    )
    source: str = Field(
        ...,
        description="Coarse origin preserved from the document.",
    )
    title: str = Field(
        ...,
        description="Heading preserved from the document.",
    )
    content: str = Field(
        ...,
        description="The chunk's text (never empty, never modified later).",
    )
    knowledge_type: KnowledgeType = Field(
        ...,
        description="Bounded knowledge category preserved from the document.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Source metadata preserved from the document.",
    )

    @field_validator("source")
    @classmethod
    def _source_bounded(cls, v: str) -> str:
        return _bound_string(v, "knowledge source", MAX_KNOWLEDGE_SOURCE_LENGTH)

    @field_validator("title")
    @classmethod
    def _title_bounded(cls, v: str) -> str:
        return _bound_string(v, "knowledge title", MAX_KNOWLEDGE_TITLE_LENGTH)

    @field_validator("content")
    @classmethod
    def _content_bounded(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("chunk content must not be blank")
        if len(v) > MAX_CHUNK_CONTENT_LENGTH:
            raise KnowledgeBoundError(
                f"chunk content exceeds MAX_CHUNK_CONTENT_LENGTH="
                f"{MAX_CHUNK_CONTENT_LENGTH} (length {len(v)})"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "chunk metadata")

    @model_validator(mode="after")
    def _chunk_secret_free(self) -> "KnowledgeChunk":
        try:
            serialized = self.model_dump_json()
        except Exception:  # pragma: no cover - defensive
            return self
        _assert_no_secrets(serialized, "knowledge chunk")
        return self


# ---------------------------------------------------------------------------
# KnowledgeItem — one validated, retrieved knowledge item.
# ---------------------------------------------------------------------------


class KnowledgeItem(BaseModel):
    """One piece of retrieved security knowledge.

    This is the artifact that travels into the AI investigation prompt as
    **reference material only**.  It deliberately carries no security-event
    provenance and no evidence identity; it is classified by its
    ``knowledge_type`` and ``source``.
    """

    knowledge_id: uuid.UUID = Field(
        ...,
        description=(
            "Identity of the retrieved knowledge unit.  Distinct from any "
            "evidence_id: a knowledge id can never be used as an evidence "
            "reference."
        ),
    )
    source: str = Field(
        ...,
        description="Coarse origin of the knowledge.",
    )
    title: str = Field(
        ...,
        description="Heading of the retrieved knowledge.",
    )
    content: str = Field(
        ...,
        description=(
            "Retrieved content, preserved verbatim (never modified or "
            "hallucinated by the retrieval layer)."
        ),
    )
    knowledge_type: KnowledgeType = Field(
        ...,
        description="Bounded knowledge category.",
    )
    relevance_score: float = Field(
        ...,
        description=(
            "Similarity score reported by the vector store for the "
            "cosine contract: finite, in [-1.0, 1.0]."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Source metadata preserved from the chunk.",
    )

    @field_validator("source")
    @classmethod
    def _source_bounded(cls, v: str) -> str:
        return _bound_string(v, "knowledge source", MAX_KNOWLEDGE_SOURCE_LENGTH)

    @field_validator("title")
    @classmethod
    def _title_bounded(cls, v: str) -> str:
        return _bound_string(v, "knowledge title", MAX_KNOWLEDGE_TITLE_LENGTH)

    @field_validator("content")
    @classmethod
    def _content_bounded(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("knowledge content must not be blank")
        if len(v) > MAX_CHUNK_CONTENT_LENGTH:
            raise KnowledgeBoundError(
                f"knowledge content exceeds MAX_CHUNK_CONTENT_LENGTH="
                f"{MAX_CHUNK_CONTENT_LENGTH} (length {len(v)})"
            )
        return v

    @field_validator("relevance_score")
    @classmethod
    def _score_valid(cls, v: float) -> float:
        import math

        if not math.isfinite(v):
            raise ValueError(
                "relevance_score must be a finite number; NaN and infinity "
                "are not accepted"
            )
        if not (-1.0 <= v <= 1.0):
            raise ValueError(
                f"relevance_score must be in [-1.0, 1.0] for the cosine "
                f"vector-store contract, got {v}"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "knowledge metadata")

    @model_validator(mode="after")
    def _item_secret_free(self) -> "KnowledgeItem":
        try:
            serialized = self.model_dump_json()
        except Exception:  # pragma: no cover - defensive
            return self
        _assert_no_secrets(serialized, "knowledge item")
        return self


# ---------------------------------------------------------------------------
# KnowledgeIndexRecord — the indexed unit sent to the vector store.
# ---------------------------------------------------------------------------


class KnowledgeIndexRecord(BaseModel):
    """A chunk paired with its embedding vector, ready for storage.

    The vector store abstraction (`app/services/knowledge/vector_store.py`)
    consumes these records, so investigation code never talks to Qdrant
    directly.
    """

    chunk_id: uuid.UUID = Field(..., description="Chunk identity.")
    document_id: uuid.UUID = Field(..., description="Source document identity.")
    index: int = Field(..., ge=0, description="Position within the document.")
    source: str = Field(..., description="Coarse origin.")
    title: str = Field(..., description="Heading.")
    content: str = Field(..., description="Chunk text.")
    knowledge_type: KnowledgeType = Field(..., description="Knowledge category.")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Source metadata.",
    )
    vector: list[float] = Field(
        ...,
        description="The chunk's embedding vector.",
    )

    @field_validator("source")
    @classmethod
    def _source_bounded(cls, v: str) -> str:
        return _bound_string(v, "knowledge source", MAX_KNOWLEDGE_SOURCE_LENGTH)

    @field_validator("title")
    @classmethod
    def _title_bounded(cls, v: str) -> str:
        return _bound_string(v, "knowledge title", MAX_KNOWLEDGE_TITLE_LENGTH)

    @field_validator("content")
    @classmethod
    def _content_bounded(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("chunk content must not be blank")
        if len(v) > MAX_CHUNK_CONTENT_LENGTH:
            raise KnowledgeBoundError(
                f"chunk content exceeds MAX_CHUNK_CONTENT_LENGTH="
                f"{MAX_CHUNK_CONTENT_LENGTH} (length {len(v)})"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "knowledge metadata")

    @field_validator("vector")
    @classmethod
    def _vector_valid(cls, v: list[float]) -> list[float]:
        import math

        if not v:
            raise ValueError("embedding vector must not be empty")
        for value in v:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("embedding vector must contain only numbers")
            if not math.isfinite(float(value)):
                raise ValueError(
                    "embedding vector must contain only finite numbers; "
                    "NaN and infinity are not accepted"
                )
        return [float(value) for value in v]

    @model_validator(mode="after")
    def _record_secret_free(self) -> "KnowledgeIndexRecord":
        try:
            serialized = self.model_dump_json()
        except Exception:  # pragma: no cover - defensive
            return self
        _assert_no_secrets(serialized, "knowledge index record")
        return self