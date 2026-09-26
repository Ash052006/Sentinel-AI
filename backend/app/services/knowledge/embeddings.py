"""Embedding providers — Step 13.

A thin ``EmbeddingProvider`` abstraction keeps the RAG layer independent of
any single embedding backend.  The shipped implementation is the offline,
deterministic one:

* no network calls, no model downloads, no provider keys;
* identical text always produces the identical vector (KCI-compatible);
* the embedding space is finite, bounded, and closed under the contract
  that later indexes with cosine distance keep scores inside ``[-1, 1]``.

Every ``embed`` call re-scans its input at this trust boundary — the
"before embedding" secret check — and validates both input length and the
produced vector.  No input text, vector contents, or configuration values
ever appear in exception messages.
"""

from __future__ import annotations

import abc
import hashlib
import math
import re
from typing import Sequence

from app.core.config import settings
from app.services.knowledge.exceptions import (
    KnowledgeConfigError,
    KnowledgeEmbeddingError,
    KnowledgeSafetyError,
)
from app.services.knowledge.safety import assert_knowledge_safe

#: Upper bound on characters embedded in a single call (all chunk content
#: is far smaller; the guard exists so misuse fails deterministically).
MAX_EMBEDDING_INPUT_LENGTH = 32_768

_TOKEN_RE = re.compile(r"[^\W_]+")


def validate_embedding_vector(vector: Sequence[float]) -> list[float]:
    """Validate an embedding for the knowledge contract.

    Asserts the vector is a non-empty sequence of finite floats.

    Raises:
        KnowledgeEmbeddingError: when the vector is empty or carries
            non-finite values.
    """
    if not isinstance(vector, (list, tuple)) or len(vector) == 0:
        raise KnowledgeEmbeddingError(
            "an embedding vector must be a non-empty sequence of floats"
        )
    values = list(vector)
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise KnowledgeEmbeddingError(
                "embedding vectors may only contain real numbers"
            )
        if not math.isfinite(float(value)):
            raise KnowledgeEmbeddingError(
                "embedding vectors must contain only finite values"
            )
    return values


class EmbeddingProvider(abc.ABC):
    """Produces validated embedding vectors for knowledge content."""

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Stable, low-cardinality identifier for dependency isolation."""

    @property
    @abc.abstractmethod
    def model_name(self) -> str | None:
        """Optional model identifier; ``None`` for provider-less providers."""

    @property
    @abc.abstractmethod
    def dimension(self) -> int:
        """Fixed embedding dimensionality."""

    @abc.abstractmethod
    def embed(self, text: str) -> list[float]:
        """Embed *text* and return a validated vector."""


def _deterministic_tokens(text: str) -> list[str]:
    matches = _TOKEN_RE.findall(text.lower())
    if matches:
        return matches
    return [text.strip()[:64]]


class DeterministicEmbeddingProvider(EmbeddingProvider):
    """Offline, deterministic, provider-less embedding.

    The vector for a text is a stable, normalised bag-of-tokens signature
    over the configured dimension: token positions are hashed, so similar
    vocabulary yields similar cosine similarity, while the result depends
    only on the text — never on time, randomness, or external services.
    """

    _provider_name = "deterministic"

    def __init__(
        self,
        *,
        dimension: int | None = None,
        model: str | None = None,
    ) -> None:
        resolved = dimension if dimension is not None else settings.embedding_dimension
        if isinstance(resolved, bool) or not isinstance(resolved, int) or resolved < 1:
            raise KnowledgeConfigError(
                "embedding dimension must be a positive integer"
            )
        self._dimension = resolved
        self._model = model or settings.embedding_model

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def model_name(self) -> str | None:
        return self._model

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed(self, text: str) -> list[float]:
        if not isinstance(text, str):
            raise KnowledgeEmbeddingError(
                "embedding input must be text"
            )
        stripped = text.strip()
        if not stripped:
            raise KnowledgeEmbeddingError(
                "embedding input must not be empty"
            )
        if len(stripped) > MAX_EMBEDDING_INPUT_LENGTH:
            raise KnowledgeEmbeddingError(
                "embedding input exceeds its length bound"
            )
        try:
            assert_knowledge_safe(stripped, "embedding input")
        except KnowledgeSafetyError as exc:
            raise KnowledgeEmbeddingError(
                "embedding input was rejected by the secret scan"
            ) from exc

        vector = self._compute(stripped)
        return validate_embedding_vector(vector)

    def _compute(self, text: str) -> list[float]:
        dims = [0.0 for _ in range(self._dimension)]
        for token in _deterministic_tokens(text):
            for i in range(self._dimension):
                digest = hashlib.sha256(f"{i}:{token}".encode("utf-8")).digest()
                raw = int.from_bytes(digest[:4], byteorder="big")
                dims[i] += (raw / 2_147_483_648.0) - 1.0
        norm = math.sqrt(sum(v * v for v in dims))
        if norm == 0.0:
            dims[0] = 1.0
        else:
            dims = [v / norm for v in dims]
        return dims


def create_embedding_provider() -> EmbeddingProvider:
    """Instantiate the configured embedding provider.

    Raises:
        KnowledgeConfigError: for any provider other than the shipped
            deterministic one.  SentinelAI does not bundle remote embedding
            SDKs, so unknown names fail closed.
    """
    name = settings.embedding_provider
    if name is None or name == DeterministicEmbeddingProvider._provider_name:
        return DeterministicEmbeddingProvider()
    raise KnowledgeConfigError(
        f"unsupported embedding_provider '{name}'"
    )