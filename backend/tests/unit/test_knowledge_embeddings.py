"""Step 13 — Knowledge embedding tests.

Covers the ``EmbeddingProvider`` abstraction and the deterministic, offline
provider: determinism, dimensionality, input validation, the before-embed
secret scan, vector validation (finite/non-empty), and fail-closed config
resolution.
"""

import math

import pytest

from app.services.knowledge.embeddings import (
    MAX_EMBEDDING_INPUT_LENGTH,
    DeterministicEmbeddingProvider,
    EmbeddingProvider,
    create_embedding_provider,
    validate_embedding_vector,
)
from app.services.knowledge.exceptions import (
    KnowledgeConfigError,
    KnowledgeEmbeddingError,
)


def _provider(dimension: int = 16) -> DeterministicEmbeddingProvider:
    return DeterministicEmbeddingProvider(dimension=dimension)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_identical_text_identical_vector():
    a = _provider().embed("initial access via credential dumping")
    b = _provider().embed("initial access via credential dumping")
    assert a == b


def test_vectors_are_stable_across_provider_instances():
    v1 = _provider().embed("same text")
    v2 = _provider().embed("same text")
    assert v1 == v2


def test_different_text_differs():
    assert _provider().embed("alpha beta") != _provider().embed("gamma zeta")


def test_provider_names_and_dimension():
    p = _provider(dimension=32)
    assert p.provider_name == "deterministic"
    assert p.dimension == 32
    assert isinstance(p.model_name, str) or p.model_name is None


def test_embedding_is_unit_norm():
    vector = _provider(dimension=64).embed("initial access technique")
    norm = math.sqrt(sum(v * v for v in vector))
    assert abs(norm - 1.0) < 1e-6


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["", "   ", "\n\t", 42, None, ["x"]])
def test_embed_rejects_empty_or_non_text(bad):
    with pytest.raises((KnowledgeEmbeddingError, TypeError)):
        _provider().embed(bad)  # type: ignore[arg-type]


def test_embed_rejects_oversized_input():
    with pytest.raises(KnowledgeEmbeddingError):
        _provider().embed("x" * (MAX_EMBEDDING_INPUT_LENGTH + 1))


@pytest.mark.parametrize(
    "secret_text",
    [
        "api_key=sk-live",
        "uses bearer token",
        "password=hunter2",
        "jwt payload",
    ],
)
def test_embed_rejects_secret_shaped_input(secret_text):
    with pytest.raises(KnowledgeEmbeddingError):
        _provider().embed(secret_text)


# ---------------------------------------------------------------------------
# Vector validation
# ---------------------------------------------------------------------------


def test_validate_embedding_vector_empty_rejected():
    with pytest.raises(KnowledgeEmbeddingError):
        validate_embedding_vector([])


@pytest.mark.parametrize(
    "bad",
    [[math.nan], [math.inf], [0.1, "x"], [True], [None]],
)
def test_validate_embedding_vector_rejects_bad_values(bad):
    with pytest.raises((KnowledgeEmbeddingError, TypeError)):
        validate_embedding_vector(bad)


def test_validate_embedding_vector_finite_ok():
    assert validate_embedding_vector([0.1, -0.2, 0.3]) == [0.1, -0.2, 0.3]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_provider_dimension_must_be_positive():
    with pytest.raises(KnowledgeConfigError):
        DeterministicEmbeddingProvider(dimension=0)
    with pytest.raises(KnowledgeConfigError):
        DeterministicEmbeddingProvider(dimension=-3)


def test_create_embedding_provider_defaults_to_deterministic(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "embedding_provider", "deterministic")
    provider = create_embedding_provider()
    assert isinstance(provider, DeterministicEmbeddingProvider)


def test_create_embedding_provider_unsupported_fails_closed(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "embedding_provider", "openai")
    with pytest.raises(KnowledgeConfigError):
        create_embedding_provider()


def test_embedding_provider_is_abstract():
    with pytest.raises(TypeError):
        EmbeddingProvider()  # type: ignore[abstract]