"""Step 13 — Knowledge secret-safety scanner tests.

The RAG layer must never carry credential-shaped content across any trust
boundary.  This module verifies the shared scanner and its lock-step
agreement with the Step 12B and Step 12C pattern sets, so a future drift
between layers is caught here.
"""

import pytest

from app.services.knowledge.exceptions import KnowledgeSafetyError
from app.services.knowledge.safety import SECRET_PATTERNS, assert_knowledge_safe
from app.schemas.investigation_context import _SECRET_PATTERNS as _TWELVE_B_PATTERNS
from app.agents.investigation._safety import SECRET_PATTERNS as _TWELVE_C_PATTERNS
from app.schemas.knowledge import _SECRET_PATTERNS as _KNOWLEDGE_SCHEMA_PATTERNS


@pytest.mark.parametrize(
    "value",
    [
        "api_key=sk-live-1234",
        {"Authorization": "Bearer xxx"},
        "bearer token",
        "super_secret_value",
        "password=hunter2",
        "cookie=sessionid",
        "session_token=abc",
        {"jwt": "eyJ.eyJ"},
    ],
)
def test_assert_knowledge_safe_detects(value):
    with pytest.raises(KnowledgeSafetyError):
        assert_knowledge_safe(value, "field")


def test_assert_knowledge_safe_case_insensitive():
    with pytest.raises(KnowledgeSafetyError):
        assert_knowledge_safe("API_KEY=live", "field")
    with pytest.raises(KnowledgeSafetyError):
        assert_knowledge_safe("Bearer x", "field")


def test_assert_knowledge_safe_passes_clean_values():
    for value in (
        "modern initial access technique",
        {"note": "credential rotation is ordinary telemetry"},
        ["sigma rule", 'title: "Suspicious PowerShell"'],
        {"nested": {"list": [1, 2, 3]}},
    ):
        assert_knowledge_safe(value, "field")  # does not raise


def test_safety_error_is_value_error_and_operational():
    assert issubclass(KnowledgeSafetyError, ValueError)


def test_lock_step_with_twelve_b_and_twelve_c():
    # The knowledge layer must carry the *same* family of forbidden patterns
    # as the 12B context safety and the 12C prompt safety, so no layer can be
    # bypassed through pattern drift.
    assert set(SECRET_PATTERNS) == set(_TWELVE_B_PATTERNS)
    assert set(SECRET_PATTERNS) == set(_TWELVE_C_PATTERNS)
    assert set(SECRET_PATTERNS) == set(_KNOWLEDGE_SCHEMA_PATTERNS)


def test_pattern_set_exact():
    assert SECRET_PATTERNS == (
        "api_key",
        "authorization",
        "bearer",
        "secret",
        "password",
        "cookie",
        "session_token",
        "jwt",
    )