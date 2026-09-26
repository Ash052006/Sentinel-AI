"""Secret-safety scanner shared by the Step 12C trust boundary.

Defence-in-depth: the Step 12B ``InvestigationContext`` contract already
refuses credential-shaped payloads.  This module re-checks the **serialized
text** destined for (and received from) the AI provider, so plain string
fields that 12B preserves as untrusted data can never smuggle
credential-shaped content across the AI trust boundary.  If unsafe content
is detected the caller *fails closed* — nothing reaches the provider and no
model output is placed into domain objects.
"""

from __future__ import annotations

import json
from typing import Any

#: Forbidden credential-shaped substrings, kept in lock-step with the Step
#: 12B ``app/schemas/investigation_context`` extended pattern set
#: (``api_key`` / ``authorization`` / ``bearer`` / ``secret`` plus the
#: credential families the AI boundary explicitly refuses: ``password`` /
#: ``cookie`` / ``session_token`` / ``jwt``).
SECRET_PATTERNS = (
    "api_key",
    "authorization",
    "bearer",
    "secret",
    "password",
    "cookie",
    "session_token",
    "jwt",
)


def assert_no_secrets(value: Any, field: str) -> None:
    """Raise ``ValueError`` when *value* contains a credential-shaped string.

    The check is applied to the lowercased serialized representation so
    case variations cannot bypass it.  Detecting a pattern rejects the
    content outright (fail closed); nothing is redacted or silently
    substituted.
    """
    serialized = json.dumps(value).lower()
    for pattern in SECRET_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"{field} must not contain secrets ('{pattern}' detected)"
            )