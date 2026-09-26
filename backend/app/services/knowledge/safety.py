"""Secret-safety scanner shared by the Knowledge & RAG layer (Step 13).

Defence-in-depth: knowledge content is attacker-adjacent reference material
that is never treated as instructions, and it must also never smuggle
credential-shaped content across the RAG layers.  The scanner is applied at
every trust boundary:

* **before embedding** — document/chunk content is scanned before any
  vector is computed;
* **before storage** — index records are scanned before they are upserted;
* **after retrieval** — retrieved knowledge items are rescanned;
* **before Gemini** — the serialized InvestigationKnowledgeContext is
  scanned again by the Step 12C prompt builder.

The pattern set is kept in lock-step with the Step 12B / Step 12C sets.
"""

from __future__ import annotations

import json
from typing import Any

from app.services.knowledge.exceptions import KnowledgeSafetyError

#: Forbidden credential-shaped strings, kept in lock-step with
#: ``app/schemas/investigation_context.py`` and
#: ``app/agents/investigation/_safety.py``.
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


def assert_knowledge_safe(value: Any, field: str) -> None:
    """Raise :class:`KnowledgeSafetyError` when *value* carries secrets.

    The check is applied to the lowercased serialized representation so
    case variations cannot bypass it.
    """
    serialized = json.dumps(value).lower()
    for pattern in SECRET_PATTERNS:
        if pattern in serialized:
            raise KnowledgeSafetyError(
                f"{field} must not contain secrets ('{pattern}' detected)"
            )