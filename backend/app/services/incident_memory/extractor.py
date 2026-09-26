"""Deterministic Incident Memory extractor — Step 16 foundation.

The extractor is the single entry point of the memory layer.  It consumes
:class:`~app.services.incident_memory.input.IncidentMemoryInput` (explicit,
structured incident information) and produces zero or more
:class:`~app.schemas.incident_memory.IncidentMemory` records.

* **Zero-memory is a valid result.**  Insufficient or empty input yields an
  empty list — it is never an exception and never a fabricated summary.
* **No inference in any form.**  No NLP, no LLM, no RAG retrieval, no
  invented indicators/techniques/attackers/verdicts, no provenance
  conversion.  The only values the extractor introduces are the memory's
  own ``memory_id`` (:func:`uuid.uuid4` by default) and ``created_at``
  (UTC ``now`` by default); both are injectable for deterministic tests.
* **Fail-closed secrets.**  The whole constructed input is re-scanned at
  the service boundary with credential-shaped *value* patterns; a match
  raises :class:`IncidentMemorySafetyError` (rejection, never redaction).
* **Strict output re-validation.**  Every assembled memory must re-validate
  against the Step 16 contract; a genuine failure raises
  :class:`IncidentMemoryValidationError`, never a silent empty result.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from app.schemas.incident_memory import IncidentMemory, MemoryType
from app.services.incident_memory import policy
from app.services.incident_memory.exceptions import (
    IncidentMemoryExtractionError,
    IncidentMemorySafetyError,
    IncidentMemoryValidationError,
    InvalidIncidentMemoryInputError,
    UnsupportedMemorySignalError,
)
from app.services.incident_memory.input import IncidentMemoryInput

#: Credential-shaped substrings scanned at construction (schema layer).
_SENSITIVE_SUBSTRINGS = (
    "api_key",
    "authorization",
    "bearer",
    "secret",
    "password",
    "cookie",
    "session_token",
    "jwt",
)

#: Credential-shaped *value* patterns scanned at the service boundary.
_SECRET_VALUE_PATTERNS = re.compile(
    r"(?<![A-Za-z0-9])(?:api[_-]?key|authorization|bearer|secret|password|cookie|"
    r"session[_-]?token|jwt)(?![A-Za-z0-9])",
    re.IGNORECASE,
)


class IncidentMemoryExtractor:
    """Deterministic, stateless extractor of incident memories."""

    def extract(
        self,
        input_data: IncidentMemoryInput,
        *,
        clock: datetime | None = None,
        uuid_factory: Callable[[], uuid.UUID] | None = None,
        memory_types: list[MemoryType] | None = None,
    ) -> list[IncidentMemory]:
        """Extract zero or more deterministic memories from *input_data*.

        Arguments mirror the staging contracts' injection pattern:

        * ``clock`` — timezone-aware datetime stamped as every memory's
          ``created_at`` (default: ``datetime.now(timezone.utc)``).
        * ``uuid_factory`` — minted IDs for assembled memories (default:
          :func:`uuid.uuid4`).
        * ``memory_types`` — restrict extraction to these categories; a
          value that is not a supported category raises
          :class:`UnsupportedMemorySignalError`.

        Raises
        ------
        InvalidIncidentMemoryInputError:
            *input_data* is not an ``IncidentMemoryInput``, or
            ``clock``/``uuid_factory`` are unusable.
        UnsupportedMemorySignalError:
            *memory_types* names an unsupported category.
        IncidentMemorySafetyError:
            secret-shaped content is detected in the constructed input.
        IncidentMemoryValidationError:
            an assembled memory fails contract re-validation.
        IncidentMemoryExtractionError:
            any unexpected assembly failure (chained to its cause).
        """
        if not isinstance(input_data, IncidentMemoryInput):
            raise InvalidIncidentMemoryInputError(
                "incident memory extraction requires an IncidentMemoryInput; "
                "got an unsupported object"
            )

        if clock is None:
            clock = datetime.now(timezone.utc)
        if not isinstance(clock, datetime) or (
            clock.tzinfo is None or clock.tzinfo.utcoffset(clock) is None
        ):
            raise InvalidIncidentMemoryInputError(
                "clock must be a timezone-aware datetime instance"
            )

        if uuid_factory is None:
            uuid_factory = uuid.uuid4
        if not callable(uuid_factory):
            raise InvalidIncidentMemoryInputError(
                "uuid_factory must be callable"
            )

        candidates = self._normalize_memory_types(memory_types)
        self._assert_no_secrets(input_data)

        memories: list[IncidentMemory] = []
        for memory_type in policy.satisfied_memory_types(
            input_data, candidates
        ):
            try:
                memories.append(
                    policy.memory_for_type(
                        input_data,
                        memory_type,
                        timestamp=clock,
                        uuid_factory=uuid_factory,
                    )
                )
            except ValidationError as exc:
                raise IncidentMemoryValidationError(
                    "an assembled incident memory failed contract "
                    "re-validation"
                ) from exc
            except Exception as exc:
                raise IncidentMemoryExtractionError(
                    "incident memory extraction failed unexpectedly"
                ) from exc
        return memories

    @staticmethod
    def _normalize_memory_types(
        memory_types: list[MemoryType] | None,
    ) -> tuple[MemoryType, ...] | None:
        if memory_types is None:
            return None
        normalized: list[MemoryType] = []
        for candidate in memory_types:
            try:
                member = MemoryType(candidate)
            except (TypeError, ValueError) as exc:
                raise UnsupportedMemorySignalError(
                    "incident memory extraction referenced an unsupported "
                    "memory category"
                ) from exc
            if member not in normalized:
                normalized.append(member)
        return tuple(normalized)

    @staticmethod
    def _assert_no_secrets(input_data: IncidentMemoryInput) -> None:
        """Defence-in-depth service-boundary secret scan (fail closed).

        Serializes the whole input and scans for credential-shaped *value*
        patterns in addition to the substring scan the schema layer already
        performed.  Shape-based: benign words that merely look like the
        patterns are still rejected — secrets are rejected, never redacted.
        """
        data = input_data.model_dump(mode="json")
        for field, value in _string_values(data).items():
            match = _SECRET_VALUE_PATTERNS.search(value)
            if match is not None:
                raise IncidentMemorySafetyError(
                    "incident memory extraction input must not contain "
                    f"secret-shaped content ('{match.group(0)}'); secrets "
                    "are rejected, never redacted"
                )
        serialized = json.dumps(data, sort_keys=True).lower()
        for pattern in _SENSITIVE_SUBSTRINGS:
            if pattern in serialized:
                raise IncidentMemorySafetyError(
                    "incident memory extraction input must not contain "
                    f"secret-shaped content ('{pattern}'); secrets are "
                    "rejected, never redacted"
                )


def _string_values(obj: Any, acc: dict[str, str] | None = None) -> dict[str, str]:
    """Collect a label→text map of every string in a JSON-safe structure.

    A deterministic, shape-based scan surface: the concrete identity is
    not used, only its serialized string form.
    """
    if acc is None:
        acc = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and _is_string(value):
                acc[key] = value
            else:
                _string_values(value, acc)
    elif isinstance(obj, list):
        for value in obj:
            _string_values(value, acc)
    return acc


def _is_string(value: Any) -> bool:
    return isinstance(value, str)