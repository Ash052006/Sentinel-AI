"""Incident Memory extraction input contract — Step 16 foundation.

The deterministic memory extractor consumes *explicitly supplied structured
incident information* only.  ``IncidentMemoryInput`` is that explicit
signal: a validated, bounded bundle of the exact structured facts a caller
wants to remember (sources, indicators, entities, techniques, findings,
actions, outcome) plus an optional correlation anchor, title/summary, and
an independent confidence value.

Nothing is inferred here.  If the caller did not supply it, memory cannot
contain it.  Provenance lives on every ``MemorySource`` and is never
converted; content items reference those sources by id and every reference
must resolve within the same input.

Secret safety: secret-shaped content is rejected at construction (matching
the schema-convention ``ValueError`` path); the extractor additionally
re-scans the whole constructed input at the service boundary and raises
:class:`~app.services.incident_memory.exceptions.IncidentMemorySafetyError`.
"""

from __future__ import annotations

import uuid
from math import isfinite
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.incident_memory import (
    MAX_MEMORY_ACTIONS,
    MAX_MEMORY_ENTITIES,
    MAX_MEMORY_FINDINGS,
    MAX_MEMORY_INDICATORS,
    MAX_MEMORY_SOURCES,
    MAX_MEMORY_SUMMARY_LENGTH,
    MAX_MEMORY_TECHNIQUES,
    MAX_MEMORY_TITLE_LENGTH,
    MemoryAction,
    MemoryEntity,
    MemoryFinding,
    MemoryIndicator,
    MemoryOutcome,
    MemorySource,
    MemoryTechnique,
)
from app.schemas.incident_memory import _assert_no_secrets, _bound_string


class IncidentMemoryInput(BaseModel):
    """Explicit structured incident information the extractor may remember.

    Field-for-field, this is the envelope that becomes ``IncidentMemory``
    records.  Lists preserve the exact order supplied; nothing is sorted,
    deduplicated, or inferred.
    """

    model_config = {"extra": "ignore"}

    correlation_id: uuid.UUID | None = None
    title: str = Field(...)
    summary: str | None = None
    sources: list[MemorySource] = Field(default_factory=list)
    indicators: list[MemoryIndicator] = Field(default_factory=list)
    entities: list[MemoryEntity] = Field(default_factory=list)
    techniques: list[MemoryTechnique] = Field(default_factory=list)
    findings: list[MemoryFinding] = Field(default_factory=list)
    actions: list[MemoryAction] = Field(default_factory=list)
    outcome: MemoryOutcome | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("title")
    @classmethod
    def _title_bounded(cls, v: Any) -> str:
        return _bound_string(v, "title", MAX_MEMORY_TITLE_LENGTH)

    @field_validator("summary")
    @classmethod
    def _summary_bounded(cls, v: Any) -> str | None:
        if v is None:
            return None
        return _bound_string(v, "summary", MAX_MEMORY_SUMMARY_LENGTH)

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence_finite(cls, v: Any) -> Any:
        if isinstance(v, bool):
            raise ValueError("confidence must be a finite floating-point number")
        if isinstance(v, (int, float)) and not isfinite(v):
            raise ValueError("confidence must be finite")
        return v

    @field_validator("sources")
    @classmethod
    def _sources_bounded(cls, v: list[MemorySource]) -> list[MemorySource]:
        if len(v) > MAX_MEMORY_SOURCES:
            raise ValueError(
                f"input sources exceed the maximum of {MAX_MEMORY_SOURCES}"
            )
        return v

    @field_validator("indicators")
    @classmethod
    def _indicators_bounded(cls, v: list[MemoryIndicator]) -> list[MemoryIndicator]:
        if len(v) > MAX_MEMORY_INDICATORS:
            raise ValueError(
                f"input indicators exceed the maximum of {MAX_MEMORY_INDICATORS}"
            )
        return v

    @field_validator("entities")
    @classmethod
    def _entities_bounded(cls, v: list[MemoryEntity]) -> list[MemoryEntity]:
        if len(v) > MAX_MEMORY_ENTITIES:
            raise ValueError(
                f"input entities exceed the maximum of {MAX_MEMORY_ENTITIES}"
            )
        return v

    @field_validator("techniques")
    @classmethod
    def _techniques_bounded(cls, v: list[MemoryTechnique]) -> list[MemoryTechnique]:
        if len(v) > MAX_MEMORY_TECHNIQUES:
            raise ValueError(
                f"input techniques exceed the maximum of {MAX_MEMORY_TECHNIQUES}"
            )
        return v

    @field_validator("findings")
    @classmethod
    def _findings_bounded(cls, v: list[MemoryFinding]) -> list[MemoryFinding]:
        if len(v) > MAX_MEMORY_FINDINGS:
            raise ValueError(
                f"input findings exceed the maximum of {MAX_MEMORY_FINDINGS}"
            )
        return v

    @field_validator("actions")
    @classmethod
    def _actions_bounded(cls, v: list[MemoryAction]) -> list[MemoryAction]:
        if len(v) > MAX_MEMORY_ACTIONS:
            raise ValueError(
                f"input actions exceed the maximum of {MAX_MEMORY_ACTIONS}"
            )
        return v

    @model_validator(mode="after")
    def _ensure_source_references_resolve(self) -> "IncidentMemoryInput":
        """Content ``source_ids`` must resolve to this input's sources."""
        present = {str(source.source_id) for source in self.sources}
        collections: list[list] = [
            list(self.indicators),
            list(self.entities),
            list(self.techniques),
            list(self.findings),
            list(self.actions),
        ]
        missing: list[str] = []
        for items in collections:
            for item in items:
                for reference in getattr(item, "source_ids"):
                    if str(reference) not in present:
                        missing.append(str(reference))
        if self.outcome is not None:
            for reference in self.outcome.source_ids:
                if str(reference) not in present:
                    missing.append(str(reference))
        if missing:
            raise ValueError(
                "input content references must resolve to the input's "
                "sources; unresolved: "
                + ", ".join(sorted(set(missing)))
            )
        return self

    @model_validator(mode="after")
    def _ensure_whole_input_secret_free(self) -> "IncidentMemoryInput":
        """Defence-in-depth: the entire input is secret-screened as text.

        Shapes that a per-field scan could miss (e.g. a title containing a
        secret pattern) are rejected here.  The extractor re-checks on the
        service boundary so this is not the only gate.
        """
        _assert_no_secrets(self.model_dump(mode="json"), "incident memory input")
        return self

    def clone(self) -> "IncidentMemoryInput":
        """Return an independent deep copy of this structured input.

        Content models are already copied by Pydantic at construction; the
        JSON round-trip here guarantees no mutable state is ever shared
        with callers or with the extractor.
        """
        return IncidentMemoryInput.model_validate_json(self.model_dump_json())