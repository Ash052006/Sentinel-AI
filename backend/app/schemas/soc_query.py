"""Natural Language SOC query intent + response contracts — Step 23.

Step 23 introduces a controlled Natural Language SOC interface: an
authenticated SOC user asks a question in natural language and the system
translates it into a **structured, read-only SOC query intent** that is
validated against an explicit allowlist grammar **before** any database
work.  This module defines that grammar's contracts:

* the bounded, typed :class:`SOCModelIntent` — the *candidate* structured
  intent the LLM is allowed to produce (its output is **untrusted** and
  must pass deterministic validation before execution);
* the validated :class:`SOCQueryIntent` — the normalized intent the
  read-only executor dispatches on;
* the resource / operation / execution-mode enumerations;
* the structured :class:`SOCQueryResponse` result contract that
  distinguishes the validated intent, deterministic execution metadata,
  the serialized read-model results, count/pagination, deterministic
  semantic labels, and a deterministic human-readable note.

Design principles (mirroring the project's existing contracts):

* **No ``dict[str, Any]`` core contract** — ``resource``/``operation`` are
  enumerations, targets and filters are typed models, and pagination is a
  bounded model.  Unknown fields are rejected everywhere (``extra="forbid"``),
  matching Steps 12C / 16 / 22 strict-contract philosophy.
* **Explicit bounds everywhere, reject never truncate** — IDs are strong
  types, ``rule_id`` is bounded, ``limit``/``page_size`` are capped to the
  exact service caps they feed (``SOC_MAX_PAGE_SIZE`` / ``SOC_MAX_RECENT_LIMIT``
  equal the existing query-service caps), and oversized input is rejected.
* **The intent contract is read-only by shape** — it carries only resource,
  operation, an optional single target identifier, bounded filters, and
  pagination.  It structurally cannot express SQL, arbitrary code, writes,
  or function names — anything outside the grammar is rejected.
* **Results are serialized read models** — execution returns the existing
  query-layer read models (never SQLAlchemy objects, never raw rows) as
  JSON-safe dictionaries, preserving their semantics untouched.

The LLM is only ever responsible for parsing user language into a
:class:`SOCModelIntent` candidate; it cannot execute, cannot name
functions, and cannot affect anything beyond that candidate.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.incident_memory import MemoryType
from app.schemas.risk import RiskLevel


# ---------------------------------------------------------------------------
# Bounds — reject, never truncate.
# ---------------------------------------------------------------------------

#: Maximum length of the raw user query accepted by the API and the engine.
SOC_MAX_QUERY_LENGTH = 2048

#: Maximum serialized size of the LLM's structured output.
SOC_MAX_MODEL_OUTPUT_BYTES = 4096

#: Page-size cap — must stay <= the query services' ``MAX_PAGE_SIZE``.
SOC_MAX_PAGE_SIZE = 200

#: Recent-feed limit cap — must stay <= the query services' ``MAX_RECENT_LIMIT``.
SOC_MAX_RECENT_LIMIT = 200

#: Default page size for paginated operations (matches the services).
SOC_DEFAULT_PAGE_SIZE = 50

#: Default limit for recent-feed operations (matches the services).
SOC_DEFAULT_RECENT_LIMIT = 50

#: Max length of a ``rule_id`` accepted by rule-scoped intents
#: (matches the detection query service bound).
SOC_MAX_RULE_ID_LENGTH = 255


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SOCResource(str, Enum):
    """The allowlisted read resources the Natural Language SOC may query.

    Only resources with an established read/query service are listed.
    ``incident_learning`` is intentionally **not** listed: no read-only
    Incident Memory Learning query service exists, and Step 23 must not
    create a query implementation merely for Natural Language SOC.
    """

    DETECTIONS = "detections"
    CORRELATIONS = "correlations"
    RISK_ASSESSMENTS = "risk_assessments"
    INCIDENT_MEMORIES = "incident_memories"


class SOCOperation(str, Enum):
    """The operation vocabulary of the SOC query grammar."""

    GET = "get"
    LIST = "list"
    RECENT = "recent"
    BY_EVENT = "by_event"
    BY_CORRELATION = "by_correlation"
    BY_DETECTION = "by_detection"
    BY_RULE = "by_rule"


class SOCExecutionMode(str, Enum):
    """How the executor satisfies an intent — a declarative dispatch class.

    Each ``(resource, operation)`` combination in the registry maps to
    exactly one mode, which determines which existing query-service method
    is called and which pagination shape is legal.
    """

    EXACT_LOOKUP = "exact_lookup"
    PAGED_QUERY = "paged_query"
    RECENT_FEED = "recent_feed"


# ---------------------------------------------------------------------------
# Filters — bounded, explicitly declared.
# ---------------------------------------------------------------------------


class SOCFilters(BaseModel):
    """Declared, bounded query filters.

    A filter is only *valid* for specific ``(resource, operation)`` pairs
    (enforced deterministically by the validator); the model schema merely
    constrains the value types.  Unknown filter fields are rejected.
    """

    model_config = ConfigDict(extra="forbid")

    memory_type: MemoryType | None = Field(
        default=None,
        description=(
            "Native database-side filter valid only for "
            "incident_memories.list (surfaces the existing "
            "IncidentMemoryQueryService.list_memories filter)."
        ),
    )
    risk_level: RiskLevel | None = Field(
        default=None,
        description=(
            "Filter valid only for risk_assessments.recent; applied as a "
            "deterministic in-process post-filter over the bounded recent "
            "feed against the persisted RiskAssessmentRecord.level."
        ),
    )


# ---------------------------------------------------------------------------
# Candidate LLM intent (untrusted model output)
# ---------------------------------------------------------------------------


class SOCModelIntent(BaseModel):
    """The structured intent candidate the LLM may produce (untrusted).

    The LLM's raw output is strictly parsed and validated against *this*
    contract before anything else.  Only ``resource`` and ``operation`` are
    required; target identifiers, filters, and pagination are optional
    bounded candidates that the deterministic validator re-checks against
    the allowlist grammar.  Unknown fields, malformed IDs, out-of-bounds
    values, multiple target identifiers, and inconsistent pagination are
    rejected here — never "repaired".
    """

    model_config = ConfigDict(extra="forbid")

    resource: SOCResource = Field(..., description="Allowlisted read resource.")
    operation: SOCOperation = Field(..., description="Operation on the resource.")

    correlation_id: uuid.UUID | None = Field(
        default=None,
        description="Target correlation identifier (only where the grammar allows it).",
    )
    event_id: uuid.UUID | None = Field(
        default=None,
        description="Target event identifier (only where the grammar allows it).",
    )
    detection_id: uuid.UUID | None = Field(
        default=None,
        description="Target detection identifier (only where the grammar allows it).",
    )
    risk_assessment_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Target risk-assessment identifier (only where the grammar allows it)."
        ),
    )
    memory_id: uuid.UUID | None = Field(
        default=None,
        description="Target incident-memory identifier (only where the grammar allows it).",
    )
    rule_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=SOC_MAX_RULE_ID_LENGTH,
        description=(
            "Target detection rule identifier (a bounded, non-secret "
            "application-defined identifier; only where the grammar allows it)."
        ),
    )
    filters: SOCFilters = Field(
        default_factory=SOCFilters,
        description="Bounded declared filters (validity is grammar-checked).",
    )
    limit: int | None = Field(
        default=None,
        ge=1,
        le=SOC_MAX_RECENT_LIMIT,
        description="Recent-feed limit candidate (recent operations only).",
    )
    page: int | None = Field(
        default=None,
        ge=1,
        description="1-based page candidate (paginated operations only).",
    )
    page_size: int | None = Field(
        default=None,
        ge=1,
        le=SOC_MAX_PAGE_SIZE,
        description="Page-size candidate (paginated operations only).",
    )

    @model_validator(mode="after")
    def _single_target_identifier(self) -> "SOCModelIntent":
        ids = [
            name
            for name in (
                "correlation_id",
                "event_id",
                "detection_id",
                "risk_assessment_id",
                "memory_id",
                "rule_id",
            )
            if getattr(self, name) is not None
        ]
        if len(ids) > 1:
            raise ValueError(
                "an intent may carry at most one target identifier; "
                f"received {', '.join(sorted(ids))}"
            )
        return self

    @model_validator(mode="after")
    def _pagination_consistency(self) -> "SOCModelIntent":
        if self.limit is not None and (self.page is not None or self.page_size is not None):
            raise ValueError(
                "limit and page/page_size are mutually exclusive pagination shapes"
            )
        if self.page_size is not None and self.page is None:
            raise ValueError("page_size requires page")
        return self


# ---------------------------------------------------------------------------
# Validated intent (executor input)
# ---------------------------------------------------------------------------


class SOCQueryTarget(BaseModel):
    """The single (or absent) target identifier of a validated intent."""

    model_config = ConfigDict(extra="forbid")

    event_id: uuid.UUID | None = Field(default=None)
    correlation_id: uuid.UUID | None = Field(default=None)
    detection_id: uuid.UUID | None = Field(default=None)
    risk_assessment_id: uuid.UUID | None = Field(default=None)
    memory_id: uuid.UUID | None = Field(default=None)
    rule_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=SOC_MAX_RULE_ID_LENGTH,
    )

    @model_validator(mode="after")
    def _single_target_identifier(self) -> "SOCQueryTarget":
        ids = [
            name
            for name in (
                "event_id",
                "correlation_id",
                "detection_id",
                "risk_assessment_id",
                "memory_id",
                "rule_id",
            )
            if getattr(self, name) is not None
        ]
        if len(ids) > 1:
            raise ValueError(
                "a query may carry at most one target identifier; "
                f"received {', '.join(sorted(ids))}"
            )
        return self


class SOCPagination(BaseModel):
    """Exact pagination shape for a validated intent.

    Exactly one of the three shapes is present (enforced by the validator):
    a recent-feed ``limit``, a ``page``/``page_size`` pair, or nothing
    (exact lookups).  Defaults are filled in by the deterministic validator.
    """

    model_config = ConfigDict(extra="forbid")

    page: int | None = Field(default=None, ge=1)
    page_size: int | None = Field(default=None, ge=1, le=SOC_MAX_PAGE_SIZE)
    limit: int | None = Field(default=None, ge=1, le=SOC_MAX_RECENT_LIMIT)

    @model_validator(mode="after")
    def _exact_pagination_shape(self) -> "SOCPagination":
        if self.limit is not None and (self.page is not None or self.page_size is not None):
            raise ValueError(
                "recent-feed limit and page/page_size cannot be combined"
            )
        if self.page_size is not None and self.page is None:
            raise ValueError("page_size requires page")
        return self


class SOCQueryIntent(BaseModel):
    """A validated SOC query intent ready for deterministic execution.

    Produced exclusively by the deterministic validator from an
    :class:`SOCModelIntent` candidate — never directly from the LLM.  The
    ``mode`` declares the dispatch class; ``target`` carries at most one
    identifier; ``filters`` carries only grammar-legal filters; and
    ``pagination`` carries exactly the shape the operation requires.
    """

    model_config = ConfigDict(extra="forbid")

    resource: SOCResource = Field(...)
    operation: SOCOperation = Field(...)
    mode: SOCExecutionMode = Field(...)
    target: SOCQueryTarget = Field(default_factory=SOCQueryTarget)
    filters: SOCFilters = Field(default_factory=SOCFilters)
    pagination: SOCPagination = Field(default_factory=SOCPagination)


# ---------------------------------------------------------------------------
# Response contract
# ---------------------------------------------------------------------------


class SOCExecutionMetadata(BaseModel):
    """Deterministic execution metadata for one SOC query response."""

    model_config = ConfigDict(extra="forbid")

    resource: SOCResource = Field(...)
    operation: SOCOperation = Field(...)
    mode: SOCExecutionMode = Field(...)
    page: int | None = Field(default=None, ge=1)
    page_size: int | None = Field(default=None, ge=1, le=SOC_MAX_PAGE_SIZE)
    limit: int | None = Field(default=None, ge=1, le=SOC_MAX_RECENT_LIMIT)
    applied_filters: list[str] = Field(
        default_factory=list,
        description=(
            "Deterministic string list of the filters actually applied, e.g. "
            "``['risk_level=high']``."
        ),
    )
    parser_provider: str | None = Field(
        default=None,
        description="Provider name that parsed the query (e.g. 'gemini').",
    )
    parser_model: str | None = Field(
        default=None,
        description="Model name that parsed the query, when known.",
    )
    recorded_at: datetime = Field(
        ...,
        description="UTC instant the response was assembled (timezone-aware).",
    )


class SOCQueryResponse(BaseModel):
    """The structured Natural Language SOC response contract.

    Distinguishes the validated intent, deterministic execution metadata,
    the serialized read-model results, count/pagination, deterministic
    semantic labels, and a deterministic human-readable note.  No arbitrary
    Python objects, no SQLAlchemy objects, and no database internals are
    ever returned.  ``read_only`` is pinned ``True`` by construction.
    """

    model_config = ConfigDict(extra="forbid")

    intent: SOCQueryIntent = Field(..., description="The validated query intent.")
    metadata: SOCExecutionMetadata = Field(
        ...,
        description="Deterministic execution metadata.",
    )
    read_only: Literal[True] = Field(
        default=True,
        description="Pinned true — the Natural Language SOC interface is read-only.",
    )
    found: bool = Field(
        ...,
        description="Whether any result matched the validated intent.",
    )
    count: int = Field(
        ...,
        ge=0,
        le=SOC_MAX_PAGE_SIZE,
        description="Number of result records returned (never truncated above bounds).",
    )
    total: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Total matching records for paginated operations (from the "
            "existing page contract); None for feeds and exact lookups."
        ),
    )
    items: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Serialized existing query-layer read models (JSON-safe dicts), "
            "preserving their original semantics."
        ),
    )
    semantics: list[str] = Field(
        default_factory=list,
        description=(
            "Deterministic semantic labels describing what the results are "
            "(e.g. historical incident memory is never presented as a "
            "current observation)."
        ),
    )
    note: str = Field(
        ...,
        description=(
            "Deterministic human-readable summary built by the formatter — "
            "never fabricated by an LLM."
        ),
    )


# ---------------------------------------------------------------------------
# API request contract
# ---------------------------------------------------------------------------


class SOCQueryRequest(BaseModel):
    """The single Natural Language SOC request body."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(
        ...,
        min_length=1,
        max_length=SOC_MAX_QUERY_LENGTH,
        description=(
            "Natural-language security-data question (bounded; oversized or "
            "blank input is rejected, never truncated)."
        ),
    )

    @model_validator(mode="after")
    def _query_not_blank(self) -> "SOCQueryRequest":
        if not self.query.strip():
            raise ValueError("query must not be blank")
        return self


# ---------------------------------------------------------------------------
# Gemini structured-output companion schema (mirrors SOCModelIntent).
# ---------------------------------------------------------------------------
#
# Sent to Gemini as its ``responseSchema`` so the model is constrained to the
# shape of the candidate intent.  Pydantic validation of the actual returned
# payload remains authoritative.

SOC_INTENT_MODEL_JSON_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "resource": {"type": "STRING"},
        "operation": {"type": "STRING"},
        "correlation_id": {"type": "STRING"},
        "event_id": {"type": "STRING"},
        "detection_id": {"type": "STRING"},
        "risk_assessment_id": {"type": "STRING"},
        "memory_id": {"type": "STRING"},
        "rule_id": {"type": "STRING"},
        "filters": {
            "type": "OBJECT",
            "properties": {
                "memory_type": {"type": "STRING"},
                "risk_level": {"type": "STRING"},
            },
        },
        "limit": {"type": "INTEGER"},
        "page": {"type": "INTEGER"},
        "page_size": {"type": "INTEGER"},
    },
    "required": ["resource", "operation"],
}