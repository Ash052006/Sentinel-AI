"""Threat Hunting Domain Contract — V2.19.

Defines the **structured, allowlisted hunting grammar** and the persisted
read models for analyst-driven threat hunts: the closed hunt lifecycle, the
closed filter/operator vocabulary that maps 1:1 onto existing SentinelAI
persisted records, and the evidence/finding/timeline read models.

Pipeline position::

    Detection -> Correlation -> Risk -> Investigation -> Attribution
        -> Memory -> [ Threat Hunting (this module) ] -> Findings & Timeline

Design principles:

* **Analyst-driven and read-only.**  A hunt queries existing persisted
  analytical records (detection results, correlation results + members,
  risk assessments, threat-intel indicators/lookups, incident memory,
  audit logs) within a bounded time range.  A hunt **never** mutates
  events, never issues a response action, never reaches SOAR, and never
  executes an automatic mitigation.
* **Structured grammar, never a query language.**  Filters are a closed
  set of ``(field, operator, value)`` triples, each field mapped to a real
  existing column and each operator restricted per field.  There is no
  raw SQL, no OpenSearch DSL, no arbitrary string, no expression tree,
  and no client-supplied backend query anywhere in this contract.
* **Bounded everywhere.**  Every hunt has a timezone-aware ``start_time``
  and ``end_time`` with a maximum window, a maximum filter count, per
  surface/evidence caps, and page-bounded reads.  A hunt can never load an
  unbounded data set.
* **Bounded time range required.**  ``start < end`` and
  ``end - start <= HUNT_MAX_WINDOW_HOURS`` are enforced at the boundary;
  there is no "search everything" request.
* **Provenance is never fabricated.**  Finding and evidence provenance is
  taken from the persisted source record ``(observed / enriched /
  detected / correlated / risk_assessed / recalled)`` — a hunt can never
  silently convert reconstructed or memory data into observed evidence,
  and it never produces ``ai_generated`` content.
* **Deterministic findings.**  Findings are derived from the collected
  evidence (grouped counts, inherited severities).  No ML confidence is
  invented; a numeric confidence is omitted when it cannot be defended.

Most important boundary:

    Threat Hunting investigates.  It does NOT execute, mutate, block,
    quarantine, or orchestrate anything.  It has no provider, no action,
    no operation vocabulary and no write path to any security control.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.correlation import CorrelationStatus
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.incident_memory import MemoryType
from app.schemas.risk import RiskLevel
from app.services.threat_intelligence.types import IndicatorType

# ---------------------------------------------------------------------------
# Bounds & constants (single source of truth)
# ---------------------------------------------------------------------------

#: Deterministic UUIDv5 namespace for hunt/finding/timeline identities.
HUNT_NAMESPACE = uuid.UUID("7f3a1b2c-9e4d-4a56-b7c8-9d0e1f2a3b4c")

#: Maximum length of a hunt name.
HUNT_MAX_NAME_LENGTH = 120

#: Maximum allowed hunt window in hours (30 days) — hard upper bound.
HUNT_MAX_WINDOW_HOURS = 720

#: Maximum number of structured filters in a single hunt.
HUNT_MAX_FILTERS = 8

#: Maximum number of values in an IN/NOT_IN filter set.
HUNT_MAX_FILTER_SET = 20

#: Maximum length of a single filter value.
HUNT_MAX_FILTER_VALUE_LENGTH = 2048

#: Maximum records retrieved per surface query (bounded, never streamed).
HUNT_SURFACE_CAP = 200

#: Maximum total evidence items (primary + linked) for one hunt run.
HUNT_MAX_EVIDENCE = 300

#: Maximum total timeline items for one hunt run.
HUNT_MAX_TIMELINE_ITEMS = 300

#: Maximum total deterministic findings for one hunt run.
HUNT_MAX_FINDINGS = 25

#: Maximum rows/items returned by read pages (pagination convention).
HUNT_DEFAULT_PAGE_SIZE = 50
HUNT_MAX_PAGE_SIZE = 200

#: Length caps for persisted human-readable text.
HUNT_MAX_TITLE_LENGTH = 200
HUNT_MAX_SUMMARY_LENGTH = 500
HUNT_MAX_DESCRIPTION_LENGTH = 1000
HUNT_MAX_SOURCE_KEY_LENGTH = 255
HUNT_MAX_ERROR_CODE_LENGTH = 64
HUNT_MAX_ERROR_MESSAGE_LENGTH = 500

#: Closed set of provenance values a hunt may carry on evidence/findings.
#: Deliberately excludes ai_generated/policy_decided/response_executed/
#: approval_reviewed/learned — a hunt never fabricates those.
HUNT_EVIDENCE_PROVENANCES = frozenset(
    {"observed", "enriched", "detected", "correlated", "risk_assessed", "recalled"}
)

_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret", "password", "token")


def _assert_no_secrets(value: str, field: str) -> None:
    lowered = value.lower()
    for pattern in _SECRET_PATTERNS:
        if pattern in lowered:
            raise ValueError(f"{field} must not contain secrets ('{pattern}' detected)")


def _assert_json_compatible(value: Any, field: str) -> None:
    try:
        import json

        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise ValueError(f"{field} must be JSON-compatible") from exc


def _reject_control_characters(value: str, field: str) -> str:
    if any(
        ch != "\t"
        and ((o := ord(ch)) < 32 or o == 127 or 128 <= o <= 159)
        for ch in value
    ):
        raise ValueError(f"{field} must not contain control characters")
    return value


def _ensure_tz_aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field} must be timezone-aware (UTC instants accepted)")
    return value


def _require_non_blank(value: str, field: str) -> str:
    if not value.strip():
        raise ValueError(f"{field} must not be blank")
    return value.strip()


# ---------------------------------------------------------------------------
# Closed enums
# ---------------------------------------------------------------------------


class ThreatHuntStatus(str, Enum):
    """Closed hunt lifecycle.

    * ``draft``    — created and validated, not yet executed.
    * ``running``  — a run has begun (transient; execution is synchronous).
    * ``completed``— the run finished within bounds; findings/timeline persisted.
    * ``failed``   — the run was refused or blew a bound (structured error).
    * ``cancelled``— an authorized analyst cancelled a non-terminal hunt.
    """

    DRAFT = "draft"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class HuntType(str, Enum):
    """Closed set of deterministic hunt templates.

    Only templates that existing SentinelAI persisted data can actually
    support are included.  There is deliberately no process/network
    template: no process or raw-network telemetry is persisted, so such a
    hunt could not be answered honestly.
    """

    AUTHENTICATION_ANOMALY = "authentication_anomaly"
    INDICATOR_HUNT = "indicator_hunt"
    PRIVILEGE_ACTIVITY = "privilege_activity"
    MULTI_STAGE_ACTIVITY = "multi_stage_activity"
    DETECTION_REVIEW = "detection_review"


class HuntFilterField(str, Enum):
    """Closed set of huntable fields.

    Every field maps 1:1 to a real column of an existing persisted record.
    """

    EVENT_ID = "event_id"
    DETECTION_ID = "detection_id"
    RULE_ID = "rule_id"
    RULE_TYPE = "rule_type"
    SEVERITY = "severity"
    CORRELATION_ID = "correlation_id"
    CORRELATION_STATUS = "correlation_status"
    RISK_LEVEL = "risk_level"
    INDICATOR_TYPE = "indicator_type"
    INDICATOR_VALUE = "indicator_value"
    MEMORY_TYPE = "memory_type"
    AUDIT_ACTION = "audit_action"
    AUDIT_RESOURCE = "audit_resource"
    ACTOR_IP = "actor_ip"


class HuntOperator(str, Enum):
    """Closed set of safe comparison operators.

    Operators are assigned per field (see ``FIELD_OPERATORS``); arbitrary
    expressions / cross-field math are impossible by construction.
    """

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"


class HuntEvidenceType(str, Enum):
    """Closed set of persisted evidence kinds a hunt may reference."""

    AUDIT_LOG = "audit_log"
    DETECTION = "detection"
    CORRELATION = "correlation"
    CORRELATION_MEMBER = "correlation_member"
    RISK_ASSESSMENT = "risk_assessment"
    INDICATOR = "indicator"
    INDICATOR_LOOKUP = "indicator_lookup"
    INCIDENT_MEMORY = "incident_memory"


# ---------------------------------------------------------------------------
# Grammar matrix (single source of truth — service + engine both consult it)
# ---------------------------------------------------------------------------

#: Allowed operators per field.
FIELD_OPERATORS: dict[HuntFilterField, frozenset[HuntOperator]] = {
    HuntFilterField.EVENT_ID: frozenset({HuntOperator.EQUALS}),
    HuntFilterField.DETECTION_ID: frozenset({HuntOperator.EQUALS}),
    HuntFilterField.RULE_ID: frozenset(
        {HuntOperator.EQUALS, HuntOperator.NOT_EQUALS, HuntOperator.IN, HuntOperator.NOT_IN}
    ),
    HuntFilterField.RULE_TYPE: frozenset({HuntOperator.EQUALS, HuntOperator.IN}),
    HuntFilterField.SEVERITY: frozenset({HuntOperator.EQUALS, HuntOperator.IN}),
    HuntFilterField.CORRELATION_ID: frozenset({HuntOperator.EQUALS}),
    HuntFilterField.CORRELATION_STATUS: frozenset({HuntOperator.EQUALS, HuntOperator.IN}),
    HuntFilterField.RISK_LEVEL: frozenset({HuntOperator.EQUALS, HuntOperator.IN}),
    HuntFilterField.INDICATOR_TYPE: frozenset({HuntOperator.EQUALS, HuntOperator.IN}),
    HuntFilterField.INDICATOR_VALUE: frozenset(
        {HuntOperator.EQUALS, HuntOperator.NOT_EQUALS,
         HuntOperator.CONTAINS, HuntOperator.STARTS_WITH, HuntOperator.ENDS_WITH}
    ),
    HuntFilterField.MEMORY_TYPE: frozenset({HuntOperator.EQUALS, HuntOperator.IN}),
    HuntFilterField.AUDIT_ACTION: frozenset(
        {HuntOperator.EQUALS, HuntOperator.NOT_EQUALS, HuntOperator.IN, HuntOperator.STARTS_WITH}
    ),
    HuntFilterField.AUDIT_RESOURCE: frozenset({HuntOperator.EQUALS, HuntOperator.NOT_EQUALS}),
    HuntFilterField.ACTOR_IP: frozenset({HuntOperator.EQUALS, HuntOperator.NOT_EQUALS}),
}

#: Value kind per field — drives coercion and validity checks.
FIELD_VALUE_KIND: dict[HuntFilterField, Literal[
    "uuid", "str", "rule_type", "severity", "correlation_status",
    "risk_level", "indicator_type", "memory_type",
]] = {
    HuntFilterField.EVENT_ID: "uuid",
    HuntFilterField.DETECTION_ID: "uuid",
    HuntFilterField.RULE_ID: "str",
    HuntFilterField.RULE_TYPE: "rule_type",
    HuntFilterField.SEVERITY: "severity",
    HuntFilterField.CORRELATION_ID: "uuid",
    HuntFilterField.CORRELATION_STATUS: "correlation_status",
    HuntFilterField.RISK_LEVEL: "risk_level",
    HuntFilterField.INDICATOR_TYPE: "indicator_type",
    HuntFilterField.INDICATOR_VALUE: "str",
    HuntFilterField.MEMORY_TYPE: "memory_type",
    HuntFilterField.AUDIT_ACTION: "str",
    HuntFilterField.AUDIT_RESOURCE: "str",
    HuntFilterField.ACTOR_IP: "str",
}

_ENUM_CHOICES: dict[str, frozenset[str]] = {
    "rule_type": frozenset(member.value for member in RuleType),
    "severity": frozenset(member.value for member in DetectionSeverity),
    "correlation_status": frozenset(member.value for member in CorrelationStatus),
    "risk_level": frozenset(member.value for member in RiskLevel),
    "indicator_type": frozenset(member.value for member in IndicatorType),
    "memory_type": frozenset(member.value for member in MemoryType),
}

#: Allowed filter fields per hunt type (a hunt can never ask for a field
#: its template does not touch).
HUNT_TYPE_FIELDS: dict[HuntType, frozenset[HuntFilterField]] = {
    HuntType.AUTHENTICATION_ANOMALY: frozenset(
        {HuntFilterField.AUDIT_ACTION, HuntFilterField.AUDIT_RESOURCE, HuntFilterField.ACTOR_IP}
    ),
    HuntType.INDICATOR_HUNT: frozenset(
        {HuntFilterField.INDICATOR_TYPE, HuntFilterField.INDICATOR_VALUE}
    ),
    HuntType.DETECTION_REVIEW: frozenset(
        {
            HuntFilterField.EVENT_ID, HuntFilterField.DETECTION_ID,
            HuntFilterField.RULE_ID, HuntFilterField.RULE_TYPE, HuntFilterField.SEVERITY,
        }
    ),
    HuntType.PRIVILEGE_ACTIVITY: frozenset(
        {
            HuntFilterField.EVENT_ID, HuntFilterField.DETECTION_ID,
            HuntFilterField.RULE_ID, HuntFilterField.RULE_TYPE, HuntFilterField.SEVERITY,
            HuntFilterField.RISK_LEVEL,
        }
    ),
    HuntType.MULTI_STAGE_ACTIVITY: frozenset(
        {HuntFilterField.CORRELATION_ID, HuntFilterField.CORRELATION_STATUS}
    ),
}

#: Closed set of evidence provenance values (mirrors the DB CHECK).
EVIDENCE_PROVENANCE_VALUES = tuple(sorted(HUNT_EVIDENCE_PROVENANCES))

#: Severity ladder used only for ordering (never to fabricate a value).
_SEVERITY_RANK = {value: idx for idx, value in enumerate(
    ("low", "medium", "high", "critical")
)}


# ---------------------------------------------------------------------------
# Structured filter
# ---------------------------------------------------------------------------


class HuntFilter(BaseModel):
    """One structured, allowlisted filter triple.

    ``IN`` / ``NOT_IN`` filters carry a ``values`` list; every other
    operator carries a single ``value``.  Exactly one form is accepted.
    """

    model_config = ConfigDict(extra="forbid")

    field: HuntFilterField = Field(
        ...,
        description="The closed field this filter applies to.",
    )
    operator: HuntOperator = Field(
        ...,
        description="The closed operator this filter applies.",
    )
    value: str | None = Field(
        default=None,
        description="Single value for scalar operators (EQUALS/CONTAINS/...).",
    )
    values: list[str] | None = Field(
        default=None,
        description="Value set for IN / NOT_IN operators (bounded list).",
    )

    @field_validator("field")
    @classmethod
    def _field_allowed(cls, v: HuntFilterField) -> HuntFilterField:
        return v

    @model_validator(mode="after")
    def _validate_shape_and_coercion(self) -> "HuntFilter":
        set_value: str | None = self.value
        set_values: list[str] | None = self.values
        is_set_op = self.operator in (HuntOperator.IN, HuntOperator.NOT_IN)

        if self.operator not in FIELD_OPERATORS[self.field]:
            raise ValueError(
                f"operator '{self.operator.value}' is not valid for field "
                f"'{self.field.value}'"
            )

        if is_set_op:
            if set_value is not None or set_values is None or not set_values:
                raise ValueError(
                    f"filter '{self.field.value}' with operator "
                    f"'{self.operator.value}' requires a non-empty 'values' list"
                )
            if len(set_values) > HUNT_MAX_FILTER_SET:
                raise ValueError(
                    f"filter set exceeds the maximum of {HUNT_MAX_FILTER_SET} values"
                )
            coerced: list[str] = []
            for item in set_values:
                coerced.append(self._coerce_single(item, "values"))
            self.values = coerced
        else:
            if set_values is not None or set_value is None:
                raise ValueError(
                    f"filter '{self.field.value}' with operator "
                    f"'{self.operator.value}' requires a single 'value'"
                )
            self.value = self._coerce_single(set_value, "value")
        return self

    def _coerce_single(self, raw: str, slot: str) -> str:
        kind = FIELD_VALUE_KIND[self.field]
        clean = _reject_control_characters(raw, slot)
        _assert_no_secrets(clean, self.field.value)
        if not clean.strip():
            raise ValueError(f"{self.field.value} filter {slot} must not be blank")
        if len(clean) > HUNT_MAX_FILTER_VALUE_LENGTH:
            raise ValueError(
                f"{self.field.value} filter {slot} exceeds "
                f"{HUNT_MAX_FILTER_VALUE_LENGTH} characters"
            )
        if kind == "uuid":
            try:
                return str(uuid.UUID(clean.strip()))
            except ValueError as exc:
                raise ValueError(
                    f"{self.field.value} filter must be a valid UUID"
                ) from exc
        if kind in _ENUM_CHOICES:
            if clean not in _ENUM_CHOICES[kind]:
                allowed = ", ".join(sorted(_ENUM_CHOICES[kind]))
                raise ValueError(
                    f"{self.field.value} filter value '{clean}' is not in "
                    f"the closed set ({allowed})"
                )
            return clean
        return clean.strip()

    @property
    def scalar_value(self) -> str | None:
        """The single scalar value (valid for non-set operators)."""
        if self.operator in (HuntOperator.IN, HuntOperator.NOT_IN):
            return None
        return self.value

    @property
    def set_values(self) -> list[str] | None:
        if self.operator in (HuntOperator.IN, HuntOperator.NOT_IN):
            return self.values or []
        return None


# ---------------------------------------------------------------------------
# Create request
# ---------------------------------------------------------------------------


class ThreatHuntCreate(BaseModel):
    """Boundary input for creating a hunt (draft) and later running it."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        ...,
        max_length=HUNT_MAX_NAME_LENGTH,
        description="Short, secret-free, analyst-assigned hunt name.",
    )
    hunt_type: HuntType = Field(
        ...,
        description="The closed hunt template to execute.",
    )
    description: str = Field(
        default="",
        max_length=HUNT_MAX_DESCRIPTION_LENGTH,
        description="Free-form, secret-free analyst description (never executed).",
    )
    start_time: datetime = Field(
        ...,
        description="Timezone-aware start of the bounded hunting window.",
    )
    end_time: datetime = Field(
        ...,
        description="Timezone-aware end of the bounded hunting window (exclusive).",
    )
    filters: list[HuntFilter] = Field(
        default_factory=list,
        max_length=HUNT_MAX_FILTERS,
        description="Optional structured filters (bounded, allowlisted per type).",
    )

    @field_validator("name")
    @classmethod
    def _name_safe(cls, v: str) -> str:
        clean = _reject_control_characters(v, "name")
        clean = _require_non_blank(clean, "name")
        _assert_no_secrets(clean, "name")
        return clean

    @field_validator("description")
    @classmethod
    def _description_safe(cls, v: str) -> str:
        if not v:
            return ""
        clean = _reject_control_characters(v, "description")
        _assert_no_secrets(clean, "description")
        return clean.strip()

    @field_validator("start_time", "end_time")
    @classmethod
    def _bounded_times(cls, v: datetime) -> datetime:
        return _ensure_tz_aware(v, "timestamp")

    @model_validator(mode="after")
    def _validate_window(self) -> "ThreatHuntCreate":
        if self.end_time <= self.start_time:
            raise ValueError("end_time must be after start_time")
        window_hours = (self.end_time - self.start_time).total_seconds() / 3600.0
        if window_hours > HUNT_MAX_WINDOW_HOURS:
            raise ValueError(
                f"hunting window exceeds the maximum of "
                f"{HUNT_MAX_WINDOW_HOURS} hours ({HUNT_MAX_WINDOW_HOURS // 24} days)"
            )
        if len(self.filters) > HUNT_MAX_FILTERS:
            raise ValueError(f"a hunt may carry at most {HUNT_MAX_FILTERS} filters")
        allowed = HUNT_TYPE_FIELDS[self.hunt_type]
        seen: set[HuntFilterField] = set()
        for flt in self.filters:
            if flt.field not in allowed:
                raise ValueError(
                    f"field '{flt.field.value}' is not supported by hunt type "
                    f"'{self.hunt_type.value}'"
                )
            if flt.field in seen:
                raise ValueError(
                    f"field '{flt.field.value}' may appear at most once per hunt"
                )
            seen.add(flt.field)
        return self


# ---------------------------------------------------------------------------
# Read models
# ---------------------------------------------------------------------------


class ThreatHuntSummary(BaseModel):
    """Read-only summary of one persisted hunt."""

    model_config = ConfigDict(extra="forbid")

    hunt_id: uuid.UUID = Field(
        ...,
        description="Deterministic/unique identity of the hunt.",
    )
    name: str = Field(
        ...,
        description="The analyst-assigned hunt name.",
    )
    hunt_type: HuntType = Field(
        ...,
        description="The closed hunt template that was/will be executed.",
    )
    status: ThreatHuntStatus = Field(
        ...,
        description="Closed lifecycle status of the hunt.",
    )
    start_time: datetime = Field(
        ...,
        description="Timezone-aware start of the hunting window.",
    )
    end_time: datetime = Field(
        ...,
        description="Timezone-aware end of the hunting window.",
    )
    created_by: uuid.UUID = Field(
        ...,
        description="Trusted identity that created the hunt.",
    )
    created_by_role: str = Field(
        ...,
        description="Role label of the creating actor.",
    )
    created_at: datetime = Field(
        ...,
        description="When the hunt was created (UTC, tz-aware).",
    )
    started_at: datetime | None = Field(
        default=None,
        description="When the run began (None before run).",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="When the run completed or failed (None otherwise).",
    )
    result_count: int = Field(
        default=0,
        description="Total evidence items collected by the run.",
    )
    finding_count: int = Field(
        default=0,
        description="Total findings produced by the run.",
    )
    timeline_count: int = Field(
        default=0,
        description="Total timeline items produced by the run.",
    )
    error_code: str | None = Field(
        default=None,
        description="Sanitized structured error code when the run failed.",
    )
    error_message: str | None = Field(
        default=None,
        description="Sanitized human-readable error message when the run failed.",
    )


class ThreatHuntDetail(ThreatHuntSummary):
    """Full read model: summary plus the persisted structured filters."""

    description: str = Field(
        default="",
        max_length=HUNT_MAX_DESCRIPTION_LENGTH,
        description="Free-form analyst description (never executed).",
    )
    filters: list[HuntFilter] = Field(
        default_factory=list,
        description="The structured filters the run compiled (as stored).",
    )


class ThreatHuntEvidenceRecord(BaseModel):
    """Read-only view of one piece of hunt evidence."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: uuid.UUID = Field(
        ...,
        description="Deterministic identity of the evidence item (within the hunt).",
    )
    evidence_type: HuntEvidenceType = Field(
        ...,
        description="Which persisted record kind this evidence references.",
    )
    reference_id: uuid.UUID = Field(
        ...,
        description="Identity of the referenced existing record (never a copy).",
    )
    event_id: uuid.UUID | None = Field(
        default=None,
        description="Referenced event identity when the source record carries one.",
    )
    correlation_id: uuid.UUID | None = Field(
        default=None,
        description="Referenced correlation identity when applicable.",
    )
    provenance: str = Field(
        ...,
        description="Envelope provenance of the referenced record (never invented).",
    )
    severity: str | None = Field(
        default=None,
        description="Inherited severity/level when the source record carries one.",
    )
    observed_at: datetime | None = Field(
        default=None,
        description="The record's own event timestamp (UTC, tz-aware).",
    )
    title: str = Field(
        ...,
        description="Short deterministic descriptor of the evidence.",
    )
    summary: str = Field(
        ...,
        description="Deterministic, secret-free one-line summary from the record.",
    )


class ThreatHuntFindingRecord(BaseModel):
    """Read-only view of one deterministic finding."""

    model_config = ConfigDict(extra="forbid")

    finding_id: uuid.UUID = Field(
        ...,
        description="Deterministic identity of the finding.",
    )
    title: str = Field(
        ...,
        description="Short deterministic finding title.",
    )
    description: str = Field(
        ...,
        description="Deterministic, evidence-derived description.",
    )
    severity: str | None = Field(
        default=None,
        description="Inherited severity/level only when defensible from evidence.",
    )
    provenance: str = Field(
        ...,
        description="Provenance of the underlying evidence (never invented).",
    )
    observed_at: datetime | None = Field(
        default=None,
        description="Earliest evidence timestamp in the finding (None if none).",
    )
    evidence_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="The evidence items this finding is derived from.",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Bounded, deterministic grouping context (e.g. rule_id, counts).",
    )


class ThreatHuntTimelineItemRecord(BaseModel):
    """Read-only view of one deterministic timeline item."""

    model_config = ConfigDict(extra="forbid")

    timeline_item_id: uuid.UUID = Field(
        ...,
        description="Deterministic identity of the timeline item.",
    )
    evidence_id: uuid.UUID = Field(
        ...,
        description="The evidence item this timeline entry references.",
    )
    observed_at: datetime | None = Field(
        default=None,
        description="Chronological key (the evidence's own timestamp).",
    )
    evidence_type: HuntEvidenceType = Field(
        ...,
        description="Evidence kind of the referenced item.",
    )
    evidence_summary: str = Field(
        ...,
        description="Deterministic summary copied from the referenced evidence.",
    )
    provenance: str = Field(
        ...,
        description="Provenance of the referenced evidence (never invented).",
    )


class ThreatHuntPage(BaseModel):
    """Paged list of hunt summaries."""

    model_config = ConfigDict(extra="forbid")

    items: list[ThreatHuntSummary] = Field(
        ...,
        description="The page of hunt summaries.",
    )
    total: int = Field(
        ...,
        description="Total matching hunts (full unpaginated count).",
    )
    page: int = Field(..., ge=1, description="One-based current page.")
    page_size: int = Field(..., ge=1, le=200, description="Rows per page.")
    status_filter: ThreatHuntStatus | None = Field(
        default=None,
        description="The status filter applied, if any.",
    )
    hunt_type_filter: HuntType | None = Field(
        default=None,
        description="The hunt-type filter applied, if any.",
    )


class ThreatHuntEvidencePage(BaseModel):
    """Paged list of evidence for one hunt."""

    model_config = ConfigDict(extra="forbid")

    items: list[ThreatHuntEvidenceRecord] = Field(
        ...,
        description="The page of evidence items.",
    )
    total: int = Field(..., description="Total evidence items for the hunt.")
    page: int = Field(..., ge=1, description="One-based current page.")
    page_size: int = Field(..., ge=1, le=200, description="Rows per page.")


class ThreatHuntFindingPage(BaseModel):
    """Paged list of findings for one hunt."""

    model_config = ConfigDict(extra="forbid")

    items: list[ThreatHuntFindingRecord] = Field(
        ...,
        description="The page of findings.",
    )
    total: int = Field(..., description="Total findings for the hunt.")
    page: int = Field(..., ge=1, description="One-based current page.")
    page_size: int = Field(..., ge=1, le=200, description="Rows per page.")


class ThreatHuntTimelinePage(BaseModel):
    """Paged list of timeline items for one hunt."""

    model_config = ConfigDict(extra="forbid")

    items: list[ThreatHuntTimelineItemRecord] = Field(
        ...,
        description="The page of timeline items (chronological order).",
    )
    total: int = Field(..., description="Total timeline items for the hunt.")
    page: int = Field(..., ge=1, description="One-based current page.")
    page_size: int = Field(..., ge=1, le=200, description="Rows per page.")


__all__ = [
    "HUNT_NAMESPACE",
    "HUNT_MAX_NAME_LENGTH",
    "HUNT_MAX_WINDOW_HOURS",
    "HUNT_MAX_FILTERS",
    "HUNT_MAX_FILTER_SET",
    "HUNT_MAX_FILTER_VALUE_LENGTH",
    "HUNT_SURFACE_CAP",
    "HUNT_MAX_EVIDENCE",
    "HUNT_MAX_FINDINGS",
    "HUNT_MAX_TIMELINE_ITEMS",
    "HUNT_DEFAULT_PAGE_SIZE",
    "HUNT_MAX_PAGE_SIZE",
    "HUNT_MAX_TITLE_LENGTH",
    "HUNT_MAX_SUMMARY_LENGTH",
    "HUNT_MAX_DESCRIPTION_LENGTH",
    "HUNT_MAX_SOURCE_KEY_LENGTH",
    "HUNT_MAX_ERROR_CODE_LENGTH",
    "HUNT_MAX_ERROR_MESSAGE_LENGTH",
    "HUNT_EVIDENCE_PROVENANCES",
    "EVIDENCE_PROVENANCE_VALUES",
    "ThreatHuntStatus",
    "HuntType",
    "HuntFilterField",
    "HuntOperator",
    "HuntEvidenceType",
    "FIELD_OPERATORS",
    "FIELD_VALUE_KIND",
    "HUNT_TYPE_FIELDS",
    "HuntFilter",
    "ThreatHuntCreate",
    "ThreatHuntSummary",
    "ThreatHuntDetail",
    "ThreatHuntEvidenceRecord",
    "ThreatHuntFindingRecord",
    "ThreatHuntTimelineItemRecord",
    "ThreatHuntPage",
    "ThreatHuntEvidencePage",
    "ThreatHuntFindingPage",
    "ThreatHuntTimelinePage",
]