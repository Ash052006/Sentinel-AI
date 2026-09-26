"""AI Incident Report contracts (V2.20).

Strict Pydantic contracts for the evidence-grounded AI Incident Report
Generator.  Canonical, single-source-of-truth schema module for the
feature; the schema module defines the **contracts only** — the pure,
deterministic assembly of a :class:`IncidentReportContext` lives in
``app/services/reporting/context.py`` and the strict model-output contract
lives in ``app/services/reporting/model_output.py``.

Trust boundary
--------------
    persisted SentinelAI records
          +
    bounded read-only context builder
          |
          v
    IncidentReportContext   (this module — the AI's only source material)
          |
          v
    ReportPromptBuilder / IncidentReportGeminiClient
          |
          v
    IncidentReportModelOutput (this module — strictly validated LLM prose)
          |
          v
    IncidentReport (this module — authoritative assembled report)
          |
          v
    incident_reports table (persisted, provenance-safe JSONB)

Design principles (mirroring the existing SentinelAI contracts):

* **Allowlisting** — each source maps through an explicit field allowlist;
  database internals never leak into the AI context or the report payload.
* **Provenance-preserving** — every evidence-bearing record keeps its
  source provenance; nothing is upgraded, downgraded or relabelled.
* **DATA != INSTRUCTION** — source telemetry is structured data only.
* **Explicit availability** — each source is ``PROVIDED`` / ``NONE_FOUND``
  / ``NOT_PROVIDED`` and the two absence states are never collapsed.
* **Bounded** — every list and string is explicitly bounded, and bounds
  **reject** (fail closed) rather than silently truncate security evidence.
* **Secret-safe** — structured payloads are JSON-compatible, refuse
  credential-shaped content, and the serialized context/report is
  re-scanned before crossing the AI boundary or being persisted.
* **Deterministic & immutable** — identical inputs produce byte-identical
  output; the builder never mutates a source record.
* **Read-only** — constructing any contract here performs no analysis, no
  risk calculation, no attribution, no hunt execution, no policy/response/
  approval/SOAR execution.

This module reuses the existing per-source context records and the
``InputAvailability`` / ``Provenance`` semantics already defined by the
V1–V2.19 architecture (``app.schemas.investigation_context`` /
``app.schemas.security_event``); it never invents provenance or availability
values.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.agents.investigation._safety import assert_no_secrets
from app.schemas.correlation import CorrelationStatus
from app.schemas.investigation_context import (
    CorrelationContext,
    DetectionContext,
    IncidentMemoryReferenceContext,
    InputAvailability,
    RiskContext,
)
from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Version + bounds — explicit, documented, conservative limits.
# ---------------------------------------------------------------------------

#: The report schema version this contract represents.
REPORT_SCHEMA_VERSION = "2.20"

#: Maximum correlation members the context/report may carry.
MAX_REPORT_MEMBERS = 1000

#: Maximum resolved detection records carried (per correlation).
MAX_REPORT_DETECTIONS = 500

#: Maximum threat-intelligence lookup records carried.
MAX_REPORT_THREAT_INTEL = 500

#: Maximum per-event threat-intelligence lookups read before refusing.
MAX_REPORT_THREAT_INTEL_PER_EVENT = 500

#: Maximum incident memories carried (historical reference only).
MAX_REPORT_MEMORIES = 50

#: Maximum completed threat hunts carried.
MAX_REPORT_THREAT_HUNTS = 50

#: Maximum approval requests carried.
MAX_REPORT_APPROVALS = 100

#: Maximum SOAR executions carried.
MAX_REPORT_SOAR_EXECUTIONS = 100

#: Maximum distinct security-event references carried.
MAX_REPORT_EVENT_REFERENCES = 1000

#: Maximum entries in the evidence reference catalog.
MAX_REPORT_EVIDENCE_REFERENCES = 2000

#: Maximum timeline items assembled.
MAX_REPORT_TIMELINE_ITEMS = 2000

#: Maximum AI findings the model may return.
MAX_REPORT_FINDINGS = 25

#: Maximum catalog references a single AI finding may cite.
MAX_REPORT_FINDING_EVIDENCE_REFERENCES = 16

#: Maximum AI limitations / follow-up items the model may return.
MAX_REPORT_LIMITATIONS = 50
MAX_REPORT_FOLLOW_UP_ITEMS = 50

#: Maximum length of a single short label/title string.
MAX_REPORT_STRING_LENGTH = 4096

#: Maximum length of a single AI prose paragraph.
MAX_REPORT_PROSE_LENGTH = 20000

#: Maximum serialized size of the complete AI context.
MAX_REPORT_CONTEXT_BYTES = 512 * 1024

#: Maximum serialized size of the complete persisted report payload.
MAX_REPORT_PAYLOAD_BYTES = 1024 * 1024

#: Maximum length of a persisted report title.
MAX_REPORT_TITLE_LENGTH = 255

#: Maximum length of a persisted sanitized error code / message.
MAX_REPORT_ERROR_CODE_LENGTH = 64
MAX_REPORT_ERROR_MESSAGE_LENGTH = 500

#: List-page defaults (bounded offset pagination, mirroring the existing
#: query services).
DEFAULT_REPORT_PAGE_SIZE = 50
MAX_REPORT_PAGE_SIZE = 200

#: Number of most-recent completed hunts scanned when looking for a
#: window overlap (newest first, then filtered server-side).
MAX_REPORT_THREAT_HUNT_SCAN = 200


# ---------------------------------------------------------------------------
# Report metadata / identity enums
# ---------------------------------------------------------------------------


class ReportStatus(str, Enum):
    """Lifecycle status of a persisted report row."""

    GENERATED = "generated"
    FAILED = "failed"


class ReportSourceKind(str, Enum):
    """Every source class an incident report may draw from.

    ``security_events`` refers to raw security-event telemetry.  SentinelAI
    has **no persisted security-event store** in V1–V2.19, so that source is
    always reported as ``NOT_PROVIDED`` and is never fabricated.
    """

    CORRELATION = "correlation"
    DETECTIONS = "detections"
    THREAT_INTELLIGENCE = "threat_intelligence"
    RISK_ASSESSMENT = "risk_assessment"
    INVESTIGATION = "investigation"
    ATTRIBUTION = "attribution"
    INCIDENT_MEMORY = "incident_memory"
    THREAT_HUNTS = "threat_hunts"
    POLICY_DECISIONS = "policy_decisions"
    SOAR_EXECUTIONS = "soar_executions"
    SECURITY_EVENTS = "security_events"


class ReportRecordType(str, Enum):
    """The persisted record kinds the evidence catalog may reference.

    Every value here corresponds to a record that actually exists in the
    repository's persistence layer (or, for ``security_event_reference``,
    to an ``event_id`` referenced by such persisted records).  Values are
    deliberately limited to what the context builder can actually emit.
    """

    CORRELATION = "correlation"
    CORRELATION_MEMBER = "correlation_member"
    DETECTION = "detection"
    RISK_ASSESSMENT = "risk_assessment"
    INCIDENT_MEMORY = "incident_memory"
    THREAT_HUNT = "threat_hunt"
    APPROVAL_REQUEST = "approval_request"
    SOAR_EXECUTION = "soar_execution"
    THREAT_INTEL_LOOKUP = "threat_intel_lookup"
    SECURITY_EVENT_REFERENCE = "security_event_reference"


# ---------------------------------------------------------------------------
# Secret / payload hygiene helpers (mirroring investigation_context.py)
# ---------------------------------------------------------------------------


def _validate_payload(value: dict[str, Any], field: str) -> dict[str, Any]:
    """Validate a structured payload and return an independent JSON clone."""
    try:
        serialized = json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be JSON-compatible: {exc}") from exc
    assert_no_secrets(serialized, field)
    return json.loads(serialized)


def _bound_string(value: str, field: str, max_length: int) -> str:
    if not value.strip():
        raise ValueError(f"{field} must not be blank")
    if len(value) > max_length:
        raise ValueError(f"{field} exceeds max length {max_length}")
    return value


# ---------------------------------------------------------------------------
# Availability — explicit provided / not-provided / none-found semantics.
# ---------------------------------------------------------------------------


class ReportSourceAvailability(BaseModel):
    """Structural record of which report sources are present.

    ``correlation`` is always ``PROVIDED`` (a report is anchored to one).
    ``investigation`` and ``attribution`` are always ``NOT_PROVIDED`` in
    V2.20 because SentinelAI has no persisted investigation-result store and
    no persisted attribution-result store; they are never presented as
    ``NONE_FOUND`` (absence is not an observed fact).
    """

    model_config = ConfigDict(extra="forbid")

    correlation: InputAvailability = Field(
        default=InputAvailability.PROVIDED,
        description="The anchored correlation (always provided).",
    )
    detections: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="PROVIDED / NONE_FOUND / NOT_PROVIDED.",
    )
    threat_intelligence: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="PROVIDED / NONE_FOUND / NOT_PROVIDED.",
    )
    risk_assessment: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="PROVIDED when the correlation has a persisted assessment; "
        "NOT_PROVIDED when none exists (never NONE_FOUND).",
    )
    investigation: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="Always NOT_PROVIDED in V2.20 — no persisted investigation "
        "result store exists.",
    )
    attribution: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="Always NOT_PROVIDED in V2.20 — no persisted attribution "
        "result store exists.",
    )
    incident_memory: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="PROVIDED / NONE_FOUND (retrieval ran, nothing cited the "
        "correlation) / NOT_PROVIDED.",
    )
    threat_hunts: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="PROVIDED when completed hunts overlap the incident window; "
        "NONE_FOUND when scanned completed hunts (bounded) had no overlap.",
    )
    policy_decisions: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="PROVIDED / NONE_FOUND from persisted approval requests for "
        "the correlation (the persisted policy/approval trace).",
    )
    soar_executions: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="PROVIDED / NONE_FOUND from persisted SOAR executions for "
        "the correlation.",
    )
    security_events: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="Always NOT_PROVIDED in V2.20 — no persisted security-event "
        "store exists.",
    )

    @field_validator("correlation")
    @classmethod
    def _correlation_always_provided(cls, value: InputAvailability) -> InputAvailability:
        if value is not InputAvailability.PROVIDED:
            raise ValueError("correlation is required and must be PROVIDED")
        return value


# ---------------------------------------------------------------------------
# Evidence references
# ---------------------------------------------------------------------------


class ReportEvidenceReference(BaseModel):
    """One entry in the evidence reference catalog.

    ``reference_id`` is a deterministic catalog identity the LLM is allowed
    to cite; ``record_type`` + ``target_id`` prove the citation resolves to
    a record that actually exists (collected by the read-only builder);
    ``provenance`` preserves the source record's provenance.  The generator
    validates every model citation against this catalog.
    """

    model_config = ConfigDict(extra="forbid")

    reference_id: uuid.UUID = Field(
        ...,
        description="Deterministic catalog identity (the only id the model may cite).",
    )
    record_type: ReportRecordType = Field(
        ...,
        description="The persisted record kind referenced.",
    )
    target_id: uuid.UUID = Field(
        ...,
        description="The identity of the referenced persisted record.",
    )
    provenance: Provenance = Field(
        ...,
        description="The referenced record's provenance, preserved verbatim.",
    )


# ---------------------------------------------------------------------------
# AI output pieces
# ---------------------------------------------------------------------------


class ReportFinding(BaseModel):
    """An AI-proposed finding, strictly grounded in catalog references."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(
        min_length=1,
        max_length=MAX_REPORT_STRING_LENGTH,
        description="Concise human-readable finding title.",
    )
    summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_STRING_LENGTH,
        description="Structured finding summary grounded in the cited references.",
    )
    evidence_references: list[uuid.UUID] = Field(
        max_length=MAX_REPORT_FINDING_EVIDENCE_REFERENCES,
        description=(
            "References into the supplied evidence catalog.  Resolution is "
            "enforced by the generator — every cited id must exist in the "
            "catalog."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.AI_GENERATED,
        description="AI findings are always AI_GENERATED synthesis; the "
        "grounding provenance lives on each cited reference.",
    )

    @field_validator("title")
    @classmethod
    def _title_not_blank(cls, value: str) -> str:
        return _bound_string(value, "finding title", MAX_REPORT_STRING_LENGTH)

    @field_validator("summary")
    @classmethod
    def _summary_not_blank(cls, value: str) -> str:
        return _bound_string(value, "finding summary", MAX_REPORT_STRING_LENGTH)

    @field_validator("provenance")
    @classmethod
    def _ai_generated_only(cls, value: Provenance) -> Provenance:
        if value is not Provenance.AI_GENERATED:
            raise ValueError(
                "report findings are AI-generated and must carry "
                "AI_GENERATED provenance"
            )
        return value


# ---------------------------------------------------------------------------
# Report-specific context records (each derived from persisted source data).
# ---------------------------------------------------------------------------


class SecurityEventReferenceContext(BaseModel):
    """One referenced security event identity.

    SentinelAI has no persisted event store, so a report never fabricates an
    event payload.  This record only carries an ``event_id`` that is
    definitively **referenced by persisted analytical records** (correlation
    members / detections), with the provenance of the referencing record.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: uuid.UUID = Field(
        ...,
        description="Event identity referenced by persisted analytical records.",
    )
    provenance: Provenance = Field(
        ...,
        description="Provenance of the referencing record (e.g. CORRELATED).",
    )
    referenced_by: list[ReportRecordType] = Field(
        default_factory=list,
        description="Which persisted record types reference this event.",
    )


class ThreatIntelLookupContext(BaseModel):
    """One persisted threat-intelligence lookup (with its indicator)."""

    model_config = ConfigDict(extra="forbid")

    lookup_id: uuid.UUID = Field(..., description="Persisted lookup row id.")
    event_id: uuid.UUID = Field(..., description="Event the lookup was for.")
    indicator_id: uuid.UUID = Field(..., description="Persisted indicator id.")
    indicator_value: str = Field(
        ...,
        description="Normalized indicator value (untrusted data, verbatim).",
    )
    indicator_type: str = Field(..., description="Indicator classification.")
    provider: str = Field(..., description="Provider name.")
    status: str = Field(..., description="Persisted lookup status.")
    found: bool | None = Field(
        default=None,
        description="Whether the provider had information (when performed).",
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Provider confidence in [0.0, 1.0], preserved verbatim.",
    )
    performed_at: datetime = Field(
        ...,
        description="Lookup instant (timezone-aware).",
    )
    provenance: Provenance = Field(
        default=Provenance.ENRICHED,
        description="External intelligence is always ENRICHED.",
    )

    @field_validator("indicator_value")
    @classmethod
    def _indicator_bounded(cls, value: str) -> str:
        return _bound_string(value, "indicator value", MAX_REPORT_STRING_LENGTH)

    @field_validator("provider")
    @classmethod
    def _provider_bounded(cls, value: str) -> str:
        return _bound_string(value, "provider", MAX_REPORT_STRING_LENGTH)

    @field_validator("indicator_type")
    @classmethod
    def _indicator_type_bounded(cls, value: str) -> str:
        return _bound_string(value, "indicator type", MAX_REPORT_STRING_LENGTH)

    @field_validator("performed_at")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("performed_at must be timezone-aware")
        return value

    @field_validator("provenance")
    @classmethod
    def _enriched_only(cls, value: Provenance) -> Provenance:
        if value is not Provenance.ENRICHED:
            raise ValueError("threat-intelligence lookups must carry ENRICHED provenance")
        return value


class ThreatHuntContext(BaseModel):
    """One completed threat hunt whose window overlaps the incident.

    The hunt record is a persisted operational record; there is no
    provenance value for hunts in the fixed enum, so the record is presented
    as ``OBSERVED`` operational history (documented in
    ``docs/development/ai_incident_report_generator_v220.md``).
    """

    model_config = ConfigDict(extra="forbid")

    hunt_id: uuid.UUID = Field(..., description="Persisted hunt identity.")
    name: str = Field(..., description="Analyst-assigned hunt name.")
    hunt_type: str = Field(..., description="Closed hunt template identifier.")
    start_time: datetime = Field(..., description="Hunt window start.")
    end_time: datetime = Field(..., description="Hunt window end (exclusive).")
    started_at: datetime | None = Field(
        default=None,
        description="When the run began.",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="When the run completed.",
    )
    result_count: int = Field(..., ge=0, description="Evidence items collected.")
    finding_count: int = Field(..., ge=0, description="Findings produced.")
    timeline_count: int = Field(..., ge=0, description="Timeline items produced.")
    created_by_role: str = Field(..., description="Role label of the creating actor.")
    provenance: Provenance = Field(
        default=Provenance.OBSERVED,
        description="Persisted operational history (see module docstring).",
    )

    @field_validator("name")
    @classmethod
    def _name_bounded(cls, value: str) -> str:
        return _bound_string(value, "hunt name", MAX_REPORT_STRING_LENGTH)

    @field_validator("hunt_type")
    @classmethod
    def _hunt_type_bounded(cls, value: str) -> str:
        return _bound_string(value, "hunt type", MAX_REPORT_STRING_LENGTH)

    @field_validator("created_by_role")
    @classmethod
    def _role_bounded(cls, value: str) -> str:
        return _bound_string(value, "created_by_role", MAX_REPORT_STRING_LENGTH)

    @field_validator("start_time", "end_time", "started_at", "completed_at")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.tzinfo.utcoffset(value) is None):
            raise ValueError("hunt timestamps must be timezone-aware")
        return value


class ApprovalRequestContext(BaseModel):
    """One persisted approval request (the persisted policy/approval trace)."""

    model_config = ConfigDict(extra="forbid")

    approval_id: uuid.UUID = Field(..., description="Persisted approval identity.")
    policy_decision_id: uuid.UUID = Field(..., description="The routed decision.")
    action_type: str = Field(..., description="Proposed action (closed vocabulary).")
    target: str = Field(..., description="Canonical controlled target.")
    status: str = Field(..., description="pending/approved/rejected/expired/cancelled.")
    reason: str = Field(..., description="Deterministic policy reason.")
    policy_rule_id: str = Field(..., description="The policy rule requiring approval.")
    risk_level: str = Field(..., description="Carried risk level.")
    risk_score: float | None = Field(
        default=None, ge=0.0, le=1.0, description="Carried risk score."
    )
    confidence: float | None = Field(
        default=None, ge=0.0, le=1.0, description="Carried confidence."
    )
    requested_at: datetime = Field(..., description="When the request was created.")
    resolved_at: datetime | None = Field(
        default=None, description="When a human (or lapse) resolved it."
    )
    response_status: str | None = Field(
        default=None,
        description="What the response layer did after an approved grant "
        "(executed/failed/skipped/rejected) — approved is not executed.",
    )
    response_provider: str | None = Field(
        default=None, description="Which provider ran, when applicable."
    )
    provenance: Provenance = Field(
        default=Provenance.APPROVAL_REVIEWED,
        description="Always APPROVAL_REVIEWED (CHECK-pinned on the row).",
    )

    @field_validator("action_type", "status", "policy_rule_id", "target", "reason", "risk_level")
    @classmethod
    def _strings_bounded(cls, value: str) -> str:
        return _bound_string(value, "approval field", MAX_REPORT_STRING_LENGTH)

    @field_validator("requested_at", "resolved_at")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.tzinfo.utcoffset(value) is None):
            raise ValueError("approval timestamps must be timezone-aware")
        return value

    @field_validator("provenance")
    @classmethod
    def _approval_reviewed_only(cls, value: Provenance) -> Provenance:
        if value is not Provenance.APPROVAL_REVIEWED:
            raise ValueError(
                "approval requests must carry APPROVAL_REVIEWED provenance"
            )
        return value


class SoarExecutionContext(BaseModel):
    """One persisted SOAR execution (the persisted response/SOAR trace).

    Like hunts, a SOAR execution is a persisted operational record with no
    provenance value in the fixed enum; it is presented as ``OBSERVED``
    operational history.  A row's status is execution status (succeeded /
    failed / partial / cancelled / rejected), never a claim that an action
    *ever* ran outside that record.
    """

    model_config = ConfigDict(extra="forbid")

    execution_id: uuid.UUID = Field(..., description="Persisted execution identity.")
    policy_decision_id: uuid.UUID = Field(..., description="Authorizing decision.")
    approval_id: uuid.UUID | None = Field(
        default=None, description="Approval grant consulted, when applicable."
    )
    response_id: uuid.UUID = Field(..., description="Response result this run builds upon.")
    playbook_id: str = Field(..., description="The registered playbook that ran.")
    playbook_version: str = Field(..., description="The playbook version that ran.")
    primary_action: str = Field(..., description="The authorized action orchestrated.")
    target: str = Field(..., description="Canonical target.")
    status: str = Field(..., description="Execution lifecycle status.")
    failure_policy: str = Field(..., description="stop/continue on failure.")
    simulated: bool = Field(..., description="True only for a validated dry-run.")
    error_code: str | None = Field(default=None, description="Sanitized error code.")
    started_at: datetime | None = Field(
        default=None, description="When execution began."
    )
    completed_at: datetime | None = Field(
        default=None, description="When execution finished."
    )
    created_by_role: str = Field(..., description="Role of the requesting actor.")
    provenance: Provenance = Field(
        default=Provenance.OBSERVED,
        description="Persisted operational history (see module docstring).",
    )

    @field_validator("playbook_id", "playbook_version", "primary_action", "target", "status", "failure_policy", "created_by_role")
    @classmethod
    def _strings_bounded(cls, value: str) -> str:
        return _bound_string(value, "soar field", MAX_REPORT_STRING_LENGTH)

    @field_validator("started_at", "completed_at")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.tzinfo.utcoffset(value) is None):
            raise ValueError("soar timestamps must be timezone-aware")
        return value


class IncidentFactContext(BaseModel):
    """Deterministic incident overview facts derived from persisted records.

    Facts only — never analysis.  Counts reflect what the read-only builder
    actually collected; unresolved detection references are surfaced (not
    hidden) so absence is never fabricated into presence.
    """

    model_config = ConfigDict(extra="forbid")

    correlation_id: uuid.UUID = Field(..., description="The incident anchor.")
    status: CorrelationStatus = Field(..., description="Correlation lifecycle status.")
    confidence: float | None = Field(
        default=None, ge=0.0, le=1.0, description="Correlation confidence."
    )
    established_at: datetime = Field(
        ...,
        description="Correlation establishment timestamp.",
    )
    member_count: int = Field(..., ge=0, description="Persisted correlation members.")
    resolved_detection_count: int = Field(
        ..., ge=0, description="Members whose detection records exist."
    )
    unresolved_detection_count: int = Field(
        ..., ge=0, description="Members whose detection record was not found."
    )
    distinct_event_reference_count: int = Field(
        ..., ge=0, description="Distinct event ids referenced by persisted records."
    )
    earliest_member_timestamp: datetime | None = Field(
        default=None, description="Earliest correlation member timestamp."
    )
    latest_member_timestamp: datetime | None = Field(
        default=None, description="Latest correlation member timestamp."
    )
    provenance: Provenance = Field(
        default=Provenance.CORRELATED,
        description="Incident facts are anchored to the correlation (CORRELATED).",
    )

    @field_validator("established_at", "earliest_member_timestamp", "latest_member_timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.tzinfo.utcoffset(value) is None):
            raise ValueError("incident timestamps must be timezone-aware")
        return value

    @field_validator("provenance")
    @classmethod
    def _correlated_only(cls, value: Provenance) -> Provenance:
        if value is not Provenance.CORRELATED:
            raise ValueError("incident facts must carry CORRELATED provenance")
        return value


class ReportTimelineItem(BaseModel):
    """One deterministic timeline entry built from an actual persisted timestamp."""

    model_config = ConfigDict(extra="forbid")

    occurred_at: datetime = Field(
        ...,
        description="The source record's own timestamp (never invented).",
    )
    kind: str = Field(..., description="Short deterministic event kind label.")
    summary: str = Field(..., description="Deterministic, secret-free descriptor.")
    reference_id: uuid.UUID = Field(
        ...,
        description="Catalog reference the entry derives from.",
    )
    provenance: Provenance = Field(
        ...,
        description="Provenance of the underlying record.",
    )

    @field_validator("occurred_at")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value

    @field_validator("kind")
    @classmethod
    def _kind_bounded(cls, value: str) -> str:
        return _bound_string(value, "timeline kind", 64)

    @field_validator("summary")
    @classmethod
    def _summary_bounded(cls, value: str) -> str:
        return _bound_string(value, "timeline summary", 500)


# ---------------------------------------------------------------------------
# IncidentReportContext — the AI's only source material.
# ---------------------------------------------------------------------------


class IncidentReportContext(BaseModel):
    """The complete, validated, bounded incident report context.

    Built deterministically and read-only by ``ReportContextBuilder``; this
    is the input representation supplied (delimited, as data) to the LLM.
    ``evidence_catalog`` is the authoritative set of references the model
    may cite.
    """

    model_config = ConfigDict(extra="forbid")

    incident: IncidentFactContext = Field(...)
    correlation: CorrelationContext = Field(...)
    detections: list[DetectionContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_DETECTIONS,
    )
    threat_intelligence: list[ThreatIntelLookupContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_THREAT_INTEL,
    )
    risk_assessment: RiskContext | None = Field(default=None)
    incident_memories: list[IncidentMemoryReferenceContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_MEMORIES,
    )
    threat_hunts: list[ThreatHuntContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_THREAT_HUNTS,
    )
    approvals: list[ApprovalRequestContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_APPROVALS,
    )
    soar_executions: list[SoarExecutionContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_SOAR_EXECUTIONS,
    )
    security_event_references: list[SecurityEventReferenceContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_EVENT_REFERENCES,
    )
    evidence_catalog: list[ReportEvidenceReference] = Field(
        default_factory=list,
        max_length=MAX_REPORT_EVIDENCE_REFERENCES,
    )
    availability: ReportSourceAvailability = Field(...)

    @field_validator("evidence_catalog")
    @classmethod
    def _catalog_unique(cls, v: list[ReportEvidenceReference]) -> list[ReportEvidenceReference]:
        ids = [item.reference_id for item in v]
        if len(set(ids)) != len(ids):
            raise ValueError("evidence catalog must not contain duplicate reference ids")
        return v

    @model_validator(mode="after")
    def _enforce_total_size_bound(self) -> "IncidentReportContext":
        size = len(self.model_dump_json().encode("utf-8"))
        if size > MAX_REPORT_CONTEXT_BYTES:
            raise ValueError(
                "incident report context exceeds "
                f"MAX_REPORT_CONTEXT_BYTES={MAX_REPORT_CONTEXT_BYTES} "
                f"(serialized size {size}); the context is refused rather "
                "than truncated"
            )
        return self


# ---------------------------------------------------------------------------
# LLM model output contract (see model_output.py for JSON schema + bounds).
# ---------------------------------------------------------------------------


class IncidentReportAI(BaseModel):
    """AI-generated prose: strictly bounded, strictly grounded."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(
        min_length=1,
        max_length=MAX_REPORT_TITLE_LENGTH,
        description="Concise report title (generated within bounds).",
    )
    executive_summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI-grounded executive summary.",
    )
    incident_overview: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI prose overview grounded in the incident facts.",
    )
    investigation_summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI overview of investigation availability (NOT_PROVIDED "
        "in V2.20 when no persisted investigation record exists).",
    )
    attribution_summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI overview of attribution availability (NOT_PROVIDED in "
        "V2.20 — no attribution logic runs during report generation).",
    )
    threat_hunting_summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI summary of the actual completed hunts provided.",
    )
    response_summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI summary of the persisted policy/approval/SOAR records "
        "(approved/planned is never claimed as executed).",
    )
    findings: list[ReportFinding] = Field(
        default_factory=list,
        max_length=MAX_REPORT_FINDINGS,
        description="AI findings, each citing only catalog references.",
    )
    limitations: list[str] = Field(
        default_factory=list,
        max_length=MAX_REPORT_LIMITATIONS,
        description="AI-stated limitations over unavailable/bounded sources.",
    )
    recommended_follow_up: list[str] = Field(
        default_factory=list,
        max_length=MAX_REPORT_FOLLOW_UP_ITEMS,
        description="Evidence-grounded follow-up; never autonomous remediation "
        "instructions.",
    )

    @field_validator("title")
    @classmethod
    def _title_bounded(cls, value: str) -> str:
        return _bound_string(value, "report title", MAX_REPORT_TITLE_LENGTH)

    @field_validator("limitations", "recommended_follow_up")
    @classmethod
    def _list_items_bounded(cls, value: list[str]) -> list[str]:
        return [
            _bound_string(item, "follow-up/limitation item", MAX_REPORT_STRING_LENGTH)
            for item in value
        ]


# ---------------------------------------------------------------------------
# The authoritative assembled report (persisted as the row payload).
# ---------------------------------------------------------------------------


class IncidentReport(BaseModel):
    """A single assembled incident report.

    The persisted, provenance-safe representation of one generation.  The
    deterministic sections (incident facts, correlation, detections, TI,
    risk, memories, hunts, approvals, SOAR, timeline, evidence catalog,
    availability, source limitations) are assembled by the application from
    existing records; the ``ai`` block is the strictly-validated LLM prose.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["2.20"] = Field(
        default="2.20",
        description="Report schema version (locked).",
    )
    report_id: uuid.UUID = Field(..., description="Persisted report identity.")
    correlation_id: uuid.UUID = Field(..., description="The incident anchor.")
    generated_at: datetime = Field(
        ...,
        description="Timezone-aware completion instant (not security evidence).",
    )
    generated_by: uuid.UUID = Field(..., description="Trusted identity that generated it.")
    generated_by_role: str = Field(..., description="Role label of the generator.")
    model: str = Field(..., description="Model identifier used.")
    availability: ReportSourceAvailability = Field(...)
    incident: IncidentFactContext = Field(...)
    correlation: CorrelationContext = Field(...)
    detections: list[DetectionContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_DETECTIONS,
    )
    threat_intelligence: list[ThreatIntelLookupContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_THREAT_INTEL,
    )
    risk_assessment: RiskContext | None = Field(default=None)
    incident_memories: list[IncidentMemoryReferenceContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_MEMORIES,
    )
    threat_hunts: list[ThreatHuntContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_THREAT_HUNTS,
    )
    approvals: list[ApprovalRequestContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_APPROVALS,
    )
    soar_executions: list[SoarExecutionContext] = Field(
        default_factory=list,
        max_length=MAX_REPORT_SOAR_EXECUTIONS,
    )
    timeline: list[ReportTimelineItem] = Field(
        default_factory=list,
        max_length=MAX_REPORT_TIMELINE_ITEMS,
    )
    evidence_catalog: list[ReportEvidenceReference] = Field(
        default_factory=list,
        max_length=MAX_REPORT_EVIDENCE_REFERENCES,
    )
    source_limitations: list[str] = Field(
        default_factory=list,
        max_length=MAX_REPORT_LIMITATIONS,
        description="Deterministic limitations derived from availability and "
        "bounded reads.",
    )
    ai: IncidentReportAI = Field(...)

    @field_validator("generated_at")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("generated_at must be timezone-aware")
        return value

    @field_validator("generated_by_role")
    @classmethod
    def _role_bounded(cls, value: str) -> str:
        return _bound_string(value, "generated_by_role", MAX_REPORT_STRING_LENGTH)

    @model_validator(mode="after")
    def _enforce_total_size_bound(self) -> "IncidentReport":
        size = len(self.model_dump_json().encode("utf-8"))
        if size > MAX_REPORT_PAYLOAD_BYTES:
            raise ValueError(
                "incident report payload exceeds "
                f"MAX_REPORT_PAYLOAD_BYTES={MAX_REPORT_PAYLOAD_BYTES} "
                f"(serialized size {size}); the report is refused rather "
                "than truncated"
            )
        return self


# ---------------------------------------------------------------------------
# API read models
# ---------------------------------------------------------------------------


class IncidentReportGenerateRequest(BaseModel):
    """POST /incident-reports/generate body."""

    model_config = ConfigDict(extra="forbid")

    correlation_id: uuid.UUID = Field(
        ...,
        description="The persisted correlation to write the report about.",
    )
    report_version: Literal["2.20"] = Field(
        default=REPORT_SCHEMA_VERSION,
        description="Report schema version (only 2.20 is supported).",
    )


class IncidentReportSummary(BaseModel):
    """One row summary (list surface)."""

    model_config = ConfigDict(extra="forbid")

    report_id: uuid.UUID = Field(...)
    correlation_id: uuid.UUID = Field(...)
    status: ReportStatus = Field(...)
    title: str | None = Field(default=None, description="Generated title (when generated).")
    model: str | None = Field(default=None)
    generated_by: uuid.UUID = Field(...)
    generated_by_role: str = Field(...)
    generated_at: datetime | None = Field(
        default=None,
        description="Completion instant — None while/if the attempt failed.",
    )
    error_code: str | None = Field(default=None)
    error_message: str | None = Field(default=None)
    created_at: datetime = Field(...)
    updated_at: datetime = Field(...)


class IncidentReportRecord(IncidentReportSummary):
    """One full report (detail surface)."""

    payload: IncidentReport | None = Field(
        default=None,
        description="The assembled report payload (None for failed rows).",
    )


class IncidentReportPage(BaseModel):
    """Bounded page of report summaries."""

    model_config = ConfigDict(extra="forbid")

    items: list[IncidentReportSummary] = Field(...)
    total: int = Field(...)
    page: int = Field(...)
    page_size: int = Field(...)
    correlation_id: uuid.UUID | None = Field(
        default=None,
        description="Correlation filter echoed back, when applied.",
    )


__all__ = [
    "REPORT_SCHEMA_VERSION",
    "MAX_REPORT_MEMBERS",
    "MAX_REPORT_DETECTIONS",
    "MAX_REPORT_THREAT_INTEL",
    "MAX_REPORT_THREAT_INTEL_PER_EVENT",
    "MAX_REPORT_MEMORIES",
    "MAX_REPORT_THREAT_HUNTS",
    "MAX_REPORT_APPROVALS",
    "MAX_REPORT_SOAR_EXECUTIONS",
    "MAX_REPORT_EVENT_REFERENCES",
    "MAX_REPORT_EVIDENCE_REFERENCES",
    "MAX_REPORT_TIMELINE_ITEMS",
    "MAX_REPORT_FINDINGS",
    "MAX_REPORT_FINDING_EVIDENCE_REFERENCES",
    "MAX_REPORT_LIMITATIONS",
    "MAX_REPORT_FOLLOW_UP_ITEMS",
    "MAX_REPORT_STRING_LENGTH",
    "MAX_REPORT_PROSE_LENGTH",
    "MAX_REPORT_CONTEXT_BYTES",
    "MAX_REPORT_PAYLOAD_BYTES",
    "MAX_REPORT_TITLE_LENGTH",
    "MAX_REPORT_ERROR_CODE_LENGTH",
    "MAX_REPORT_ERROR_MESSAGE_LENGTH",
    "DEFAULT_REPORT_PAGE_SIZE",
    "MAX_REPORT_PAGE_SIZE",
    "MAX_REPORT_THREAT_HUNT_SCAN",
    "ReportStatus",
    "ReportSourceKind",
    "ReportRecordType",
    "ReportSourceAvailability",
    "ReportEvidenceReference",
    "ReportFinding",
    "SecurityEventReferenceContext",
    "ThreatIntelLookupContext",
    "ThreatHuntContext",
    "ApprovalRequestContext",
    "SoarExecutionContext",
    "IncidentFactContext",
    "ReportTimelineItem",
    "IncidentReportContext",
    "IncidentReportAI",
    "IncidentReport",
    "IncidentReportGenerateRequest",
    "IncidentReportSummary",
    "IncidentReportRecord",
    "IncidentReportPage",
]