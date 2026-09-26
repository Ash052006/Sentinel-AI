"""Threat Hunting grammar — closed surfaces, filters and templates — V2.19.

The grammar is the *only* way a hunt may express intent: a bounded time
window over a closed set of surfaces, plus a closed set of structured
filters, each pinned to a real column of an existing persisted record.

Everything here is static and deterministic; there is no code path that
accepts a query string, an expression tree, a raw SQL fragment or an
OpenSearch DSL payload.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field as dc_field
from datetime import datetime

from app.schemas.threat_hunting import (
    HuntFilter,
    HuntFilterField,
    HuntOperator,
    HuntType,
)

HUNT_NAMESPACE_V5 = uuid.UUID("7f3a1b2c-9e4d-4a56-b7c8-9d0e1f2a3b4c")


# ---------------------------------------------------------------------------
# Predicate (the runtime form of a filter edge)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Predicate:
    """One runtime filter predicate mapped to a real column.

    ``column`` is always an internal constant (never client-supplied);
    ``operator`` is a closed ``HuntOperator`` value; ``value`` is a coerced
    scalar ``str`` or a bounded ``list[str]`` for IN/NOT_IN.
    """

    column: str
    operator: str
    value: str | list[str]

    def human(self) -> str:
        if self.operator in (HuntOperator.IN.value, HuntOperator.NOT_IN.value):
            rendered = ", ".join(str(v) for v in self.value)
            return f"{self.column} {self.operator} ({rendered})"
        return f"{self.column} {self.operator} {self.value}"


# ---------------------------------------------------------------------------
# Surfaces
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SurfaceDef:
    """One persisted record kind a hunt may collect.

    ``reader`` is ``'records'`` (direct persistence query) or ``'reuse'``
    (bounded read through an existing query service).
    """

    key: str
    evidence_type: str
    provenance: str
    range_target: str
    reader: str
    description: str
    exposed_field_targets: dict[str, str] = dc_field(default_factory=dict)

    def column_for(self, field: str) -> str | None:
        return self.exposed_field_targets.get(field)


SURFACES: dict[str, SurfaceDef] = {
    "detection": SurfaceDef(
        key="detection",
        evidence_type="detection",
        provenance="detected",
        range_target="detected_at",
        reader="records",
        description="Persisted detection results (detection_results)",
        exposed_field_targets={
            HuntFilterField.EVENT_ID.value: "event_id",
            HuntFilterField.DETECTION_ID.value: "detection_id",
            HuntFilterField.RULE_ID.value: "rule_id",
            HuntFilterField.RULE_TYPE.value: "rule_type",
            HuntFilterField.SEVERITY.value: "severity",
        },
    ),
    "audit": SurfaceDef(
        key="audit",
        evidence_type="audit_log",
        provenance="observed",
        range_target="created_at",
        reader="records",
        description="Persisted audit log entries (audit_logs)",
        exposed_field_targets={
            HuntFilterField.AUDIT_ACTION.value: "action",
            HuntFilterField.AUDIT_RESOURCE.value: "resource",
            HuntFilterField.ACTOR_IP.value: "ip_address",
        },
    ),
    "indicator": SurfaceDef(
        key="indicator",
        evidence_type="indicator",
        provenance="enriched",
        range_target="first_seen_at",
        reader="records",
        description="Persisted threat-intel indicators (threat_intel_indicators)",
        exposed_field_targets={
            HuntFilterField.INDICATOR_TYPE.value: "indicator_type",
            HuntFilterField.INDICATOR_VALUE.value: "value",
        },
    ),
    "lookup": SurfaceDef(
        key="lookup",
        evidence_type="indicator_lookup",
        provenance="enriched",
        range_target="result_timestamp",
        reader="records",
        description="Persisted indicator-lookup results (threat_intel_lookups)",
        exposed_field_targets={},
    ),
    "correlation": SurfaceDef(
        key="correlation",
        evidence_type="correlation",
        provenance="correlated",
        range_target="timestamp",
        reader="records",
        description="Persisted correlation results (correlation_results)",
        exposed_field_targets={
            HuntFilterField.CORRELATION_ID.value: "correlation_id",
            HuntFilterField.CORRELATION_STATUS.value: "status",
        },
    ),
    "correlation_member": SurfaceDef(
        key="correlation_member",
        evidence_type="correlation_member",
        provenance="correlated",
        range_target="timestamp",
        reader="records",
        description="Members of collected correlations (correlation_members)",
        exposed_field_targets={
            HuntFilterField.CORRELATION_ID.value: "correlation_id",
        },
    ),
    "risk": SurfaceDef(
        key="risk",
        evidence_type="risk_assessment",
        provenance="risk_assessed",
        range_target="timestamp",
        reader="reuse",
        description="Risk assessments of collected correlations (risk_assessments)",
        exposed_field_targets={
            HuntFilterField.RISK_LEVEL.value: "level",
        },
    ),
    "memory": SurfaceDef(
        key="memory",
        evidence_type="incident_memory",
        provenance="recalled",
        range_target="created_at",
        reader="reuse",
        description="Incident memory citing collected correlations (incident_memories)",
        exposed_field_targets={
            HuntFilterField.MEMORY_TYPE.value: "memory_type",
        },
    ),
}

#: field value -> owning surface key
SURFACE_FOR_FIELD: dict[HuntFilterField, str] = {
    HuntFilterField.EVENT_ID: "detection",
    HuntFilterField.DETECTION_ID: "detection",
    HuntFilterField.RULE_ID: "detection",
    HuntFilterField.RULE_TYPE: "detection",
    HuntFilterField.SEVERITY: "detection",
    HuntFilterField.INDICATOR_TYPE: "indicator",
    HuntFilterField.INDICATOR_VALUE: "indicator",
    HuntFilterField.CORRELATION_ID: "correlation",
    HuntFilterField.CORRELATION_STATUS: "correlation",
    HuntFilterField.RISK_LEVEL: "risk",
    HuntFilterField.MEMORY_TYPE: "memory",
    HuntFilterField.AUDIT_ACTION: "audit",
    HuntFilterField.AUDIT_RESOURCE: "audit",
    HuntFilterField.ACTOR_IP: "audit",
}


@dataclass(frozen=True)
class DefaultFilter:
    """An implicit template predicate (declared by the template, never dynamic)."""

    surface: str
    column: str
    operator: str
    value: str | list[str]


@dataclass(frozen=True)
class LinkSpec:
    """One bounded follow-up step from already-collected evidence.

    ``kind`` is a closed discriminator that selects the exact bounded
    implementation in the engine:
      records-kind links match target rows on ``anchor_column`` in the set
        of values gathered from parent evidence;
      reuse-kind links read through an existing bounded query service.
    """

    name: str
    surface: str
    kind: str
    from_evidence_keys: tuple[str, ...]
    anchor_column: str = ""
    page_size: int = 100

    def __post_init__(self) -> None:
        if self.kind in ("members", "lookups_by_indicator") and not self.anchor_column:
            raise ValueError(f"link '{self.name}' requires an anchor column")


@dataclass(frozen=True)
class HuntTemplate:
    """The fixed, explicit surface/filter vocabulary of one hunt type.

    ``primary_surfaces`` are collected directly within the time window;
    ``links`` follow evidence already collected (bounded); ``defaults`` pin
    the implicit predicate of the template (e.g. auth-only audit actions).
    """

    hunt_type: HuntType
    title: str
    primary_surfaces: tuple[str, ...]
    links: tuple[LinkSpec, ...] = dc_field(default_factory=tuple)
    defaults: tuple[DefaultFilter, ...] = dc_field(default_factory=tuple)
    explanation: str = ""

    @property
    def surfaces_involved(self) -> tuple[str, ...]:
        seen: list[str] = []
        for key in self.primary_surfaces:
            if key not in seen:
                seen.append(key)
        for link in self.links:
            if link.surface not in seen:
                seen.append(link.surface)
        return tuple(seen)


# ---------------------------------------------------------------------------
# Templates (the closed specification of each hunt type)
# ---------------------------------------------------------------------------


TEMPLATES: dict[HuntType, HuntTemplate] = {
    HuntType.AUTHENTICATION_ANOMALY: HuntTemplate(
        hunt_type=HuntType.AUTHENTICATION_ANOMALY,
        title="Authentication anomaly hunt",
        primary_surfaces=("audit",),
        defaults=(
            DefaultFilter(
                surface="audit",
                column="action",
                operator=HuntOperator.STARTS_WITH.value,
                value="auth.",
            ),
            DefaultFilter(
                surface="audit",
                column="resource",
                operator=HuntOperator.IN.value,
                value=["auth", "role_check"],
            ),
        ),
        explanation=(
            "Collects audit entries for auth actions/resources within the window; "
            "findings group by actor IP and action."
        ),
    ),
    HuntType.INDICATOR_HUNT: HuntTemplate(
        hunt_type=HuntType.INDICATOR_HUNT,
        title="Indicator hunt",
        primary_surfaces=("indicator",),
        links=(
            LinkSpec(
                name="lookups_for_indicator",
                surface="lookup",
                kind="lookups_by_indicator",
                anchor_column="indicator_id",
                from_evidence_keys=("indicator",),
            ),
        ),
        explanation=(
            "Collects threat-intel indicators matching the filters; for each "
            "indicator, follows the boundary lookups that used it."
        ),
    ),
    HuntType.PRIVILEGE_ACTIVITY: HuntTemplate(
        hunt_type=HuntType.PRIVILEGE_ACTIVITY,
        title="Privilege activity hunt",
        primary_surfaces=("detection",),
        links=(
            LinkSpec(
                name="correlations_for_detection_events",
                surface="correlation",
                kind="reuse_correlations_by_event",
                from_evidence_keys=("detection",),
            ),
            LinkSpec(
                name="risk_for_correlations",
                surface="risk",
                kind="reuse_risk_by_correlation",
                from_evidence_keys=("correlation",),
            ),
        ),
        explanation=(
            "Collects detections and enriches each with the correlations found "
            "for its events and the correlations' risk assessments."
        ),
    ),
    HuntType.MULTI_STAGE_ACTIVITY: HuntTemplate(
        hunt_type=HuntType.MULTI_STAGE_ACTIVITY,
        title="Multi-stage activity hunt",
        primary_surfaces=("correlation",),
        links=(
            LinkSpec(
                name="members_of_correlations",
                surface="correlation_member",
                kind="members",
                anchor_column="correlation_id",
                from_evidence_keys=("correlation",),
            ),
            LinkSpec(
                name="risk_for_correlations",
                surface="risk",
                kind="reuse_risk_by_correlation",
                from_evidence_keys=("correlation",),
            ),
            LinkSpec(
                name="memory_for_correlations",
                surface="memory",
                kind="reuse_memory_by_correlation",
                from_evidence_keys=("correlation",),
            ),
        ),
        explanation=(
            "Collects correlations; follows their members, risk assessments "
            "and citing incident memory."
        ),
    ),
    HuntType.DETECTION_REVIEW: HuntTemplate(
        hunt_type=HuntType.DETECTION_REVIEW,
        title="Detection review hunt",
        primary_surfaces=("detection",),
        explanation=(
            "Collects persisted detection results within the window, filtered "
            "by the structured filters."
        ),
    ),
}


def compile_predicates(
    hunt_type: HuntType,
    filters: list[HuntFilter],
) -> tuple[tuple[Predicate, ...], tuple[str, ...]]:
    """Compile the hunt's structured filters into runtime predicates.

    Returns ``(predicates, surface_keys)``.  Validation of field/operator/
    value shape happened at the boundary (``ThreatHuntCreate``); this step
    maps fields onto their owning surface's real columns and merges in the
    template's implicit defaults.
    """
    template = TEMPLATES[hunt_type]
    edges: list[Predicate] = []
    for default in template.defaults:
        edges.append(
            Predicate(column=default.column, operator=default.operator, value=default.value)
        )
    for flt in filters:
        surface_key = SURFACE_FOR_FIELD[flt.field]
        surface = SURFACES[surface_key]
        column = surface.column_for(flt.field.value)
        if column is None:  # pragma: no cover - contract guarantees a mapping
            raise ValueError(f"field '{flt.field.value}' has no column mapping")
        value: str | list[str]
        if flt.operator in (HuntOperator.IN.value, HuntOperator.NOT_IN.value):
            value = list(flt.set_values or [])
        else:
            value = flt.scalar_value or ""
        edges.append(Predicate(column=column, operator=flt.operator.value, value=value))
    return tuple(edges), template.surfaces_involved


def evidence_key(surface_key: str, reference_id: uuid.UUID) -> str:
    """Deterministic hunt-wide evidence identity key."""
    return f"{surface_key}:{str(reference_id)}"


def udid(hunt_id: uuid.UUID, seed_suffix: str) -> uuid.UUID:
    """Deterministic artifact identity (UUIDv5) scoped to a hunt run."""
    return uuid.uuid5(HUNT_NAMESPACE_V5, f"{str(hunt_id)}::{seed_suffix}")


__all__ = [
    "HUNT_NAMESPACE_V5",
    "Predicate",
    "SurfaceDef",
    "SURFACES",
    "SURFACE_FOR_FIELD",
    "DefaultFilter",
    "LinkSpec",
    "HuntTemplate",
    "TEMPLATES",
    "compile_predicates",
    "evidence_key",
    "udid",
]