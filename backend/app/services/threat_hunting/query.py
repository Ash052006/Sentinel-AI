"""Threat Hunting bounded reads — V2.19.

Every collector in this module is a **bounded, read-only** query over one
persisted record kind, always pinned to a real column of that record.  All
queries are time-windowed and count-before-fetch capped; no collector ever
streams an unbounded set.  ``reuse`` surfaces read through the existing
bounded query services (correlation / risk / incident memory) instead of
duplicating their SQL.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.correlation_member import CorrelationMember
from app.models.correlation_result import CorrelationResult
from app.models.detection_result import DetectionResult
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import ThreatIntelLookup
from app.schemas.correlation_query import CorrelationPage, CorrelationResultRecord
from app.schemas.incident_memory_query import IncidentMemoryPage, IncidentMemoryRecord
from app.schemas.risk_query import RiskAssessmentPage, RiskAssessmentRecord
from app.schemas.threat_hunting import HUNT_SURFACE_CAP
from app.services.correlation_query import CorrelationQueryService
from app.services.incident_memory_query import IncidentMemoryQueryService
from app.services.risk_query import RiskQueryService

from .grammar import Predicate, SurfaceDef

#: column-name allowlist used to reject any non-contractual predicate.
_ALLOWED_COLUMNS: dict[str, frozenset[str]] = {
    "detection": frozenset({"event_id", "detection_id", "rule_id", "rule_type", "severity"}),
    "audit": frozenset({"action", "resource", "ip_address"}),
    "indicator": frozenset({"indicator_type", "value"}),
    "lookup": frozenset({"indicator_id"}),
    "correlation": frozenset({"correlation_id", "status"}),
    "correlation_member": frozenset({"correlation_id"}),
    "risk": frozenset({"level"}),
    "memory": frozenset({"memory_type"}),
}

_MODELS: dict[str, object] = {
    "detection": DetectionResult,
    "audit": AuditLog,
    "indicator": ThreatIntelIndicator,
    "lookup": ThreatIntelLookup,
    "correlation": CorrelationResult,
    "correlation_member": CorrelationMember,
}


def _model_for(surface: SurfaceDef) -> object:
    if surface.key not in _MODELS:
        raise ValueError(f"no persisted model for surface '{surface.key}'")
    return _MODELS[surface.key]


def _sanitize_postfix(value: str) -> str:
    unsafe = ("'", '"', "\\", ";", "--", "/*", "*/")
    for token in unsafe:
        if token in value:
            return "redacted"
    return value


def _concise(value: str, limit: int = 90) -> str:
    return " ".join(value.split())[:limit]


def _build_stmt(
    surface: SurfaceDef,
    start: datetime,
    end: datetime,
    predicates: Iterable[Predicate],
    extra: dict[str, Iterable[str]] | None,
) -> tuple[object, str | None]:
    """Build a windowed select for one persisted record kind.

    Returns ``(statement, error)``.  ``error`` is non-None only when a
    predicate/extra column is not in the closed allowlist (defense in
    depth against any non-grammar query).
    """
    model = _model_for(surface)
    target = getattr(model, surface.range_target)
    stmt = select(model).where(target >= start).where(target < end)
    for pred in predicates:
        if pred.column not in _ALLOWED_COLUMNS[surface.key]:
            return None, f"predicate column '{pred.column}' is not allowed on '{surface.key}'"
        column = getattr(model, pred.column)
        op = pred.operator
        value = pred.value
        if op == "equals":
            stmt = stmt.where(column == value)
        elif op == "not_equals":
            stmt = stmt.where(column != value)
        elif op == "in":
            stmt = stmt.where(column.in_(value))
        elif op == "not_in":
            stmt = stmt.where(~column.in_(value))
        elif op == "contains":
            stmt = stmt.where(column.contains(_sanitize_postfix(value)))
        elif op == "starts_with":
            stmt = stmt.where(column.startswith(_sanitize_postfix(value)))
        elif op == "ends_with":
            stmt = stmt.where(column.endswith(_sanitize_postfix(value)))
        else:
            return None, f"operator '{op}' is not supported on '{surface.key}'"
    if extra:
        for column_name, values in extra.items():
            if column_name not in _ALLOWED_COLUMNS[surface.key]:
                return None, f"extra column '{column_name}' is not allowed on '{surface.key}'"
            stmt = stmt.where(getattr(model, column_name).in_(list(values)))
    return stmt, None


def collect_records(
    db: Session,
    surface: SurfaceDef,
    *,
    start: datetime,
    end: datetime,
    predicates: Iterable[Predicate],
    extra: dict[str, Iterable[str]] | None = None,
    limit: int = HUNT_SURFACE_CAP,
) -> tuple[list[object], int, str | None]:
    """Count-then-fetch a bounded page of one persisted record kind.

    Returns ``(rows, total, error)``.  ``total`` is the full count over the
    window (plus predicates/extra); ``rows`` is at most ``limit`` rows.  A
    surface whose count exceeds ``limit`` is reported via ``total`` and the
    engine decides (per contract) whether to fail the hunt.
    """
    stmt, err = _build_stmt(surface, start, end, predicates, extra)
    if err is not None:
        return [], 0, err
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    model = _model_for(surface)
    stmt = stmt.order_by(getattr(model, surface.range_target).desc(), model.id.asc())
    rows = list(db.scalars(stmt.limit(limit)).all())
    return rows, total, None


# ---------------------------------------------------------------------------
# Reuse collectors (bounded reads through existing query services)
# ---------------------------------------------------------------------------


def _windowed(records: list, attr: str, start: datetime, end: datetime) -> list:
    return [
        rec
        for rec in records
        if (instant := getattr(rec, attr, None)) is not None and start <= instant < end
    ]


def _filter_records(records: list, predicates: list[Predicate]) -> list:
    """Python-side predicate filter for reuse surfaces.

    Records carry enum-typed attributes whose ``.value`` is compared; the
    contract allows only ``equals``/``not_equals``/``in``/``not_in`` here.
    """
    if not predicates:
        return records
    filtered: list = []
    for rec in records:
        keep = True
        for pred in predicates:
            attr = getattr(rec, pred.column, None)
            if attr is None:
                keep = False
                break
            attr_value = str(attr.value if hasattr(attr, "value") else attr)
            values: list[str] = (
                [str(v) for v in pred.value] if isinstance(pred.value, list) else [str(pred.value)]
            )
            if pred.operator == "equals":
                keep = attr_value in values
            elif pred.operator == "in":
                keep = attr_value in values
            elif pred.operator == "not_equals":
                keep = attr_value not in values
            elif pred.operator == "not_in":
                keep = attr_value not in values
            else:
                keep = False
            if not keep:
                break
        if keep:
            filtered.append(rec)
    return filtered


def _reuse_summary(kind: str, exc: Exception) -> str:
    return f"{kind} read refused by the existing query service: {_concise(str(exc))}"


def collect_correlations_by_events(
    db: Session,
    surface: SurfaceDef,
    *,
    start: datetime,
    end: datetime,
    predicates: Iterable[Predicate],
    event_ids: Iterable[uuid.UUID],
    page_size: int = 100,
) -> tuple[list[CorrelationResultRecord], int, str | None]:
    """Correlation reads through CorrelationQueryService (reuse, bounded)."""
    service = CorrelationQueryService()
    collected: list[CorrelationResultRecord] = []
    predicates = list(predicates)
    for event_id in sorted(set(event_ids)):
        page = 1
        while True:
            try:
                result: CorrelationPage = service.list_correlations_for_event(
                    db, event_id, page=page, page_size=page_size
                )
            except Exception as exc:
                return [], 0, _reuse_summary("correlation", exc)
            collected.extend(result.items)
            if not result.items or page * page_size >= result.total:
                break
            page += 1
    collected = _filter_records(
        _windowed(collected, "timestamp", start, end), predicates
    )
    return collected, len(collected), None


def collect_risk_by_correlations(
    db: Session,
    surface: SurfaceDef,
    *,
    start: datetime,
    end: datetime,
    predicates: Iterable[Predicate],
    correlation_ids: Iterable[uuid.UUID],
    page_size: int = 50,
) -> tuple[list[RiskAssessmentRecord], int, str | None]:
    """Risk reads through RiskQueryService (reuse, bounded)."""
    service = RiskQueryService()
    collected: list[RiskAssessmentRecord] = []
    predicates = list(predicates)
    for correlation_id in sorted(set(correlation_ids)):
        page = 1
        while True:
            try:
                result: RiskAssessmentPage = service.list_assessments_for_correlation(
                    db, correlation_id, page=page, page_size=page_size
                )
            except Exception as exc:
                return [], 0, _reuse_summary("risk", exc)
            collected.extend(result.items)
            if not result.items or page * page_size >= result.total:
                break
            page += 1
    collected = _filter_records(
        _windowed(collected, "timestamp", start, end), predicates
    )
    return collected, len(collected), None


def collect_memory_by_correlations(
    db: Session,
    surface: SurfaceDef,
    *,
    start: datetime,
    end: datetime,
    predicates: Iterable[Predicate],
    correlation_ids: Iterable[uuid.UUID],
    page_size: int = 50,
) -> tuple[list[IncidentMemoryRecord], int, str | None]:
    """Incident-memory reads through IncidentMemoryQueryService (reuse, bounded)."""
    service = IncidentMemoryQueryService()
    collected: list[IncidentMemoryRecord] = []
    predicates = list(predicates)
    for correlation_id in sorted(set(correlation_ids)):
        page = 1
        while True:
            try:
                result: IncidentMemoryPage = service.list_memories_for_correlation(
                    db, correlation_id, page=page, page_size=page_size
                )
            except Exception as exc:
                return [], 0, _reuse_summary("incident memory", exc)
            collected.extend(result.items)
            if not result.items or page * page_size >= result.total:
                break
            page += 1
    collected = _filter_records(
        _windowed(collected, "created_at", start, end), predicates
    )
    return collected, len(collected), None


__all__ = [
    "collect_records",
    "collect_correlations_by_events",
    "collect_risk_by_correlations",
    "collect_memory_by_correlations",
]