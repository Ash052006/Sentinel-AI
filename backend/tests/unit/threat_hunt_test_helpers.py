"""Shared SQLite adapters and seed builders for the V2.19 Threat Hunting suite.

Runs the same SQLAlchemy models used against PostgreSQL in production
(``JSONB`` rendered as ``JSON``, native ``UUID`` pinned to ``CHAR(32)``)
on an in-memory SQLite engine, exactly like :mod:`tests.unit.soar_test_helpers`.
The seed builders produce the persisted analytical history a hunt observes
(detections / correlations + members / risks / indicators + lookups /
incident memory / audit log) inside the supplied session without touching
the live database.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler

if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731
# Pin native PG ``UUID(as_uuid=True)`` columns to fixed-size text on the
# test SQLite engines (see the explanation in soar_test_helpers).
SQLiteTypeCompiler.visit_UUID = lambda self, type_, **kw: "CHAR(32)"  # noqa: E731
SQLiteTypeCompiler.visit_uuid = lambda self, type_, **kw: "CHAR(32)"  # noqa: E731

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.correlation_member import CorrelationMember
from app.models.correlation_result import CorrelationResult
from app.models.detection_result import DetectionResult
from app.models.incident_memory import IncidentMemoryRow
from app.models.risk_assessment import RiskAssessment
from app.models.role import Role
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import ThreatIntelLookup
from app.models.user import User
from app.schemas.correlation import CorrelationStatus
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.incident_memory import MemoryType
from app.schemas.risk import RiskLevel
from app.services.threat_intelligence.types import IndicatorType

TZ = timezone.utc
NOW = datetime(2026, 9, 24, 12, 0, 0, tzinfo=TZ)

ACTOR_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")


def a_detection(
    db: Session,
    *,
    event_id: uuid.UUID,
    detection_id: uuid.UUID,
    rule_id: str,
    rule_type: RuleType = RuleType.SIGMA,
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    at: datetime = NOW,
    confidence: float = 0.9,
) -> DetectionResult:
    row = DetectionResult(
        event_id=event_id,
        detection_id=detection_id,
        rule_id=rule_id,
        rule_type=rule_type,
        severity=severity,
        matched=True,
        confidence=confidence,
        evidence={},
        result_metadata={},
        detected_at=at,
    )
    db.add(row)
    db.flush()
    return row


def a_audit(
    db: Session,
    *,
    action: str,
    resource: str | None = None,
    ip_address: str | None = None,
    user_id: uuid.UUID | None = None,
    at: datetime = NOW,
    details: str | None = None,
) -> AuditLog:
    row = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        details=details,
        ip_address=ip_address,
        created_at=at,
    )
    db.add(row)
    db.flush()
    return row


def a_correlation(
    db: Session,
    *,
    correlation_id: uuid.UUID,
    status: CorrelationStatus = CorrelationStatus.ACTIVE,
    at: datetime = NOW,
    members: list[tuple[uuid.UUID, uuid.UUID, datetime, int]] | None = None,
) -> CorrelationResult:
    row = CorrelationResult(
        correlation_id=correlation_id,
        status=status,
        confidence=None,
        evidence={},
        result_metadata={},
        timestamp=at,
    )
    db.add(row)
    db.flush()
    if members:
        for detection_id, event_id, member_at, order in members:
            db.add(
                CorrelationMember(
                    correlation_id=correlation_id,
                    detection_id=detection_id,
                    event_id=event_id,
                    timestamp=member_at,
                    member_order=order,
                )
            )
        db.flush()
    return row


def a_risk(
    db: Session,
    *,
    risk_assessment_id: uuid.UUID,
    correlation_id: uuid.UUID,
    score: float = 0.8,
    level: RiskLevel = RiskLevel.HIGH,
    at: datetime = NOW,
    confidence: float = 0.75,
) -> RiskAssessment:
    row = RiskAssessment(
        risk_assessment_id=risk_assessment_id,
        correlation_id=correlation_id,
        score=score,
        level=level,
        confidence=confidence,
        factors=[],
        evidence=[],
        assessment_metadata={},
        timestamp=at,
    )
    db.add(row)
    db.flush()
    return row


def a_indicator(
    db: Session,
    *,
    value: str,
    indicator_type: IndicatorType | str = IndicatorType.IP,
    first_seen_at: datetime = NOW,
) -> ThreatIntelIndicator:
    kind = (
        indicator_type
        if isinstance(indicator_type, IndicatorType)
        else IndicatorType(indicator_type)
    )
    row = ThreatIntelIndicator(
        value=value,
        indicator_type=kind,
        canonical_key=f"{kind.value}:{value}",
        first_seen_at=first_seen_at,
        last_seen_at=first_seen_at,
    )
    db.add(row)
    db.flush()
    return row


def a_lookup(
    db: Session,
    *,
    indicator_id: uuid.UUID,
    event_id: uuid.UUID,
    provider: str = "abuseipdb",
    found: bool = True,
    result_timestamp: datetime = NOW,
) -> ThreatIntelLookup:
    from app.models.threat_intel_lookup import LookupStatus

    row = ThreatIntelLookup(
        event_id=event_id,
        indicator_id=indicator_id,
        provider=provider,
        status=LookupStatus.SUCCESS,
        found=found,
        confidence=0.8,
        result_timestamp=result_timestamp,
        evidence={},
        result_metadata={},
    )
    db.add(row)
    db.flush()
    return row


def a_memory(
    db: Session,
    *,
    memory_id: uuid.UUID,
    memory_type: MemoryType = MemoryType.INCIDENT_SUMMARY,
    title: str = "Prior incident",
    summary: str = "A correlated prior incident judged similar.",
    correlation_id: uuid.UUID | None = None,
    created_at: datetime = NOW,
) -> IncidentMemoryRow:
    row = IncidentMemoryRow(
        memory_id=memory_id,
        memory_type=memory_type.value,
        title=title,
        summary=summary,
        correlation_id=correlation_id,
        sources={},
        indicators={},
        entities={},
        techniques={},
        findings={},
        actions={},
        outcomes={},
        memory_metadata={},
        confidence=None,
        created_at=created_at,
    )
    db.add(row)
    db.flush()
    return row


def seed_actor(db: Session, *, role_name: str = "admin") -> User:
    """Create (or reuse) a role + trusted analyst actor for service tests."""
    role = db.query(Role).filter(Role.name == role_name).one_or_none()
    if role is None:
        role = Role(name=role_name, description=f"{role_name} role")
        db.add(role)
        db.flush()
    user = User(
        email=f"hunt-actor-{uuid.uuid4().hex[:8]}@example.com",
        password_hash="not-a-real-hash",
        is_active=True,
        role_id=role.id,
    )
    db.add(user)
    db.flush()
    user.role = role  # eager for service.read role.name
    return user


__all__ = [
    "TZ",
    "NOW",
    "ACTOR_ID",
    "a_detection",
    "a_audit",
    "a_correlation",
    "a_risk",
    "a_indicator",
    "a_lookup",
    "a_memory",
    "seed_actor",
]