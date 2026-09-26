"""Bounded, deterministic, read-only incident report context builder (V2.20).

Assembles an :class:`~app.schemas.incident_report.IncidentReportContext`
(the AI's only source material) plus the deterministic report sections
(timeline) from **already-persisted** SentinelAI records for one correlation.

Trust boundary::

    persisted records (correlation/members/detections/risk/memory/
    hunts/approvals/SOAR/threat-intel)
          |
          v
    ReportContextBuilder    (this module — read-only, bounded, allowlisted)
          |
          v
    IncidentReportContext + timeline   (the AI's only source material)

Contract rules honoured here:

* **Read-only** — the builder never calls ``add``/``delete``, ``flush``,
  ``commit`` or ``rollback``, and never touches an execution/policy/
  approval/provider path.  Everything it consumes already exists.
* **Allowlisting** — each source maps through an explicit field allowlist;
  database internals never leak into the context.
* **Provenance-preserving** — each record keeps its source provenance
  (CORRELATED / DETECTED / RISK_ASSESSED / RECALLED / ENRICHED /
  APPROVAL_REVIEWED).  Threat hunts and SOAR executions are persisted
  operational records with no enum value, presented as ``OBSERVED`` with
  that decision documented in ``docs/development/
  ai_incident_report_generator_v220.md``.
* **Availability** — ``investigation`` / ``attribution`` / ``security_events``
  are always ``NOT_PROVIDED`` (no persisted store exists) and are never
  fabricated; ``risk_assessment`` is ``PROVIDED``/``NOT_PROVIDED`` only.
* **Bounded** — every section carries an explicit cap and a violation
  raises :class:`ReportBoundError` (fail closed, never silently truncated).
* **Deterministic & immutable** — identical persisted state produces
  byte-identical context and timeline; the builder never mutates sources.
* **Secret-safe** — the persisted payloads were already vet-ted at write;
  the contracts re-validate secret-free JSON payloads and the prompt
  builder re-scans the serialized context before it crosses the AI boundary.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.models.approval_request import ApprovalRequestRow
from app.models.soar_execution import SoarExecutionRow
from app.models.threat_intel_lookup import ThreatIntelLookup
from app.repositories.approval import ApprovalRepository
from app.repositories.soar import SoarRepository
from app.repositories.threat_intelligence import ThreatIntelRepository
from app.schemas.correlation_query import CorrelationResultRecord
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.detection_query import DetectionResultRecord
from app.schemas.incident_memory_query import IncidentMemoryRecord
from app.schemas.incident_report import (
    MAX_REPORT_APPROVALS,
    MAX_REPORT_DETECTIONS,
    MAX_REPORT_EVENT_REFERENCES,
    MAX_REPORT_EVIDENCE_REFERENCES,
    MAX_REPORT_MEMBERS,
    MAX_REPORT_MEMORIES,
    MAX_REPORT_SOAR_EXECUTIONS,
    MAX_REPORT_THREAT_HUNT_SCAN,
    MAX_REPORT_THREAT_HUNTS,
    MAX_REPORT_THREAT_INTEL,
    MAX_REPORT_THREAT_INTEL_PER_EVENT,
    MAX_REPORT_TIMELINE_ITEMS,
    ApprovalRequestContext,
    IncidentFactContext,
    IncidentReportContext,
    ReportEvidenceReference,
    ReportRecordType,
    ReportSourceAvailability,
    ReportTimelineItem,
    SecurityEventReferenceContext,
    SoarExecutionContext,
    ThreatHuntContext,
    ThreatIntelLookupContext,
)
from app.schemas.investigation_context import (
    CorrelationContext,
    CorrelationMemberContext,
    DetectionContext,
    IncidentMemoryReferenceContext,
    InputAvailability,
    RiskContext,
)
from app.schemas.risk_query import RiskAssessmentRecord
from app.schemas.security_event import Provenance
from app.schemas.threat_hunting import ThreatHuntSummary, ThreatHuntStatus
from app.services.correlation_query import CorrelationQueryService
from app.services.detection_query import DetectionQueryService
from app.services.incident_memory_query import IncidentMemoryQueryService
from app.services.risk_query import RiskQueryService
from app.services.threat_hunting.service import ThreatHuntService

from .errors import (
    ReportBoundError,
    ReportContextError,
    ReportCorrelationNotFoundError,
    ReportValidationError,
)

#: Deterministic namespace for report evidence-catalog reference ids.  The
#: same persisted record always derives the same catalog reference id, so
#: the catalog is reproducible across generations.
_REPORT_REFERENCE_NAMESPACE = uuid.UUID("c2bfe6a1-3b8e-4f1a-9c2d-5e7f0a1b3c4d")


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalize a possibly-naive DB instant to tz-aware UTC (both backends)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _coerce_uuid(value: object) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))


def _catalog_id(record_type: ReportRecordType, target_id: uuid.UUID) -> uuid.UUID:
    """Deterministic catalog reference id over (record_type, target_id)."""
    return uuid.uuid5(_REPORT_REFERENCE_NAMESPACE, f"{record_type.value}:{target_id}")


def _added_catalog(
    catalog: list[ReportEvidenceReference],
    record_type: ReportRecordType,
    target_id: uuid.UUID,
    provenance: Provenance,
) -> ReportEvidenceReference:
    """Append a catalog entry and return it (bound checked once at the end)."""
    ref = ReportEvidenceReference(
        reference_id=_catalog_id(record_type, target_id),
        record_type=record_type,
        target_id=target_id,
        provenance=provenance,
    )
    catalog.append(ref)
    return ref


class ReportQuerySources:
    """Replaceable read sources so the builder is testable without a DB.

    Every default factory is stateless; tests may inject fakes.  All reads
    are strictly read-only.
    """

    def __init__(
        self,
        *,
        correlation_service: Callable[[], CorrelationQueryService] = CorrelationQueryService,
        detection_service: Callable[[], DetectionQueryService] = DetectionQueryService,
        risk_service: Callable[[], RiskQueryService] = RiskQueryService,
        memory_service: Callable[[], IncidentMemoryQueryService] = IncidentMemoryQueryService,
        threat_intel_repository: Callable[[Session], ThreatIntelRepository] = ThreatIntelRepository,
        approval_repository: Callable[[Session], ApprovalRepository] = ApprovalRepository,
        soar_repository: Callable[[Session], SoarRepository] = SoarRepository,
    ) -> None:
        self.correlation_service = correlation_service
        self.detection_service = detection_service
        self.risk_service = risk_service
        self.memory_service = memory_service
        self.threat_intel_repository = threat_intel_repository
        self.approval_repository = approval_repository
        self.soar_repository = soar_repository


class ReportContextBuild:
    """The deterministic outcome of one context build.

    ``context`` is the AI's only source material; ``timeline`` and
    ``source_limitations`` are deterministic, app-assembled sections derived
    from the same reads (the LLM never produces them).
    """

    __slots__ = ("context", "timeline", "source_limitations")

    def __init__(
        self,
        context: IncidentReportContext,
        timeline: list[ReportTimelineItem],
        source_limitations: list[str],
    ) -> None:
        self.context = context
        self.timeline = timeline
        self.source_limitations = source_limitations


class ReportContextBuilder:
    """Read-only context assembly for one correlation (V2.20)."""

    def __init__(
        self,
        sources: ReportQuerySources | None = None,
        *,
        actor=None,
    ) -> None:
        self.sources = sources or ReportQuerySources()
        self._actor = actor

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def build(self, db: Session, correlation_id: uuid.UUID) -> ReportContextBuild:
        """Assemble the deterministic report context + timeline.

        Raises:
            ReportCorrelationNotFoundError: the correlation does not exist.
            ReportBoundError: a documented report bound was exceeded.
            ReportContextError: a source read failed (sanitized).
            ReportValidationError: a persisted record violated a carried
                contract (fail closed).
        """
        record = self._load_correlation(db, correlation_id)
        if record is None:
            raise ReportCorrelationNotFoundError(correlation_id)

        timeline: list[ReportTimelineItem] = []
        catalog: list[ReportEvidenceReference] = []

        correlation = self._build_correlation(record, timeline, catalog)
        detection_map, member_events = self._build_detections(
            db, record, correlation, timeline, catalog
        )
        risk = self._build_risk(db, record, timeline, catalog)
        memories = self._build_memories(db, record, timeline, catalog)
        threat_intel = self._build_threat_intel(
            db, member_events, timeline, catalog
        )
        hunts = self._build_hunts(db, record, correlation, timeline, catalog)
        approvals = self._build_approvals(db, record, timeline, catalog)
        soar_executions = self._build_soar(db, record, timeline, catalog)
        event_references = self._build_event_references(member_events)

        incident = self._build_incident_facts(record, detection_map)
        availability = self._build_availability(
            detections=correlation.members,
            resolved_detections=detection_map,
            threat_intel=threat_intel,
            risk=risk,
            memories=memories,
            hunts=hunts,
            approvals=approvals,
            soar=soar_executions,
        )

        self._assert_bounds(
            catalog=catalog,
            timeline=timeline,
            event_references=event_references,
        )

        context = IncidentReportContext(
            incident=incident,
            correlation=correlation,
            detections=[detection_map[d] for d in _sorted_member_order(detection_map)],
            threat_intelligence=threat_intel,
            risk_assessment=risk,
            incident_memories=memories,
            threat_hunts=hunts,
            approvals=approvals,
            soar_executions=soar_executions,
            security_event_references=event_references,
            evidence_catalog=catalog,
            availability=availability,
        )
        return ReportContextBuild(
            context=context,
            timeline=timeline,
            source_limitations=derive_source_limitations(context),
        )

    # ------------------------------------------------------------------
    # Per-source builders
    # ------------------------------------------------------------------

    def _load_correlation(
        self, db: Session, correlation_id: uuid.UUID
    ) -> CorrelationResultRecord | None:
        try:
            return self.sources.correlation_service().get_correlation(
                db, correlation_id
            )
        except ReportCorrelationNotFoundError:
            raise
        except Exception as exc:
            raise ReportContextError("failed to load the correlation") from exc

    def _build_correlation(
        self,
        record: CorrelationResultRecord,
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> CorrelationContext:
        if len(record.members) > MAX_REPORT_MEMBERS:
            raise ReportBoundError(
                f"correlation members exceed MAX_REPORT_MEMBERS="
                f"{MAX_REPORT_MEMBERS} (got {len(record.members)})"
            )
        members: list[CorrelationMemberContext] = []
        ordered = sorted(record.members, key=lambda m: (m.member_order, m.id))
        for member in ordered:
            members.append(
                CorrelationMemberContext(
                    detection_id=_coerce_uuid(member.detection_id),
                    event_id=_coerce_uuid(member.event_id),
                    timestamp=_as_utc(member.timestamp),
                )
            )
        correlation = CorrelationContext(
            correlation_id=_coerce_uuid(record.correlation_id),
            status=record.status,
            confidence=record.confidence,
            members=members,
            evidence=dict(record.evidence or {}),
            timestamp=_as_utc(record.timestamp),
            provenance=Provenance.CORRELATED,
        )
        t = _as_utc(record.timestamp)
        if t is not None:
            timeline.append(
                ReportTimelineItem(
                    occurred_at=t,
                    kind="correlation",
                    summary="Correlation established",
                    reference_id=_added_catalog(
                        catalog,
                        ReportRecordType.CORRELATION,
                        _coerce_uuid(record.correlation_id),
                        Provenance.CORRELATED,
                    ).reference_id,
                    provenance=Provenance.CORRELATED,
                )
            )
        return correlation

    def _build_detections(
        self,
        db: Session,
        record: CorrelationResultRecord,
        correlation: CorrelationContext,
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> tuple[dict[uuid.UUID, DetectionContext], set[uuid.UUID]]:
        """Resolve each member's detection record.

        Returns a ``{detection_id: DetectionContext}`` map ordered by member
        position, plus the distinct referenced event-id set (members +
        resolved detections).
        """
        detections: dict[uuid.UUID, DetectionContext] = {}
        member_events: set[uuid.UUID] = set()
        ordered = sorted(record.members, key=lambda m: (m.member_order, m.id))
        for member in ordered:
            detection_id = _coerce_uuid(member.detection_id)
            member_events.add(_coerce_uuid(member.event_id))
            if detection_id in detections:
                continue
            resolved = self._get_detection(db, detection_id)
            if resolved is None:
                continue
            if len(detections) >= MAX_REPORT_DETECTIONS:
                raise ReportBoundError(
                    f"resolved detections exceed MAX_REPORT_DETECTIONS="
                    f"{MAX_REPORT_DETECTIONS} (got {len(detections)})"
                )
            ctx = DetectionContext(
                detection_id=_coerce_uuid(resolved.detection_id),
                event_id=_coerce_uuid(resolved.event_id),
                rule_id=resolved.rule_id,
                rule_type=RuleType(resolved.rule_type),
                rule_version=resolved.rule_version,
                severity=DetectionSeverity(resolved.severity),
                confidence=resolved.confidence,
                evidence=dict(resolved.evidence or {}),
                metadata=dict(resolved.result_metadata or {}),
                timestamp=_as_utc(resolved.detected_at),
                provenance=Provenance.DETECTED,
            )
            member_events.add(_coerce_uuid(resolved.event_id))
            detections[ctx.detection_id] = ctx
            ref = _added_catalog(
                catalog,
                ReportRecordType.DETECTION,
                ctx.detection_id,
                Provenance.DETECTED,
            )
            t = _as_utc(resolved.detected_at)
            if t is not None:
                timeline.append(
                    ReportTimelineItem(
                        occurred_at=t,
                        kind="detection",
                        summary="Detection evaluated (rule matched)",
                        reference_id=ref.reference_id,
                        provenance=Provenance.DETECTED,
                    )
                )
        # Member timeline entries reference each member's catalog entry.
        member_refs: dict[uuid.UUID, ReportEvidenceReference] = {}
        for member in ordered:
            member_id_key = (_coerce_uuid(member.detection_id), _coerce_uuid(member.event_id))
            ref = member_refs.get(member_id_key)
            if ref is None:
                ref = _added_catalog(
                    catalog,
                    ReportRecordType.CORRELATION_MEMBER,
                    _coerce_uuid(member.detection_id),
                    Provenance.CORRELATED,
                )
                member_refs[member_id_key] = ref
            t = _as_utc(member.timestamp)
            if t is not None:
                timeline.append(
                    ReportTimelineItem(
                        occurred_at=t,
                        kind="member",
                        summary="Correlation member added",
                        reference_id=ref.reference_id,
                        provenance=Provenance.CORRELATED,
                    )
                )
        return detections, member_events

    def _get_detection(
        self, db: Session, detection_id: uuid.UUID
    ) -> DetectionResultRecord | None:
        try:
            return self.sources.detection_service().get_result(db, detection_id)
        except Exception as exc:  # pragma: no cover - defensive
            raise ReportContextError("failed to resolve a member detection") from exc

    def _build_risk(
        self,
        db: Session,
        record: CorrelationResultRecord,
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> RiskContext | None:
        try:
            page = self.sources.risk_service().list_assessments_for_correlation(
                db,
                record.correlation_id,
                page=1,
                page_size=1,
            )
        except Exception as exc:
            raise ReportContextError("failed to load risk assessments") from exc
        if not page.items:
            return None
        assessment = page.items[0]
        ctx = RiskContext(
            risk_assessment_id=_coerce_uuid(assessment.risk_assessment_id),
            correlation_id=_coerce_uuid(assessment.correlation_id),
            score=assessment.score,
            level=assessment.level,
            confidence=assessment.confidence,
            factors=list(assessment.factors or []),
            evidence=list(assessment.evidence or []),
            timestamp=_as_utc(assessment.timestamp),
            provenance=Provenance.RISK_ASSESSED,
        )
        ref = _added_catalog(
            catalog,
            ReportRecordType.RISK_ASSESSMENT,
            ctx.risk_assessment_id,
            Provenance.RISK_ASSESSED,
        )
        t = _as_utc(assessment.timestamp)
        if t is not None:
            timeline.append(
                ReportTimelineItem(
                    occurred_at=t,
                    kind="risk_assessment",
                    summary="Risk assessment recorded",
                    reference_id=ref.reference_id,
                    provenance=Provenance.RISK_ASSESSED,
                )
            )
        return ctx

    def _build_memories(
        self,
        db: Session,
        record: CorrelationResultRecord,
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> list[IncidentMemoryReferenceContext]:
        try:
            page = self.sources.memory_service().list_memories_for_correlation(
                db,
                record.correlation_id,
                page=1,
                page_size=MAX_REPORT_MEMORIES,
            )
        except Exception as exc:
            raise ReportContextError("failed to load incident memories") from exc
        if page.total > MAX_REPORT_MEMORIES:
            raise ReportBoundError(
                f"incident memories exceed MAX_REPORT_MEMORIES="
                f"{MAX_REPORT_MEMORIES} (got {page.total})"
            )
        memories: list[IncidentMemoryReferenceContext] = []
        for memory in page.items:
            self._build_memory(memory, memories, timeline, catalog)
        return memories

    def _build_memory(
        self,
        memory: IncidentMemoryRecord,
        memories: list[IncidentMemoryReferenceContext],
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> None:
        ctx = IncidentMemoryReferenceContext(
            memory_id=_coerce_uuid(memory.memory_id),
            memory_type=memory.memory_type,
            title=memory.title,
            summary=memory.summary,
            correlation_id=(
                _coerce_uuid(memory.correlation_id)
                if memory.correlation_id is not None
                else None
            ),
            created_at=_as_utc(memory.created_at),
            confidence=memory.confidence,
            provenance=Provenance.RECALLED,
            sources=list(memory.sources or []),
            memory_metadata=dict(memory.memory_metadata or {}),
        )
        memories.append(ctx)
        ref = _added_catalog(
            catalog,
            ReportRecordType.INCIDENT_MEMORY,
            ctx.memory_id,
            Provenance.RECALLED,
        )
        t = _as_utc(memory.created_at)
        if t is not None:
            timeline.append(
                ReportTimelineItem(
                    occurred_at=t,
                    kind="memory",
                    summary="Incident memory persisted",
                    reference_id=ref.reference_id,
                    provenance=Provenance.RECALLED,
                )
            )

    def _build_threat_intel(
        self,
        db: Session,
        event_ids: set[uuid.UUID],
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> list[ThreatIntelLookupContext]:
        repo = self.sources.threat_intel_repository(db)
        lookups: list[ThreatIntelLookupContext] = []
        for event_id in sorted(event_ids, key=str):
            try:
                rows = repo.get_lookups_for_event(
                    event_id, limit=MAX_REPORT_THREAT_INTEL_PER_EVENT + 1
                )
            except Exception as exc:
                raise ReportContextError("failed to load threat-intel lookups") from exc
            rows = sorted(rows, key=lambda r: (r.performed_at or datetime.min, r.id)) if rows else rows
            if len(rows) > MAX_REPORT_THREAT_INTEL_PER_EVENT:
                raise ReportBoundError(
                    f"threat-intel lookups for event {event_id} exceed "
                    f"MAX_REPORT_THREAT_INTEL_PER_EVENT="
                    f"{MAX_REPORT_THREAT_INTEL_PER_EVENT} (got {len(rows)})"
                )
            for row in rows:
                if len(lookups) >= MAX_REPORT_THREAT_INTEL:
                    raise ReportBoundError(
                        f"threat-intel lookups exceed MAX_REPORT_THREAT_INTEL="
                        f"{MAX_REPORT_THREAT_INTEL} (got {len(lookups)})"
                    )
                self._build_lookup(row, lookups, timeline, catalog)
        return lookups

    def _build_lookup(
        self,
        row: ThreatIntelLookup,
        lookups: list[ThreatIntelLookupContext],
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> None:
        try:
            indicator = row.indicator  # relationship (bounded lazy load)
            indicator_type = indicator.indicator_type.value if indicator else "unknown"
            indicator_value = indicator.value if indicator else ""
        except Exception as exc:
            raise ReportContextError("failed to resolve a threat-intel indicator") from exc
        ctx = ThreatIntelLookupContext(
            lookup_id=_coerce_uuid(row.id),
            event_id=_coerce_uuid(row.event_id),
            indicator_id=_coerce_uuid(row.indicator_id),
            indicator_value=indicator_value,
            indicator_type=indicator_type,
            provider=row.provider,
            status=row.status.value if hasattr(row.status, "value") else str(row.status),
            found=row.found,
            confidence=row.confidence,
            performed_at=_as_utc(row.performed_at),
            provenance=Provenance.ENRICHED,
        )
        lookups.append(ctx)
        ref = _added_catalog(
            catalog,
            ReportRecordType.THREAT_INTEL_LOOKUP,
            ctx.lookup_id,
            Provenance.ENRICHED,
        )
        t = _as_utc(row.performed_at)
        if t is not None:
            timeline.append(
                ReportTimelineItem(
                    occurred_at=t,
                    kind="threat_intel_lookup",
                    summary="Threat-intelligence lookup performed",
                    reference_id=ref.reference_id,
                    provenance=Provenance.ENRICHED,
                )
            )

    def _build_hunts(
        self,
        db: Session,
        record: CorrelationResultRecord,
        correlation: CorrelationContext,
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> list[ThreatHuntContext]:
        member_ts = [m.timestamp for m in correlation.members if m.timestamp is not None]
        if not member_ts:
            return []
        incident_start = min(member_ts)
        incident_end = max(member_ts)
        try:
            page = ThreatHuntService.list(
                db,
                actor=self._actor,
                page=1,
                page_size=MAX_REPORT_THREAT_HUNT_SCAN,
                status_filter=ThreatHuntStatus.COMPLETED,
            )
        except Exception as exc:
            raise ReportContextError("failed to load completed threat hunts") from exc
        overlapping = [
            h
            for h in page.items
            if self._hunt_overlaps(h, incident_start, incident_end)
        ]
        if len(overlapping) > MAX_REPORT_THREAT_HUNTS:
            raise ReportBoundError(
                f"overlapping completed hunts exceed MAX_REPORT_THREAT_HUNTS="
                f"{MAX_REPORT_THREAT_HUNTS} (got {len(overlapping)})"
            )
        hunts: list[ThreatHuntContext] = []
        sentinel = datetime.min.replace(tzinfo=timezone.utc)
        for summary in sorted(
            overlapping,
            key=lambda h: (h.completed_at or sentinel, h.hunt_id),
            reverse=True,
        ):
            self._build_hunt(summary, hunts, timeline, catalog)
        return hunts

    @staticmethod
    def _hunt_overlaps(
        summary: ThreatHuntSummary, incident_start: datetime, incident_end: datetime
    ) -> bool:
        start = summary.start_time
        end = summary.end_time
        if start is None or end is None:
            return False
        return start < incident_end and end > incident_start

    def _build_hunt(
        self,
        summary: ThreatHuntSummary,
        hunts: list[ThreatHuntContext],
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> None:
        ctx = ThreatHuntContext(
            hunt_id=_coerce_uuid(summary.hunt_id),
            name=summary.name,
            hunt_type=summary.hunt_type.value,
            start_time=_as_utc(summary.start_time),
            end_time=_as_utc(summary.end_time),
            started_at=_as_utc(summary.started_at),
            completed_at=_as_utc(summary.completed_at),
            result_count=summary.result_count,
            finding_count=summary.finding_count,
            timeline_count=summary.timeline_count,
            created_by_role=summary.created_by_role,
            provenance=Provenance.OBSERVED,
        )
        hunts.append(ctx)
        ref = _added_catalog(
            catalog, ReportRecordType.THREAT_HUNT, ctx.hunt_id, Provenance.OBSERVED
        )
        if ctx.started_at is not None:
            timeline.append(
                ReportTimelineItem(
                    occurred_at=ctx.started_at,
                    kind="threat_hunt",
                    summary="Threat hunt started",
                    reference_id=ref.reference_id,
                    provenance=Provenance.OBSERVED,
                )
            )
        if ctx.completed_at is not None:
            timeline.append(
                ReportTimelineItem(
                    occurred_at=ctx.completed_at,
                    kind="threat_hunt",
                    summary="Threat hunt completed",
                    reference_id=ref.reference_id,
                    provenance=Provenance.OBSERVED,
                )
            )

    def _build_approvals(
        self,
        db: Session,
        record: CorrelationResultRecord,
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> list[ApprovalRequestContext]:
        repo = self.sources.approval_repository(db)
        try:
            rows = repo.list_for_correlation(
                record.correlation_id, limit=MAX_REPORT_APPROVALS + 1
            )
        except Exception as exc:
            raise ReportContextError("failed to load approval requests") from exc
        rows = sorted(rows, key=lambda r: (r.requested_at or datetime.min, r.id), reverse=True)
        if len(rows) > MAX_REPORT_APPROVALS:
            raise ReportBoundError(
                f"approval requests exceed MAX_REPORT_APPROVALS="
                f"{MAX_REPORT_APPROVALS} (got {len(rows)})"
            )
        approvals: list[ApprovalRequestContext] = []
        for row in rows:
            self._build_approval(row, approvals, timeline, catalog)
        return approvals

    def _build_approval(
        self,
        row: ApprovalRequestRow,
        approvals: list[ApprovalRequestContext],
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> None:
        ctx = ApprovalRequestContext(
            approval_id=_coerce_uuid(row.approval_id),
            policy_decision_id=_coerce_uuid(row.policy_decision_id),
            action_type=row.action_type,
            target=row.target,
            status=row.status,
            reason=row.reason,
            policy_rule_id=row.policy_rule_id,
            risk_level=row.risk_level,
            risk_score=row.risk_score,
            confidence=row.confidence,
            requested_at=_as_utc(row.requested_at),
            resolved_at=_as_utc(row.resolved_at),
            response_status=row.response_status,
            response_provider=row.response_provider,
            provenance=Provenance.APPROVAL_REVIEWED,
        )
        approvals.append(ctx)
        ref = _added_catalog(
            catalog,
            ReportRecordType.APPROVAL_REQUEST,
            ctx.approval_id,
            Provenance.APPROVAL_REVIEWED,
        )
        requested = _as_utc(row.requested_at)
        if requested is not None:
            timeline.append(
                ReportTimelineItem(
                    occurred_at=requested,
                    kind="approval_request",
                    summary="Approval requested",
                    reference_id=ref.reference_id,
                    provenance=Provenance.APPROVAL_REVIEWED,
                )
            )
        resolved = _as_utc(row.resolved_at)
        if resolved is not None:
            timeline.append(
                ReportTimelineItem(
                    occurred_at=resolved,
                    kind="approval_request",
                    summary="Approval resolved",
                    reference_id=ref.reference_id,
                    provenance=Provenance.APPROVAL_REVIEWED,
                )
            )

    def _build_soar(
        self,
        db: Session,
        record: CorrelationResultRecord,
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> list[SoarExecutionContext]:
        repo = self.sources.soar_repository(db)
        try:
            rows = repo.list_for_correlation(
                record.correlation_id, limit=MAX_REPORT_SOAR_EXECUTIONS + 1
            )
        except Exception as exc:
            raise ReportContextError("failed to load SOAR executions") from exc
        rows = sorted(rows, key=lambda r: (r.created_at or datetime.min, r.id), reverse=True)
        if len(rows) > MAX_REPORT_SOAR_EXECUTIONS:
            raise ReportBoundError(
                f"SOAR executions exceed MAX_REPORT_SOAR_EXECUTIONS="
                f"{MAX_REPORT_SOAR_EXECUTIONS} (got {len(rows)})"
            )
        executions: list[SoarExecutionContext] = []
        for row in rows:
            self._build_soar_execution(row, executions, timeline, catalog)
        return executions

    def _build_soar_execution(
        self,
        row: SoarExecutionRow,
        executions: list[SoarExecutionContext],
        timeline: list[ReportTimelineItem],
        catalog: list[ReportEvidenceReference],
    ) -> None:
        ctx = SoarExecutionContext(
            execution_id=_coerce_uuid(row.execution_id),
            policy_decision_id=_coerce_uuid(row.policy_decision_id),
            approval_id=(
                _coerce_uuid(row.approval_id) if row.approval_id is not None else None
            ),
            response_id=_coerce_uuid(row.response_id),
            playbook_id=row.playbook_id,
            playbook_version=row.playbook_version,
            primary_action=row.primary_action,
            target=row.target,
            status=row.status,
            failure_policy=row.failure_policy,
            simulated=bool(row.simulated),
            error_code=row.error_code,
            started_at=_as_utc(row.started_at),
            completed_at=_as_utc(row.completed_at),
            created_by_role=row.created_by_role,
            provenance=Provenance.OBSERVED,
        )
        executions.append(ctx)
        ref = _added_catalog(
            catalog,
            ReportRecordType.SOAR_EXECUTION,
            ctx.execution_id,
            Provenance.OBSERVED,
        )
        started = _as_utc(row.started_at)
        if started is not None:
            timeline.append(
                ReportTimelineItem(
                    occurred_at=started,
                    kind="soar_execution",
                    summary="SOAR execution started",
                    reference_id=ref.reference_id,
                    provenance=Provenance.OBSERVED,
                )
            )
        completed = _as_utc(row.completed_at)
        if completed is not None:
            timeline.append(
                ReportTimelineItem(
                    occurred_at=completed,
                    kind="soar_execution",
                    summary="SOAR execution completed",
                    reference_id=ref.reference_id,
                    provenance=Provenance.OBSERVED,
                )
            )

    def _build_event_references(
        self, event_ids: set[uuid.UUID]
    ) -> list[SecurityEventReferenceContext]:
        refs: list[SecurityEventReferenceContext] = []
        for event_id in sorted(event_ids, key=str):
            if len(refs) >= MAX_REPORT_EVENT_REFERENCES:
                raise ReportBoundError(
                    f"security event references exceed "
                    f"MAX_REPORT_EVENT_REFERENCES={MAX_REPORT_EVENT_REFERENCES} "
                    f"(got {len(refs)})"
                )
            refs.append(
                SecurityEventReferenceContext(
                    event_id=event_id,
                    provenance=Provenance.CORRELATED,
                    referenced_by=[
                        ReportRecordType.CORRELATION_MEMBER,
                        ReportRecordType.DETECTION,
                    ],
                )
            )
        return refs

    def _build_incident_facts(
        self,
        record: CorrelationResultRecord,
        detection_map: dict[uuid.UUID, DetectionContext],
    ) -> IncidentFactContext:
        member_ts = [
            _as_utc(m.timestamp)
            for m in record.members
            if m.timestamp is not None
        ]
        correlation_ts = _as_utc(record.timestamp)
        facts = IncidentFactContext(
            correlation_id=_coerce_uuid(record.correlation_id),
            status=record.status,
            confidence=record.confidence,
            established_at=correlation_ts,
            member_count=len(record.members),
            resolved_detection_count=len(detection_map),
            unresolved_detection_count=max(
                0,
                len({_coerce_uuid(m.detection_id) for m in record.members})
                - len(detection_map),
            ),
            distinct_event_reference_count=len(
                {_coerce_uuid(m.event_id) for m in record.members}
            ),
            earliest_member_timestamp=min(member_ts) if member_ts else None,
            latest_member_timestamp=max(member_ts) if member_ts else None,
            provenance=Provenance.CORRELATED,
        )
        return facts

    def _build_availability(
        self,
        *,
        detections: list[CorrelationMemberContext],
        resolved_detections: dict[uuid.UUID, DetectionContext],
        threat_intel: list[ThreatIntelLookupContext],
        risk: RiskContext | None,
        memories: list[IncidentMemoryReferenceContext],
        hunts: list[ThreatHuntContext],
        approvals: list[ApprovalRequestContext],
        soar: list[SoarExecutionContext],
    ) -> ReportSourceAvailability:
        detection_availability: InputAvailability
        if resolved_detections:
            detection_availability = InputAvailability.PROVIDED
        elif detections:
            detection_availability = InputAvailability.NONE_FOUND
        else:
            detection_availability = InputAvailability.NOT_PROVIDED
        threat_intel_availability = (
            InputAvailability.PROVIDED if threat_intel else InputAvailability.NONE_FOUND
        )
        memory_availability = (
            InputAvailability.PROVIDED if memories else InputAvailability.NONE_FOUND
        )
        hunt_availability = (
            InputAvailability.PROVIDED if hunts else InputAvailability.NONE_FOUND
        )
        approval_availability = (
            InputAvailability.PROVIDED if approvals else InputAvailability.NONE_FOUND
        )
        soar_availability = (
            InputAvailability.PROVIDED if soar else InputAvailability.NONE_FOUND
        )
        return ReportSourceAvailability(
            correlation=InputAvailability.PROVIDED,
            detections=detection_availability,
            threat_intelligence=threat_intel_availability,
            risk_assessment=(
                InputAvailability.PROVIDED if risk is not None else InputAvailability.NOT_PROVIDED
            ),
            investigation=InputAvailability.NOT_PROVIDED,
            attribution=InputAvailability.NOT_PROVIDED,
            incident_memory=memory_availability,
            threat_hunts=hunt_availability,
            policy_decisions=approval_availability,
            soar_executions=soar_availability,
            security_events=InputAvailability.NOT_PROVIDED,
        )

    # ------------------------------------------------------------------
    # Bound enforcement (fail closed, never truncate)
    # ------------------------------------------------------------------

    @staticmethod
    def _assert_bounds(
        *,
        catalog: list[ReportEvidenceReference],
        timeline: list[ReportTimelineItem],
        event_references: list[SecurityEventReferenceContext],
    ) -> None:
        if len(catalog) > MAX_REPORT_EVIDENCE_REFERENCES:
            raise ReportBoundError(
                f"evidence catalog exceeds MAX_REPORT_EVIDENCE_REFERENCES="
                f"{MAX_REPORT_EVIDENCE_REFERENCES} (got {len(catalog)})"
            )
        if len(timeline) > MAX_REPORT_TIMELINE_ITEMS:
            raise ReportBoundError(
                f"timeline exceeds MAX_REPORT_TIMELINE_ITEMS="
                f"{MAX_REPORT_TIMELINE_ITEMS} (got {len(timeline)})"
            )
        if len(event_references) > MAX_REPORT_EVENT_REFERENCES:
            raise ReportBoundError(
                f"security event references exceed "
                f"MAX_REPORT_EVENT_REFERENCES={MAX_REPORT_EVENT_REFERENCES} "
                f"(got {len(event_references)})"
            )


def _sorted_member_order(
    detection_map: dict[uuid.UUID, DetectionContext]
) -> list[uuid.UUID]:
    """Deterministic detection ordering (by detection_id; member-order is
    preserved through the correlation's own member list upstream)."""
    return sorted(detection_map)


def derive_source_limitations(context: IncidentReportContext) -> list[str]:
    """Deterministic, human-readable limitations derived from availability.

    Read verbatim from the availability record — never a verdict, never
    ``green``/``red`` claims.
    """
    a = context.availability
    lines: list[str] = []
    if a.security_events is InputAvailability.NOT_PROVIDED:
        lines.append(
            "security_events: not_provided in V2.20 (no persisted "
            "security-event store exists)"
        )
    if a.investigation is InputAvailability.NOT_PROVIDED:
        lines.append(
            "investigation: not_provided in V2.20 (no persisted "
            "investigation-result store exists)"
        )
    if a.attribution is InputAvailability.NOT_PROVIDED:
        lines.append(
            "attribution: not_provided in V2.20 (no persisted "
            "attribution-result store exists)"
        )
    if a.threat_hunts is InputAvailability.NONE_FOUND:
        lines.append(
            "threat_hunts: none_found (bounded scan of the most-recent "
            "completed hunts found no window overlap)"
        )
    if a.detections is InputAvailability.NONE_FOUND:
        lines.append(
            "detections: none_found (no persisted detection record resolved "
            "for the correlation's members)"
        )
    if a.threat_intelligence is InputAvailability.NONE_FOUND:
        lines.append("threat_intelligence: none_found (no persisted lookups)")
    if a.incident_memory is InputAvailability.NONE_FOUND:
        lines.append(
            "incident_memory: none_found (no memories cite the correlation)"
        )
    if a.policy_decisions is InputAvailability.NONE_FOUND:
        lines.append(
            "policy_decisions: none_found (no persisted approval requests)"
        )
    if a.soar_executions is InputAvailability.NONE_FOUND:
        lines.append("soar_executions: none_found (no persisted executions)")
    if not lines:
        lines.append(
            "No source is missing in this report; every availability flag "
            "was provided."
        )
    return lines


__all__ = [
    "ReportQuerySources",
    "ReportContextBuild",
    "ReportContextBuilder",
    "derive_source_limitations",
]