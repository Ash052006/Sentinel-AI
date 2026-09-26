"""Threat Hunting engine — V2.19.

Executes one bounded hunt: a deterministic, read-only pipeline over the
closed surfaces of the grammar, producing the hunt's evidence, findings and
timeline.  The engine:

* never **mutates** any living record — it only ever observes persisted
  analytical history and writes the hunt's own artifacts;
* never executes a response action, never reaches SOAR, never raises a
  boundary request;
* hard-fails (``LIMITS_EXCEEDED``) instead of silently truncating
  evidence, so a hunt never claims a bounded result from an unbounded
  collection;
* preserves provenance verbatim from each source envelope and never
  fabricates a confidence or a severity.
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.correlation_member import CorrelationMember
from app.models.correlation_result import CorrelationResult
from app.models.detection_result import DetectionResult
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import ThreatIntelLookup
from app.schemas.correlation_query import CorrelationResultRecord
from app.schemas.incident_memory_query import IncidentMemoryRecord
from app.schemas.risk_query import RiskAssessmentRecord
from app.schemas.threat_hunting import (
    HUNT_MAX_EVIDENCE,
    HUNT_MAX_FINDINGS,
    HUNT_MAX_TIMELINE_ITEMS,
    HUNT_SURFACE_CAP,
    HuntType,
)

from .errors import HuntLimitError, HuntExecutionError
from .grammar import SURFACES, TEMPLATES, Predicate, udid
from .query import (
    collect_correlations_by_events,
    collect_memory_by_correlations,
    collect_records,
    collect_risk_by_correlations,
)

_SEVERITY_ORDER = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class EvidenceItem:
    surface: str
    key: str
    evidence_type: str
    provenance: str
    reference_id: uuid.UUID
    event_id: uuid.UUID | None
    correlation_id: uuid.UUID | None
    severity: str | None
    subject: str | None
    observed_at: datetime | None
    title: str
    summary: str


@dataclass(frozen=True)
class FindingItem:
    finding_id: uuid.UUID
    title: str
    description: str
    severity: str | None
    provenance: str
    observed_at: datetime | None
    evidence_ids: list[uuid.UUID]
    context: dict


@dataclass(frozen=True)
class TimelineItem:
    timeline_item_id: uuid.UUID
    evidence_id: uuid.UUID
    reference_id: uuid.UUID
    observed_at: datetime | None
    evidence_type: str
    evidence_summary: str
    provenance: str


@dataclass(frozen=True)
class HuntRunResult:
    evidence: list
    findings: list
    timeline: list


def _short(value) -> str:
    return str(value)[:8]


def _sev_rank(severity: str | None) -> int:
    return _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else -1


def _sev_label(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _concise(value: str, limit: int = 200) -> str:
    value = " ".join(value.split())
    return value[:limit] + ("…" if len(value) > limit else "")


def _sort_evidence_key(item: EvidenceItem) -> tuple:
    observed = item.observed_at
    return (observed is not None, _as_utc(observed) if observed else datetime.max, item.key)


class ThreatHuntEngine:
    """One synchronous, fully deterministic, bounded hunt run."""

    def __init__(
        self,
        db: Session,
        *,
        surface_cap: int = HUNT_SURFACE_CAP,
        max_evidence: int = HUNT_MAX_EVIDENCE,
        max_findings: int = HUNT_MAX_FINDINGS,
        max_timeline: int = HUNT_MAX_TIMELINE_ITEMS,
    ) -> None:
        self._db = db
        self._surface_cap = surface_cap
        self._max_evidence = max_evidence
        self._max_findings = max_findings
        self._max_timeline = max_timeline
        self._hunt_id: uuid.UUID = uuid.uuid4()

    # ------------------------------------------------------------------
    # identity
    # ------------------------------------------------------------------

    def _evidence_id(self, key: str) -> uuid.UUID:
        return udid(self._hunt_id, f"evidence:{key}")

    def _finding_id(self, kind: str, group_key: str) -> uuid.UUID:
        return udid(self._hunt_id, f"finding:{kind}:{group_key}")

    def _timeline_id(self, idx: int) -> uuid.UUID:
        return udid(self._hunt_id, f"timeline:{idx:04d}")

    # ------------------------------------------------------------------
    # execution
    # ------------------------------------------------------------------

    def run(
        self,
        *,
        hunt_id: uuid.UUID,
        hunt_type: HuntType,
        start_time: datetime,
        end_time: datetime,
        predicates: tuple[Predicate, ...],
    ) -> HuntRunResult:
        self._hunt_id = hunt_id
        template = TEMPLATES[hunt_type]
        evidence_by_key: dict[str, EvidenceItem] = {}

        for surface_key in template.primary_surfaces:
            self._collect_primary(surface_key, start_time, end_time, predicates, evidence_by_key)

        for link in template.links:
            self._run_link(hunt_id, link, start_time, end_time, predicates, evidence_by_key)

        evidence = sorted(evidence_by_key.values(), key=_sort_evidence_key)
        if len(evidence) > self._max_evidence:
            raise HuntLimitError(
                f"hunt collected {len(evidence)} evidence items (limit {self._max_evidence})"
            )
        findings = self._build_findings(template, evidence)
        timeline = self._build_timeline(evidence)
        return HuntRunResult(evidence=evidence, findings=findings, timeline=timeline)

    def _allowed_for(self, surface_key: str) -> frozenset[str]:
        from .query import _ALLOWED_COLUMNS

        return _ALLOWED_COLUMNS[surface_key]

    def _predicates_for(self, surface_key: str, predicates) -> list[Predicate]:
        allowed = self._allowed_for(surface_key)
        return [p for p in predicates if p.column in allowed]

    def _collect_primary(self, surface_key, start_time, end_time, predicates, evidence_by_key):
        surface = SURFACES[surface_key]
        relevant = self._predicates_for(surface_key, predicates)
        rows, total, err = collect_records(
            self._db, surface, start=start_time, end=end_time, predicates=relevant
        )
        if err is not None:
            raise HuntExecutionError(f"surface '{surface_key}': {err}")
        if total > self._surface_cap:
            raise HuntLimitError(
                f"surface '{surface_key}' matched {total} records (limit {self._surface_cap})"
            )
        for row in rows:
            self._add_evidence(evidence_by_key, self._to_evidence(surface_key, row))

    def _run_link(self, hunt_id, link, start_time, end_time, predicates, evidence_by_key):
        parents = [e for e in evidence_by_key.values() if e.surface in link.from_evidence_keys]
        if not parents:
            return
        surface = SURFACES[link.surface]
        relevant = self._predicates_for(link.surface, predicates)

        if link.kind in ("members", "lookups_by_indicator"):
            anchors = {e.reference_id for e in parents if e.reference_id}
            if not anchors:
                return
            rows, total, err = collect_records(
                self._db,
                surface,
                start=start_time,
                end=end_time,
                predicates=relevant,
                extra={link.anchor_column: set(anchors)},
            )
            if err is not None:
                raise HuntExecutionError(f"link '{link.name}': {err}")
            if total + len(evidence_by_key) > self._max_evidence:
                raise HuntLimitError(
                    f"link '{link.name}' would exceed the evidence bound ({self._max_evidence})"
                )
            for row in rows:
                self._add_evidence(evidence_by_key, self._to_evidence(link.surface, row))
            return

        if link.kind == "reuse_correlations_by_event":
            events = {e.event_id for e in parents if e.event_id}
            if not events:
                return
            records, total, err = collect_correlations_by_events(
                self._db,
                surface,
                start=start_time,
                end=end_time,
                predicates=relevant,
                event_ids={u for u in events},
            )
        elif link.kind == "reuse_risk_by_correlation":
            correlation_ids = {e.reference_id for e in parents if e.reference_id}
            if not correlation_ids:
                return
            records, total, err = collect_risk_by_correlations(
                self._db,
                surface,
                start=start_time,
                end=end_time,
                predicates=relevant,
                correlation_ids={u for u in correlation_ids},
            )
        elif link.kind == "reuse_memory_by_correlation":
            correlation_ids = {e.reference_id for e in parents if e.reference_id}
            if not correlation_ids:
                return
            records, total, err = collect_memory_by_correlations(
                self._db,
                surface,
                start=start_time,
                end=end_time,
                predicates=relevant,
                correlation_ids={u for u in correlation_ids},
            )
        else:
            raise HuntExecutionError(f"unknown link kind '{link.kind}'")
        if err is not None:
            raise HuntExecutionError(f"link '{link.name}': {err}")
        if total + len(evidence_by_key) > self._max_evidence:
            raise HuntLimitError(
                f"link '{link.name}' would exceed the evidence bound ({self._max_evidence})"
            )
        for rec in records:
            self._add_evidence(evidence_by_key, self._to_evidence(link.surface, rec))

    def _add_evidence(self, evidence_by_key, item: EvidenceItem) -> None:
        if item.key not in evidence_by_key:
            evidence_by_key[item.key] = item

    # ------------------------------------------------------------------
    # evidence conversion (verbatim provenance / severities)
    # ------------------------------------------------------------------

    def _to_evidence(self, surface_key: str, source) -> EvidenceItem:
        from .grammar import evidence_key

        surface = SURFACES[surface_key]

        if isinstance(source, DetectionResult):
            rule_type = _sev_label(source.rule_type)
            severity = _sev_label(source.severity)
            return EvidenceItem(
                surface=surface_key,
                key=evidence_key(surface_key, source.detection_id),
                evidence_type=surface.evidence_type,
                provenance=surface.provenance,
                reference_id=source.detection_id,
                event_id=source.event_id,
                correlation_id=None,
                severity=severity,
                subject=source.rule_id,
                observed_at=source.detected_at,
                title=f"Detection {_short(source.detection_id)}",
                summary=(
                    f"Rule '{source.rule_id}' ({rule_type}) detected "
                    f"with severity {severity}"
                ),
            )
        if isinstance(source, AuditLog):
            return EvidenceItem(
                surface=surface_key,
                key=evidence_key(surface_key, source.id),
                evidence_type=surface.evidence_type,
                provenance=surface.provenance,
                reference_id=source.id,
                event_id=None,
                correlation_id=None,
                severity=None,
                subject=source.ip_address,
                observed_at=source.created_at,
                title=f"Audit {source.action}",
                summary=f"Audit '{source.action}' on resource '{source.resource or 'unknown'}'",
            )
        if isinstance(source, (CorrelationResult, CorrelationResultRecord)):
            correlation_id = source.correlation_id
            status = _sev_label(source.status)
            return EvidenceItem(
                surface=surface_key,
                key=evidence_key(surface_key, correlation_id),
                evidence_type=surface.evidence_type,
                provenance=surface.provenance,
                reference_id=correlation_id,
                event_id=None,
                correlation_id=correlation_id,
                severity=None,
                subject=None,
                observed_at=source.timestamp,
                title=f"Correlation {_short(correlation_id)}",
                summary=f"Correlation {_short(correlation_id)} with status {status}",
            )
        if isinstance(source, CorrelationMember):
            return EvidenceItem(
                surface=surface_key,
                key=evidence_key(surface_key, source.id),
                evidence_type=surface.evidence_type,
                provenance=surface.provenance,
                reference_id=source.id,
                event_id=source.event_id,
                correlation_id=source.correlation_id,
                severity=None,
                subject=None,
                observed_at=source.timestamp,
                title=f"Correlation member {source.member_order}",
                summary=(
                    f"Member {source.member_order} of correlation {_short(source.correlation_id)} "
                    f"(detection {_short(source.detection_id)})"
                ),
            )
        if isinstance(source, RiskAssessmentRecord):
            level = _sev_label(source.level)
            return EvidenceItem(
                surface=surface_key,
                key=evidence_key(surface_key, source.risk_assessment_id),
                evidence_type=surface.evidence_type,
                provenance=surface.provenance,
                reference_id=source.risk_assessment_id,
                event_id=None,
                correlation_id=source.correlation_id,
                severity=level,
                subject=None,
                observed_at=source.timestamp,
                title=f"Risk {level}",
                summary=(
                    f"Risk {level} (score {source.score:.2f}) "
                    f"for correlation {_short(source.correlation_id)}"
                ),
            )
        if isinstance(source, ThreatIntelIndicator):
            indicator_type = _sev_label(source.indicator_type)
            return EvidenceItem(
                surface=surface_key,
                key=evidence_key(surface_key, source.id),
                evidence_type=surface.evidence_type,
                provenance=surface.provenance,
                reference_id=source.id,
                event_id=None,
                correlation_id=None,
                severity=None,
                subject=source.value,
                observed_at=source.first_seen_at,
                title=f"Indicator {indicator_type}",
                summary=f"{indicator_type} indicator '{_concise(source.value)}'",
            )
        if isinstance(source, ThreatIntelLookup):
            return EvidenceItem(
                surface=surface_key,
                key=evidence_key(surface_key, source.id),
                evidence_type=surface.evidence_type,
                provenance=surface.provenance,
                reference_id=source.id,
                event_id=source.event_id,
                correlation_id=None,
                severity=None,
                subject=None,
                observed_at=source.result_timestamp,
                title=f"Indicator lookup {source.provider}",
                summary=(
                    f"{source.provider} lookup {'found' if source.found else 'not found'} "
                    f"for event {_short(source.event_id)}"
                ),
            )
        if isinstance(source, IncidentMemoryRecord):
            return EvidenceItem(
                surface=surface_key,
                key=evidence_key(surface_key, source.memory_id),
                evidence_type=surface.evidence_type,
                provenance=surface.provenance,
                reference_id=source.memory_id,
                event_id=None,
                correlation_id=source.correlation_id,
                severity=None,
                subject=None,
                observed_at=source.created_at,
                title=_concise(source.title),
                summary=_concise(source.summary),
            )
        raise HuntExecutionError(f"unsupported evidence source {type(source).__name__}")

    # ------------------------------------------------------------------
    # findings (deterministic, bounded, evidence-derived only)
    # ------------------------------------------------------------------

    def _build_findings(self, template, evidence):
        findings: list[FindingItem] = []
        if template.hunt_type in (HuntType.DETECTION_REVIEW, HuntType.PRIVILEGE_ACTIVITY):
            findings += self._detection_findings(evidence)
        if template.hunt_type in (HuntType.MULTI_STAGE_ACTIVITY, HuntType.PRIVILEGE_ACTIVITY):
            findings += self._correlation_findings(evidence)
        if template.hunt_type == HuntType.INDICATOR_HUNT:
            findings += self._indicator_findings(evidence)
        if template.hunt_type == HuntType.AUTHENTICATION_ANOMALY:
            findings += self._audit_findings(evidence)

        findings.sort(key=lambda f: (-_sev_rank(f.severity), f.title, str(f.finding_id)))

        projected = findings
        omitted_groups = 0
        if len(findings) >= self._max_findings:
            projected = findings[: self._max_findings - 1]
            omitted_groups = len(findings) - len(projected)

        summary = self._summary_finding(template, evidence, omitted_groups)
        if summary is not None:
            projected.append(summary)
        projected.sort(key=lambda f: (-_sev_rank(f.severity), f.title, str(f.finding_id)))
        return projected

    def _detection_findings(self, evidence):
        groups: dict[str, list] = {}
        for e in evidence:
            if e.surface == "detection":
                groups.setdefault(e.subject or e.title, []).append(e)
        out = []
        for rule_id in sorted(groups):
            members = sorted(groups[rule_id], key=lambda m: m.key)
            sev = max(
                (m.severity for m in members if m.severity), key=_sev_rank, default=None
            )
            obs = min(
                (_as_utc(m.observed_at) for m in members if m.observed_at is not None),
                default=None,
            )
            out.append(
                FindingItem(
                    finding_id=self._finding_id("rule", rule_id),
                    title=f"Rule '{rule_id}' — {len(members)} detection(s)",
                    description=(
                        f"Rule '{rule_id}' produced {len(members)} persisted detection(s) "
                        "within the hunt window."
                    ),
                    severity=sev,
                    provenance="detected",
                    observed_at=obs,
                    evidence_ids=sorted(
                        {self._evidence_id(m.key) for m in members}, key=lambda u: str(u)
                    ),
                    context={
                        "rule_id": rule_id,
                        "count": len(members),
                        "event_count": len({m.event_id for m in members if m.event_id}),
                        "severities": sorted({m.severity for m in members if m.severity}),
                        "subject_kind": "rule_id",
                    },
                )
            )
        return out

    def _audit_findings(self, evidence):
        groups: dict[str, list] = {}
        for e in evidence:
            if e.surface != "audit":
                continue
            key = e.subject or f"no_ip|{e.title}"
            groups.setdefault(key, []).append(e)
        out = []
        for key in sorted(groups):
            members = sorted(groups[key], key=lambda m: m.key)
            actions = Counter()
            for m in members:
                actions[m.title.removeprefix("Audit ")] += 1
            obs = min(
                (_as_utc(m.observed_at) for m in members if m.observed_at is not None),
                default=None,
            )
            out.append(
                FindingItem(
                    finding_id=self._finding_id("subject", key),
                    title=f"Auth activity from {key} — {len(members)} event(s)",
                    description=(
                        f"Auth action(s) attributed to '{key}' within the hunt window."
                    ),
                    severity=None,
                    provenance="observed",
                    observed_at=obs,
                    evidence_ids=sorted(
                        {self._evidence_id(m.key) for m in members}, key=lambda u: str(u)
                    ),
                    context={
                        "subject": key,
                        "count": len(members),
                        "action_counts": dict(sorted(actions.items())),
                        "subject_kind": "actor_ip" if not key.startswith("no_ip|") else "action",
                    },
                )
            )
        return out

    def _indicator_findings(self, evidence):
        groups: dict[str, list] = {}
        for e in evidence:
            if e.surface != "indicator":
                continue
            kind = e.title.removeprefix("Indicator ")
            groups.setdefault(kind, []).append(e)
        out = []
        for kind in sorted(groups):
            members = sorted(groups[kind], key=lambda m: m.key)
            values = sorted({m.subject for m in members if m.subject})
            obs = min(
                (_as_utc(m.observed_at) for m in members if m.observed_at is not None),
                default=None,
            )
            out.append(
                FindingItem(
                    finding_id=self._finding_id("indicator", kind),
                    title=f"{kind} indicators — {len(members)} indicator(s)",
                    description=(
                        f"{len(members)} {kind} indicator(s) matched within the hunt window."
                    ),
                    severity=None,
                    provenance="enriched",
                    observed_at=obs,
                    evidence_ids=sorted(
                        {self._evidence_id(m.key) for m in members}, key=lambda u: str(u)
                    ),
                    context={
                        "indicator_type": kind,
                        "count": len(members),
                        "values": values[:20],
                        "value_truncated": len(values) > 20,
                    },
                )
            )
        return out

    def _correlation_findings(self, evidence):
        corr_evidence = [e for e in evidence if e.surface == "correlation"]
        out = []
        for corr in sorted(corr_evidence, key=lambda e: e.key):
            correlation_id = corr.reference_id
            members = [
                e
                for e in evidence
                if e.surface == "correlation_member" and e.correlation_id == correlation_id
            ]
            risks = [
                e for e in evidence if e.surface == "risk" and e.correlation_id == correlation_id
            ]
            sev = max(
                (r.severity for r in risks if r.severity), key=_sev_rank, default=None
            )
            context: dict = {
                "correlation_id": str(correlation_id),
                "member_count": len(members),
            }
            if risks:
                context["risk_levels"] = sorted(
                    {r.severity for r in risks if r.severity}
                )
                context["risk_assessment_count"] = len(risks)
            out.append(
                FindingItem(
                    finding_id=self._finding_id("correlation", str(correlation_id)),
                    title=f"Correlation {_short(correlation_id)} "
                    f"({len(members)} member(s))",
                    description=(
                        f"Correlation {_short(correlation_id)} with {len(members)} "
                        "persisted member(s) within the hunt window."
                    ),
                    severity=sev,
                    provenance="correlated",
                    observed_at=corr.observed_at,
                    evidence_ids=sorted(
                        {self._evidence_id(m.key) for m in [corr, *members]},
                        key=lambda u: str(u),
                    ),
                    context=context,
                )
            )
        return out

    def _summary_finding(self, template, evidence, omitted_groups: int = 0):
        surfaces = Counter(e.surface for e in evidence)
        provenance = Counter(e.provenance for e in evidence).most_common(1)
        obs = min(
            (_as_utc(e.observed_at) for e in evidence if e.observed_at is not None),
            default=None,
        )
        kind = template.title
        context = {
            "evidence_count": len(evidence),
            "surface_counts": dict(sorted(surfaces.items())),
        }
        if omitted_groups:
            context["omitted_findings"] = omitted_groups
        return FindingItem(
            finding_id=self._finding_id("summary", kind.replace(" ", "_").lower()),
            title=template.title,
            description=(
                f"Collected {len(evidence)} evidence item(s) across "
                f"{len(surfaces)} surface(s) within the bounded hunt window."
            ),
            severity=None,
            provenance=provenance[0][0] if provenance else "observed",
            observed_at=obs,
            evidence_ids=sorted(
                {self._evidence_id(e.key) for e in evidence}, key=lambda u: str(u)
            ),
            context=context,
        )

    # ------------------------------------------------------------------
    # timeline (chronological, deterministic)
    # ------------------------------------------------------------------

    def _build_timeline(self, evidence):
        if len(evidence) > self._max_timeline:
            raise HuntLimitError(
                f"hunt timeline would contain {len(evidence)} items "
                f"(limit {self._max_timeline})"
            )
        timeline = []
        for idx, item in enumerate(evidence):
            timeline.append(
                TimelineItem(
                    timeline_item_id=self._timeline_id(idx),
                    evidence_id=self._evidence_id(item.key),
                    reference_id=item.reference_id,
                    observed_at=item.observed_at,
                    evidence_type=item.evidence_type,
                    evidence_summary=item.summary,
                    provenance=item.provenance,
                )
            )
        return timeline


__all__ = [
    "EvidenceItem",
    "FindingItem",
    "TimelineItem",
    "HuntRunResult",
    "ThreatHuntEngine",
]