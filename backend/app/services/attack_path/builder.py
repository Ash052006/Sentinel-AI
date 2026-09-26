"""Attack Path Visualization — deterministic graph builder — V2.21.

Read-only projection over persisted records.  The builder:

* loads the correlation and each evidence surface through the existing
  read-only query services (V2.20 architecture) — it never executes a
  playbook, never reaches a provider, never flushes, never writes;
* emits only real, persisted identities as node ids and only
  persisted-row-pair relationships as edges (closed vocabularies from
  ``app.schemas.attack_path``);
* orders every node/edge deterministically so identical inputs produce an
  identical graph (node : ``(surface priority, node_id)``; edge :
  ``edge_id``), which makes the projection byte-stable across runs;
* applies explicit caps: when a cap is reached expansion stops in a fixed
  deterministic order and ``truncated`` is exposed in metadata — truncation
  is never silent;
* keeps ``fields`` secrets-safe: only whitelisted, bounded scalar columns
  are surfaced; raw ``evidence``/``result_metadata`` dict blobs are never
  carried into the graph.

The builder does **not** infer missing attack steps, does not predict
activity, and does not consult any external service.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.repositories.approval import ApprovalRepository
from app.repositories.soar import SoarRepository
from app.repositories.threat_hunting import (
    list_hunts_with_evidence_for_correlation,
)
from app.repositories.threat_intelligence import ThreatIntelRepository
from app.schemas.attack_path import (
    AttackPathEdge,
    AttackPathEdgeType,
    AttackPathNode,
    AttackPathNodeType,
)
from app.schemas.correlation import CorrelationResult
from app.schemas.investigation_context import InputAvailability
from app.schemas.security_event import Provenance
from app.services.attack_path.constants import (
    ATTACK_PATH_BOUNDS,
    MAX_ATTACK_PATH_EDGES,
    MAX_ATTACK_PATH_NODES,
    MAX_CORRELATION_APPROVALS,
    MAX_CORRELATION_DETECTIONS,
    MAX_CORRELATION_HUNTS,
    MAX_CORRELATION_INDICATORS,
    MAX_CORRELATION_MEMORIES,
    MAX_CORRELATION_RISK_ASSESSMENTS,
    MAX_CORRELATION_SOAR_EXECUTIONS,
    MAX_LOOKUPS_PER_DETECTION,
    SURFACE_LABEL,
    surface_priority,
)
from app.services.attack_path.errors import (
    AttackPathCorrelationNotFoundError,
    AttackPathSourceError,
)
from app.services.correlation_query import CorrelationQueryService
from app.services.detection_query import DetectionQueryService
from app.services.incident_memory_query import IncidentMemoryQueryService
from app.services.risk_query import RiskQueryService

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

# Allowlisted decision-snapshot keys (approval ``decision`` dict) that may be
# surfaced; everything else in the stored dict stays out of the graph.
_DECISION_ALLOWLIST = (
    "status",
    "rule_id",
    "action",
    "target",
    "reason",
    "risk_level",
)


@dataclass(frozen=True)
class AttackPathBuildResult:
    """Fully assembled, deterministic projection for one correlation."""

    graph_type: str
    nodes: list[AttackPathNode]
    edges: list[AttackPathEdge]
    availability: dict[str, InputAvailability]
    correlation_id: uuid.UUID
    generated_at: datetime
    truncated: bool
    limitation: str | None
    bounds: dict[str, int] = field(default_factory=lambda: dict(ATTACK_PATH_BOUNDS))


def _safe_text(value: Any, *, limit: int = 160) -> str | None:
    """Bounded, control-character-free scalar text (never a dict/list)."""
    if value is None:
        return None
    if not isinstance(value, (str, int, float, bool)):
        return None
    text = str(value).strip()
    text = _CONTROL_RE.sub(" ", text)
    return text[:limit] if text else None


def _safe_label(value: str | None, fallback: str) -> str:
    """Deterministic, bounded, printable label for a graph node."""
    text = _safe_text(value, limit=200)
    if not text:
        text = fallback
    return f"{text[:100]}…" if len(text) > 100 else text


def _fmt_float(value: float | None) -> str | None:
    if value is None:
        return None
    return f"{value:g}"


def _enum_value(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "value"):
        return _safe_text(value.value)
    return _safe_text(value)


def _fmt_bool(value: bool) -> str:
    return "true" if value else "false"


class AttackPathGraphBuilder:
    """Assembles the V2.21 attack-path projection for one correlation."""

    def __init__(
        self,
        db: Session,
        correlation_id: uuid.UUID | str,
        *,
        now: datetime | None = None,
    ) -> None:
        self.db = db
        self.correlation_id = _coerce_uuid(correlation_id)
        self.now = now if now is not None else datetime.now(timezone.utc)
        self.nodes: dict[str, AttackPathNode] = {}
        self.edges: dict[str, AttackPathEdge] = {}
        self.truncation_parts: list[str] = []
        self.member_count = 0
        self.resolved_detection_count = 0
        self.built_indicator_count = 0
        self.built_risk = False
        self.built_memory = False
        self.built_hunt = False
        self.built_policy = False
        self.built_approval = False
        self.built_soar = False

    # ------------------------------------------------------------------
    # Public entrypoint
    # ------------------------------------------------------------------

    def build(self) -> AttackPathBuildResult:
        correlation = self._load_correlation()
        self._build_correlation_node(correlation)
        self._build_detections_and_indicators(correlation)
        self._build_risk(correlation.correlation_id)
        self._build_memories(correlation.correlation_id)
        self._build_hunts(correlation.correlation_id)
        self._build_approvals(correlation.correlation_id)
        self._build_soar(correlation.correlation_id)
        self._trim_to_bounds()

        ordered_nodes = sorted(
            self.nodes.values(),
            key=lambda n: (surface_priority(n.node_type), n.node_id),
        )
        ordered_edges = sorted(self.edges.values(), key=lambda e: e.edge_id)
        availability = self._availability()
        limitation = "; ".join(self.truncation_parts) if self.truncation_parts else None
        return AttackPathBuildResult(
            graph_type="attack_path",
            nodes=ordered_nodes,
            edges=ordered_edges,
            availability=availability,
            correlation_id=correlation.correlation_id,
            generated_at=self.now,
            truncated=bool(self.truncation_parts),
            limitation=limitation,
        )

    # ------------------------------------------------------------------
    # Surface loaders
    # ------------------------------------------------------------------

    def _guard(self, surface: str, fn):
        try:
            return fn()
        except AttackPathCorrelationNotFoundError:
            raise
        except Exception as exc:
            raise AttackPathSourceError(f"failed to load {surface}") from exc

    def _load_correlation(self) -> CorrelationResult:
        return self._guard(
            "correlation",
            lambda: CorrelationQueryService().get_correlation(
                self.db, self.correlation_id
            ),
        ) or (_raise_missing(self.correlation_id))

    def _build_correlation_node(self, record: CorrelationResult) -> None:
        members = sorted(record.members, key=lambda m: (m.member_order, str(m.id)))
        self.member_count = len(members)
        node = AttackPathNode(
            node_id=f"correlation:{record.correlation_id}",
            node_type=AttackPathNodeType.CORRELATION,
            label=f"Correlation {record.correlation_id}",
            provenance=(
                record.provenance
                if record.provenance is not None
                else Provenance.CORRELATED
            ),
            source_reference=str(record.correlation_id),
            occurrence=record.timestamp,
            status=record.status.value if record.status is not None else None,
            severity=None,
            fields={
                "status": record.status.value if record.status is not None else "unknown",
                "confidence": (
                    _fmt_float(record.confidence) if record.confidence is not None else "n/a"
                ),
                "member_count": str(len(members)),
            },
            evidence_references=[str(m.id) for m in members],
        )
        self._add_node(node)

    def _build_detections_and_indicators(
        self, record: CorrelationResult
    ) -> None:
        detection_service = DetectionQueryService()
        ti = ThreatIntelRepository(self.db)
        members = sorted(record.members, key=lambda m: (m.member_order, str(m.id)))
        detection_events: dict[str, CorrelationRecordEvent] = {}

        for member in members:
            detection_id = _coerce_uuid(member.detection_id)
            detection_node_id = f"detection:{detection_id}"
            member_ref = str(member.id)

            if (
                detection_node_id not in self.nodes
                and len(self._nodes_of_type(AttackPathNodeType.DETECTION))
                >= MAX_CORRELATION_DETECTIONS
            ):
                self._record_truncation(
                    AttackPathNodeType.DETECTION,
                    f"more than {MAX_CORRELATION_DETECTIONS} distinct detections",
                )
                continue

            resolved = self._guard(
                "member detection",
                lambda: detection_service.get_result(self.db, detection_id),
            )
            if resolved is None:
                continue

            first_seen = detection_node_id not in self.nodes
            if first_seen:
                node = AttackPathNode(
                    node_id=detection_node_id,
                    node_type=AttackPathNodeType.DETECTION,
                    label=_safe_label(
                        resolved.rule_id, f"Detection {detection_id}"
                    ),
                    provenance=Provenance.DETECTED,
                    source_reference=str(resolved.detection_id),
                    occurrence=resolved.detected_at,
                    status=None,
                    severity=(
                        resolved.severity.value
                        if resolved.severity is not None
                        else None
                    ),
                    fields={
                        "rule_id": _safe_text(resolved.rule_id) or "",
                        "rule_type": _safe_text(
                            resolved.rule_type.value
                            if resolved.rule_type is not None
                            else None
                        )
                        or "",
                        "rule_version": _safe_text(resolved.rule_version) or "",
                        "severity": (
                            resolved.severity.value
                            if resolved.severity is not None
                            else ""
                        ),
                        "confidence": (
                            _fmt_float(resolved.confidence)
                            if resolved.confidence is not None
                            else ""
                        ),
                        "event_id": _safe_text(resolved.event_id) or "",
                    },
                    evidence_references=[member_ref],
                )
                self._add_node(node)
                self.resolved_detection_count += 1
                detection_events[detection_node_id] = CorrelationRecordEvent(
                    detection_id=detection_id,
                    event_id=resolved.event_id,
                )
            else:
                self.nodes[detection_node_id].evidence_references.append(member_ref)

            self._add_edge(
                AttackPathEdge(
                    edge_id=f"{AttackPathEdgeType.CORRELATION_HAS_DETECTION.value}:{member_ref}",
                    source_node_id=f"correlation:{record.correlation_id}",
                    target_node_id=detection_node_id,
                    relationship_type=AttackPathEdgeType.CORRELATION_HAS_DETECTION,
                    provenance=Provenance.CORRELATED,
                    source_reference=member_ref,
                    evidence_references=[member_ref],
                )
            )

        # Indicators: one edge per persisted lookup row (event <=> indicator).
        for event in detection_events.values():
            if event.event_id is None:
                continue
            lookups = self._guard(
                "threat indicator lookups",
                lambda: ti.get_lookups_for_event(
                    event.event_id,
                    limit=MAX_LOOKUPS_PER_DETECTION + 1,
                ),
            )
            if len(lookups) > MAX_LOOKUPS_PER_DETECTION:
                self._record_truncation(
                    AttackPathNodeType.INDICATOR,
                    f"more than {MAX_LOOKUPS_PER_DETECTION} lookups for a single "
                    f"event (event {event.event_id})",
                )
                lookups = lookups[:MAX_LOOKUPS_PER_DETECTION]
            for lookup in lookups:
                self._add_indicator_edge(event, lookup)

    def _add_indicator_edge(self, event, lookup: Any) -> None:
        indicator = getattr(lookup, "indicator", None)
        if indicator is None:
            return
        indicator_node_id = f"indicator:{indicator.id}"
        lookup_ref = str(lookup.id)
        is_new = indicator_node_id not in self.nodes
        if (
            is_new
            and len(self._nodes_of_type(AttackPathNodeType.INDICATOR))
            >= MAX_CORRELATION_INDICATORS
        ):
            self._record_truncation(
                AttackPathNodeType.INDICATOR,
                f"more than {MAX_CORRELATION_INDICATORS} distinct indicators",
            )
            return
        if is_new:
            node = AttackPathNode(
                node_id=indicator_node_id,
                node_type=AttackPathNodeType.INDICATOR,
                label=_safe_label(indicator.value, f"Indicator {indicator.id}"),
                provenance=Provenance.ENRICHED,
                source_reference=str(indicator.id),
                occurrence=indicator.first_seen_at,
                status=None,
                severity=None,
                fields={
                    "indicator_type": _safe_text(
                        (
                            indicator.indicator_type.value
                            if getattr(indicator.indicator_type, "value", None)
                            else indicator.indicator_type
                        )
                    )
                    or "",
                    "value": _safe_text(indicator.value) or "",
                },
                evidence_references=[lookup_ref],
            )
            self._add_node(node)
            self.built_indicator_count += 1
        else:
            self.nodes[indicator_node_id].evidence_references.append(lookup_ref)

        detection_node_id = f"detection:{event.detection_id}"
        if detection_node_id not in self.nodes:
            return
        self._add_edge(
            AttackPathEdge(
                edge_id=(
                    f"{AttackPathEdgeType.DETECTION_HAS_INDICATOR.value}:{lookup_ref}"
                ),
                source_node_id=detection_node_id,
                target_node_id=indicator_node_id,
                relationship_type=AttackPathEdgeType.DETECTION_HAS_INDICATOR,
                provenance=Provenance.ENRICHED,
                source_reference=lookup_ref,
                evidence_references=[lookup_ref],
            )
        )

    def _build_risk(self, correlation_id: uuid.UUID) -> None:
        page = self._guard(
            "risk assessments",
            lambda: RiskQueryService().list_assessments_for_correlation(
                self.db,
                correlation_id,
                page=1,
                page_size=MAX_CORRELATION_RISK_ASSESSMENTS,
            ),
        )
        if page.total > MAX_CORRELATION_RISK_ASSESSMENTS:
            self._record_truncation(
                AttackPathNodeType.RISK,
                f"more than {MAX_CORRELATION_RISK_ASSESSMENTS} risk assessments "
                f"(found {page.total})",
            )
        for assessment in page.items:
            assessment_id = str(assessment.risk_assessment_id)
            node = AttackPathNode(
                node_id=f"risk:{assessment_id}",
                node_type=AttackPathNodeType.RISK,
                label=f"Risk assessment {assessment.level or assessment_id[:8]}",
                provenance=Provenance.RISK_ASSESSED,
                source_reference=assessment_id,
                occurrence=assessment.timestamp,
                status=None,
                severity=_enum_value(assessment.level),
                fields={
                    "score": _fmt_float(assessment.score) or "",
                    "level": _enum_value(assessment.level) or "",
                    "confidence": _fmt_float(assessment.confidence) or "",
                },
                evidence_references=[assessment_id],
            )
            self._add_node(node)
            self.built_risk = True
            self._add_edge(
                AttackPathEdge(
                    edge_id=(
                        f"{AttackPathEdgeType.CORRELATION_HAS_RISK.value}:"
                        f"{assessment_id}"
                    ),
                    source_node_id=f"correlation:{correlation_id}",
                    target_node_id=f"risk:{assessment_id}",
                    relationship_type=AttackPathEdgeType.CORRELATION_HAS_RISK,
                    provenance=Provenance.RISK_ASSESSED,
                    source_reference=assessment_id,
                    evidence_references=[assessment_id],
                )
            )

    def _build_memories(self, correlation_id: uuid.UUID) -> None:
        page = self._guard(
            "incident memories",
            lambda: IncidentMemoryQueryService().list_memories_for_correlation(
                self.db,
                correlation_id,
                page=1,
                page_size=MAX_CORRELATION_MEMORIES,
            ),
        )
        if page.total > MAX_CORRELATION_MEMORIES:
            self._record_truncation(
                AttackPathNodeType.MEMORY,
                f"more than {MAX_CORRELATION_MEMORIES} citing memories "
                f"(found {page.total})",
            )
        for memory in page.items:
            if len(self._nodes_of_type(AttackPathNodeType.MEMORY)) >= (
                MAX_CORRELATION_MEMORIES
            ):
                break
            memory_id = str(memory.memory_id)
            node = AttackPathNode(
                node_id=f"memory:{memory_id}",
                node_type=AttackPathNodeType.MEMORY,
                label=_safe_label(memory.title, f"Incident memory {memory_id[:8]}"),
                provenance=Provenance.RECALLED,
                source_reference=memory_id,
                occurrence=memory.created_at,
                status=None,
                severity=None,
                fields={
                    "memory_type": _safe_text(memory.memory_type) or "",
                    "title": _safe_text(memory.title) or "",
                    "confidence": _fmt_float(memory.confidence) or "",
                },
                evidence_references=[memory_id],
            )
            self._add_node(node)
            self.built_memory = True
            self._add_edge(
                AttackPathEdge(
                    edge_id=(
                        f"{AttackPathEdgeType.CORRELATION_HAS_MEMORY.value}:"
                        f"{memory_id}"
                    ),
                    source_node_id=f"correlation:{correlation_id}",
                    target_node_id=f"memory:{memory_id}",
                    relationship_type=AttackPathEdgeType.CORRELATION_HAS_MEMORY,
                    provenance=Provenance.RECALLED,
                    source_reference=memory_id,
                    evidence_references=[memory_id],
                )
            )

    def _build_hunts(self, correlation_id: uuid.UUID) -> None:
        pairs = self._guard(
            "threat hunts",
            lambda: list_hunts_with_evidence_for_correlation(
                self.db,
                correlation_id,
                limit=MAX_CORRELATION_HUNTS + 1,
            ),
        )
        if len(pairs) > MAX_CORRELATION_HUNTS:
            self._record_truncation(
                AttackPathNodeType.HUNT,
                f"more than {MAX_CORRELATION_HUNTS} hunts citing the correlation",
            )
            pairs = pairs[:MAX_CORRELATION_HUNTS]
        for hunt, evidence_rows in pairs:
            hunt_id = str(hunt.hunt_id)
            node = AttackPathNode(
                node_id=f"hunt:{hunt_id}",
                node_type=AttackPathNodeType.HUNT,
                label=_safe_label(hunt.name, f"Hunt {hunt_id[:8]}"),
                provenance=Provenance.OBSERVED,
                source_reference=hunt_id,
                occurrence=hunt.start_time,
                status=_safe_text(hunt.status),
                severity=None,
                fields={
                    "hunt_type": _safe_text(hunt.hunt_type) or "",
                    "status": _safe_text(hunt.status) or "",
                    "result_count": str(hunt.result_count),
                    "finding_count": str(hunt.finding_count),
                    "timeline_count": str(hunt.timeline_count),
                },
                evidence_references=[str(e.evidence_id) for e in evidence_rows],
            )
            self._add_node(node)
            self.built_hunt = True
            self._add_edge(
                AttackPathEdge(
                    edge_id=(
                        f"{AttackPathEdgeType.CORRELATION_HAS_HUNT.value}:{hunt_id}"
                    ),
                    source_node_id=f"correlation:{correlation_id}",
                    target_node_id=f"hunt:{hunt_id}",
                    relationship_type=AttackPathEdgeType.CORRELATION_HAS_HUNT,
                    provenance=Provenance.OBSERVED,
                    source_reference=hunt_id,
                    evidence_references=[str(e.evidence_id) for e in evidence_rows],
                )
            )

    def _build_approvals(self, correlation_id: uuid.UUID) -> None:
        rows = self._guard(
            "approval requests",
            lambda: ApprovalRepository(self.db).list_for_correlation(
                correlation_id,
                limit=MAX_CORRELATION_APPROVALS + 1,
            ),
        )
        if len(rows) > MAX_CORRELATION_APPROVALS:
            self._record_truncation(
                AttackPathNodeType.APPROVAL,
                f"more than {MAX_CORRELATION_APPROVALS} approval requests",
            )
            rows = rows[:MAX_CORRELATION_APPROVALS]
        for row in rows:
            row_ref = str(row.id)
            approval_id = str(row.approval_id)
            policy_id = str(row.policy_decision_id)

            policy_node_id = f"policy_decision:{policy_id}"
            if policy_node_id not in self.nodes:
                decision_status = _decision_scalar(row.decision, "status")
                policy_name = _decision_scalar(row.decision, "rule_id") or _safe_text(
                    row.policy_rule_id
                )
                self._add_node(
                    AttackPathNode(
                        node_id=policy_node_id,
                        node_type=AttackPathNodeType.POLICY_DECISION,
                        label=_safe_label(
                            policy_name, f"Policy decision {policy_id[:8]}"
                        ),
                        provenance=Provenance.POLICY_DECIDED,
                        source_reference=row_ref,
                        occurrence=row.requested_at,
                        status=decision_status,
                        severity=None,
                        fields=_approval_governance_fields(row),
                        evidence_references=[row_ref, approval_id],
                    )
                )
                self.built_policy = True
            else:
                existing = self.nodes[policy_node_id]
                existing.evidence_references.append(row_ref)
                if approval_id not in existing.evidence_references:
                    existing.evidence_references.append(approval_id)

            approval_node_id = f"approval:{approval_id}"
            if approval_node_id not in self.nodes:
                self._add_node(
                    AttackPathNode(
                        node_id=approval_node_id,
                        node_type=AttackPathNodeType.APPROVAL,
                        label=_safe_label(
                            f"{row.action_type} {row.target}",
                            f"Approval {approval_id[:8]}",
                        ),
                        provenance=Provenance.APPROVAL_REVIEWED,
                        source_reference=row_ref,
                        occurrence=row.requested_at,
                        status=_safe_text(row.status),
                        severity=None,
                        fields=_approval_review_fields(row),
                        evidence_references=[row_ref, approval_id],
                    )
                )
                self.built_approval = True

            correlation_node_id = f"correlation:{correlation_id}"
            self._add_edge(
                AttackPathEdge(
                    edge_id=(
                        f"{AttackPathEdgeType.CORRELATION_HAS_POLICY_DECISION.value}:"
                        f"{row_ref}"
                    ),
                    source_node_id=correlation_node_id,
                    target_node_id=policy_node_id,
                    relationship_type=AttackPathEdgeType.CORRELATION_HAS_POLICY_DECISION,
                    provenance=Provenance.POLICY_DECIDED,
                    source_reference=row_ref,
                    evidence_references=[row_ref, approval_id],
                )
            )
            self._add_edge(
                AttackPathEdge(
                    edge_id=(
                        f"{AttackPathEdgeType.POLICY_HAS_APPROVAL.value}:{row_ref}"
                    ),
                    source_node_id=policy_node_id,
                    target_node_id=approval_node_id,
                    relationship_type=AttackPathEdgeType.POLICY_HAS_APPROVAL,
                    provenance=Provenance.POLICY_DECIDED,
                    source_reference=row_ref,
                    evidence_references=[row_ref, approval_id],
                )
            )
            self._add_edge(
                AttackPathEdge(
                    edge_id=(
                        f"{AttackPathEdgeType.CORRELATION_HAS_APPROVAL.value}:{row_ref}"
                    ),
                    source_node_id=correlation_node_id,
                    target_node_id=approval_node_id,
                    relationship_type=AttackPathEdgeType.CORRELATION_HAS_APPROVAL,
                    provenance=Provenance.APPROVAL_REVIEWED,
                    source_reference=row_ref,
                    evidence_references=[row_ref, approval_id],
                )
            )

    def _build_soar(self, correlation_id: uuid.UUID) -> None:
        rows = self._guard(
            "soar executions",
            lambda: SoarRepository(self.db).list_for_correlation(
                correlation_id,
                limit=MAX_CORRELATION_SOAR_EXECUTIONS + 1,
            ),
        )
        if len(rows) > MAX_CORRELATION_SOAR_EXECUTIONS:
            self._record_truncation(
                AttackPathNodeType.SOAR_EXECUTION,
                f"more than {MAX_CORRELATION_SOAR_EXECUTIONS} soar executions",
            )
            rows = rows[:MAX_CORRELATION_SOAR_EXECUTIONS]
        for row in rows:
            row_ref = str(row.id)
            execution_id = str(row.execution_id)
            soar_node_id = f"soar_execution:{execution_id}"
            if soar_node_id not in self.nodes:
                self._add_node(
                    AttackPathNode(
                        node_id=soar_node_id,
                        node_type=AttackPathNodeType.SOAR_EXECUTION,
                        label=_safe_label(
                            row.playbook_id, f"SOAR execution {execution_id[:8]}"
                        ),
                        provenance=Provenance.OBSERVED,
                        source_reference=execution_id,
                        occurrence=row.started_at,
                        status=_safe_text(row.status),
                        severity=None,
                        fields=_soar_fields(row),
                        evidence_references=[row_ref, execution_id],
                    )
                )
                self.built_soar = True

            correlation_node_id = f"correlation:{correlation_id}"
            self._add_edge(
                AttackPathEdge(
                    edge_id=(
                        f"{AttackPathEdgeType.CORRELATION_HAS_SOAR_EXECUTION.value}:"
                        f"{row_ref}"
                    ),
                    source_node_id=correlation_node_id,
                    target_node_id=soar_node_id,
                    relationship_type=AttackPathEdgeType.CORRELATION_HAS_SOAR_EXECUTION,
                    provenance=Provenance.OBSERVED,
                    source_reference=execution_id,
                    evidence_references=[row_ref, execution_id],
                )
            )

            if row.policy_decision_id is not None:
                policy_node_id = f"policy_decision:{row.policy_decision_id}"
                if policy_node_id not in self.nodes:
                    self._add_node(
                        AttackPathNode(
                            node_id=policy_node_id,
                            node_type=AttackPathNodeType.POLICY_DECISION,
                            label=f"Policy decision {row.policy_decision_id}",
                            provenance=Provenance.POLICY_DECIDED,
                            source_reference=execution_id,
                            occurrence=row.started_at,
                            status=None,
                            severity=None,
                            fields={
                                "policy_decision_id": str(row.policy_decision_id),
                                "detail": (
                                    "decision record not loaded; identity "
                                    "referenced by this soar execution only"
                                ),
                            },
                            evidence_references=[row_ref, execution_id],
                        )
                    )
                    self.built_policy = True
                self._add_edge(
                    AttackPathEdge(
                        edge_id=(
                            f"{AttackPathEdgeType.POLICY_HAS_SOAR_EXECUTION.value}:"
                            f"{row_ref}"
                        ),
                        source_node_id=policy_node_id,
                        target_node_id=soar_node_id,
                        relationship_type=AttackPathEdgeType.POLICY_HAS_SOAR_EXECUTION,
                        provenance=Provenance.OBSERVED,
                        source_reference=execution_id,
                        evidence_references=[row_ref, execution_id],
                    )
                )

            if row.approval_id is not None:
                approval_node_id = f"approval:{row.approval_id}"
                if approval_node_id in self.nodes:
                    self._add_edge(
                        AttackPathEdge(
                            edge_id=(
                                f"{AttackPathEdgeType.APPROVAL_HAS_SOAR_EXECUTION.value}:"
                                f"{row_ref}"
                            ),
                            source_node_id=approval_node_id,
                            target_node_id=soar_node_id,
                            relationship_type=AttackPathEdgeType.APPROVAL_HAS_SOAR_EXECUTION,
                            provenance=Provenance.OBSERVED,
                            source_reference=execution_id,
                            evidence_references=[row_ref, execution_id],
                        )
                    )

    # ------------------------------------------------------------------
    # Availability + bounds
    # ------------------------------------------------------------------

    def _availability(self) -> dict[str, InputAvailability]:
        has = self._nodes_of_type
        detections = has(AttackPathNodeType.DETECTION)
        detections_availability: InputAvailability
        if detections:
            detections_availability = InputAvailability.PROVIDED
        elif self.member_count:
            detections_availability = InputAvailability.NONE_FOUND
        else:
            detections_availability = InputAvailability.NOT_PROVIDED
        return {
            "correlation": InputAvailability.PROVIDED,
            "detections": detections_availability,
            "indicators": (
                InputAvailability.PROVIDED
                if has(AttackPathNodeType.INDICATOR)
                else InputAvailability.NONE_FOUND
            ),
            "risk_assessment": (
                InputAvailability.PROVIDED
                if self.built_risk
                else InputAvailability.NOT_PROVIDED
            ),
            "incident_memory": (
                InputAvailability.PROVIDED
                if has(AttackPathNodeType.MEMORY)
                else InputAvailability.NONE_FOUND
            ),
            "threat_hunts": (
                InputAvailability.PROVIDED
                if has(AttackPathNodeType.HUNT)
                else InputAvailability.NONE_FOUND
            ),
            "policy_decisions": (
                InputAvailability.PROVIDED
                if has(AttackPathNodeType.POLICY_DECISION)
                else InputAvailability.NONE_FOUND
            ),
            "approvals": (
                InputAvailability.PROVIDED
                if has(AttackPathNodeType.APPROVAL)
                else InputAvailability.NONE_FOUND
            ),
            "soar_executions": (
                InputAvailability.PROVIDED
                if has(AttackPathNodeType.SOAR_EXECUTION)
                else InputAvailability.NONE_FOUND
            ),
            "investigation": InputAvailability.NOT_PROVIDED,
            "attribution": InputAvailability.NOT_PROVIDED,
            "security_events": InputAvailability.NOT_PROVIDED,
        }

    def _trim_to_bounds(self) -> None:
        if (
            len(self.nodes) <= MAX_ATTACK_PATH_NODES
            and len(self.edges) <= MAX_ATTACK_PATH_EDGES
        ):
            return
        nodes_sorted = sorted(
            self.nodes.values(),
            key=lambda n: (-surface_priority(n.node_type), n.node_id),
        )
        dropped = nodes_sorted[MAX_ATTACK_PATH_NODES:]
        if dropped:
            dropped_surfaces: list[str] = []
            seen: set[str] = set()
            for node in dropped:
                surface = SURFACE_LABEL[node.node_type]
                if surface not in seen:
                    seen.add(surface)
                    dropped_surfaces.append(surface)
                self.nodes.pop(node.node_id, None)
            self.truncation_parts.append(
                f"global max_nodes {MAX_ATTACK_PATH_NODES} reached; trimmed "
                f"{len(dropped)} node(s) from: {', '.join(dropped_surfaces)}"
            )
        self.edges = {
            edge_id: edge
            for edge_id, edge in self.edges.items()
            if edge.source_node_id in self.nodes
            and edge.target_node_id in self.nodes
        }
        if len(self.edges) > MAX_ATTACK_PATH_EDGES:
            edge_keep = sorted(self.edges.values(), key=lambda e: e.edge_id)[
                :MAX_ATTACK_PATH_EDGES
            ]
            kept_ids = {e.edge_id for e in edge_keep}
            self.edges = {
                edge_id: edge
                for edge_id, edge in self.edges.items()
                if edge_id in kept_ids
            }
            self.truncation_parts.append(
                f"global max_edges {MAX_ATTACK_PATH_EDGES} reached; "
                "saturated edge projection trimmed deterministically"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add_node(self, node: AttackPathNode) -> None:
        existing = self.nodes.get(node.node_id)
        if existing is not None and existing != node:
            raise AttackPathSourceError(
                f"conflicting node assembly for {node.node_id}"
            )
        self.nodes[node.node_id] = node

    def _add_edge(self, edge: AttackPathEdge) -> None:
        existing = self.edges.get(edge.edge_id)
        if existing is not None and existing != edge:
            raise AttackPathSourceError(f"conflicting edge assembly for {edge.edge_id}")
        self.edges[edge.edge_id] = edge

    def _nodes_of_type(self, node_type: AttackPathNodeType) -> list[AttackPathNode]:
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def _record_truncation(self, node_type: AttackPathNodeType, detail: str) -> None:
        part = f"{SURFACE_LABEL[node_type]}: {detail}"
        if part not in self.truncation_parts:
            self.truncation_parts.append(part)


@dataclass(frozen=True)
class CorrelationRecordEvent:
    """Resolved detection identity pair used for indicator lookups."""

    detection_id: uuid.UUID
    event_id: uuid.UUID | None


def _coerce_uuid(value: uuid.UUID | str) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(value)


def _raise_missing(correlation_id: uuid.UUID) -> CorrelationResult:
    raise AttackPathCorrelationNotFoundError(
        f"correlation {correlation_id} does not exist"
    )


def _decision_scalar(decision: Any, key: str) -> str | None:
    if not isinstance(decision, dict):
        return None
    return _safe_text(decision.get(key))


def _approval_governance_fields(row: Any) -> dict[str, str]:
    fields: dict[str, str] = {}
    mapping = {
        "policy_rule_id": row.policy_rule_id,
        "action_type": row.action_type,
        "target": row.target,
        "risk_level": row.risk_level,
        "risk_score": _fmt_float(row.risk_score),
        "confidence": _fmt_float(row.confidence),
    }
    for key, value in mapping.items():
        text = _safe_text(value)
        if text:
            fields[key] = text
    if isinstance(row.decision, dict):
        for key in _DECISION_ALLOWLIST:
            text = _decision_scalar(row.decision, key)
            if text:
                fields[f"decision_{key}"] = text
    return fields


def _approval_review_fields(row: Any) -> dict[str, str]:
    fields: dict[str, str] = {}
    mapping = {
        "action_type": row.action_type,
        "target": row.target,
        "status": row.status,
        "risk_level": row.risk_level,
        "confidence": _fmt_float(row.confidence),
    }
    for key, value in mapping.items():
        text = _safe_text(value)
        if text:
            fields[key] = text
    for key in ("response_status", "response_provider", "response_error_code"):
        text = _safe_text(getattr(row, key, None))
        if text:
            fields[key] = text
    return fields


def _soar_fields(row: Any) -> dict[str, str]:
    fields: dict[str, str] = {}
    mapping = {
        "playbook_id": row.playbook_id,
        "playbook_version": row.playbook_version,
        "primary_action": row.primary_action,
        "target": row.target,
        "status": row.status,
        "failure_policy": row.failure_policy,
        "response_id": row.response_id,
        "error_code": row.error_code,
    }
    for key, value in mapping.items():
        if key == "response_id" and value is not None:
            fields["response_id"] = str(value)
            continue
        text = _safe_text(value)
        if text:
            fields[key] = text
    fields["simulated"] = _fmt_bool(row.simulated)
    return fields


__all__ = [
    "AttackPathBuildResult",
    "AttackPathGraphBuilder",
]