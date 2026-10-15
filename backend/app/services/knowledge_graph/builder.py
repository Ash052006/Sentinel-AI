"""Deterministic, idempotent knowledge-graph builder — V3.22.

Reads existing persisted V2 state and materializes the graph as nodes and
edges.  Every node and edge is produced from a real V2 row and a real V2
column; nothing is inferred.

Guarantees:

* **Deterministic** — rows are read in sorted order, node/edge ids are
  ``uuid5`` of their natural key, and metadata is ordered, so rebuilding
  identical V2 state yields an identical graph.
* **Idempotent** — nodes upsert on UNIQUE ``(node_type, source_id)`` and edges
  on UNIQUE ``(source_node_id, target_node_id, relationship_type)``.  Running
  the builder twice cannot create a duplicate.
* **Provenance-safe** — every edge cites the exact V2 row that justifies it.
* **Secret-safe** — only allowlisted scalar columns are read; JSONB payloads
  are never touched.
* **LLM-free** — pure SQL. No Gemini, no RAG, no network. The builder works
  with every external dependency unavailable.
* **Bounded** — a full build is capped at ``max_correlations`` and reports
  whether it truncated.

No V2 table is modified.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from sqlalchemy import delete, func, select, tuple_
from sqlalchemy.orm import Session

from app.models.approval_request import ApprovalRequestRow
from app.models.correlation_member import CorrelationMember
from app.models.correlation_result import CorrelationResult
from app.models.detection_result import DetectionResult
from app.models.incident_memory import IncidentMemoryRow
from app.models.incident_report import IncidentReportRow
from app.models.knowledge_graph import KnowledgeGraphEdge, KnowledgeGraphNode
from app.models.risk_assessment import RiskAssessment
from app.models.soar_execution import SoarExecutionRow
from app.models.threat_hunt import ThreatHuntEvidenceRow, ThreatHuntRow
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import ThreatIntelLookup
from app.services.knowledge_graph.vocabulary import (
    DEFAULT_BOUNDS,
    NodeType,
    RelationshipType,
    TruncationReason,
    VocabularyError,
    build_edge,
    build_node,
)

logger = logging.getLogger(__name__)

#: Hard cap on how many correlations one full build may materialize.
DEFAULT_MAX_CORRELATIONS = 500


@dataclass
class BuildResult:
    """Outcome of one builder run."""

    scope: str
    correlation_ids: list[str] = field(default_factory=list)
    nodes_created: int = 0
    nodes_updated: int = 0
    nodes_pruned: int = 0
    edges_created: int = 0
    edges_updated: int = 0
    edges_pruned: int = 0
    truncated: bool = False
    truncated_reason: str | None = None
    #: Set when pruning was deliberately skipped because the build did not
    #: cover the whole scope.  Never silent: an operator must be able to see
    #: that the graph was not reconciled against all of V2.
    prune_skipped: bool = False
    prune_skipped_reason: str | None = None

    @property
    def node_count(self) -> int:
        return self.nodes_created + self.nodes_updated

    @property
    def edge_count(self) -> int:
        # Total edges derived, not merely newly created, so a rebuild reports
        # the same edge_count as the first run.
        return self.edges_created + self.edges_updated

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": "PASS",
            "scope": self.scope,
            "correlation_count": len(self.correlation_ids),
            "correlation_ids": self.correlation_ids[:25],
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes_created": self.nodes_created,
            "nodes_updated": self.nodes_updated,
            "nodes_pruned": self.nodes_pruned,
            "edges_created": self.edges_created,
            "edges_updated": self.edges_updated,
            "edges_pruned": self.edges_pruned,
            "truncated": self.truncated,
            "truncated_reason": self.truncated_reason,
            "prune_skipped": self.prune_skipped,
            "prune_skipped_reason": self.prune_skipped_reason,
            "note": (
                "Every node and edge maps to persisted V2 state. No LLM, RAG, "
                "or inference was used to create any relationship."
            ),
        }


class KnowledgeGraphBuilder:
    """Builds the V3.22 graph from persisted V2 evidence."""

    def __init__(
        self,
        *,
        max_correlations: int = DEFAULT_MAX_CORRELATIONS,
        prune: bool = True,
    ) -> None:
        self._max_correlations = max_correlations
        self._prune = prune

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def build_for_correlation(
        self, db: Session, correlation_id: uuid.UUID | str
    ) -> BuildResult:
        """Materialize the subgraph for one correlation.

        Upsert-only (``prune=False`` semantics are *not* applied): event and
        indicator nodes are shared between correlations, so a correlation-scoped
        run must never delete a node another correlation also references.
        """
        resolved = _as_uuid(correlation_id)
        if resolved is None:
            raise ValueError(f"invalid correlation id: {correlation_id!r}")

        nodes, edges = self._derive_with_db(db, [resolved])
        result = BuildResult(scope="correlation", correlation_ids=[str(resolved)])
        self._persist(db, nodes, edges, result)
        return result

    def build_all(self, db: Session) -> BuildResult:
        """Materialize the whole graph and prune anything no longer derivable.

        A full build is what guarantees graph state converges on V2 state: a
        node or edge whose V2 row has disappeared is deleted rather than left
        behind as a structural orphan.
        """
        correlation_ids, truncated = self._correlation_ids(db)
        nodes, edges = self._derive_with_db(db, correlation_ids)
        result = BuildResult(
            scope="all",
            correlation_ids=[str(c) for c in correlation_ids],
            truncated=truncated,
            truncated_reason=TruncationReason.MAX_NODES.value if truncated else None,
        )
        self._persist(db, nodes, edges, result)
        if self._prune:
            if truncated:
                # Pruning reconciles the graph against V2 by deleting whatever
                # could not be re-derived.  That is only sound when the build
                # actually read the whole scope: a build bounded by
                # ``max_correlations`` never looked at the correlations it
                # skipped, so deleting their rows would destroy valid state
                # that simply was not examined.  Skip it and say so.
                result.prune_skipped = True
                result.prune_skipped_reason = (
                    "build was truncated at max_correlations; unscanned "
                    "correlations were left untouched"
                )
            else:
                self._prune_stale(db, nodes, edges, result)
        return result

    # ------------------------------------------------------------------
    # Scope selection
    # ------------------------------------------------------------------

    def _correlation_ids(self, db: Session) -> tuple[list[uuid.UUID], bool]:
        rows = db.execute(
            select(CorrelationResult.correlation_id)
            .order_by(CorrelationResult.correlation_id)
            .limit(self._max_correlations + 1)
        ).scalars().all()
        truncated = len(rows) > self._max_correlations
        return list(rows[: self._max_correlations]), truncated

    # ------------------------------------------------------------------
    # Derivation — pure reads, no writes
    # ------------------------------------------------------------------

    def _derive_with_db(
        self, db: Session, correlation_ids: Sequence[uuid.UUID]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        nodes: dict[tuple[str, str], dict[str, Any]] = {}
        # Keyed by deterministic edge id so two V2 rows describing the same
        # relationship collapse into one edge.  V2 tables are not all unique
        # on the pair a relationship implies -- ``correlation_members`` is
        # unique on (correlation_id, member_order) but not on
        # (correlation_id, detection_id), and several enrichment tables can
        # report the same indicator for the same event -- so a list would emit
        # the same primary key twice and fail the insert.
        edges: dict[uuid.UUID, dict[str, Any]] = {}

        def add_node(node: dict[str, Any]) -> dict[str, Any]:
            nodes[(node["node_type"].value, node["source_id"])] = node
            return node

        def add_edge(edge: dict[str, Any]) -> None:
            key = edge["id"]
            previous = edges.get(key)
            if previous is None:
                edges[key] = edge
                return
            # Merge deterministically: the lexicographically smallest
            # citation becomes ``source_reference``, and every backing row
            # stays visible in ``evidence_references`` so collapsing the
            # relationship never discards evidence.
            previous["source_reference"] = min(
                previous["source_reference"], edge["source_reference"]
            )
            previous["evidence_references"] = sorted(
                set(previous["evidence_references"])
                | set(edge["evidence_references"])
            )

        if not correlation_ids:
            return [], []

        # --- CORRELATION -------------------------------------------------
        correlation_rows = db.execute(
            select(CorrelationResult).where(
                CorrelationResult.correlation_id.in_(correlation_ids)
            ).order_by(CorrelationResult.correlation_id)
        ).scalars().all()

        for row in correlation_rows:
            cid = str(row.correlation_id)
            add_node(build_node(
                NodeType.CORRELATION,
                cid,
                label=f"correlation {cid[:8]} ({row.status})",
                metadata={
                    "status": row.status,
                    "confidence": row.confidence,
                    "provenance": row.provenance,
                    "timestamp": row.timestamp,
                },
            ))

        resolved_correlations = {str(r.correlation_id) for r in correlation_rows}
        correlation_ids = [
            c for c in correlation_ids if str(c) in resolved_correlations
        ]
        if not correlation_ids:
            return [], []

        # --- correlation MEMBERS (the one authoritative membership row) ----
        member_rows = db.execute(
            select(CorrelationMember)
            .where(CorrelationMember.correlation_id.in_(correlation_ids))
            .order_by(
                CorrelationMember.correlation_id,
                CorrelationMember.member_order,
                CorrelationMember.detection_id,
            )
        ).scalars().all()

        detection_ids = sorted({m.detection_id for m in member_rows})
        member_event_ids = sorted({m.event_id for m in member_rows if m.event_id})

        # --- DETECTION ---------------------------------------------------
        detection_rows = db.execute(
            select(DetectionResult)
            .where(DetectionResult.detection_id.in_(detection_ids))
            .order_by(DetectionResult.detection_id)
        ).scalars().all() if detection_ids else []

        detection_nodes: dict[uuid.UUID, dict[str, Any]] = {}
        for row in detection_rows:
            did = str(row.detection_id)
            node = add_node(build_node(
                NodeType.DETECTION,
                did,
                label=f"{row.rule_id} [{row.severity}]",
                metadata={
                    "rule_id": row.rule_id,
                    "rule_type": row.rule_type,
                    "rule_version": row.rule_version,
                    "severity": row.severity,
                    "matched": row.matched,
                    "confidence": row.confidence,
                    "detected_at": row.detected_at,
                    "provenance": row.provenance,
                },
            ))
            detection_nodes[row.detection_id] = node

        # --- EVENT -------------------------------------------------------
        # One node per distinct persisted event identifier. Seven detections
        # sharing an event yield exactly one EVENT node.
        event_ids = set(member_event_ids)
        event_ids.update(str(r.event_id) for r in detection_rows if r.event_id)
        # Normalize to a deterministic string sort: correlation_members.event_id
        # and detection_results.event_id can differ in static type.
        event_ids = sorted(str(value) for value in event_ids)

        event_nodes = self._derive_events(db, event_ids, detection_rows, add_node)

        # --- edges: produced_detection -----------------------------------
        # Source of truth is detection_results.event_id.
        for row in sorted(detection_rows, key=lambda r: str(r.detection_id)):
            if not row.event_id:
                continue
            source = event_nodes.get(row.event_id)
            target = detection_nodes.get(row.detection_id)
            if source is None or target is None:
                continue
            add_edge(build_edge(
                RelationshipType.PRODUCED_DETECTION,
                source,
                target,
                source_reference_value=f"detection_result:{row.detection_id}",
                evidence_references=[
                    source["source_reference"],
                    target["source_reference"],
                    f"detection_result:{row.detection_id}",
                ],
            ))

        # --- edges: member_of_correlation ---------------------------------
        for member in member_rows:
            detection_node = detection_nodes.get(member.detection_id)
            if detection_node is None:
                # Membership row with no resolvable detection row: no edge is
                # created, because the relationship cannot be demonstrated.
                continue
            correlation_node = nodes.get(
                (NodeType.CORRELATION.value, str(member.correlation_id))
            )
            if correlation_node is None:
                continue
            add_edge(build_edge(
                RelationshipType.MEMBER_OF_CORRELATION,
                detection_node,
                correlation_node,
                source_reference_value=f"correlation_member:{member.id}",
                evidence_references=[
                    detection_node["source_reference"],
                    correlation_node["source_reference"],
                    f"correlation_member:{member.id}",
                ],
            ))

        self._derive_risk_assessments(db, correlation_ids, nodes, add_node, add_edge)
        self._derive_indicators(db, event_ids, nodes, add_node, add_edge)
        self._derive_memories(db, correlation_ids, nodes, add_node, add_edge)
        self._derive_approvals_and_executions(
            db, correlation_ids, nodes, add_node, add_edge
        )
        self._derive_reports(db, correlation_ids, nodes, add_node, add_edge)
        self._derive_hunts(db, correlation_ids, nodes, add_node, add_edge)

        # Deterministic edge ordering.
        ordered_edges = sorted(edges.values(), key=lambda e: str(e["id"]))
        return list(nodes.values()), ordered_edges

    # ------------------------------------------------------------------
    # Per-entity-type derivation
    # ------------------------------------------------------------------

    def _derive_events(
        self,
        db: Session,
        event_ids: Sequence[str],
        detection_rows: Sequence[DetectionResult],
        add_node,
    ) -> dict[uuid.UUID, dict[str, Any]]:
        """Create one EVENT node per distinct persisted event identifier.

        ``observed_at`` is the earliest detection time referencing the event,
        computed in Python from already-loaded rows so it stays deterministic
        and adds no query.  Returns nodes keyed by their UUID so detection
        lookups resolve regardless of UUID/string static type.
        """
        first_seen: dict[uuid.UUID, datetime] = {}
        for row in detection_rows:
            if not row.event_id:
                continue
            current = first_seen.get(row.event_id)
            if current is None or (
                row.detected_at is not None and row.detected_at < current
            ):
                first_seen[row.event_id] = row.detected_at

        # Include events known only from correlation_members, so no persisted
        # event reference is silently dropped from the graph.
        event_nodes: dict[uuid.UUID, dict[str, Any]] = {}
        for raw in event_ids:
            parsed = _as_uuid(raw)
            if parsed is None:
                logger.warning("skipping non-UUID event reference %r", raw)
                continue
            observed = first_seen.get(parsed)
            node = build_node(
                NodeType.EVENT,
                str(parsed),
                # No event payload exists in V2, so the label is the identity.
                label=f"event {str(parsed)[:8]}",
                observed_at=observed,
            )
            add_node(node)
            event_nodes[parsed] = node
        return event_nodes

    def _derive_risk_assessments(
        self, db, correlation_ids, nodes, add_node, add_edge
    ) -> None:
        rows = db.execute(
            select(RiskAssessment)
            .where(RiskAssessment.correlation_id.in_(correlation_ids))
            .order_by(RiskAssessment.risk_assessment_id)
        ).scalars().all()
        for row in rows:
            target = add_node(build_node(
                NodeType.RISK_ASSESSMENT,
                str(row.risk_assessment_id),
                label=f"{row.level} risk ({row.score})",
                metadata={
                    "score": row.score,
                    "level": row.level,
                    "confidence": row.confidence,
                    "provenance": row.provenance,
                    "timestamp": row.timestamp,
                },
            ))
            source = nodes.get(
                (NodeType.CORRELATION.value, str(row.correlation_id))
            )
            if source is None:
                continue
            add_edge(build_edge(
                RelationshipType.ASSESSED_BY,
                source,
                target,
                source_reference_value=f"risk_assessment:{row.risk_assessment_id}",
                evidence_references=[
                    source["source_reference"],
                    target["source_reference"],
                    f"risk_assessment:{row.risk_assessment_id}",
                ],
            ))

    def _derive_indicators(
        self, db, event_ids: Sequence[str], nodes, add_node, add_edge
    ) -> None:
        """EVENT -> THREAT_INDICATOR from persisted threat-intel lookups.

        There is no persisted detection->indicator column, so no such edge is
        ever created.  Mining ``detection_results.evidence`` JSONB would be
        inference, which the graph contract forbids.
        """
        if not event_ids:
            return
        rows = db.execute(
            select(ThreatIntelLookup, ThreatIntelIndicator)
            .join(
                ThreatIntelIndicator,
                ThreatIntelIndicator.id == ThreatIntelLookup.indicator_id,
            )
            .where(ThreatIntelLookup.event_id.in_(event_ids))
            .order_by(ThreatIntelLookup.id, ThreatIntelIndicator.id)
        ).all()
        for lookup, indicator in rows:
            if not lookup.event_id:
                continue
            source = nodes.get((NodeType.EVENT.value, str(lookup.event_id)))
            if source is None:
                continue
            target = add_node(build_node(
                NodeType.THREAT_INDICATOR,
                str(indicator.id),
                label=f"{indicator.indicator_type}:{indicator.value}",
                metadata={
                    "indicator_type": indicator.indicator_type,
                    "value": indicator.value,
                    "first_seen_at": indicator.first_seen_at,
                    "last_seen_at": indicator.last_seen_at,
                },
            ))
            lookup_ref = f"threat_intel_lookup:{lookup.id}"
            add_edge(build_edge(
                RelationshipType.ASSOCIATED_WITH_INDICATOR,
                source,
                target,
                source_reference_value=lookup_ref,
                evidence_references=[
                    source["source_reference"],
                    target["source_reference"],
                    lookup_ref,
                ],
            ))

    def _derive_memories(self, db, correlation_ids, nodes, add_node, add_edge) -> None:
        rows = db.execute(
            select(IncidentMemoryRow)
            .where(IncidentMemoryRow.correlation_id.in_(correlation_ids))
            .order_by(IncidentMemoryRow.memory_id)
        ).scalars().all()
        for row in rows:
            target = add_node(build_node(
                NodeType.INCIDENT_MEMORY,
                str(row.memory_id),
                label=row.title or str(row.memory_id),
                metadata={
                    "memory_type": row.memory_type,
                    "title": row.title,
                    "confidence": row.confidence,
                    "provenance": row.provenance,
                },
            ))
            source = nodes.get(
                (NodeType.CORRELATION.value, str(row.correlation_id))
            )
            if source is None:
                continue
            add_edge(build_edge(
                RelationshipType.RECALLED_BY,
                source,
                target,
                source_reference_value=f"incident_memory:{row.memory_id}",
                evidence_references=[
                    source["source_reference"],
                    target["source_reference"],
                    f"incident_memory:{row.memory_id}",
                ],
            ))

    def _derive_approvals_and_executions(
        self, db, correlation_ids, nodes, add_node, add_edge
    ) -> None:
        approvals = db.execute(
            select(ApprovalRequestRow)
            .where(ApprovalRequestRow.correlation_id.in_(correlation_ids))
            .order_by(ApprovalRequestRow.approval_id)
        ).scalars().all()

        approval_nodes: dict[uuid.UUID, dict[str, Any]] = {}
        for row in approvals:
            target = add_node(build_node(
                NodeType.APPROVAL,
                str(row.approval_id),
                label=f"{row.action_type} ({row.status})",
                metadata={
                    "action_type": row.action_type,
                    "status": row.status,
                    "risk_level": row.risk_level,
                    "risk_score": row.risk_score,
                    "confidence": row.confidence,
                    "provenance": row.provenance,
                    "policy_rule_id": row.policy_rule_id,
                    "response_status": row.response_status,
                    "requested_at": row.requested_at,
                    "expires_at": row.expires_at,
                    "resolved_at": row.resolved_at,
                },
            ))
            approval_nodes[row.approval_id] = target
            source = nodes.get(
                (NodeType.CORRELATION.value, str(row.correlation_id))
            )
            if source is None:
                continue
            add_edge(build_edge(
                RelationshipType.REQUIRES_APPROVAL,
                source,
                target,
                source_reference_value=f"approval_request:{row.approval_id}",
                evidence_references=[
                    source["source_reference"],
                    target["source_reference"],
                    f"approval_request:{row.approval_id}",
                ],
            ))

        approval_ids = list(approval_nodes)
        executions = db.execute(
            select(SoarExecutionRow)
            .where(
                (SoarExecutionRow.correlation_id.in_(correlation_ids))
                | (SoarExecutionRow.approval_id.in_(approval_ids))
                if approval_ids
                else SoarExecutionRow.correlation_id.in_(correlation_ids)
            )
            .order_by(SoarExecutionRow.execution_id)
        ).scalars().all()

        for row in executions:
            target = add_node(build_node(
                NodeType.SOAR_EXECUTION,
                str(row.execution_id),
                label=f"{row.playbook_id} ({row.status})",
                metadata={
                    "playbook_id": row.playbook_id,
                    "playbook_version": row.playbook_version,
                    "primary_action": row.primary_action,
                    "status": row.status,
                    "simulated": row.simulated,
                    "failure_policy": row.failure_policy,
                    "started_at": row.started_at,
                    "completed_at": row.completed_at,
                    "created_by_role": row.created_by_role,
                },
            ))

            if row.approval_id and row.approval_id in approval_nodes:
                approval_node = approval_nodes[row.approval_id]
                execution_ref = f"soar_execution:{row.execution_id}"
                add_edge(build_edge(
                    RelationshipType.AUTHORIZED_EXECUTION,
                    approval_node,
                    target,
                    source_reference_value=execution_ref,
                    evidence_references=[
                        approval_node["source_reference"],
                        target["source_reference"],
                        execution_ref,
                    ],
                ))

            if row.correlation_id:
                correlation_node = nodes.get(
                    (NodeType.CORRELATION.value, str(row.correlation_id))
                )
                if correlation_node is not None:
                    execution_ref = f"soar_execution:{row.execution_id}"
                    add_edge(build_edge(
                        RelationshipType.RESPONDED_BY_EXECUTION,
                        correlation_node,
                        target,
                        source_reference_value=execution_ref,
                        evidence_references=[
                            correlation_node["source_reference"],
                            target["source_reference"],
                            execution_ref,
                        ],
                    ))

    def _derive_reports(self, db, correlation_ids, nodes, add_node, add_edge) -> None:
        # incident_reports.correlation_id is a VARCHAR(36) soft reference, so it
        # is compared as text rather than cast, which cannot raise on a
        # malformed stored value.
        wanted = {str(c) for c in correlation_ids}
        rows = db.execute(
            select(IncidentReportRow)
            .order_by(IncidentReportRow.report_id)
        ).scalars().all()
        for row in rows:
            if str(row.correlation_id) not in wanted:
                continue
            # payload (JSONB) is deliberately not read: it may contain raw
            # provider output or credentials.
            target = add_node(build_node(
                NodeType.INCIDENT_REPORT,
                str(row.report_id),
                label=row.title or str(row.report_id),
                metadata={
                    "status": row.status,
                    "title": row.title,
                    "model": row.model,
                    "generated_by_role": row.generated_by_role,
                    "generated_at": row.generated_at,
                    "error_code": row.error_code,
                },
            ))
            source = nodes.get(
                (NodeType.CORRELATION.value, str(row.correlation_id))
            )
            if source is None:
                continue
            add_edge(build_edge(
                RelationshipType.REPORTED_BY,
                source,
                target,
                source_reference_value=f"incident_report:{row.report_id}",
                evidence_references=[
                    source["source_reference"],
                    target["source_reference"],
                    f"incident_report:{row.report_id}",
                ],
            ))

    def _derive_hunts(self, db, correlation_ids, nodes, add_node, add_edge) -> None:
        wanted = {str(c) for c in correlation_ids}
        rows = db.execute(
            select(ThreatHuntEvidenceRow, ThreatHuntRow)
            .join(ThreatHuntRow, ThreatHuntRow.hunt_id == ThreatHuntEvidenceRow.hunt_id)
            .order_by(ThreatHuntEvidenceRow.hunt_id, ThreatHuntEvidenceRow.evidence_id)
        ).all()
        hunt_nodes: dict[str, dict[str, Any]] = {}
        for evidence, hunt in rows:
            if str(evidence.correlation_id or "") not in wanted:
                continue
            if hunt.hunt_id not in hunt_nodes:
                hunt_nodes[hunt.hunt_id] = add_node(build_node(
                    NodeType.THREAT_HUNT,
                    str(hunt.hunt_id),
                    label=hunt.name or str(hunt.hunt_id),
                    metadata={
                        "name": hunt.name,
                        "hunt_type": hunt.hunt_type,
                        "status": hunt.status,
                        "result_count": hunt.result_count,
                        "finding_count": hunt.finding_count,
                        "timeline_count": hunt.timeline_count,
                    },
                ))
            target = hunt_nodes[hunt.hunt_id]
            source = nodes.get(
                (NodeType.CORRELATION.value, str(evidence.correlation_id))
            )
            if source is None:
                continue
            evidence_ref = f"threat_hunt_evidence:{evidence.evidence_id}"
            add_edge(build_edge(
                RelationshipType.INVESTIGATED_BY_HUNT,
                source,
                target,
                source_reference_value=evidence_ref,
                evidence_references=[
                    source["source_reference"],
                    target["source_reference"],
                    f"threat_hunt:{hunt.hunt_id}",
                    evidence_ref,
                ],
            ))

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist(
        self,
        db: Session,
        nodes: Sequence[dict[str, Any]],
        edges: Sequence[dict[str, Any]],
        result: BuildResult,
    ) -> None:
        """Upsert nodes and edges. Never duplicates, never partial."""
        node_keys = [(n["node_type"].value, n["source_id"]) for n in nodes]
        existing_nodes: dict[tuple[str, str], KnowledgeGraphNode] = {}
        if node_keys:
            rows = db.execute(
                select(KnowledgeGraphNode).where(
                    tuple_(
                        KnowledgeGraphNode.node_type,
                        KnowledgeGraphNode.source_id,
                    ).in_(node_keys)
                )
            ).scalars().all()
            existing_nodes = {(r.node_type, r.source_id): r for r in rows}

        for node in nodes:
            key = (node["node_type"].value, node["source_id"])
            observed = _observed_at(node)
            row = existing_nodes.get(key)
            if row is None:
                db.add(KnowledgeGraphNode(
                    id=node["id"],
                    node_type=key[0],
                    source_id=key[1],
                    source_reference=node["source_reference"],
                    provenance=node["provenance"].value,
                    label=node["label"],
                    node_metadata=node["metadata"],
                    observed_at=observed,
                ))
                result.nodes_created += 1
            else:
                # Deterministic refresh: identical V2 state writes identical values.
                row.source_reference = node["source_reference"]
                row.provenance = node["provenance"].value
                row.label = node["label"]
                row.node_metadata = node["metadata"]
                row.observed_at = observed
                result.nodes_updated += 1
        db.flush()

        live_node_ids = {n["id"] for n in nodes}
        edge_ids = [e["id"] for e in edges]
        existing_edges: dict[uuid.UUID, KnowledgeGraphEdge] = {}
        if edge_ids:
            rows = db.execute(
                select(KnowledgeGraphEdge).where(
                    KnowledgeGraphEdge.id.in_(edge_ids)
                )
            ).scalars().all()
            existing_edges = {r.id: r for r in rows}

        for edge in edges:
            # An edge is only written when both endpoints were just resolved
            # from real V2 rows, so a dangling edge is unconstructible.
            if (
                edge["source_node_id"] not in live_node_ids
                or edge["target_node_id"] not in live_node_ids
            ):
                continue
            row = existing_edges.get(edge["id"])
            if row is None:
                db.add(KnowledgeGraphEdge(
                    id=edge["id"],
                    source_node_id=edge["source_node_id"],
                    target_node_id=edge["target_node_id"],
                    relationship_type=edge["relationship_type"].value,
                    source_reference=edge["source_reference"],
                    evidence_references=edge["evidence_references"],
                ))
                result.edges_created += 1
            else:
                row.source_reference = edge["source_reference"]
                row.evidence_references = edge["evidence_references"]
                result.edges_updated += 1
        db.commit()

    def _prune_stale(
        self,
        db: Session,
        nodes: Sequence[dict[str, Any]],
        edges: Sequence[dict[str, Any]],
        result: BuildResult,
    ) -> None:
        """Delete persisted nodes/edges no longer derivable from V2 state.

        This is the deterministic answer to "a V2 record disappeared": its
        graph rows are removed rather than left behind as stubs.  Edges are
        removed before nodes so no structural orphan can ever survive.
        """
        live_edge_ids = {e["id"] for e in edges}
        live_node_keys = {
            (n["node_type"].value, n["source_id"]) for n in nodes
        }

        stale_edge_ids = [
            row_id
            for row_id in db.execute(select(KnowledgeGraphEdge.id)).scalars().all()
            if row_id not in live_edge_ids
        ]
        if stale_edge_ids:
            db.execute(
                delete(KnowledgeGraphEdge).where(
                    KnowledgeGraphEdge.id.in_(stale_edge_ids)
                )
            )
            result.edges_pruned += len(stale_edge_ids)

        stale_node_ids = [
            row_id
            for row_id, node_type, source_id in db.execute(
                select(
                    KnowledgeGraphNode.id,
                    KnowledgeGraphNode.node_type,
                    KnowledgeGraphNode.source_id,
                )
            ).all()
            if (node_type, source_id) not in live_node_keys
        ]
        if stale_node_ids:
            db.execute(
                delete(KnowledgeGraphNode).where(
                    KnowledgeGraphNode.id.in_(stale_node_ids)
                )
            )
            result.nodes_pruned += len(stale_node_ids)
        db.commit()


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def _observed_at(node: dict[str, Any]) -> datetime | None:
    raw = node.get("metadata", {}).get("observed_at")
    if isinstance(raw, datetime):
        return raw
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None
    return None


__all__ = ["BuildResult", "DEFAULT_MAX_CORRELATIONS", "KnowledgeGraphBuilder"]