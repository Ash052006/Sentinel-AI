"""Read-only input assembly for the playbook engine — V3.25.

Everything the engine may read is gathered here, from persisted records only, and
handed to it as a single immutable :class:`PlaybookInputs` value.  That split is
deliberate: the engine performs no I/O, so a generation run is a pure function
of its inputs and is reproducible by re-running it.

Three rules govern what becomes an input.

**Only persisted V2 entities count as evidence.**  Nothing is invented, nothing is
carried over from a prior playbook, and no narrative text from a source record is
copied into a rationale — only a typed pointer to the record.

**Downstream response artifacts are not evidence for a new proposal.**  Persisted
approvals, SOAR executions and incident reports all appear in the same
knowledge graph as detections and indicators, so a naive traversal would let an
already-executed response justify proposing the same response again.  They are
excluded from the evidence scope and reported as unavailable inputs instead.

**Untrusted text is detected but never propagated.**  Node labels are scanned for
instruction-like content.  A match sets a flag and a limitation; it does not copy
the text anywhere, so a log line cannot become a rationale.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.agents.debate.evidence import graph_snapshot_digest
from app.schemas.playbook import (
    ActionEvidence,
    DebateOverview,
    PlaybookInputs,
    PredictionOverview,
    PredictionSummary,
    ResolvableTarget,
)
from app.services.debate.persistence import DebateService
from app.services.knowledge_graph.queries import (
    BoundedGraph,
    GraphNodeNotFound,
    KnowledgeGraphQueries,
)
from app.services.knowledge_graph.vocabulary import NodeType
from app.services.playbook.exceptions import (
    PlaybookBoundsError,
    PlaybookContextError,
)
from app.services.playbook.vocabulary import (
    DEFAULT_PLAYBOOK_BOUNDS,
    EvidenceSource,
    PlaybookBounds,
    TargetType,
    TargetValidationError,
    contains_injection_pattern,
    validate_target_value,
)
from app.services.prediction.persistence import AttackPredictionService

# ---------------------------------------------------------------------------
# Node vocabulary mapping
# ---------------------------------------------------------------------------
#
# Closed mapping from the V2 knowledge-graph node vocabulary to the V3.25 evidence
# vocabulary.  Deliberately explicit: an unmapped node type is a gap to surface,
# never a node to guess at.

NODE_TYPE_TO_EVIDENCE_SOURCE: dict[NodeType, EvidenceSource] = {
    NodeType.EVENT: EvidenceSource.EVENT,
    NodeType.DETECTION: EvidenceSource.DETECTION,
    NodeType.CORRELATION: EvidenceSource.CORRELATION,
    NodeType.RISK_ASSESSMENT: EvidenceSource.RISK_ASSESSMENT,
    NodeType.THREAT_INDICATOR: EvidenceSource.THREAT_INTELLIGENCE,
    NodeType.INCIDENT_MEMORY: EvidenceSource.INCIDENT_MEMORY,
    NodeType.THREAT_HUNT: EvidenceSource.INVESTIGATION,
}

#: Node types present in the graph that must **not** be treated as evidence for a
#: new proposal.  ``APPROVAL`` and ``SOAR_EXECUTION`` are the response-layer
#: artifacts: letting them justify a playbook would let a completed response
#: propose itself.  ``INCIDENT_REPORT`` is a downstream AI-generated narrative.
DOWNSTREAM_ARTIFACT_NODE_TYPES: frozenset[NodeType] = frozenset(
    {NodeType.APPROVAL, NodeType.SOAR_EXECUTION, NodeType.INCIDENT_REPORT}
)

#: Threat-intelligence indicator types to the target type they can address.
#:
#: ``hash`` is deliberately absent.  A content digest is not a logical file path,
#: and :data:`TargetType.FILE` validates one — so mapping ``hash`` to ``FILE``
#: let a sha256 indicator resolve into a ``FILE`` target and be proposed as
#: ``quarantine_file(<digest>)``, a claim about a path that does not exist.  The
#: frozen vocabulary has no ``HASH`` target, so a hash indicator is instead
#: *non-addressable*: it remains usable evidence (a detection can still be
#: grounded on the indicator that reported it), it simply yields no target and so
#: cannot generate a file-targeted action.
INDICATOR_TYPE_TO_TARGET_TYPE: dict[str, TargetType] = {
    "ip": TargetType.IP,
    "domain": TargetType.DOMAIN,
    "url": TargetType.URL,
}

#: Engine-authored detail per evidence source.  Fixed strings, not templates
#: filled with source content — a rationale must never restate untrusted text.
_EVIDENCE_DETAIL: dict[EvidenceSource, str] = {
    EvidenceSource.EVENT: "referenced event identifier in this correlation",
    EvidenceSource.DETECTION: "persisted detection result in this correlation",
    EvidenceSource.CORRELATION: "persisted correlation result",
    EvidenceSource.RISK_ASSESSMENT: "persisted risk assessment for this correlation",
    EvidenceSource.THREAT_INTELLIGENCE: "persisted threat-intelligence indicator",
    EvidenceSource.INCIDENT_MEMORY: "persisted incident memory record",
    EvidenceSource.INVESTIGATION: "persisted threat-hunt record",
}


def evidence_reference(source: EvidenceSource, identifier: str) -> str:
    """Build a typed evidence reference of the form ``<source>:<id>``."""
    return f"{source.value}:{identifier}"


def _node_source_id(node: dict[str, Any]) -> str:
    """The node's native V2 identifier, verbatim."""
    source_id = node.get("source_id")
    if isinstance(source_id, str) and source_id:
        return source_id
    return str(node.get("id"))


def _target_from_indicator_node(
    node: dict[str, Any],
) -> ResolvableTarget | None:
    """Resolve a threat-intelligence node into an addressable target.

    Returns ``None`` when the node carries no indicator value, or when the value
    does not structurally validate for its indicator type.  A malformed indicator
    is *not* coerced into a neighbouring target type: "isolate the host that
    looks like this string" is not something a generated playbook should be able
    to say.
    """
    metadata = node.get("metadata")
    if not isinstance(metadata, dict):
        return None
    raw_value = metadata.get("value")
    indicator_type = metadata.get("indicator_type")
    if not isinstance(raw_value, str) or not isinstance(indicator_type, str):
        return None
    target_type = INDICATOR_TYPE_TO_TARGET_TYPE.get(indicator_type)
    if target_type is None:
        return None
    source = EvidenceSource.THREAT_INTELLIGENCE
    try:
        canonical = validate_target_value(target_type, raw_value)
    except TargetValidationError:
        return None
    return ResolvableTarget(
        target_type=target_type,
        value=canonical,
        reference=evidence_reference(source, _node_source_id(node)),
        from_indicator=True,
    )


class PlaybookContextAssembler:
    """Assembles :class:`PlaybookInputs` from persisted records.

    Read-only by construction: this class touches the graph, debate and
    prediction stores and never writes to them.  A playbook cannot therefore
    influence the evidence its successor will be built from.
    """

    def __init__(
        self,
        db: Session,
        *,
        bounds: PlaybookBounds = DEFAULT_PLAYBOOK_BOUNDS,
        graph_queries: KnowledgeGraphQueries | None = None,
        debate_service: DebateService | None = None,
        prediction_service: AttackPredictionService | None = None,
    ) -> None:
        self._db = db
        self._bounds = bounds
        self._graph_queries = graph_queries or KnowledgeGraphQueries()
        self._debates = debate_service or DebateService(db)
        self._predictions = prediction_service or AttackPredictionService(db)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def assemble(self, correlation_id: uuid.UUID | str) -> PlaybookInputs:
        """Gather every permitted input for ``correlation_id``.

        Raises:
            PlaybookContextError: the correlation has no graph to reason over.
            PlaybookBoundsError: the graph exceeded the configured bounds.
        """
        correlation = uuid.UUID(str(correlation_id))
        try:
            graph = self._graph_queries.get_correlation_graph(self._db, correlation)
        except GraphNodeNotFound as exc:
            # A correlation with no root node is the same grounding failure as a
            # correlation with an empty graph, so it must surface as the same
            # governed failure.  Letting ``GraphNodeNotFound`` escape would breach
            # this method's own contract: it is a ``LookupError``, not a
            # ``PlaybookError``, so every caller would miss it and the request
            # would end at the catch-all 500 instead of the documented 404 -- a
            # missing correlation reported as a server fault.
            raise PlaybookContextError(
                "no knowledge-graph entities are persisted for this correlation; a "
                "playbook cannot be grounded in an absent graph"
            ) from exc
        if graph.node_count == 0:
            raise PlaybookContextError(
                "no knowledge-graph entities are persisted for this correlation; a "
                "playbook cannot be grounded in an empty graph"
            )
        self._enforce_graph_bounds(graph)

        unavailable: dict[str, str] = {}
        untrusted_detected = self._detect_untrusted_content(graph)

        established: dict[str, ActionEvidence] = {}
        targets: dict[str, ResolvableTarget] = {}
        for node in sorted(graph.nodes, key=lambda item: str(item.get("id"))):
            node_type = self._node_type(node)
            if node_type is None:
                # Surface it rather than skipping in silence.  A node type from a
                # future release, or a malformed one, would otherwise vanish and
                # the resulting playbook would look thinner than the graph really
                # is -- the same false "nothing else was found" claim that bounds
                # enforcement refuses to make.
                raw_type = node.get("node_type")
                unavailable.setdefault(
                    f"node_type:{raw_type if isinstance(raw_type, str) else 'unknown'}",
                    "node type is not in the V3.25 evidence vocabulary",
                )
                continue
            if node_type in DOWNSTREAM_ARTIFACT_NODE_TYPES:
                unavailable.setdefault(
                    f"node_type:{node_type.value}",
                    "downstream response artifact; not evidence for a new proposal",
                )
                continue
            source = NODE_TYPE_TO_EVIDENCE_SOURCE.get(node_type)
            if source is None:
                unavailable.setdefault(
                    f"node_type:{node_type.value}",
                    "no evidence classification is defined for this node type",
                )
                continue
            reference = evidence_reference(source, _node_source_id(node))
            established[reference] = ActionEvidence(
                source=source,
                reference=reference,
                detail=_EVIDENCE_DETAIL[source],
                stance="supporting",
            )
            if node_type is NodeType.THREAT_INDICATOR:
                target = _target_from_indicator_node(node)
                if target is not None:
                    targets[target.reference] = target

        self._enforce_target_bound(targets)

        debate = self._assemble_debate(correlation, graph, unavailable)
        prediction = self._assemble_prediction(correlation, unavailable)

        return PlaybookInputs(
            correlation_id=correlation,
            graph_snapshot_digest=graph_snapshot_digest(graph),
            graph_node_count=graph.node_count,
            graph_edge_count=graph.edge_count,
            graph_truncated=bool(graph.truncated),
            graph_truncated_reason=graph.truncated_reason,
            established_evidence=established,
            targets=targets,
            prediction=prediction,
            debate=debate,
            untrusted_content_detected=untrusted_detected,
            unavailable_inputs=unavailable,
            bounds=self._bounds,
        )

    # ------------------------------------------------------------------
    # Bounds
    # ------------------------------------------------------------------

    def _enforce_graph_bounds(self, graph: BoundedGraph) -> None:
        """Reject an over-large graph rather than reasoning over a fragment.

        Truncating here would produce a playbook whose silence about the dropped
        entities reads as "nothing else was found", which is a different and more
        dangerous claim than "this run refused".
        """
        bounds = self._bounds
        if graph.node_count > bounds.max_graph_nodes:
            raise PlaybookBoundsError(
                f"correlation graph has {graph.node_count} nodes, exceeding "
                f"max_graph_nodes={bounds.max_graph_nodes}"
            )
        if graph.edge_count > bounds.max_graph_edges:
            raise PlaybookBoundsError(
                f"correlation graph has {graph.edge_count} edges, exceeding "
                f"max_graph_edges={bounds.max_graph_edges}"
            )

    def _enforce_target_bound(self, targets: dict[str, ResolvableTarget]) -> None:
        if len(targets) > self._bounds.max_targets:
            raise PlaybookBoundsError(
                f"{len(targets)} resolvable targets exceed max_targets="
                f"{self._bounds.max_targets}"
            )

    # ------------------------------------------------------------------
    # Untrusted content
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_untrusted_content(graph: BoundedGraph) -> bool:
        """Flag instruction-like content in node labels.

        The label is inspected and discarded — nothing is copied into the inputs.
        Detection exists so the resulting playbook can state that untrusted
        content was present and was not allowed to influence it.
        """
        for node in graph.nodes:
            label = node.get("label")
            if isinstance(label, str) and contains_injection_pattern(label):
                return True
        return False

    @staticmethod
    def _node_type(node: dict[str, Any]) -> NodeType | None:
        raw = node.get("node_type")
        try:
            return NodeType(raw) if isinstance(raw, str) else None
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # V3.23 debate
    # ------------------------------------------------------------------

    def _assemble_debate(
        self,
        correlation: uuid.UUID,
        graph: BoundedGraph,
        unavailable: dict[str, str],
    ) -> DebateOverview | None:
        """Reduce the latest debate to what V3.25 may consume.

        Only the consensus *shape* is carried across: state, strength, and the
        unresolved questions, gaps and dissent.  Agent arguments are not
        replayed — V3.25 reads conclusions, not rhetoric, and copying statements
        into a rationale would import untrusted text for no benefit.
        """
        sessions = self._debates.list_for_correlation(correlation)
        if not sessions:
            unavailable.setdefault(
                "debate", "no persisted V3.23 debate exists for this correlation"
            )
            return None

        session = sessions[0]
        digest = graph_snapshot_digest(graph)
        if session.metadata.graph_snapshot_digest != digest:
            unavailable.setdefault(
                "debate",
                "the persisted debate was produced from a different graph snapshot",
            )
            return None

        consensus = session.consensus
        overview = DebateOverview(
            debate_id=session.debate_id,
            consensus_state=consensus.state.value,
            consensus_strength=consensus.consensus_strength,
            unresolved_questions=[
                question[:256] for question in consensus.unresolved_questions
            ][:32],
            evidence_gaps=[gap[:256] for gap in consensus.evidence_gaps][:32],
            dissent_positions=[
                f"{item.position[:192]} ({item.reason[:48]})"
                for item in consensus.dissent
            ][:32],
        )
        unavailable.update(
            {
                f"debate_consensus:{key}": value
                for key, value in (
                    ("unresolved_questions", str(len(overview.unresolved_questions))),
                    ("evidence_gaps", str(len(overview.evidence_gaps))),
                    ("dissent", str(len(overview.dissent_positions))),
                )
                if value != "0"
            }
        )
        return overview

    # ------------------------------------------------------------------
    # V3.24 prediction
    # ------------------------------------------------------------------

    def _assemble_prediction(
        self,
        correlation: uuid.UUID,
        unavailable: dict[str, str],
    ) -> PredictionOverview | None:
        """Reduce the latest prediction session to what V3.25 may consume.

        Predictions are carried as *preparation input*.  They can justify an
        action that gathers evidence or positions a control, and they can cap the
        confidence of anything resting on them; they can never, alone, justify a
        disruptive action — an invariant the action contract enforces.
        """
        sessions = self._predictions.get_by_correlation(correlation, limit=1)
        if not sessions:
            unavailable.setdefault(
                "prediction",
                "no persisted V3.24 prediction session exists for this correlation",
            )
            return None

        session = sessions[0]
        limit = self._bounds.max_predictions
        summaries = [
            PredictionSummary(
                prediction_session_id=session.prediction_session_id,
                prediction_id=item.prediction_id,
                prediction_kind=item.prediction_kind.value,
                depth=item.depth.value,
                status=item.prediction_status.value,
                target=item.target,
                target_basis=item.target_basis.value,
                confidence=item.uncertainty.confidence,
                supporting_references=[
                    entry.reference for entry in item.uncertainty.supporting_evidence
                ][:32],
                contradicting_references=[
                    entry.reference for entry in item.uncertainty.contradicting_evidence
                ][:32],
            )
            for item in sorted(
                session.predictions, key=lambda p: str(p.prediction_id)
            )[:limit]
        ]
        if len(session.predictions) > limit:
            unavailable.setdefault(
                "prediction_coverage",
                f"{len(session.predictions) - limit} predictions beyond "
                f"max_predictions={limit} were not considered",
            )
        if not summaries:
            unavailable.setdefault(
                "prediction",
                "the persisted prediction session contains no predictions",
            )
            return None
        return PredictionOverview(
            prediction_session_id=session.prediction_session_id,
            status=session.status.value,
            predictions=summaries,
            unresolved_questions=[
                question[:256] for question in session.uncertainty.unresolved_questions
            ][:32],
            evidence_gaps=[gap[:256] for gap in session.uncertainty.evidence_gaps][
                :32
            ],
        )


def get_playbook_context_assembler(
    db: Session,
    *,
    bounds: PlaybookBounds = DEFAULT_PLAYBOOK_BOUNDS,
) -> PlaybookContextAssembler:
    """Return an assembler bound to ``db``."""
    return PlaybookContextAssembler(db, bounds=bounds)


__all__ = [
    "DOWNSTREAM_ARTIFACT_NODE_TYPES",
    "INDICATOR_TYPE_TO_TARGET_TYPE",
    "NODE_TYPE_TO_EVIDENCE_SOURCE",
    "PlaybookContextAssembler",
    "evidence_reference",
    "get_playbook_context_assembler",
]