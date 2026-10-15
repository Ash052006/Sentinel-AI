"""Input assembly for the prediction engine — V3.24.

This is the only part of V3.24 that touches a database, and it is strictly a
**reader**.  It consumes:

* the persisted **V3.22** bounded graph, via the existing
  ``KnowledgeGraphQueries`` API;
* persisted **V2** detection rows, to read ATT&CK mappings that genuinely exist
  in storage;
* the persisted **V3.23** debate, via ``DebateService``.

It writes nothing.  No graph node, no graph edge, no detection, and no debate
row is created, modified, or deleted here (§21, §22, §42).  A prediction is a new
downstream artifact, never a mutation of the state that produced it.

Graph-digest compatibility
--------------------------
The digest is computed with V3.23's own ``graph_snapshot_digest``, and the result
records both the digest V3.24 consumed and whether it matches the digest the
consumed debate was pinned to.  When they agree, it is provable that prediction
and debate reasoned over the *same* graph snapshot; when they disagree, that is
reported as an explicit limitation instead of being silently ignored.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.debate import DebateSessionRecord
from app.models.detection_result import DetectionResult
from app.schemas.attack_prediction import (
    AvailableReference,
    DebateHypothesis,
    DebateSummary,
    ObservedTechnique,
    PredictionInputs,
)
from app.schemas.debate import DebateSession
from app.services.knowledge_graph.queries import (
    BoundedGraph,
    GraphNodeNotFound,
    KnowledgeGraphQueries,
)
from app.services.knowledge_graph.vocabulary import DEFAULT_BOUNDS, NodeType
from app.services.prediction.exceptions import PredictionContextError
from app.services.prediction.vocabulary import (
    DEFAULT_PREDICTION_BOUNDS,
    PredictionBounds,
    validate_technique_id,
)

#: Node types whose graph reference can be resolved back to a real V2 row.
_RESOLVABLE_NODE_TYPES = frozenset(
    {
        NodeType.EVENT.value,
        NodeType.DETECTION.value,
        NodeType.CORRELATION.value,
        NodeType.RISK_ASSESSMENT.value,
        NodeType.THREAT_INDICATOR.value,
        NodeType.INCIDENT_MEMORY.value,
        NodeType.THREAT_HUNT.value,
        NodeType.INCIDENT_REPORT.value,
    }
)

#: Allowlisted keys inside a persisted detection's ``rule_references`` JSON that
#: may carry an ATT&CK mapping.
#:
#: V3.22 deliberately never reads detection JSONB payloads, because those are
#: untrusted security-event content.  V3.24 narrows that to exactly three keys
#: and passes every value through :func:`validate_technique_id`, so nothing but a
#: syntactically valid technique id can enter a prediction.  Arbitrary payload
#: text is never read, never cited, and never treated as evidence.
_ATTACK_ID_KEYS = ("attack", "attack_id", "mitre_attack")
_ATTACK_NAME_KEYS = ("attack_name", "attack_technique_name")
_ATTACK_TACTIC_KEYS = ("attack_tactic", "tactic")

#: Ceilings applied while reducing an upstream debate to the prediction contract.
#: They mirror the contract's own ``max_length``/``max_items`` so reduction can
#: never fail validation on well-formed upstream data.
_MAX_HYPOTHESES = 64
_MAX_HYPOTHESIS_REFS = 32


def _clamp(value: str, limit: int) -> str:
    """Trim an upstream string to ``limit`` characters, collapsing whitespace.

    Trimming rather than rejecting: the alternative is to discard a whole debate
    because one claim ran long, which would lose far more information than the
    few trailing characters are worth.
    """
    collapsed = " ".join(value.split())
    return collapsed if len(collapsed) <= limit else collapsed[:limit].rstrip()


def _as_str(value: Any, limit: int) -> str | None:
    """Coerce a persisted value to a bounded, secret-safe string.

    Only strings are accepted.  Containers, numbers and ``None`` are rejected
    rather than stringified, so a structured payload cannot smuggle content into
    a prediction field.
    """
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > limit:
        return None
    return cleaned


def _attack_mapping(detection: DetectionResult) -> tuple[str | None, str | None, str | None]:
    """Extract a persisted ATT&CK mapping from one detection row.

    Returns ``(technique_id, technique_name, tactic)``.  A malformed or absent
    mapping yields ``(None, None, None)`` — it is never repaired or guessed.
    """
    evidence = detection.evidence if isinstance(detection.evidence, dict) else {}
    references = evidence.get("rule_references")
    if not isinstance(references, dict):
        return None, None, None

    technique_id: str | None = None
    for key in _ATTACK_ID_KEYS:
        technique_id = validate_technique_id(_as_str(references.get(key), 32))
        if technique_id:
            break

    name: str | None = None
    for key in _ATTACK_NAME_KEYS:
        name = _as_str(references.get(key), 128)
        if name:
            break

    tactic: str | None = None
    for key in _ATTACK_TACTIC_KEYS:
        tactic = _as_str(references.get(key), 64)
        if tactic:
            break

    return technique_id, name, tactic


def _detection_ids_from_refs(references: list[str]) -> list[uuid.UUID]:
    """Parse ``detection:<uuid>`` references into detection ids."""
    ids: list[uuid.UUID] = []
    for reference in references:
        prefix, _, tail = reference.partition(":")
        if prefix != "detection" or not tail:
            continue
        try:
            ids.append(uuid.UUID(tail))
        except ValueError:
            continue
    return ids


def load_persisted_techniques(
    db: Session,
    references: list[str],
) -> dict[str, ObservedTechnique]:
    """Read persisted ATT&CK mappings for the detections in this correlation.

    Only detections actually referenced by the correlation's graph are read, and
    only the three allowlisted ``rule_references`` keys are inspected.  Result is
    keyed by technique id, so a technique seen on several detections accumulates
    breadth instead of being double counted.
    """
    detection_ids = _detection_ids_from_refs(references)
    if not detection_ids:
        return {}

    rows = db.execute(
        select(DetectionResult).where(DetectionResult.detection_id.in_(detection_ids))
    ).scalars().all()

    by_detection = {row.detection_id: row for row in rows}
    found: dict[str, ObservedTechnique] = {}
    for reference in sorted(dict.fromkeys(references)):
        detection_id = next(iter(_detection_ids_from_refs([reference])), None)
        row = by_detection.get(detection_id) if detection_id else None
        if row is None:
            continue
        technique_id, name, tactic = _attack_mapping(row)
        if not technique_id:
            continue
        existing = found.get(technique_id)
        if existing is None:
            found[technique_id] = ObservedTechnique(
                technique_id=technique_id,
                technique_name=name,
                tactic=tactic,
                supporting_refs=[reference],
                detection_count=1,
            )
        elif reference not in existing.supporting_refs:
            found[technique_id] = existing.model_copy(
                update={
                    "supporting_refs": sorted([*existing.supporting_refs, reference]),
                    "detection_count": existing.detection_count + 1,
                    # A name observed on a later row fills a previously blank one;
                    # the first name wins when they disagree, for determinism.
                    "technique_name": existing.technique_name or name,
                    "tactic": existing.tactic or tactic,
                }
            )
    return found


def _build_references(graph: BoundedGraph) -> dict[str, AvailableReference]:
    """Every graph node this prediction may cite, keyed by reference."""
    references: dict[str, AvailableReference] = {}
    for node in graph.nodes:
        node_type = str(node.get("node_type", ""))
        if node_type not in _RESOLVABLE_NODE_TYPES:
            continue
        reference = str(node.get("source_reference", ""))
        if not reference:
            continue
        references[reference] = AvailableReference(
            reference=reference,
            entity_kind=node_type,
            node_id=str(node.get("id", "")),
        )
    return references


def _debate_summary(
    session: DebateSession,
    *,
    available_references: frozenset[str],
) -> DebateSummary:
    """Reduce a V3.23 debate to the explicit view prediction may consume.

    Hypothesis citations are filtered to references the graph actually contains,
    so a prediction can never inherit a citation the evidence layer cannot
    resolve.  Dissent and unresolved questions are carried through verbatim:
    they are the contradicting side of §12.

    Everything read here is *clamped* to the prediction contracts' bounds rather
    than trusted to fit.  The debate is an upstream artifact this layer does not
    own, so an unusually long claim or a roster with more claims than the
    contract allows must degrade the prediction input instead of raising a
    validation error and turning a readable upstream artifact into a 500.
    """
    def resolvable(references: list[Any]) -> list[str]:
        """Keep only citations the evidence layer can resolve, bounded."""
        return sorted({ref.reference for ref in references} & available_references)[
            :_MAX_HYPOTHESIS_REFS
        ]

    consensus = session.consensus
    hypotheses: list[DebateHypothesis] = []
    # Agents are visited in a fixed order and the roster is truncated, so the same
    # persisted debate always reduces to the same summary.
    for assessment in sorted(session.assessments, key=lambda a: a.agent_id)[
        :_MAX_HYPOTHESES
    ]:
        for claim in assessment.hypotheses:
            if len(hypotheses) >= _MAX_HYPOTHESES:
                break
            hypotheses.append(
                DebateHypothesis(
                    hypothesis_id=_clamp(claim.claim_id, 128),
                    statement=_clamp(claim.statement, 1024),
                    confidence=claim.confidence,
                    category_label=_clamp(assessment.role.value, 64),
                    supporting_refs=resolvable(claim.evidence_references),
                    contesting_refs=[],
                )
            )

    dissent_positions = [
        _clamp(f"{item.raised_by_role.value}: {item.position}", 256)
        for item in consensus.dissent
    ]

    return DebateSummary(
        debate_id=session.debate_id,
        consensus_state=_clamp(consensus.state.value, 48),
        consensus_strength=consensus.consensus_strength,
        leading_hypothesis=(
            _clamp(consensus.leading_hypothesis, 1024)
            if consensus.leading_hypothesis
            else None
        ),
        unresolved_questions=sorted(
            _clamp(question, 256) for question in consensus.unresolved_questions
        )[:32],
        evidence_gaps=sorted(
            _clamp(gap, 256) for gap in consensus.evidence_gaps
        )[:32],
        dissent_positions=sorted(dissent_positions)[:32],
        provider=_clamp(session.metadata.provider, 48),
        model=_clamp(session.metadata.model, 48),
        hypotheses=hypotheses,
    )


def _load_latest_debate(
    db: Session, correlation_id: uuid.UUID
) -> tuple[DebateSession | None, str | None]:
    """Load the most recent persisted debate for a correlation, if any.

    Selection is deterministic: newest by ``created_at``, ties broken by the
    deterministic ``debate_id``, so repeated assembly picks the same artifact.
    """
    row = db.execute(
        select(DebateSessionRecord)
        .where(DebateSessionRecord.correlation_id == correlation_id)
        .order_by(
            DebateSessionRecord.created_at.desc(),
            DebateSessionRecord.id.desc(),
        )
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None, "no persisted V3.23 debate exists for this correlation"
    return DebateSession.model_validate(row.session_payload), None


def assemble_prediction_inputs(
    db: Session,
    correlation_id: uuid.UUID | str,
    *,
    bounds: PredictionBounds = DEFAULT_PREDICTION_BOUNDS,
) -> PredictionInputs:
    """Assemble every input the prediction engine is allowed to read.

    Args:
        db: an open session; this function only ever reads.
        correlation_id: the persisted V2 correlation to reason about.
        bounds: architectural bounds for the run.

    Raises:
        PredictionContextError: no persisted graph exists for the correlation.
            The caller maps this to 404, matching the V3.22/V3.23 convention.
    """
    resolved = correlation_id if isinstance(correlation_id, uuid.UUID) else uuid.UUID(str(correlation_id))

    # V3.22 read path. Reusing the existing query object is what keeps the V3.22
    # firewall intact: V3.24 never builds, prunes, or writes the graph.
    from app.agents.debate.evidence import graph_snapshot_digest

    queries = KnowledgeGraphQueries(DEFAULT_BOUNDS)
    try:
        graph = queries.get_correlation_graph(db, resolved, max_depth=bounds.max_depth + 1)
    except GraphNodeNotFound as exc:
        raise PredictionContextError(str(exc)) from exc

    digest = graph_snapshot_digest(graph)
    references = _build_references(graph)
    techniques = load_persisted_techniques(db, sorted(references))

    unavailable: dict[str, str] = {}
    for surface, reason in sorted(queries.unavailable_entity_types().items()):
        unavailable[f"graph_entity:{surface}"] = reason

    debate, debate_reason = _load_latest_debate(db, resolved)
    if debate is None and debate_reason:
        unavailable["debate"] = debate_reason
        summary = None
    else:
        summary = _debate_summary(
            debate,
            available_references=frozenset(references),
        )

    # Cross-system coherence: prove (or report) that prediction and debate saw the
    # same graph snapshot.  Recorded by the caller as a limitation when it differs.
    if debate is not None and debate.metadata.graph_snapshot_digest != digest:
        unavailable["debate_graph_snapshot_match"] = (
            "the consumed debate was pinned to graph snapshot "
            f"{debate.metadata.graph_snapshot_digest[:12]}… while this prediction "
            f"consumed {digest[:12]}…; the debate predates the current graph"
        )

    if not techniques:
        unavailable["persisted_attack_mapping"] = (
            "no persisted detection in this correlation carries an ATT&CK "
            "rule_reference mapping, so no technique id can be asserted"
        )
    return PredictionInputs(
        correlation_id=resolved,
        graph_snapshot_digest=digest,
        graph_node_count=len(graph.nodes),
        graph_edge_count=len(graph.edges),
        graph_truncated=bool(getattr(graph, "truncated", False)),
        graph_truncated_reason=getattr(graph, "truncated_reason", None),
        observed_techniques=techniques,
        evidence_refs=references,
        debate=summary,
        unavailable_inputs=unavailable,
        bounds=bounds,
    )


__all__ = [
    "assemble_prediction_inputs",
    "load_persisted_techniques",
]