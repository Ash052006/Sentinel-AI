"""Closed node / relationship vocabulary and provenance rules — V3.22.

This module is the single authority for *what may exist* in the knowledge
graph.  Nothing outside the registries declared here may be persisted as a
node type or a relationship type; construction validates against them before
any database write.

Design rules enforced here:

* Every node type names the persisted V2 table that gives it stable identity.
  ``EVENT`` is the one deliberate exception — see :data:`NODE_TYPES` and the
  contract document §2.1 — because V2 persists no event table.
* Every relationship names the exact V2 columns that justify it.  A
  relationship with no persisted source-of-truth is not in the vocabulary.
* Node metadata is built from an explicit per-type allowlist of scalar
  columns.  JSONB columns that may contain raw event payloads, provider
  responses, or credentials are never read.
* Node and edge identifiers are deterministic ``uuid5`` values derived from
  (node type, source id) and (relationship, source, target).  Identical V2
  state therefore always yields an identical graph.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Final

# ---------------------------------------------------------------------------
# Namespace
# ---------------------------------------------------------------------------

#: Fixed namespace for every deterministic graph identifier.  Frozen: changing
#: it would renumber the entire graph, so it must never be regenerated.
GRAPH_NAMESPACE: Final[uuid.UUID] = uuid.UUID("6f1d2c3b-4a59-5e6f-8a7b-9c0d1e2f3a4b")


class NodeType(str, Enum):
    """Closed node vocabulary."""

    EVENT = "EVENT"
    DETECTION = "DETECTION"
    CORRELATION = "CORRELATION"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    THREAT_INDICATOR = "THREAT_INDICATOR"
    INCIDENT_MEMORY = "INCIDENT_MEMORY"
    THREAT_HUNT = "THREAT_HUNT"
    APPROVAL = "APPROVAL"
    SOAR_EXECUTION = "SOAR_EXECUTION"
    INCIDENT_REPORT = "INCIDENT_REPORT"


class RelationshipType(str, Enum):
    """Closed relationship vocabulary."""

    PRODUCED_DETECTION = "produced_detection"
    MEMBER_OF_CORRELATION = "member_of_correlation"
    ASSESSED_BY = "assessed_by"
    ASSOCIATED_WITH_INDICATOR = "associated_with_indicator"
    RECALLED_BY = "recalled_by"
    REQUIRES_APPROVAL = "requires_approval"
    AUTHORIZED_EXECUTION = "authorized_execution"
    RESPONDED_BY_EXECUTION = "responded_by_execution"
    REPORTED_BY = "reported_by"
    INVESTIGATED_BY_HUNT = "investigated_by_hunt"


class Provenance(str, Enum):
    """Closed provenance vocabulary.

    ``REFERENCED_EVENT_IDENTIFIER`` is deliberately distinct from every
    ``PERSISTED_*`` value: V2 persists no event table, so an event node
    represents an identifier observed in persisted rows, never a retrievable
    event record.  An auditor must never be misled about that.
    """

    PERSISTED_DETECTION_RESULT = "persisted_detection_result"
    PERSISTED_CORRELATION_RESULT = "persisted_correlation_result"
    PERSISTED_RISK_ASSESSMENT = "persisted_risk_assessment"
    PERSISTED_THREAT_INTEL_INDICATOR = "persisted_threat_intel_indicator"
    PERSISTED_INCIDENT_MEMORY = "persisted_incident_memory"
    PERSISTED_THREAT_HUNT = "persisted_threat_hunt"
    PERSISTED_APPROVAL_REQUEST = "persisted_approval_request"
    PERSISTED_SOAR_EXECUTION = "persisted_soar_execution"
    PERSISTED_INCIDENT_REPORT = "persisted_incident_report"
    REFERENCED_EVENT_IDENTIFIER = "referenced_event_identifier"


class VocabularyError(ValueError):
    """Raised when something outside the closed vocabulary is requested."""


# ---------------------------------------------------------------------------
# Node type registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NodeTypeSpec:
    """Static description of one node type."""

    node_type: NodeType
    provenance: Provenance
    #: Prefix for the node's ``source_reference``.  ``EVENT`` deliberately uses
    #: ``event_reference`` rather than ``event`` so a reference can never be
    #: misread as pointing at a persisted ``events`` row.
    reference_prefix: str
    #: Human-facing description of where identity comes from.
    source_of_truth: str
    #: Maximum stored label length.
    label_max_length: int = 256
    #: Excluded to keep the event node reference-only (no payload is retrievable).
    reference_only: bool = False


NODE_TYPES: Final[dict[NodeType, NodeTypeSpec]] = {
    NodeType.EVENT: NodeTypeSpec(
        node_type=NodeType.EVENT,
        provenance=Provenance.REFERENCED_EVENT_IDENTIFIER,
        reference_prefix="event_reference",
        source_of_truth=(
            "No events table exists in V2. Identity is the event UUID persisted "
            "in detection_results.event_id / correlation_members.event_id."
        ),
        reference_only=True,
    ),
    NodeType.DETECTION: NodeTypeSpec(
        node_type=NodeType.DETECTION,
        provenance=Provenance.PERSISTED_DETECTION_RESULT,
        reference_prefix="detection",
        source_of_truth="detection_results.detection_id (unique)",
    ),
    NodeType.CORRELATION: NodeTypeSpec(
        node_type=NodeType.CORRELATION,
        provenance=Provenance.PERSISTED_CORRELATION_RESULT,
        reference_prefix="correlation",
        source_of_truth="correlation_results.correlation_id (unique)",
    ),
    NodeType.RISK_ASSESSMENT: NodeTypeSpec(
        node_type=NodeType.RISK_ASSESSMENT,
        provenance=Provenance.PERSISTED_RISK_ASSESSMENT,
        reference_prefix="risk_assessment",
        source_of_truth="risk_assessments.risk_assessment_id (unique)",
    ),
    NodeType.THREAT_INDICATOR: NodeTypeSpec(
        node_type=NodeType.THREAT_INDICATOR,
        provenance=Provenance.PERSISTED_THREAT_INTEL_INDICATOR,
        reference_prefix="threat_intel_indicator",
        source_of_truth="threat_intel_indicators.id (primary key)",
        label_max_length=512,
    ),
    NodeType.INCIDENT_MEMORY: NodeTypeSpec(
        node_type=NodeType.INCIDENT_MEMORY,
        provenance=Provenance.PERSISTED_INCIDENT_MEMORY,
        reference_prefix="incident_memory",
        source_of_truth="incident_memories.memory_id (unique)",
    ),
    NodeType.THREAT_HUNT: NodeTypeSpec(
        node_type=NodeType.THREAT_HUNT,
        provenance=Provenance.PERSISTED_THREAT_HUNT,
        reference_prefix="threat_hunt",
        source_of_truth="threat_hunts.hunt_id (unique)",
    ),
    NodeType.APPROVAL: NodeTypeSpec(
        node_type=NodeType.APPROVAL,
        provenance=Provenance.PERSISTED_APPROVAL_REQUEST,
        reference_prefix="approval",
        source_of_truth="approval_requests.approval_id (unique)",
    ),
    NodeType.SOAR_EXECUTION: NodeTypeSpec(
        node_type=NodeType.SOAR_EXECUTION,
        provenance=Provenance.PERSISTED_SOAR_EXECUTION,
        reference_prefix="soar_execution",
        source_of_truth="soar_executions.execution_id (unique)",
    ),
    NodeType.INCIDENT_REPORT: NodeTypeSpec(
        node_type=NodeType.INCIDENT_REPORT,
        provenance=Provenance.PERSISTED_INCIDENT_REPORT,
        reference_prefix="incident_report",
        source_of_truth="incident_reports.report_id (primary key)",
    ),
}


# ---------------------------------------------------------------------------
# Relationship registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RelationshipSpec:
    """Static description of one relationship type."""

    relationship_type: RelationshipType
    source_node_type: NodeType
    target_node_type: NodeType
    #: The persisted V2 columns that justify this relationship.  Documented for
    #: auditors; the builder implements exactly this join.
    v2_source_of_truth: str
    description: str


RELATIONSHIPS: Final[dict[RelationshipType, RelationshipSpec]] = {
    RelationshipType.PRODUCED_DETECTION: RelationshipSpec(
        relationship_type=RelationshipType.PRODUCED_DETECTION,
        source_node_type=NodeType.EVENT,
        target_node_type=NodeType.DETECTION,
        v2_source_of_truth="detection_results.event_id + detection_results.detection_id",
        description="A detection row records this event identifier as its source event.",
    ),
    RelationshipType.MEMBER_OF_CORRELATION: RelationshipSpec(
        relationship_type=RelationshipType.MEMBER_OF_CORRELATION,
        source_node_type=NodeType.DETECTION,
        target_node_type=NodeType.CORRELATION,
        v2_source_of_truth=(
            "correlation_members.detection_id + correlation_members.correlation_id "
            "(FK -> correlation_results.correlation_id)"
        ),
        description="A correlation member row records this detection as a member.",
    ),
    RelationshipType.ASSESSED_BY: RelationshipSpec(
        relationship_type=RelationshipType.ASSESSED_BY,
        source_node_type=NodeType.CORRELATION,
        target_node_type=NodeType.RISK_ASSESSMENT,
        v2_source_of_truth="risk_assessments.correlation_id (FK -> correlation_results.correlation_id)",
        description="A risk assessment row is scoped to this correlation.",
    ),
    RelationshipType.ASSOCIATED_WITH_INDICATOR: RelationshipSpec(
        relationship_type=RelationshipType.ASSOCIATED_WITH_INDICATOR,
        source_node_type=NodeType.EVENT,
        target_node_type=NodeType.THREAT_INDICATOR,
        v2_source_of_truth=(
            "threat_intel_lookups.event_id + threat_intel_lookups.indicator_id "
            "(FK -> threat_intel_indicators.id)"
        ),
        description=(
            "A threat-intel lookup row recorded an enrichment attempt binding "
            "this event identifier to this indicator."
        ),
    ),
    RelationshipType.RECALLED_BY: RelationshipSpec(
        relationship_type=RelationshipType.RECALLED_BY,
        source_node_type=NodeType.CORRELATION,
        target_node_type=NodeType.INCIDENT_MEMORY,
        v2_source_of_truth="incident_memories.correlation_id (soft reference, no FK by V2 design)",
        description="An incident memory row records this correlation as its origin.",
    ),
    RelationshipType.REQUIRES_APPROVAL: RelationshipSpec(
        relationship_type=RelationshipType.REQUIRES_APPROVAL,
        source_node_type=NodeType.CORRELATION,
        target_node_type=NodeType.APPROVAL,
        v2_source_of_truth="approval_requests.correlation_id (soft reference, no FK by V2 design)",
        description="An approval request row is scoped to this correlation.",
    ),
    RelationshipType.AUTHORIZED_EXECUTION: RelationshipSpec(
        relationship_type=RelationshipType.AUTHORIZED_EXECUTION,
        source_node_type=NodeType.APPROVAL,
        target_node_type=NodeType.SOAR_EXECUTION,
        v2_source_of_truth="soar_executions.approval_id -> approval_requests.approval_id",
        description="A SOAR execution row records this approval as its authorization.",
    ),
    RelationshipType.RESPONDED_BY_EXECUTION: RelationshipSpec(
        relationship_type=RelationshipType.RESPONDED_BY_EXECUTION,
        source_node_type=NodeType.CORRELATION,
        target_node_type=NodeType.SOAR_EXECUTION,
        v2_source_of_truth="soar_executions.correlation_id (soft reference, no FK by V2 design)",
        description="A SOAR execution row records this correlation as its target scope.",
    ),
    RelationshipType.REPORTED_BY: RelationshipSpec(
        relationship_type=RelationshipType.REPORTED_BY,
        source_node_type=NodeType.CORRELATION,
        target_node_type=NodeType.INCIDENT_REPORT,
        v2_source_of_truth="incident_reports.correlation_id (soft reference, no FK by V2 design)",
        description="An incident report row records this correlation as its subject.",
    ),
    RelationshipType.INVESTIGATED_BY_HUNT: RelationshipSpec(
        relationship_type=RelationshipType.INVESTIGATED_BY_HUNT,
        source_node_type=NodeType.CORRELATION,
        target_node_type=NodeType.THREAT_HUNT,
        v2_source_of_truth=(
            "threat_hunt_evidence.correlation_id + threat_hunt_evidence.hunt_id "
            "(FK -> threat_hunts.hunt_id)"
        ),
        description="A threat-hunt evidence row cites this correlation.",
    ),
}


#: Entity kinds the brief asks the graph to answer about but for which V2
#: persists no identity.  Surfaced by the API so a missing answer is explicit
#: rather than silently absent.
UNAVAILABLE_GRAPH_ENTITIES: Final[dict[str, str]] = {
    "INVESTIGATION": (
        "No investigations table exists in V2; AI investigation output is not "
        "persisted as a queryable record, so no evidence-backed node can exist."
    ),
    "POLICY_DECISION": (
        "No policy_decisions table exists in V2; approval_requests.policy_decision_id "
        "is an unenforced reference with no row to point at."
    ),
    "ATTACK_PATH": (
        "V2.21 attack paths are a computed read-only projection with no persisted "
        "identity; V3.22 does not replace or infer them."
    ),
}


# ---------------------------------------------------------------------------
# Metadata allowlist — the primary secret-safety control
# ---------------------------------------------------------------------------

#: Per node type, the ONLY scalar columns ever read into graph metadata.
#:
#: JSONB columns are deliberately absent everywhere: ``evidence``,
#: ``result_metadata``, ``payload``, ``memory_metadata``, ``execution_metadata``,
#: ``filters``, ``steps``, ``sources``, ``indicators``, ``entities``,
#: ``techniques``, ``findings``, ``actions``, ``outcomes``, ``factors``,
#: ``assessment_metadata``, ``context``, ``definition`` and ``evidence`` may all
#: carry raw event payloads or provider responses.  They are never read, so
#: they cannot leak.
SAFE_METADATA_FIELDS: Final[dict[NodeType, tuple[str, ...]]] = {
    NodeType.EVENT: ("observed_at",),
    NodeType.DETECTION: (
        "rule_id",
        "rule_type",
        "rule_version",
        "severity",
        "matched",
        "confidence",
        "detected_at",
        "provenance",
    ),
    NodeType.CORRELATION: ("status", "confidence", "provenance", "timestamp"),
    NodeType.RISK_ASSESSMENT: (
        "score",
        "level",
        "confidence",
        "provenance",
        "timestamp",
    ),
    NodeType.THREAT_INDICATOR: (
        "indicator_type",
        "value",
        "first_seen_at",
        "last_seen_at",
    ),
    NodeType.INCIDENT_MEMORY: (
        "memory_type",
        "title",
        "confidence",
        "provenance",
    ),
    NodeType.THREAT_HUNT: (
        "name",
        "hunt_type",
        "status",
        "result_count",
        "finding_count",
        "timeline_count",
    ),
    NodeType.APPROVAL: (
        "action_type",
        "status",
        "risk_level",
        "risk_score",
        "confidence",
        "provenance",
        "policy_rule_id",
        "response_status",
        "requested_at",
        "expires_at",
        "resolved_at",
    ),
    NodeType.SOAR_EXECUTION: (
        "playbook_id",
        "playbook_version",
        "primary_action",
        "status",
        "simulated",
        "failure_policy",
        "started_at",
        "completed_at",
        "created_by_role",
    ),
    NodeType.INCIDENT_REPORT: (
        "status",
        "title",
        "model",
        "generated_by_role",
        "generated_at",
        "error_code",
    ),
}


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphBounds:
    """Hard limits applied to every traversal.

    Validated on construction so a misconfigured bound can never silently
    widen a traversal or make paging meaningless.
    """

    max_nodes: int = 500
    max_edges: int = 2000
    max_depth: int = 5
    default_page_size: int = 100
    max_page_size: int = 200

    def __post_init__(self) -> None:
        if self.max_nodes < 1:
            raise ValueError("max_nodes must be at least 1")
        if self.max_edges < 1:
            raise ValueError("max_edges must be at least 1")
        if self.max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        if self.max_page_size < 1:
            raise ValueError("max_page_size must be at least 1")
        if self.default_page_size < 1:
            raise ValueError("default_page_size must be at least 1")
        if self.default_page_size > self.max_page_size:
            raise ValueError(
                "default_page_size must not exceed max_page_size "
                f"({self.default_page_size} > {self.max_page_size})"
            )


DEFAULT_BOUNDS: Final[GraphBounds] = GraphBounds()


class TruncationReason(str, Enum):
    """Why a bounded traversal stopped early.  Always reported explicitly."""

    MAX_NODES = "max_nodes"
    MAX_EDGES = "max_edges"
    MAX_DEPTH = "max_depth"
    PAGE_SIZE = "page_size"


# ---------------------------------------------------------------------------
# Deterministic identity
# ---------------------------------------------------------------------------


def deterministic_node_id(node_type: NodeType, source_id: str) -> uuid.UUID:
    """Return the stable graph node id for a V2 entity."""
    return uuid.uuid5(GRAPH_NAMESPACE, f"{node_type.value}:{source_id}")


def deterministic_edge_id(
    relationship_type: RelationshipType,
    source_node_id: uuid.UUID,
    target_node_id: uuid.UUID,
) -> uuid.UUID:
    """Return the stable graph edge id for a V2 relationship."""
    return uuid.uuid5(
        GRAPH_NAMESPACE,
        f"{relationship_type.value}|{source_node_id}|{target_node_id}",
    )


def source_reference(node_type: NodeType, source_id: str) -> str:
    """Build the node reference, e.g. ``detection:<detection_id>``."""
    spec = NODE_TYPES.get(node_type)
    if spec is None:
        raise VocabularyError(f"unknown node type: {node_type!r}")
    return f"{spec.reference_prefix}:{source_id}"


def parse_node_reference(reference: str) -> tuple[NodeType, str]:
    """Inverse of :func:`source_reference`."""
    prefix, _, source_id = reference.partition(":")
    if not source_id:
        raise VocabularyError(f"malformed source reference: {reference!r}")
    for node_type, spec in NODE_TYPES.items():
        if spec.reference_prefix == prefix:
            return node_type, source_id
    raise VocabularyError(f"unknown source reference prefix: {prefix!r}")


# ---------------------------------------------------------------------------
# Construction with validation
# ---------------------------------------------------------------------------


def build_node(
    node_type: NodeType,
    source_id: str,
    label: str,
    metadata: dict[str, Any] | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Validate and assemble one graph node.

    Raises :class:`VocabularyError` for an unknown node type or for metadata
    outside the per-type allowlist.  Whitelisting here means a caller cannot
    widen the safe surface by accident.
    """
    spec = NODE_TYPES.get(node_type)
    if spec is None:
        raise VocabularyError(f"unknown node type: {node_type!r}")

    source_id = str(source_id).strip()
    if not source_id:
        raise VocabularyError(f"{node_type.value} requires a non-empty source id")

    label = (label or "").strip() or source_id
    label = label[: spec.label_max_length]

    allowed = SAFE_METADATA_FIELDS[node_type]
    safe_metadata: dict[str, Any] = {}
    for key, value in (metadata or {}).items():
        if key not in allowed:
            # Defence in depth: the builder only ever passes allowlisted keys,
            # so reaching this branch means a caller tried to widen the surface.
            raise VocabularyError(
                f"metadata field {key!r} is not allowlisted for {node_type.value}"
            )
        if value is None:
            continue
        safe_metadata[key] = _json_safe(value)

    if node_type is NodeType.EVENT and observed_at is not None:
        # The only permitted event metadata: when the reference was observed.
        safe_metadata["observed_at"] = observed_at.isoformat()

    return {
        "id": deterministic_node_id(node_type, source_id),
        "node_type": node_type,
        "source_id": source_id,
        "label": label,
        "source_reference": f"{spec.reference_prefix}:{source_id}",
        "provenance": spec.provenance,
        "metadata": safe_metadata,
    }


def build_edge(
    relationship_type: RelationshipType,
    source: dict[str, Any],
    target: dict[str, Any],
    source_reference_value: str,
    evidence_references: list[str],
) -> dict[str, Any]:
    """Validate and assemble one graph edge.

    Rejects, before any persistence:
      * a relationship outside the closed vocabulary
      * an endpoint whose node type does not match the relationship
      * a missing/blank ``source_reference``
      * evidence that omits either endpoint or the source reference
    """
    spec = RELATIONSHIPS.get(relationship_type)
    if spec is None:
        raise VocabularyError(f"unknown relationship type: {relationship_type!r}")

    if source["node_type"] is not spec.source_node_type:
        raise VocabularyError(
            f"{relationship_type.value} requires a {spec.source_node_type.value} source, "
            f"got {source['node_type'].value}"
        )
    if target["node_type"] is not spec.target_node_type:
        raise VocabularyError(
            f"{relationship_type.value} requires a {spec.target_node_type.value} target, "
            f"got {target['node_type'].value}"
        )

    source_reference_value = (source_reference_value or "").strip()
    if not source_reference_value:
        raise VocabularyError(
            f"{relationship_type.value} requires a source_reference"
        )

    evidence = [ref for ref in (evidence_references or []) if ref and ref.strip()]
    if not evidence:
        raise VocabularyError(
            f"{relationship_type.value} requires at least one evidence reference"
        )

    required = {
        source["source_reference"],
        target["source_reference"],
        source_reference_value,
    }
    missing = required.difference(evidence)
    if missing:
        raise VocabularyError(
            f"{relationship_type.value} evidence must cite {sorted(missing)}"
        )

    # Deterministic ordering keeps serialized output byte-identical across runs.
    ordered_evidence = sorted(dict.fromkeys(evidence))

    return {
        "id": deterministic_edge_id(
            relationship_type, source["id"], target["id"]
        ),
        "relationship_type": relationship_type,
        "source_node_id": source["id"],
        "target_node_id": target["id"],
        "source_reference": source_reference_value,
        "evidence_references": ordered_evidence,
    }


def _json_safe(value: Any) -> Any:
    """Convert an allowlisted scalar into a JSON-serializable value."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def vocabulary_document() -> dict[str, Any]:
    """Machine-readable description of the closed vocabulary."""
    return {
        "node_types": [
            {
                "node_type": spec.node_type.value,
                "provenance": spec.provenance.value,
                "reference_prefix": spec.reference_prefix,
                "source_of_truth": spec.source_of_truth,
                "reference_only": spec.reference_only,
                "metadata_fields": list(SAFE_METADATA_FIELDS[spec.node_type]),
            }
            for spec in sorted(NODE_TYPES.values(), key=lambda s: s.node_type.value)
        ],
        "relationship_types": [
            {
                "relationship_type": spec.relationship_type.value,
                "source_node_type": spec.source_node_type.value,
                "target_node_type": spec.target_node_type.value,
                "v2_source_of_truth": spec.v2_source_of_truth,
                "description": spec.description,
            }
            for spec in sorted(RELATIONSHIPS.values(), key=lambda s: s.relationship_type.value)
        ],
        "unavailable_entity_types": UNAVAILABLE_GRAPH_ENTITIES,
        "bounds": {
            "max_nodes": DEFAULT_BOUNDS.max_nodes,
            "max_edges": DEFAULT_BOUNDS.max_edges,
            "max_depth": DEFAULT_BOUNDS.max_depth,
            "default_page_size": DEFAULT_BOUNDS.default_page_size,
            "max_page_size": DEFAULT_BOUNDS.max_page_size,
        },
    }


__all__ = [
    "DEFAULT_BOUNDS",
    "GRAPH_NAMESPACE",
    "NODE_TYPES",
    "RELATIONSHIPS",
    "SAFE_METADATA_FIELDS",
    "UNAVAILABLE_GRAPH_ENTITIES",
    "GraphBounds",
    "NodeType",
    "NodeTypeSpec",
    "Provenance",
    "RelationshipSpec",
    "RelationshipType",
    "TruncationReason",
    "VocabularyError",
    "build_edge",
    "build_node",
    "deterministic_edge_id",
    "deterministic_node_id",
    "parse_node_reference",
    "source_reference",
    "vocabulary_document",
]