"""Attack Path Visualization contract — V2.21.

Read-only, evidence-grounded graph projection of **already-persisted**
relationships for one correlation.  Every node and edge is backed by a
persisted record (``source_reference`` + ``evidence_references``), and the
projection carries a provenance value from the shared :class:`Provenance`
enum.  V2.21 never invents an attack step: an edge exists only when a
persisted relationship or a deterministic relationship directly supported
by persisted fields is present, and the projection never fabricates
attacker behavior, never predicts future steps, and never applies a graph
database or knowledge-graph engine.

Closed node set — each type maps to a persisted table:

* ``CORRELATION``            — ``correlation_results``
* ``DETECTION``              — ``detection_results``
* ``INDICATOR``              — ``threat_intel_indicators``
* ``RISK``                   — ``risk_assessments``
* ``MEMORY``                 — ``incident_memories``
* ``HUNT``                   — ``threat_hunts`` (via ``threat_hunt_evidence``
  rows that cite the correlation)
* ``POLICY_DECISION``        — the persisted ``policy_decision_id`` identity
  carried by ``approval_requests.decision``/``soar_executions`` rows
* ``APPROVAL``               — ``approval_requests``
* ``SOAR_EXECUTION``         — ``soar_executions``

Deliberately **absent** node types (their read model in the persisted
store does not carry a separately-provenanced record in V2.21): ``ENTITY``,
``RESPONSE``, ``INVESTIGATION`` and ``ATTRIBUTION``.  A response outcome is
represented by the approved approval request's ``response_status`` fields
and the SOAR execution's ``response_id`` reference; it is not promoted to a
node because no persisted response record exists to anchor a node or a
provenance.

Closed edge set — each relationship is read out of an existing persisted
field or row pair:

* ``CORRELATION_HAS_DETECTION``       — ``correlation_members`` rows
* ``DETECTION_HAS_INDICATOR``         — ``threat_intel_lookups`` rows
  (``event_id`` <=> resolved detection ``event_id``)
* ``CORRELATION_HAS_RISK``            — ``risk_assessments.correlation_id``
* ``CORRELATION_HAS_MEMORY``          — ``incident_memories.correlation_id``
* ``CORRELATION_HAS_HUNT``            — ``threat_hunt_evidence.correlation_id``
* ``CORRELATION_HAS_POLICY_DECISION`` — ``approval_requests`` (correlation +
  policy-decision identity)
* ``POLICY_HAS_APPROVAL``             — ``approval_requests``
* ``CORRELATION_HAS_APPROVAL``        — ``approval_requests.correlation_id``
* ``CORRELATION_HAS_SOAR_EXECUTION``  — ``soar_executions.correlation_id``
* ``POLICY_HAS_SOAR_EXECUTION``       — ``soar_executions.policy_decision_id``
* ``APPROVAL_HAS_SOAR_EXECUTION``     — ``soar_executions.approval_id``

No relationship here asserts lateral movement, attacker intent or any other
inferred step; every relationship is a direct, persisted linkage.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.investigation_context import InputAvailability
from app.schemas.security_event import Provenance

# ---------------------------------------------------------------------------
# Node / edge type vocabulary (closed)
# ---------------------------------------------------------------------------


class AttackPathNodeType(str, Enum):
    """Closed set of graph node types (each backed by a persisted table)."""

    CORRELATION = "correlation"
    DETECTION = "detection"
    INDICATOR = "indicator"
    RISK = "risk"
    MEMORY = "memory"
    HUNT = "hunt"
    POLICY_DECISION = "policy_decision"
    APPROVAL = "approval"
    SOAR_EXECUTION = "soar_execution"


class AttackPathEdgeType(str, Enum):
    """Closed set of evidence-grounded graph edge types."""

    CORRELATION_HAS_DETECTION = "correlation_has_detection"
    DETECTION_HAS_INDICATOR = "detection_has_indicator"
    CORRELATION_HAS_RISK = "correlation_has_risk"
    CORRELATION_HAS_MEMORY = "correlation_has_memory"
    CORRELATION_HAS_HUNT = "correlation_has_hunt"
    CORRELATION_HAS_POLICY_DECISION = "correlation_has_policy_decision"
    POLICY_HAS_APPROVAL = "policy_has_approval"
    CORRELATION_HAS_APPROVAL = "correlation_has_approval"
    CORRELATION_HAS_SOAR_EXECUTION = "correlation_has_soar_execution"
    POLICY_HAS_SOAR_EXECUTION = "policy_has_soar_execution"
    APPROVAL_HAS_SOAR_EXECUTION = "approval_has_soar_execution"


# ---------------------------------------------------------------------------
# Node / edge shapes
# ---------------------------------------------------------------------------


class AttackPathNode(BaseModel):
    """One evidence-grounded node in the attack-path projection.

    ``fields`` is a whitelisted, bounded set of scalar strings taken from
    persisted record columns — never a raw evidence/metadata payload — so a
    display never leaks secrets embedded in stored dicts.  ``label`` is a
    deterministic, control-character-free, bounded human label.
    """

    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(min_length=1, max_length=160)
    node_type: AttackPathNodeType
    label: str = Field(min_length=1, max_length=256)
    provenance: Provenance
    source_reference: str = Field(min_length=1, max_length=160)
    occurrence: datetime | None = None
    status: str | None = Field(default=None, max_length=160)
    severity: str | None = Field(default=None, max_length=64)
    fields: dict[str, str] = Field(default_factory=dict)
    evidence_references: list[str] = Field(default_factory=list)


class AttackPathEdge(BaseModel):
    """One evidence-grounded edge in the attack-path projection.

    ``source_reference`` names the persisted record that establishes the
    relationship (the correlation-member row id, lookup row id, approval
    row id, execution row id, hunt-evidence id, risk-assessment id or
    incident-memory id).  ``evidence_references`` repeats the exact row
    identities so the UI can link back to the store.
    """

    model_config = ConfigDict(extra="forbid")

    edge_id: str = Field(min_length=1, max_length=200)
    source_node_id: str
    target_node_id: str
    relationship_type: AttackPathEdgeType
    provenance: Provenance
    source_reference: str = Field(min_length=1, max_length=160)
    evidence_references: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Availability, metadata, response envelope
# ---------------------------------------------------------------------------


class AttackPathAvailability(BaseModel):
    """Per-surface availability for one attack-path projection.

    Mirrors the V2.20 report availability contract so a viewer can
    distinguish ``not_provided`` (the surface is out of V2.21 scope or was
    not consulted) from ``none_found`` (the surface was consulted and no
    match exists for this correlation).
    """

    model_config = ConfigDict(extra="forbid")

    correlation: InputAvailability
    detections: InputAvailability
    indicators: InputAvailability
    risk_assessment: InputAvailability
    incident_memory: InputAvailability
    threat_hunts: InputAvailability
    policy_decisions: InputAvailability
    approvals: InputAvailability
    soar_executions: InputAvailability
    investigation: InputAvailability = InputAvailability.NOT_PROVIDED
    attribution: InputAvailability = InputAvailability.NOT_PROVIDED
    security_events: InputAvailability = InputAvailability.NOT_PROVIDED


class AttackPathMetadata(BaseModel):
    """Envelope metadata for one attack-path projection."""

    model_config = ConfigDict(extra="forbid")

    correlation_id: uuid.UUID
    generated_at: datetime
    node_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)
    truncated: bool
    limitation: str | None = Field(default=None, max_length=512)
    bounds: dict[str, int] = Field(default_factory=dict)


class AttackPathGraph(BaseModel):
    """Deterministically ordered node + edge projection."""

    model_config = ConfigDict(extra="forbid")

    nodes: list[AttackPathNode] = Field(default_factory=list)
    edges: list[AttackPathEdge] = Field(default_factory=list)


class AttackPathResponse(BaseModel):
    """Full V2.21 attack-path payload for one correlation."""

    model_config = ConfigDict(extra="forbid")

    graph: AttackPathGraph
    metadata: AttackPathMetadata
    availability: AttackPathAvailability


__all__ = [
    "AttackPathNodeType",
    "AttackPathEdgeType",
    "AttackPathNode",
    "AttackPathEdge",
    "AttackPathAvailability",
    "AttackPathMetadata",
    "AttackPathGraph",
    "AttackPathResponse",
]