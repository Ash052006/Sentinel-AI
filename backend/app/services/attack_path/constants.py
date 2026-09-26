"""Attack Path Visualization bounds and surface priorities — V2.21.

Explicit, documented caps.  When a cap is reached the builder applies a
deterministic expansion stop and flags ``truncated`` in metadata — truncation
is never silent.  ``SURFACE_PRIORITY`` drives the deterministic global-bound
trim (the most auxiliary surfaces are trimmed first, in a fixed order).
"""

from __future__ import annotations

from app.schemas.attack_path import AttackPathNodeType

# Global graph bounds (both enforced after assembly, deterministically).
MAX_ATTACK_PATH_NODES = 120
MAX_ATTACK_PATH_EDGES = 240

# Per-surface expansion caps.
MAX_CORRELATION_DETECTIONS = 40
MAX_CORRELATION_INDICATORS = 40
MAX_LOOKUPS_PER_DETECTION = 8
MAX_CORRELATION_RISK_ASSESSMENTS = 10
MAX_CORRELATION_MEMORIES = 20
MAX_CORRELATION_HUNTS = 10
MAX_CORRELATION_APPROVALS = 20
MAX_CORRELATION_SOAR_EXECUTIONS = 20

# Deterministic trim order for the global node/edge bounds.  Lower number =
# kept first (core surfaces); higher number = trimmed first (auxiliary).
SURFACE_PRIORITY: dict[AttackPathNodeType, int] = {
    AttackPathNodeType.CORRELATION: 0,
    AttackPathNodeType.DETECTION: 1,
    AttackPathNodeType.INDICATOR: 2,
    AttackPathNodeType.RISK: 3,
    AttackPathNodeType.MEMORY: 4,
    AttackPathNodeType.HUNT: 5,
    AttackPathNodeType.POLICY_DECISION: 6,
    AttackPathNodeType.APPROVAL: 7,
    AttackPathNodeType.SOAR_EXECUTION: 8,
}

# A readable name per surface used in limitation strings.
SURFACE_LABEL: dict[AttackPathNodeType, str] = {
    AttackPathNodeType.CORRELATION: "correlation",
    AttackPathNodeType.DETECTION: "detections",
    AttackPathNodeType.INDICATOR: "indicators",
    AttackPathNodeType.RISK: "risk assessments",
    AttackPathNodeType.MEMORY: "incident memories",
    AttackPathNodeType.HUNT: "threat hunts",
    AttackPathNodeType.POLICY_DECISION: "policy decisions",
    AttackPathNodeType.APPROVAL: "approvals",
    AttackPathNodeType.SOAR_EXECUTION: "soar executions",
}

# Machine-readable bounds summary surfaced in metadata.bounds.
ATTACK_PATH_BOUNDS: dict[str, int] = {
    "max_nodes": MAX_ATTACK_PATH_NODES,
    "max_edges": MAX_ATTACK_PATH_EDGES,
    "max_detections": MAX_CORRELATION_DETECTIONS,
    "max_indicators": MAX_CORRELATION_INDICATORS,
    "max_lookups_per_detection": MAX_LOOKUPS_PER_DETECTION,
    "max_risk_assessments": MAX_CORRELATION_RISK_ASSESSMENTS,
    "max_memories": MAX_CORRELATION_MEMORIES,
    "max_hunts": MAX_CORRELATION_HUNTS,
    "max_approvals": MAX_CORRELATION_APPROVALS,
    "max_soar_executions": MAX_CORRELATION_SOAR_EXECUTIONS,
}


def surface_priority(node_type: AttackPathNodeType) -> int:
    """Return the deterministic trim priority for a node type."""
    return SURFACE_PRIORITY[node_type]


__all__ = [
    "MAX_ATTACK_PATH_NODES",
    "MAX_ATTACK_PATH_EDGES",
    "MAX_CORRELATION_DETECTIONS",
    "MAX_CORRELATION_INDICATORS",
    "MAX_LOOKUPS_PER_DETECTION",
    "MAX_CORRELATION_RISK_ASSESSMENTS",
    "MAX_CORRELATION_MEMORIES",
    "MAX_CORRELATION_HUNTS",
    "MAX_CORRELATION_APPROVALS",
    "MAX_CORRELATION_SOAR_EXECUTIONS",
    "SURFACE_PRIORITY",
    "SURFACE_LABEL",
    "ATTACK_PATH_BOUNDS",
    "surface_priority",
]