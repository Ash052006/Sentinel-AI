"""Deterministic policy-decision identity derivation — Hardening H2.F-01.

Single source of truth for the UUIDv5 ``policy_decision_id`` that the
engine mints at decision time and that the approval workflow recomputes
before trusting a submitted decision.

A ``policy_decision_id`` is a UUIDv5 over the *canonical* decision content
(a fixed set of nine fields, serialized with ``sort_keys`` + compact
separators).  Because the content is self-contained — the id is a pure
function of the decision's own fields — any consumer can independently
recompute it and reject decisions whose id does not match their content.
Submitting a decision with a *different* id than its own fields imply is
therefore self-inconsistent (either a client bug or a client attempting
to fabricate engine provenance), and is rejected.

The engine and the verification path MUST share this implementation: the
byte-exact content and serialization are fixed here and nowhere else.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from app.schemas.policy_decision import POLICY_DECISION_NAMESPACE, PolicyDecision

#: Fixed, canonical JSON serialization for identity content.  Never change
#: these parameters: doing so silently mints a *different* identity for the
#: same decision.
_SERIALIZE_KWARGS: dict[str, Any] = {
    "sort_keys": True,
    "separators": (",", ":"),
    "default": str,
}


def policy_decision_id_content(
    *,
    correlation_id: Any,
    requested_action: Any,
    decision: Any,
    policy_rule_id: str,
    reason: str,
    risk_level: Any,
    risk_score: float,
    confidence: float | None,
    timestamp: Any,
) -> dict[str, Any]:
    """Build the canonical content a ``policy_decision_id`` is derived from.

    Values are normalized exactly as the engine assembles them: enums and
    datetimes become their string forms, so a recomputed identity from a
    deserialized decision equals the engine-minted identity byte-for-byte.
    """
    return {
        "correlation_id": str(correlation_id),
        "requested_action": (
            requested_action.value
            if not isinstance(requested_action, str)
            else requested_action
        ),
        "decision": decision.value if not isinstance(decision, str) else decision,
        "policy_rule_id": policy_rule_id,
        "reason": reason,
        "risk_level": risk_level.value if not isinstance(risk_level, str) else risk_level,
        "risk_score": risk_score,
        "confidence": confidence,
        "timestamp": timestamp.isoformat()
        if isinstance(timestamp, datetime)
        else str(timestamp),
    }


def derive_policy_decision_id(content: dict[str, Any]) -> uuid.UUID:
    """Derive the UUIDv5 identity for fully-normalized decision content."""
    canonical = json.dumps(content, **_SERIALIZE_KWARGS)
    return uuid.uuid5(POLICY_DECISION_NAMESPACE, canonical)


def recompute_decision_id(decision: PolicyDecision) -> uuid.UUID:
    """Re-derive the identity a validated decision *must* carry.

    Used by trusting consumers (the approval workflow) to confirm a
    submitted decision is self-consistent; if this differs from
    ``decision.policy_decision_id`` the decision was altered or minted by
    something other than the engine.
    """
    content = policy_decision_id_content(
        correlation_id=decision.correlation_id,
        requested_action=decision.requested_action,
        decision=decision.decision,
        policy_rule_id=decision.policy_rule_id,
        reason=decision.reason,
        risk_level=decision.risk_level,
        risk_score=decision.risk_score,
        confidence=decision.confidence,
        timestamp=decision.timestamp,
    )
    return derive_policy_decision_id(content)


__all__ = [
    "policy_decision_id_content",
    "derive_policy_decision_id",
    "recompute_decision_id",
]