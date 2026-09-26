"""Detection Rules API (Step 26) — read-only surface for the loaded rule set.

Exposes the repository Sigma + YARA rule set (loaded via
:mod:`app.services.detection.rule_loader`) together with *real* persisted
match statistics through a thin FastAPI transport.

Architecture::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> DetectionRuleQueryService (Step 26, read-only)
        -> detection_rule_query response schema
        -> HTTP response

Design principles:

* **Thin transport only** — every route validates its HTTP input, calls one
  ``DetectionRuleQueryService`` method, and returns a read model.  No route
  constructs its own SQL, evaluates rules, or mutates state.
* **Read-only** — only ``GET`` endpoints.  Enabling/disabling rules is out
  of scope for the management view (the registry semantics remain owned by
  the registry/detection layer).
* **Reuses existing security** — the existing JWT ``HTTPBearer`` dependency
  and ``require_role`` RBAC factory are reused verbatim.
* **Real statistics only** — match counts, last-matched timestamps, and
  analytics buckets are computed from persisted ``detection_results`` rows;
  a rule that never matched reports ``0`` / ``None`` honestly.
* **Consistent HTTP semantics** — miss on an exact rule lookup returns 404;
  the collection returns 200 with the loaded rules as ``items``; invalid
  windows are rejected with 422.

Static/segmented paths (``/analytics``) are registered before the
parameterized ``/{rule_id}`` route so they never resolve as a rule id.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, require_role
from app.models.user import User
from app.schemas.detection_rule_query import (
    DetectionRuleAnalytics,
    DetectionRuleDetail,
    DetectionRuleRecord,
)
from app.services.detection_rule_query import DetectionRuleQueryService

logger = logging.getLogger(__name__)

router = APIRouter()

#: Same SOC role model as every other detection-facing surface.
_SOC_ROLES = ("admin", "analyst", "ciso")

#: Stateless, read-only rule query service shared by every route.
_service = DetectionRuleQueryService()


@router.get(
    "",
    response_model=list[DetectionRuleRecord],
    summary="List loaded detection rules with real match statistics",
)
def list_detection_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),  # noqa: ARG001
) -> list[DetectionRuleRecord]:
    """Return every Sigma + YARA rule currently loaded from the repo rule set.

    Each entry carries the rule's definition metadata plus its real
    persisted match count and newest match timestamp (0 / ``None`` when the
    rule never matched).
    """
    return _service.list_rules(db)


@router.get(
    "/analytics",
    response_model=DetectionRuleAnalytics,
    summary="Detection activity over a bounded window",
)
def detection_rule_analytics(
    window: str = Query(
        default="30d",
        pattern="^(1h|6h|24h|7d|30d)$",
        description="Window: 1h, 6h, 24h, 7d or 30d.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),  # noqa: ARG001
) -> DetectionRuleAnalytics:
    """Return persisted detection activity over *window*.

    Only rows whose ``rule_id`` belongs to the loaded rule set are counted;
    if the window has no data the buckets are empty and totals are zero —
    reported honestly, never fabricated.
    """
    return _service.analytics(db, window)


@router.get(
    "/{rule_id}",
    response_model=DetectionRuleDetail,
    summary="Fetch one detection rule with its preview content",
)
def get_detection_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),  # noqa: ARG001
) -> DetectionRuleDetail:
    """Return a single rule plus its evaluator-ready content.

    404 when *rule_id* is not among the loaded repository rules.
    """
    rule = _service.get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )
    return rule