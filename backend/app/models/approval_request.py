"""Approval request persistence model (V2.16).

The **persistence contract** for a single V2.16 human-in-the-loop
approval request over a ``REQUIRES_APPROVAL`` Step 24 policy decision.

Design intent
-------------
* ``approval_id`` (the deterministic domain identity) and
  ``policy_decision_id`` are both **unique** and indexed: one policy
  decision has exactly one approval lifecycle, and re-creating a request
  for an already-resolved decision is a no-op (or a conflict) rather than
  a second row.
* The request **references** its correlation by plain ``correlation_id``
  with no foreign key — exactly like incident memories: an approval
  record must outlive every lifecycle it cites.  ``requested_by`` /
  ``resolved_by`` do reference ``users.id`` (the trusted identity store
  is authoritative and stable).
* The full ``decision`` snapshot (JSONB) is preserved verbatim so the
  approved path can reconstruct the exact Step 24 decision and re-present
  it to the Step 25 executor — the approval layer never re-judges policy
  and never fabricates an ``ALLOWED`` state.
* ``action_type`` / ``risk_level`` / ``status`` / ``provenance`` are all
  CHECK-pinned closed vocabularies.  ``provenance`` is constrained to
  ``approval_reviewed`` so an approval can never be persisted as any prior
  value.
* ``response_status`` / ``response_provider`` / ``response_error_code``
  record, for an *approved* request only, what the Step 25 Response layer
  subsequently did.  They are deliberately distinct from ``status``:
  approved != executed.
* Expiry is lazy (no scheduler): pending requests are expired on read by
  comparing ``expires_at``, and transitions are conditional
  (``status = 'pending' AND expires_at > now``).

This model defines the layout only; the repository/service that drives it
(Step V2.16) is implemented separately.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.approval import (
    APPROVAL_MAX_COMMENT_LENGTH,
    APPROVAL_MAX_REASON_LENGTH,
    APPROVAL_MAX_ROLE_LENGTH,
    APPROVAL_MAX_RULE_ID_LENGTH,
    APPROVAL_MAX_TARGET_LENGTH,
)
from app.schemas.security_event import Provenance


class ApprovalRequestRow(UUIDTimestampMixin, Base):
    """A single persisted approval request.

    Attributes:
        approval_id: Deterministic domain identity (UUIDv5).  Unique.
        policy_decision_id: The Step 24 decision being routed.  Unique —
            one decision has exactly one approval lifecycle.
        correlation_id: The correlation the decision concerns (plain
            reference, no FK — approvals outlive cited lifecycles).
        action_type: Proposed action, inherited from the decision, pinned
            to the six Step 24 members.
        target: Canonicalized controlled target identifier.
        status: pending / approved / rejected / expired / cancelled.
        reason: The decision's deterministic policy reason.
        policy_rule_id: The policy rule that required approval.
        risk_level / risk_score / confidence: carried from the decision.
        evidence: Sanitized structured references from the decision.
        decision: Full decision snapshot (JSONB) for reconstruction.
        request_note: Optional secret-free requester note.
        requested_by / requested_by_role: Who asked (trusted identity).
        requested_at / expires_at: Time window for a human decision.
        resolved_at / resolved_by / resolution_reason: How it resolved.
        response_status / response_provider / response_error_code: What
            the Step 25 layer did after an APPROVED grant (distinct from
            the approval status).
        provenance: Always ``approval_reviewed`` (CHECK-pinned).
    """

    __tablename__ = "approval_requests"
    __table_args__ = (
        CheckConstraint(
            "action_type IN ('block_ip', 'block_domain', 'quarantine_file', "
            "'disable_account', 'terminate_session', 'isolate_endpoint')",
            name="approval_action_type",
        ),
        CheckConstraint(
            "risk_level IN ('low', 'medium', 'high', 'critical')",
            name="approval_risk_level",
        ),
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')",
            name="approval_status",
        ),
        CheckConstraint(
            "response_status IS NULL OR response_status IN "
            "('executed', 'failed', 'skipped', 'rejected')",
            name="approval_response_status",
        ),
        CheckConstraint(
            "length(target) <= 512",
            name="approval_target_length",
        ),
        CheckConstraint(
            "length(reason) <= 500",
            name="approval_reason_length",
        ),
        CheckConstraint(
            "length(policy_rule_id) <= 64",
            name="approval_rule_id_length",
        ),
        CheckConstraint(
            "request_note IS NULL OR length(request_note) <= 500",
            name="approval_request_note_length",
        ),
        CheckConstraint(
            "length(requested_by_role) <= 32",
            name="approval_requested_by_role_length",
        ),
        CheckConstraint(
            "resolution_reason IS NULL OR length(resolution_reason) <= 500",
            name="approval_resolution_reason_length",
        ),
        CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0.0 AND risk_score <= 1.0)",
            name="approval_risk_score_range",
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)",
            name="approval_confidence_range",
        ),
        CheckConstraint(
            "provenance = 'approval_reviewed'",
            name="approval_provenance",
        ),
        CheckConstraint(
            "status = 'pending' OR resolved_at IS NOT NULL",
            name="approval_resolved_at",
        ),
        CheckConstraint(
            "status IN ('pending', 'expired') OR resolved_by IS NOT NULL",
            name="approval_resolved_by",
        ),
    )

    approval_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        comment=(
            "Deterministic domain identity of this approval (UUIDv5 over "
            "decision/action/target/requester content).  Unique "
            "- one approval = one identity forever."
        ),
    )

    policy_decision_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        comment=(
            "The Step 24 policy decision being routed.  Unique — one "
            "decision has exactly one approval lifecycle."
        ),
    )

    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment=(
            "The Step 10A correlation the decision concerns.  Deliberately "
            "a plain UUID with NO foreign key: an approval record must "
            "outlive the correlation lifecycle it cites (mirrors the "
            "incident-memory convention)."
        ),
    )

    action_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment=(
            "Proposed action, inherited from the decision, pinned by CHECK "
            "to the six Step 24 members.  Never supplied by the client."
        ),
    )

    target: Mapped[str] = mapped_column(
        String(APPROVAL_MAX_TARGET_LENGTH),
        nullable=False,
        comment=(
            "Canonicalized controlled target identifier, structurally "
            "validated per action by the Response validator.  Bounded to "
            "512 characters by CHECK."
        ),
    )

    status: Mapped[str] = mapped_column(
        String(16),
        default="pending",
        nullable=False,
        index=True,
        comment=(
            "pending / approved / rejected / expired / cancelled "
            "(CHECK-pinned).  Terminal states never transition; approved "
            "is idempotent and never re-executes."
        ),
    )

    reason: Mapped[str] = mapped_column(
        String(APPROVAL_MAX_REASON_LENGTH),
        nullable=False,
        comment=(
            "The decision's deterministic policy reason, preserved verbatim "
            "and bounded to 500 characters by CHECK."
        ),
    )

    policy_rule_id: Mapped[str] = mapped_column(
        String(APPROVAL_MAX_RULE_ID_LENGTH),
        nullable=False,
        comment=(
            "The policy rule that required approval (the rule id cited by "
            "the decision)."
        ),
    )

    risk_level: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="Risk level carried from the decision (low/medium/high/critical).",
    )

    risk_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Risk score carried from the decision, when available, in [0.0, 1.0].",
    )

    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Confidence carried from the decision, when available, in [0.0, 1.0].",
    )

    evidence: Mapped[list] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        comment=(
            "Sanitized, structured references preserved from the decision "
            "(JSONB) — never fabricated, never rewritten."
        ),
    )

    decision: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Full Step 24 decision snapshot (JSONB) preserved verbatim so "
            "the approved path can reconstruct the exact decision and "
            "re-present it to the Step 25 executor."
        ),
    )

    request_note: Mapped[str | None] = mapped_column(
        String(APPROVAL_MAX_COMMENT_LENGTH),
        nullable=True,
        comment="Optional secret-free requester note for the human reviewer.",
    )

    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
        comment="Authenticated identity of the requester (trusted identity store).",
    )

    requested_by_role: Mapped[str] = mapped_column(
        String(APPROVAL_MAX_ROLE_LENGTH),
        nullable=False,
        comment="The requester's role as read from the trusted identity store.",
    )

    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Timezone-aware instant the request was created.",
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment=(
            "Timezone-aware instant the pending request expires (fixed TTL; "
            "lazy-expired, no scheduler)."
        ),
    )

    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timezone-aware instant a human (or lapse) resolved the request.",
    )

    resolved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True,
        comment="Authenticated identity of the human who resolved the request.",
    )

    resolution_reason: Mapped[str | None] = mapped_column(
        String(APPROVAL_MAX_COMMENT_LENGTH),
        nullable=True,
        comment="The human's own comment, or the documentary expiry reason.",
    )

    response_status: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        comment=(
            "What the Step 25 Response layer did after an APPROVED grant "
            "('executed'/'failed'/'skipped'/'rejected', CHECK-pinned).  "
            "Distinct from and never conflated with the approval status."
        ),
    )

    response_provider: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment=(
            "Which provider ran when an approved grant reached the Response "
            "layer (simulated mock in V2.16), or None when nothing ran."
        ),
    )

    response_error_code: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Sanitized response error/rejection code when applicable.",
    )

    provenance: Mapped[str] = mapped_column(
        String(32),
        default=Provenance.APPROVAL_REVIEWED.value,
        nullable=False,
        comment=(
            "Envelope-level provenance, constrained by CHECK to "
            "APPROVAL_REVIEWED — an approval is a human governance action "
            "and can never be stored as any prior value."
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<ApprovalRequestRow id={self.id} "
            f"approval_id={self.approval_id} "
            f"decision={self.policy_decision_id} "
            f"status={self.status}>"
        )