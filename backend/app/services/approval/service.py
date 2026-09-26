"""Approval orchestration service (V2.16) — human-in-the-loop governance.

Routes a ``REQUIRES_APPROVAL`` Step 24 policy decision to an authorized
human, records their decision as a permanent, provenance-pinned approval
record, and — only when granted — hands the *original* decision (rebuilt
from its persisted snapshot) to the Step 25 Response layer so the mock
provider can simulate the action under the executor's independent gate.

Doctrine enforced here:

* **Humans decide; nothing else.** Approvals are created from concrete
  policy decisions, and every resolution (approve/reject/cancel) is a
  human act recorded with the actor's trusted identity and comment.  No
  LLM, no engine, no auto-approval, no scoring — ever.
* **Approval is authorization, not execution.**  ``approved`` only grants
  the underlying decision; the Response layer (which owns its own gate)
  does all execution.  ``response_status`` is a *different* field.
* **One lifecycle per decision.**  ``policy_decision_id`` is unique.
  Re-creating a later request for the same decision is idempotent while
  PENDING/APPROVED and a conflict once resolved.
* **Concurrency-safe transitions.**  Resolution is a single conditional
  ``UPDATE ... WHERE status='pending' AND expires_at > now`` so exactly one
  simultaneous human wins; an already-expired pending request can never be
  approved.
* **Deterministic identity.**  ``approval_id`` is a UUIDv5 over
  (decision, action, target, requester) content — no randomness.
* **Idempotent grants.**  Approving an already-approved request returns the
  stored record and never re-executes.
* **The approved path re-presents the same decision** (rebuilt from the
  stored snapshot) — it never fabricates an ``ALLOWED`` state.
* **Decisions must be self-consistent.**  The decision submitted for
  routing must carry the deterministic ``policy_decision_id`` its own
  content implies (recomputed here against the engine's canonical
  derivation).  A decision whose id does not match its fields is rejected
  outright — no record is created, so nothing can be probed or poisoned
  through the routing boundary (H2.F-01).
* **Dual-control (four-eyes).**  The user who *requested* an approval
  cannot also *resolve* it.  Approvals are a two-person control: one SOC
  member requests, a *different* SOC member approves/rejects/cancels.  A
  requester attempting to resolve their own request is rejected before any
  state transition (H2.F-04).

The service owns transactions.  It receives the caller-owned ``db``
session, commits its own units (creation / resolution), and audits each
consumer-visible lifecycle step via :func:`log_action` after its commit so
the audit trail cannot be rolled back with a later failure.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.approval_request import ApprovalRequestRow
from app.repositories.approval import ApprovalRepository
from app.schemas.approval import (
    APPROVAL_NAMESPACE,
    APPROVAL_PENDING_TTL,
    ApprovalDecisionInput,
    ApprovalPage,
    ApprovalRecord,
    ApprovalRequestCreate,
    ApprovalStatus,
)
from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)
from app.schemas.response import ResponseRequest
from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance
from app.services.approval.errors import (
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalServiceError,
    ApprovalValidationError,
)
from app.services.audit_service import log_action
from app.services.policy.identity import recompute_decision_id
from app.services.response import validator as _v  # noqa: A004
from app.services.response.approval_gate import (
    APPROVAL_EXPIRED,
    APPROVAL_MISMATCH,
    APPROVAL_NOT_APPROVED,
    APPROVAL_NOT_GIVEN,
    APPROVAL_UNKNOWN,
    ApprovalGateResult,
    ApprovalVerifier,
    GRANT_GRANTED,
)
from app.services.response.errors import (
    ResponseInternalError,
    ResponseValidationError,
)
from app.services.response.service import ResponseMitigationService

logger = logging.getLogger(__name__)

#: Default page size for paginated reads (bounded offset pagination).
DEFAULT_PAGE_SIZE = 50

#: Hard cap on a single page.
MAX_PAGE_SIZE = 200

#: Default limit for the "recent approvals" feed.
DEFAULT_RECENT_LIMIT = 50

#: Hard cap on the "recent approvals" feed.
MAX_RECENT_LIMIT = 200

#: Roles authorized to drive the workflow (the existing SOC role model).
APPROVAL_SOC_ROLES = ("admin", "analyst", "ciso")


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalize a possibly-naive database instant to tz-aware UTC.

    SQLite stores ``DateTime(timezone=True)`` as naive UTC; PostgreSQL
    returns tz-aware values.  Normalizing at the read boundary gives both
    backends identical records.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _to_record(row: ApprovalRequestRow) -> ApprovalRecord:
    """Convert a persisted row into its approved-path read record."""
    decision = PolicyDecision.model_validate(row.decision)
    return ApprovalRecord(
        id=row.id,
        approval_id=row.approval_id,
        policy_decision_id=row.policy_decision_id,
        correlation_id=row.correlation_id,
        action_type=ResponseActionType(decision.requested_action),
        target=row.target,
        status=ApprovalStatus(row.status),
        reason=row.reason,
        policy_rule_id=row.policy_rule_id,
        risk_level=RiskLevel(row.risk_level),
        risk_score=row.risk_score,
        confidence=row.confidence,
        evidence=list(row.evidence or []),
        request_note=row.request_note,
        requested_by=row.requested_by,
        requested_by_role=row.requested_by_role,
        requested_at=_as_utc(row.requested_at),
        expires_at=_as_utc(row.expires_at),
        resolved_at=_as_utc(row.resolved_at),
        resolved_by=row.resolved_by,
        resolution_reason=row.resolution_reason,
        response_status=row.response_status,
        response_provider=row.response_provider,
        response_error_code=row.response_error_code,
        provenance=Provenance(row.provenance),
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )


class ApprovalGrantVerifier:
    """DB-backed :class:`ApprovalVerifier` for the Response executor seam.

    A read-only enforcement stub consulted by the executor *after* the
    approval service has committed an ``approved`` transition, so the grant
    is already durable and visible.  It never changes state.
    """

    def __init__(
        self,
        db: Session,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._db = db
        self._clock = clock or _default_now

    def verify_grant(
        self,
        *,
        approval_id: uuid.UUID | None,
        policy_decision_id: uuid.UUID,
        action_type: ResponseActionType,
        now: datetime,
    ) -> ApprovalGateResult:
        if approval_id is None:
            return ApprovalGateResult(ok=False, error_code=APPROVAL_NOT_GIVEN)
        row = ApprovalRepository(self._db).get_by_approval_id(approval_id)
        if row is None:
            return ApprovalGateResult(ok=False, error_code=APPROVAL_UNKNOWN)
        if (
            row.policy_decision_id != policy_decision_id
            or row.action_type != action_type.value
        ):
            return ApprovalGateResult(ok=False, error_code=APPROVAL_MISMATCH)
        if row.status == ApprovalStatus.APPROVED.value:
            return GRANT_GRANTED
        if row.status == ApprovalStatus.EXPIRED.value:
            return ApprovalGateResult(ok=False, error_code=APPROVAL_EXPIRED)
        return ApprovalGateResult(ok=False, error_code=APPROVAL_NOT_APPROVED)


class ApprovalService:
    """Orchestrates the human-in-the-loop approval workflow.

    Every method accepts the caller-owned ``db`` session as its first
    argument and commits its own transactions (creation / resolution), so a
    granted approval is permanent even if a later response step fails.
    """

    def __init__(
        self,
        repository_factory: Callable[[Session], ApprovalRepository] = ApprovalRepository,
    ) -> None:
        self._repository_factory = repository_factory

    def _repo(self, db: Session) -> ApprovalRepository:
        return self._repository_factory(db)

    @staticmethod
    def _now(clock: Callable[[], datetime]) -> datetime:
        return clock()

    def _reconcile(self, db: Session, now: datetime) -> None:
        """Lazily expire overdue pending requests (no scheduler)."""
        try:
            self._repo(db).expire_overdue(now=now)
            db.commit()
        except SQLAlchemyError as exc:
            logger.warning("Approval expiry reconciliation failed: %s", exc)
            db.rollback()

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create_request(
        self,
        db: Session,
        payload: ApprovalRequestCreate,
        *,
        actor_user_id: uuid.UUID,
        actor_role: str,
        ip_address: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> ApprovalRecord:
        """Create a pending approval for a REQUIRES_APPROVAL decision.

        Enforces the create doctrine: only ``REQUIRES_APPROVAL`` decisions
        may be routed; the action is inherited from the decision; the target
        is structurally validated per action by the Response validator; the
        identity is deterministic.  Re-creating a request whose decision is
        still PENDING or APPROVED returns the existing record
        (idempotently); a resolved decision conflicts (409).
        """
        clock = clock or _default_now
        if payload.decision.decision is not PolicyDecisionStatus.REQUIRES_APPROVAL:
            raise ApprovalValidationError(
                "only REQUIRES_APPROVAL policy decisions can be routed for "
                "human approval"
            )
        if payload.decision.requires_approval is not True:
            raise ApprovalValidationError(
                "the decision must declare requires_approval=True"
            )
        if payload.decision.provenance is not Provenance.POLICY_DECIDED:
            raise ApprovalValidationError(
                "only decisions with provenance POLICY_DECIDED can be routed "
                "for human approval"
            )
        if recompute_decision_id(payload.decision) != payload.decision.policy_decision_id:
            raise ApprovalValidationError(
                "the decision's policy_decision_id does not match its "
                "content; only coherent engine-issued decisions can be "
                "routed for human approval"
            )

        decision = payload.decision
        try:
            target = _v.validate_target(decision.requested_action, payload.target)
        except ResponseValidationError as exc:
            raise ApprovalValidationError(str(exc)) from exc

        now = self._now(clock)
        repo = self._repo(db)

        # One lifecycle per decision: idempotent while pending/approved.
        existing = self._get_existing_or_reconcile(repo, db, decision.policy_decision_id, now)
        if existing is not None:
            return _to_record(existing)

        approval_id = uuid.uuid5(
            APPROVAL_NAMESPACE,
            json.dumps(
                {
                    "policy_decision_id": str(decision.policy_decision_id),
                    "action_type": decision.requested_action.value,
                    "target": target,
                    "requested_by": str(actor_user_id),
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

        row = ApprovalRequestRow(
            approval_id=approval_id,
            policy_decision_id=decision.policy_decision_id,
            correlation_id=decision.correlation_id,
            action_type=decision.requested_action.value,
            target=target,
            status=ApprovalStatus.PENDING.value,
            reason=decision.reason,
            policy_rule_id=decision.policy_rule_id,
            risk_level=decision.risk_level.value,
            risk_score=decision.risk_score,
            confidence=decision.confidence,
            evidence=[item.model_dump(mode="json") for item in decision.evidence],
            decision=decision.model_dump(mode="json"),
            request_note=payload.request_note,
            requested_by=actor_user_id,
            requested_by_role=actor_role,
            requested_at=now,
            expires_at=now + APPROVAL_PENDING_TTL,
        )
        repo.add(row)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            stale = self._get_existing_or_reconcile(
                repo, db, decision.policy_decision_id, now
            )
            if stale is not None:
                return _to_record(stale)
            raise ApprovalServiceError("failed to persist the approval request") from exc
        except SQLAlchemyError as exc:
            db.rollback()
            raise ApprovalServiceError("failed to persist the approval request") from exc

        log_action(
            db,
            "approval.created",
            user_id=actor_user_id,
            resource=f"approval:{row.approval_id}",
            details=f"routed decision {row.policy_decision_id} for human approval",
            ip_address=ip_address,
        )
        return _to_record(row)

    def _get_existing_or_reconcile(
        self,
        repo: ApprovalRepository,
        db: Session,
        policy_decision_id: uuid.UUID,
        now: datetime,
    ) -> ApprovalRequestRow | None:
        """Return the decision's existing request, expiring it first if it
        lapsed; raise a conflict when the decision already resolved."""
        existing = repo.get_by_policy_decision_id(policy_decision_id)
        if existing is None:
            return None
        repo.expire_overdue(now=now)
        db.commit()
        existing = repo.get_by_policy_decision_id(policy_decision_id)
        if existing.status in (
            ApprovalStatus.PENDING.value,
            ApprovalStatus.APPROVED.value,
        ):
            return existing
        raise ApprovalConflictError(
            f"a request for decision {policy_decision_id} has already resolved"
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_request(
        self,
        db: Session,
        approval_id: uuid.UUID | str,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> ApprovalRecord | None:
        """Return one approval record by domain ``approval_id`` (or None)."""
        approval_id = self._coerce_uuid(approval_id, field="approval_id")
        now = self._now(clock or _default_now)
        self._reconcile(db, now)
        try:
            row = self._repo(db).get_by_approval_id(approval_id)
        except SQLAlchemyError as exc:
            raise self._db_error(exc, approval_id=approval_id) from exc
        return None if row is None else _to_record(row)

    def list_requests(
        self,
        db: Session,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        status: ApprovalStatus | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> ApprovalPage:
        """Return one deterministic page of approval records."""
        page, page_size = self._validate_page(page, page_size)
        now = self._now(clock or _default_now)
        self._reconcile(db, now)
        repo = self._repo(db)
        try:
            total = repo.count_rows(
                status=None if status is None else status.value
            )
            rows = repo.list_page(
                limit=page_size,
                offset=(page - 1) * page_size,
                status=None if status is None else status.value,
            )
        except SQLAlchemyError as exc:
            raise self._db_error(exc) from exc
        return ApprovalPage(
            items=[_to_record(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

    def list_recent_requests(
        self,
        db: Session,
        *,
        limit: int = DEFAULT_RECENT_LIMIT,
        status: ApprovalStatus | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> list[ApprovalRecord]:
        """Return up to *limit* newest approval records (bounded feed)."""
        limit = self._validate_recent_limit(limit)
        now = self._now(clock or _default_now)
        self._reconcile(db, now)
        try:
            rows = self._repo(db).list_recent(
                limit=limit,
                status=None if status is None else status.value,
            )
        except SQLAlchemyError as exc:
            raise self._db_error(exc) from exc
        return [_to_record(row) for row in rows]

    def expire_pending(
        self,
        db: Session,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> int:
        """Force a lazy-expiry reconciliation pass; returns how many expired."""
        now = self._now(clock or _default_now)
        try:
            n = self._repo(db).expire_overdue(now=now)
            db.commit()
        except SQLAlchemyError as exc:
            db.rollback()
            raise self._db_error(exc) from exc
        if n:
            log_action(
                db,
                "approval.expired",
                user_id=None,
                resource="approval",
                details=f"{n} pending request(s) exceeded the approval TTL",
            )
        return n

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def approve(
        self,
        db: Session,
        approval_id: uuid.UUID | str,
        decision: ApprovalDecisionInput,
        *,
        actor_user_id: uuid.UUID,
        actor_role: str,
        ip_address: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> ApprovalRecord:
        """Grant an approval: transition to APPROVED and, on success, hand
        the decision to the Step 25 Response layer (approved != executed)."""
        return self._resolve(
            db,
            approval_id,
            target_status=ApprovalStatus.APPROVED,
            comment=decision.comment,
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            ip_address=ip_address,
            clock=clock or _default_now,
        )

    def reject(
        self,
        db: Session,
        approval_id: uuid.UUID | str,
        decision: ApprovalDecisionInput,
        *,
        actor_user_id: uuid.UUID,
        actor_role: str,
        ip_address: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> ApprovalRecord:
        """Refuse an approval.  Terminal; never executes anything."""
        return self._resolve(
            db,
            approval_id,
            target_status=ApprovalStatus.REJECTED,
            comment=decision.comment,
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            ip_address=ip_address,
            clock=clock or _default_now,
        )

    def cancel(
        self,
        db: Session,
        approval_id: uuid.UUID | str,
        decision: ApprovalDecisionInput,
        *,
        actor_user_id: uuid.UUID,
        actor_role: str,
        ip_address: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> ApprovalRecord:
        """Withdraw a request before resolution.  Terminal."""
        return self._resolve(
            db,
            approval_id,
            target_status=ApprovalStatus.CANCELLED,
            comment=decision.comment,
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            ip_address=ip_address,
            clock=clock or _default_now,
        )

    def _resolve(
        self,
        db: Session,
        approval_id: uuid.UUID | str,
        *,
        target_status: ApprovalStatus,
        comment: str,
        actor_user_id: uuid.UUID,
        actor_role: str,
        ip_address: str | None,
        clock: Callable[[], datetime],
    ) -> ApprovalRecord:
        del actor_role  # role is validated by the route's authorized dependency
        approval_id = self._coerce_uuid(approval_id, field="approval_id")
        now = self._now(clock)
        self._reconcile(db, now)
        repo = self._repo(db)

        row = repo.get_by_approval_id(approval_id)
        if row is None:
            raise ApprovalNotFoundError(approval_id)

        if row.requested_by == actor_user_id:
            # Dual-control (four-eyes): the author of an approval request
            # cannot also resolve it.  Checked before any status handling so
            # a requester can never self-grant or withdraw-probe their own
            # request (H2.F-04).
            raise ApprovalValidationError(
                "the user who requested this approval cannot also resolve it "
                "(dual-control / four-eyes required)"
            )

        if row.status == target_status.value:
            # Approving an already-approved grant is idempotent; any other
            # repeated terminal state is a lifecycle conflict.
            if target_status is ApprovalStatus.APPROVED:
                return _to_record(row)
            raise ApprovalConflictError(
                f"approval request is already {row.status}"
            )

        if row.status in (ApprovalStatus.REJECTED.value,
                          ApprovalStatus.EXPIRED.value,
                          ApprovalStatus.CANCELLED.value):
            raise ApprovalConflictError(
                f"approval request is already {row.status} and cannot "
                f"transition to {target_status.value}"
            )

        claimed = repo.resolve_pending(
            approval_id,
            now=now,
            target_status=target_status.value,
            resolved_by=actor_user_id,
            resolution_reason=comment,
        )
        if claimed is None:
            stale = repo.get_by_approval_id(approval_id)
            if stale is None:
                raise ApprovalNotFoundError(approval_id)
            raise ApprovalConflictError(
                f"approval request was already resolved as {stale.status}"
            )
        db.commit()

        if target_status is ApprovalStatus.APPROVED:
            self._execute_response(db, claimed, clock)

        log_action(
            db,
            f"approval.{target_status.value}",
            user_id=actor_user_id,
            resource=f"approval:{claimed.approval_id}",
            details=f"decision {claimed.policy_decision_id} resolved by a human",
            ip_address=ip_address,
        )
        return _to_record(claimed)

    def _execute_response(
        self,
        db: Session,
        row: ApprovalRequestRow,
        clock: Callable[[], datetime],
    ) -> None:
        """After an APPROVED commit, re-present the original decision to the
        Step 25 Response layer and record what it did.

        The grant is already durable (the transition committed), so a
        response-step failure is recorded on the row — never rolled back.
        """
        now = self._now(clock)
        try:
            decision = PolicyDecision.model_validate(row.decision)
        except Exception as exc:  # noqa: BLE001 - defensive, sanitized
            logger.warning("Approval decision snapshot unreadable: %s", exc)
            row.response_status = "rejected"
            row.response_error_code = "APPROVAL_DECISION_UNREADABLE"
            row.updated_at = now
            db.commit()
            return

        try:
            target = _v.validate_target(decision.requested_action, row.target)
        except ResponseValidationError as exc:
            logger.warning("Approval target revalidation failed: %s", exc)
            row.response_status = "rejected"
            row.response_error_code = "APPROVAL_TARGET_INVALID"
            row.updated_at = now
            db.commit()
            return

        request = ResponseMitigationService.derive_response_id(
            policy_decision_id=decision.policy_decision_id,
            action=decision.requested_action,
            target=target,
        )
        request_model = ResponseRequest(
            response_id=request,
            policy_decision_id=decision.policy_decision_id,
            correlation_id=row.correlation_id,
            action_type=decision.requested_action,
            target=target,
            approval_id=row.approval_id,
            metadata={"source": "approval"},
        )
        verifier = ApprovalGrantVerifier(db, clock=clock)
        service = ResponseMitigationService(clock=clock, approval_verifier=verifier)
        try:
            result = service.execute(request_model, decision, clock=clock)
        except (ResponseValidationError, ResponseInternalError) as exc:
            logger.warning("Approved response execution failed: %s", exc)
            row.response_status = "failed"
            row.response_error_code = "APPROVAL_EXECUTION_FAILED"
            row.updated_at = now
            db.commit()
            return

        row.response_status = result.execution_status.value
        row.response_provider = result.provider
        row.response_error_code = result.error_code
        row.updated_at = now
        db.commit()
        log_action(
            db,
            "approval.response_executed",
            user_id=None,
            resource=f"approval:{row.approval_id}",
            details=(
                f"Response layer reported {result.execution_status.value}"
                f"{_response_suffix(result.provider, result.error_code)}"
            ),
        )

    # ------------------------------------------------------------------
    # Validation + error helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_uuid(value: object, *, field: str) -> uuid.UUID:
        try:
            if isinstance(value, uuid.UUID):
                return value
            return uuid.UUID(str(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ApprovalValidationError(f"{field} must be a valid UUID") from exc

    @staticmethod
    def _validate_page(page: object, page_size: object) -> tuple[int, int]:
        try:
            page_int = int(page)
            page_size_int = int(page_size)
        except (TypeError, ValueError) as exc:
            raise ApprovalValidationError("page and page_size must be integers") from exc
        if page_int < 1:
            raise ApprovalValidationError("page must be >= 1")
        if page_size_int < 1:
            raise ApprovalValidationError("page_size must be >= 1")
        if page_size_int > MAX_PAGE_SIZE:
            raise ApprovalValidationError(f"page_size must not exceed {MAX_PAGE_SIZE}")
        return page_int, page_size_int

    @staticmethod
    def _validate_recent_limit(limit: object) -> int:
        try:
            limit_int = int(limit)
        except (TypeError, ValueError) as exc:
            raise ApprovalValidationError("limit must be an integer") from exc
        if limit_int < 1:
            raise ApprovalValidationError("limit must be >= 1")
        if limit_int > MAX_RECENT_LIMIT:
            raise ApprovalValidationError(f"limit must not exceed {MAX_RECENT_LIMIT}")
        return limit_int

    @staticmethod
    def _db_error(
        exc: Exception,
        *,
        approval_id: uuid.UUID | None = None,
    ) -> ApprovalServiceError:
        """Build a sanitized service error from a low-level failure."""
        logger.warning(
            "Approval service failed (approval=%s): %s", approval_id, exc
        )
        return ApprovalServiceError("approval data is unavailable")


def _response_suffix(
    provider: str | None,
    error_code: str | None,
) -> str:
    parts = []
    if provider:
        parts.append(f"via {provider}")
    if error_code:
        parts.append(f"({error_code})")
    return (" " + " ".join(parts)) if parts else ""


__all__ = [
    "APPROVAL_SOC_ROLES",
    "ApprovalGrantVerifier",
    "ApprovalService",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_RECENT_LIMIT",
    "MAX_PAGE_SIZE",
    "MAX_RECENT_LIMIT",
]