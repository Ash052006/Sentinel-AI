"""Risk assessment query service (Step 11D) — read-only retrieval over 11C persistence.

Provides validated, read-only access to persisted risk assessments without any
write surface: it composes :class:`RiskRepository` reads and converts rows into
:mod:`app.schemas.risk_query` read models.  It is the layer a future risk read
API will call — no endpoints are added here.

Design principles:

* **Read-only** — ``RiskQueryService`` never calls ``add``/``delete``,
  ``flush``, ``commit``, or ``rollback``.  Callers own the session and its
  transaction; queries never mutate it.  (A failed read leaves the session
  untouched — the owner decides whether to roll back.)
* **Validated input** — risk-assessment / correlation UUIDs and page
  semantics are validated up front; invalid input raises
  :class:`RiskQueryValidationError` before any database work.
* **Sanitized failures** — database errors surface as :class:`RiskQueryError`
  with safe, consumer-facing messages.  Raw driver/SQL text is logged, never
  propagated.
* **Deterministic pages** — every list orders by ``timestamp`` descending
  with a stable secondary key (``risk_assessment_id`` ascending), so page
  boundaries never drift.
* **No recalculation** — the query layer is a retrieval layer, never a risk
  engine: scores, levels, confidence, factors, evidence, metadata, and
  provenance are surfaced exactly as persisted.  Nothing is re-derived.

Pipeline::

    RiskPersistenceService (11C-B writes, then commit)
        -> risk_assessments
            -> RiskQueryService (this module, read-only)
                -> RiskAssessmentRecord / RiskAssessmentPage
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.models.risk_assessment import RiskAssessment as RiskAssessmentRow
from app.repositories.risk import RiskRepository
from app.schemas.risk_query import (
    RiskAssessmentPage,
    RiskAssessmentRecord,
)
from app.schemas.security_event import Provenance

logger = logging.getLogger(__name__)

#: Default page size for paginated reads (bounded offset pagination).
DEFAULT_PAGE_SIZE = 50

#: Hard cap on a single page; guards against unbounded result materialization.
MAX_PAGE_SIZE = 200

#: Default limit for the "recent assessments" feed.
DEFAULT_RECENT_LIMIT = 50

#: Hard cap on the "recent assessments" feed.
MAX_RECENT_LIMIT = 200


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class RiskQueryError(Exception):
    """Raised when a risk assessment query cannot be satisfied.

    Instances never contain credentials, raw evidence, raw factor payloads,
    raw event payloads, raw database/SQL error text, or tracebacks — only
    safe contextual identifiers such as the risk-assessment / correlation
    UUIDs.  The underlying exception is preserved as ``__cause__`` for
    server-side logging.
    """

    def __init__(
        self,
        risk_assessment_id: uuid.UUID | None = None,
        correlation_id: uuid.UUID | None = None,
        reason: str = "",
    ) -> None:
        message = "Risk query failed"
        if risk_assessment_id is not None:
            message += f" for risk assessment {risk_assessment_id}"
        if correlation_id is not None:
            message += f" for correlation {correlation_id}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.risk_assessment_id = risk_assessment_id
        self.correlation_id = correlation_id


class RiskQueryValidationError(RiskQueryError):
    """Raised when query input cannot be validated safely.

    Raised *before* any database work: malformed UUIDs and out-of-bounds
    page/limit arguments all land here.
    """


# ---------------------------------------------------------------------------
# Validation + safe value helpers
# ---------------------------------------------------------------------------


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalize a possibly-naive database instant to a tz-aware UTC value.

    SQLite stores ``DateTime(timezone=True)`` columns as naive UTC instants;
    PostgreSQL returns tz-aware values.  Normalizing at the read boundary
    gives consumers identical records on both backends.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _coerce_uuid(value: object, *, field: str) -> uuid.UUID:
    """Return *value* as a UUID, rejecting anything that is not one."""
    try:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise RiskQueryValidationError(
            reason=f"{field} must be a valid UUID"
        ) from exc


def _validate_page(page: object, page_size: object) -> tuple[int, int]:
    """Validate 1-based pagination arguments; return corrected integers."""
    try:
        page_int = int(page)
        page_size_int = int(page_size)
    except (TypeError, ValueError) as exc:
        raise RiskQueryValidationError(
            reason="page and page_size must be integers"
        ) from exc
    if page_int < 1:
        raise RiskQueryValidationError(reason="page must be >= 1")
    if page_size_int < 1:
        raise RiskQueryValidationError(reason="page_size must be >= 1")
    if page_size_int > MAX_PAGE_SIZE:
        raise RiskQueryValidationError(
            reason=f"page_size must not exceed {MAX_PAGE_SIZE}"
        )
    return page_int, page_size_int


def _validate_recent_limit(limit: object) -> int:
    """Validate the recent-assessments feed limit; return its integer value."""
    try:
        limit_int = int(limit)
    except (TypeError, ValueError) as exc:
        raise RiskQueryValidationError(reason="limit must be an integer") from exc
    if limit_int < 1:
        raise RiskQueryValidationError(reason="limit must be >= 1")
    if limit_int > MAX_RECENT_LIMIT:
        raise RiskQueryValidationError(
            reason=f"limit must not exceed {MAX_RECENT_LIMIT}"
        )
    return limit_int


# ---------------------------------------------------------------------------
# Row -> read-model conversion (read boundary normalization)
# ---------------------------------------------------------------------------


def _to_result_record(row: RiskAssessmentRow) -> RiskAssessmentRecord:
    """Convert a persisted ``risk_assessments`` row into its read record."""
    return RiskAssessmentRecord(
        id=row.id,
        risk_assessment_id=row.risk_assessment_id,
        correlation_id=row.correlation_id,
        score=row.score,
        level=row.level,
        confidence=row.confidence,
        factors=list(row.factors or []),
        evidence=list(row.evidence or []),
        assessment_metadata=dict(row.assessment_metadata or {}),
        timestamp=_as_utc(row.timestamp),
        provenance=Provenance(row.provenance),
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )


# ---------------------------------------------------------------------------
# Query service
# ---------------------------------------------------------------------------


class RiskQueryService:
    """Read-only retrieval over the Step 11C persistence layer.

    Every method follows the persistence-service convention of receiving the
    caller-owned ``db`` session as the first argument::

        service = RiskQueryService()
        record  = service.get_assessment(db, risk_assessment_id)

    Read-only guarantee: this service never calls ``add``/``delete``,
    ``flush``, ``commit``, or ``rollback`` on the session.  It composes
    repository reads and converts rows to read models; callers own the
    transaction, and a session that hit a real database failure here should
    be rolled back by its owner.

    Args:
        repository_factory: Optional repository factory; defaults to
            :class:`RiskRepository`.  Injected for testability.
    """

    def __init__(
        self,
        repository_factory: Callable[[Session], RiskRepository] = RiskRepository,
    ) -> None:
        self._repository_factory = repository_factory

    def _repo(self, db: Session) -> RiskRepository:
        return self._repository_factory(db)

    @staticmethod
    def _db_error(
        exc: Exception,
        *,
        risk_assessment_id: uuid.UUID | None = None,
        correlation_id: uuid.UUID | None = None,
        reason: str,
    ) -> RiskQueryError:
        """Build a sanitized query error from a low-level failure.

        The raw exception is logged for operators; only the safe *reason*
        string reaches the consumer.
        """
        logger.warning(
            "Risk query failed (reason=%s, risk_assessment=%s, correlation=%s): %s",
            reason,
            risk_assessment_id,
            correlation_id,
            exc,
        )
        return RiskQueryError(
            risk_assessment_id=risk_assessment_id,
            correlation_id=correlation_id,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Assessment detail
    # ------------------------------------------------------------------

    def get_assessment(
        self,
        db: Session,
        risk_assessment_id: uuid.UUID | str,
    ) -> RiskAssessmentRecord | None:
        """Return the persisted assessment with *risk_assessment_id*, or ``None``.

        Unknown IDs produce a controlled not-found result (``None``), never
        an error.
        """
        risk_assessment_id = _coerce_uuid(
            risk_assessment_id, field="risk_assessment_id"
        )
        try:
            row = self._repo(db).get_by_risk_assessment_id(risk_assessment_id)
        except RiskQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc,
                risk_assessment_id=risk_assessment_id,
                reason="failed to load risk assessment",
            ) from exc
        if row is None:
            return None
        return _to_result_record(row)

    # ------------------------------------------------------------------
    # Assessments: correlation-scoped, recent feed
    # ------------------------------------------------------------------

    def list_assessments_for_correlation(
        self,
        db: Session,
        correlation_id: uuid.UUID | str,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> RiskAssessmentPage:
        """Return one bounded page of a correlation's persisted assessments.

        Multiple RiskAssessments for the same correlation are allowed (11C-A
        historical semantics) — **all** matching rows are eligible, never
        collapsed to one.  Deterministic ordering: ``timestamp`` descending,
        ``risk_assessment_id`` ascending.  ``total`` is the correlation's
        full assessment count (unaffected by pagination).
        """
        correlation_id = _coerce_uuid(correlation_id, field="correlation_id")
        page, page_size = _validate_page(page, page_size)
        repo = self._repo(db)
        try:
            total = repo.count_assessments_for_correlation(correlation_id)
            rows = repo.list_assessments_for_correlation(
                correlation_id, limit=page_size, offset=(page - 1) * page_size
            )
        except RiskQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc,
                correlation_id=correlation_id,
                reason="failed to list risk assessments for correlation",
            ) from exc
        return RiskAssessmentPage(
            items=[_to_result_record(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

    def list_recent_assessments(
        self,
        db: Session,
        *,
        limit: int = DEFAULT_RECENT_LIMIT,
    ) -> list[RiskAssessmentRecord]:
        """Return up to *limit* newest persisted assessments across all rows.

        A bounded feed (not paginated), mirroring the detection
        recent-results and correlation recent-correlations conventions.
        Ordering is deterministic: ``timestamp`` descending,
        ``risk_assessment_id`` ascending.
        """
        limit = _validate_recent_limit(limit)
        try:
            rows = self._repo(db).list_recent_assessments(limit=limit)
        except RiskQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to list recent risk assessments"
            ) from exc
        return [_to_result_record(row) for row in rows]

    # ------------------------------------------------------------------
    # Counting
    # ------------------------------------------------------------------

    def count_assessments(self, db: Session) -> int:
        """Return the total number of persisted assessments.

        Computed with a database-side ``COUNT`` — never a full-table Python
        materialization.
        """
        try:
            return self._repo(db).count_assessments()
        except RiskQueryError:
            raise
        except Exception as exc:
            raise self._db_error(exc, reason="failed to count risk assessments") from exc

    def count_assessments_for_correlation(
        self,
        db: Session,
        correlation_id: uuid.UUID | str,
    ) -> int:
        """Return the number of persisted assessments of *correlation_id*
        (database-side COUNT)."""
        correlation_id = _coerce_uuid(correlation_id, field="correlation_id")
        try:
            return self._repo(db).count_assessments_for_correlation(correlation_id)
        except RiskQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to count risk assessments for correlation"
            ) from exc