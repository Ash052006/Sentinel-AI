"""Risk assessment persistence service (Step 11C-B).

Translates Step 11A :class:`~app.schemas.risk.RiskAssessment` objects into
PostgreSQL persistence operations using the Step 11C-A contract model
(:class:`~app.models.risk_assessment.RiskAssessment`) through the
:class:`~app.repositories.risk.RiskRepository`.

Pipeline:::

    RiskAssessment      (Step 11B RiskScoringAgent output)
        ↓  (this service)
    risk_assessments    (one row per assessment, keyed by risk_assessment_id)

Behavioural guarantees
----------------------
* **No risk scoring.**  The service never scores, recomputes, re-derives, or
  reinterprets risk.  It persists the Step 11B ``RiskAssessment`` exactly:
  ``score``, ``level``, ``confidence``, ``factors``, ``evidence``,
  ``metadata``, ``timestamp``, and ``provenance`` are stored as produced.
  There is no second scoring engine here.
* **No reading into risk.**  The service stores one assessment at a time and
  returns a summary; it does **not** read risk back, query, filter,
  paginate, or expose assessments.
* **Transactional.**  All work for one ``persist_assessment`` call commits
  in a single ``Session.commit()``; any failure rolls the unit back and
  raises a safe :class:`RiskPersistenceError` (no partial state).
* **Idempotent.**  Re-persisting the same assessment reuses the existing
  row: assessments are identified by their unique ``risk_assessment_id``.
  Legitimate re-scoring of a correlation (a fresh ``risk_assessment_id``)
  is preserved as a historical row; ``correlation_id`` itself is **not**
  unique.
* **Provenance.**  Every row is stored with ``Provenance.RISK_ASSESSED`` —
  never ``observed``/``enriched``/``reconstructed``/``detected``/
  ``correlated`` (enforced by CHECK constraint).
* **Referencing.**  An assessment references its correlation by
  ``correlation_id`` only; no ``CorrelationResult`` data is duplicated.
* **Secret-safe.**  Structured factors/evidence/metadata is recursively
  key-redacted before persistence (defence-in-depth on top of the Step 11A
  validators), and error messages never contain payloads or secrets.
* **Non-mutating.**  The source ``RiskAssessment`` is never mutated; its
  structured lists/dicts are serialized into independent, JSON-compatible
  copies.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.models.risk_assessment import RiskAssessment
from app.repositories.risk import RiskRepository
from app.schemas.risk import RiskAssessment as RiskAssessmentSchema
from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance

logger = logging.getLogger(__name__)

#: Hard cap on serialized structured factors/evidence/metadata (defense in depth).
_MAX_STRUCTURED_CHARS = 262_144

#: Marker substituted for detected credentials anywhere in stored data.
_REDACTED = "<redacted>"


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class RiskPersistenceError(Exception):
    """Raised when a risk assessment cannot be persisted.

    Instances never contain credentials, raw evidence, raw factor payloads,
    raw event payloads, or raw database/SQL error text — only safe contextual
    identifiers such as the risk-assessment / correlation UUIDs.
    """

    def __init__(
        self,
        risk_assessment_id: uuid.UUID | None = None,
        reason: str = "",
    ) -> None:
        message = "Failed to persist risk assessment"
        if risk_assessment_id is not None:
            message += f" for risk assessment {risk_assessment_id}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.risk_assessment_id = risk_assessment_id


class RiskPersistenceValidationError(RiskPersistenceError):
    """Raised when an assessment cannot be mapped to a persistence row safely.

    Used for pre-commit validation failures (e.g. factors exceeding the
    bounded size, or a non-``RiskAssessment`` item) that must abort the
    transaction.
    """


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskPersistenceSummary:
    """Summary of one ``persist_assessment`` invocation."""

    risk_assessment_id: uuid.UUID
    correlation_id: uuid.UUID
    assessments_created: int = 0
    assessments_skipped: int = 0

    @property
    def is_empty(self) -> bool:
        """True when nothing was persisted (e.g. an idempotent re-persist)."""
        return self.assessments_created == 0


# ---------------------------------------------------------------------------
# Secret-safe sanitization (defense-in-depth)
# ---------------------------------------------------------------------------

#: Structured keys whose values are credentials and must be redacted.
#: Kept in lock-step with ``app/services/correlation_persistence.py``.
_SECRET_KEY_PATTERN = re.compile(
    r"(?i)^(?:api[_-]?key|apikey|authorization|auth[_-]?header|set[_-]?cookie|"
    r"cookie|password|passwd|secret|token|access[_-]?key|client[_-]?secret)$"
)


def _redact_structured(value: Any) -> Any:
    """Recursively redact credential values inside structured JSON data."""
    if isinstance(value, dict):
        return {
            key: (
                _REDACTED
                if _SECRET_KEY_PATTERN.match(str(key))
                else _redact_structured(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_structured(item) for item in value]
    return value


def _prepare_structured(
    data: Any,
    *,
    field: str,
    risk_assessment_id: uuid.UUID | None = None,
) -> Any:
    """Redact credentials and enforce the bounded-size rule for JSON columns.

    *data* is any JSON-compatible value (dict for metadata, list for
    factors/evidence).  Returns an independent, redacted copy — the source
    assessment is never mutated and the source lists/dicts are never shared.
    """
    if data is None:
        return None
    redacted = _redact_structured(data)
    try:
        serialized = len(json.dumps(redacted))
    except (TypeError, ValueError) as exc:
        # Non-JSON-compatible structured data is a validation failure: the
        # assessment cannot be stored safely as JSONB.  Never leaks the
        # offending payload into the message.
        raise RiskPersistenceValidationError(
            risk_assessment_id=risk_assessment_id,
            reason=f"{field} is not JSON-compatible",
        ) from exc
    if serialized > _MAX_STRUCTURED_CHARS:
        raise RiskPersistenceValidationError(
            risk_assessment_id=risk_assessment_id,
            reason=f"{field} exceeds the {_MAX_STRUCTURED_CHARS}-character persistence bound",
        )
    return redacted


# ---------------------------------------------------------------------------
# Persistence service
# ---------------------------------------------------------------------------


class RiskPersistenceService:
    """Coordinates persistence of Step 11A assessments through the repository.

    The service owns the transaction boundary: one ``persist_assessment``
    call stages the row and publishes it with a single ``commit()``.  The
    Risk Scoring Agent never commits or rolls back — persistence is an
    injected side-effect sink.

    Args:
        repository_factory: Optional repository factory; defaults to
            :class:`RiskRepository`.  Injected for testability.
        clock: Optional UTC time source; reserved for parity with the
            detection/correlation persistence services.  The row's
            ``timestamp`` comes from the Step 11A assessment itself, so the
            clock is unused by the current persistence path.  As with the
            correlation service, this is idempotency-neutral bookkeeping.
    """

    def __init__(
        self,
        repository_factory: Callable[[Session], RiskRepository] = RiskRepository,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository_factory = repository_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def persist_assessment(
        self,
        db: Session,
        assessment: RiskAssessmentSchema,
    ) -> RiskPersistenceSummary:
        """Persist *assessment* atomically and return a summary.

        One logical transaction: the row is staged, a single ``commit()``
        publishes it, and any failure rolls the unit back before a safe
        exception propagates.  An assessment whose ``risk_assessment_id`` is
        already persisted is skipped (idempotency).

        The Step 11B assessment is persisted **exactly**: ``score``,
        ``level``, ``confidence``, ``factors``, ``evidence``, ``metadata``,
        ``timestamp``, and ``provenance`` are stored as produced.  This
        service never scores, recomputes, re-derives levels, or reinterprets
        risk.

        Raises:
            RiskPersistenceValidationError: when the item is not a
                ``RiskAssessment``, carries a provenance other than
                RISK_ASSESSED, carries an invalid level, or exceeds a
                persistence bound.
            RiskPersistenceError: when the persistence fails for any other
                reason (original cause preserved).
        """
        try:
            return self._persist(db, assessment)
        except RiskPersistenceError:
            db.rollback()
            raise
        except Exception as exc:  # database errors / unexpected conditions
            logger.warning(
                "risk persistence failed (%s)",
                type(exc).__name__,
            )
            db.rollback()
            raise RiskPersistenceError() from exc

    # -- internal -----------------------------------------------------------

    def _persist(
        self,
        db: Session,
        assessment: RiskAssessmentSchema,
    ) -> RiskPersistenceSummary:
        if not isinstance(assessment, RiskAssessmentSchema):
            raise RiskPersistenceValidationError(
                reason=(
                    "each persisted item must be a RiskAssessment; received "
                    f"{type(assessment).__module__}."
                    f"{type(assessment).__qualname__}"
                )
            )

        risk_assessment_id = assessment.risk_assessment_id
        repo = self._repository_factory(db)

        if not isinstance(risk_assessment_id, uuid.UUID):
            # Re-check behind model_construct-style bypasses: the identity
            # must be a real UUID before it can navigate the persistence
            # layer.
            raise RiskPersistenceValidationError(
                reason="risk_assessment_id must be a UUID",
            )

        if not isinstance(assessment.correlation_id, uuid.UUID):
            raise RiskPersistenceValidationError(
                reason="correlation_id must be a UUID",
            )

        if repo.get_by_risk_assessment_id(risk_assessment_id) is not None:
            return RiskPersistenceSummary(
                risk_assessment_id=risk_assessment_id,
                correlation_id=assessment.correlation_id,
                assessments_created=0,
                assessments_skipped=1,
            )

        if assessment.provenance is not Provenance.RISK_ASSESSED:
            # The Step 11A schema enforces RISK_ASSESSED already; re-check
            # behind model_construct-style bypasses so no invented provenance
            # can ever be stored.
            raise RiskPersistenceValidationError(
                risk_assessment_id=risk_assessment_id,
                reason="provenance must be RISK_ASSESSED",
            )

        if not isinstance(assessment.level, RiskLevel):
            # Re-check behind model_construct-style bypasses so no invented
            # level can ever be stored.
            raise RiskPersistenceValidationError(
                risk_assessment_id=risk_assessment_id,
                reason="level must be one of low/medium/high/critical",
            )

        if assessment.timestamp is None or assessment.timestamp.tzinfo is None:
            # The Step 11A schema rejects naive timestamps already; re-check
            # behind model_construct-style bypasses so persistence only ever
            # stores timezone-aware instants.
            raise RiskPersistenceValidationError(
                risk_assessment_id=risk_assessment_id,
                reason=(
                    "timestamp must be timezone-aware "
                    "(naive timestamps are not persisted)"
                ),
            )

        repo.add(
            RiskAssessment(
                risk_assessment_id=risk_assessment_id,
                correlation_id=assessment.correlation_id,
                score=assessment.score,
                level=assessment.level,
                confidence=assessment.confidence,
                factors=_prepare_structured(
                    [factor.model_dump(mode="json") for factor in assessment.factors],
                    field="factors",
                    risk_assessment_id=risk_assessment_id,
                ),
                evidence=_prepare_structured(
                    [item.model_dump(mode="json") for item in assessment.evidence],
                    field="evidence",
                    risk_assessment_id=risk_assessment_id,
                ),
                assessment_metadata=_prepare_structured(
                    assessment.metadata,
                    field="metadata",
                    risk_assessment_id=risk_assessment_id,
                ),
                timestamp=assessment.timestamp,
                provenance=assessment.provenance.value,
            )
        )

        db.flush()
        db.commit()

        return RiskPersistenceSummary(
            risk_assessment_id=risk_assessment_id,
            correlation_id=assessment.correlation_id,
            assessments_created=1,
            assessments_skipped=0,
        )


def persist_risk_assessment(
    db: Session,
    assessment: RiskAssessmentSchema,
) -> RiskPersistenceSummary:
    """Convenience wrapper: persist *assessment* with a default service.

    Equivalent to ``RiskPersistenceService().persist_assessment(
    db, assessment)``.
    """
    return RiskPersistenceService().persist_assessment(db, assessment)