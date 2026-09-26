"""Risk assessment persistence model (Step 11C-A).

The **persistence contract** for a single Step 11A
:class:`~app.schemas.risk.RiskAssessment` produced by the Step 11B
:class:`~app.agents.risk_scoring.RiskScoringAgent`.

Design intent
-------------
* ``risk_assessment_id`` (the Step 11A ``RiskAssessment.risk_assessment_id``)
  is unique and is the **idempotency identity**: re-persisting the same
  assessment is a no-op, while a later re-scoring that produces a fresh UUID
  is a new, legitimate historical row.  ``correlation_id`` is **not** unique
  — a correlation may legitimately carry several assessments over time, so
  multiple assessment rows for one correlation are allowed and expected.
* A risk assessment **references** its correlation by ``correlation_id``;
  no ``CorrelationResult`` data is duplicated here.  The reference is a real
  foreign key back to :class:`~app.models.correlation_result.CorrelationResult`
  (``correlation_results.correlation_id``); deleting a correlation cascades
  to its assessment rows, mirroring the Step 10C-A correlation-member
  convention.
* ``score``/``confidence`` are **persisted exactly as the Step 11B engine
  produced them** — the persistence layer never recalculates risk, re-derives
  levels, or interprets factors/evidence.  Both are bounded to ``[0.0, 1.0]``
  by CHECK constraints.
* ``level`` is stored as the controlled :class:`RiskLevel` enumeration
  (``low``/``medium``/``high``/``critical``), mirroring how detection
  severity and correlation status are stored.
* ``factors``/``evidence`` are structured, bounded JSONB payloads preserving
  the Step 11A structure exactly (never flattened into prose).  They are
  redacted by the Step 11C-B persistence service before write.
* Provenance is constrained by a database CHECK constraint to the
  ``Provenance.RISK_ASSESSED`` value so risk output can **never** be
  persisted as ``observed``/``enriched``/``reconstructed``/``detected``/
  ``correlated``.

This model defines the layout only.  The repository/service that persists
``RiskAssessment`` objects (Step 11C-B) is **not** implemented here.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum as SqlEnum,
    Float,
    ForeignKeyConstraint,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance


def _risk_level_values(enum_class) -> list[str]:
    """Return the raw string values of :class:`RiskLevel`."""
    return [member.value for member in enum_class]


class RiskAssessment(UUIDTimestampMixin, Base):
    """A single persisted risk assessment.

    Attributes:
        risk_assessment_id: Step 11A ``RiskAssessment.risk_assessment_id``.
            Unique — the idempotency identity of a persisted assessment.
        correlation_id: Step 11A ``RiskAssessment.correlation_id`` — the
            evaluated correlation.  A real FK to ``correlation_results``;
            not unique, so one correlation can carry several assessments.
        score: The Step 11B risk score in ``[0.0, 1.0]`` (CHECK-constrained),
            persisted exactly as produced.
        level: Controlled risk level (``low``/``medium``/``high``/``critical``).
        confidence: Assessment confidence in ``[0.0, 1.0]``
            (CHECK-constrained), persisted exactly as produced.
        factors: Structured Step 11A factors (JSONB), preserved exactly.
        evidence: Structured Step 11A evidence (JSONB), preserved exactly.
        assessment_metadata: Safe, non-secret assessment metadata (JSONB).
        timestamp: When the assessment was produced (UTC, tz-aware).
        provenance: Risk-assessment provenance, constrained to
            ``risk_assessed``.
    """

    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint(
            "score >= 0.0 AND score <= 1.0",
            name="risk_score_range",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="risk_confidence_range",
        ),
        CheckConstraint(
            "provenance = 'risk_assessed'",
            name="provenance_risk_assessed",
        ),
        ForeignKeyConstraint(
            ["correlation_id"],
            ["correlation_results.correlation_id"],
            name="fk_risk_assessments_correlation_id_correlation_results",
            ondelete="CASCADE",
        ),
    )

    risk_assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        comment=(
            "Step 11A RiskAssessment.risk_assessment_id.  Unique identity "
            "of a persisted assessment — the idempotency key for "
            "re-persists."
        ),
    )

    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment=(
            "Step 11A RiskAssessment.correlation_id.  The evaluated "
            "correlation, referenced by FK; deleted with it (ON DELETE "
            "CASCADE).  Not unique — multiple assessments for one "
            "correlation are allowed."
        ),
    )

    score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment=(
            "Step 11B risk score in [0.0, 1.0] (CHECK-constrained), "
            "persisted exactly as the engine produced it.  Never "
            "recalculated by persistence."
        ),
    )

    level: Mapped[RiskLevel] = mapped_column(
        SqlEnum(
            RiskLevel,
            name="risk_level",
            values_callable=_risk_level_values,
            native_enum=False,
        ),
        nullable=False,
        comment=(
            "Controlled risk level (low / medium / high / critical) "
            "persisted exactly as scored.  Bookkeeping only; never a "
            "verdict."
        ),
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment=(
            "Step 11B assessment confidence in [0.0, 1.0] "
            "(CHECK-constrained), persisted exactly as produced.  "
            "Independent of score/level; never a risk score."
        ),
    )

    factors: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured Step 11A risk factors (JSONB).  Preserves the "
            "structured factors exactly — never flattened into prose or "
            "reinterpreted."
        ),
    )

    evidence: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured Step 11A risk evidence (JSONB).  Preserves the "
            "structured observations exactly — never flattened into prose."
        ),
    )

    assessment_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment="Safe, non-secret Step 11A assessment metadata (JSONB).",
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment=(
            "When the assessment was produced (11A result timestamp, UTC, "
            "tz-aware).  Descriptive bookkeeping, not evidence."
        ),
    )

    provenance: Mapped[str] = mapped_column(
        String(32),
        default=Provenance.RISK_ASSESSED.value,
        nullable=False,
        comment=(
            "Risk-assessment provenance.  Assessments are derived "
            "analytical conclusions and are constrained to RISK_ASSESSED by "
            "CHECK constraint; they can never be stored as "
            "observed/enriched/reconstructed/detected/correlated."
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<RiskAssessment id={self.id} "
            f"risk_assessment_id={self.risk_assessment_id} "
            f"correlation_id={self.correlation_id} "
            f"score={self.score} level={self.level.value}>"
        )