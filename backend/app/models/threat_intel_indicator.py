"""Threat Intelligence Indicator persistence model (Step 8C-A).

This is the **persistence contract** for a single threat-intelligence
indicator of compromise (IoC).  It is a global, deduplicated record of a
normalized indicator value and type, independent of any single event,
provider, or lookup.

Design intent
-------------
* ``canonical_key`` is the deterministic deduplication key defined by
  Step 8A (``f"{type}:{normalized_value}"``).  Its uniqueness enforces
  the rule that the same normalized indicator/type combination must never
  produce uncontrolled duplicate records.
* No aggressive URL canonicalization is introduced.  The ``value`` column
  stores the indicator exactly as extracted, and the ``canonical_key``
  applies **only** Step 8A's conservative normalization (lower-casing
  domains and hashes; leaving IPs and URLs byte-for-byte as extracted).
* ``first_seen_at`` / ``last_seen_at`` record when the indicator was
  first / most recently observed in the pipeline so freshness can be
  answered without scanning every lookup row.

This model defines the layout only.  The actual repository that performs
get-or-create / upsert (Step 8C-B) is **not** implemented here.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.services.threat_intelligence.types import IndicatorType


def _indicator_type_values(enum_class) -> list[str]:
    """Return the raw string values of :class:`IndicatorType` in order.

    This keeps the database column backed by the existing ``IndicatorType``
    enum values (``ip``, ``domain``, ``url``, ``hash``) without creating a
    second, incompatible indicator-type enum.
    """
    return [member.value for member in enum_class]


class ThreatIntelIndicator(UUIDTimestampMixin, Base):
    """A normalized, deduplicated indicator of compromise.

    Attributes:
        value: The indicator value exactly as extracted (no URL
            canonicalization is applied here).
        indicator_type: The indicator category, reusing the existing
            :class:`~app.services.threat_intelligence.types.IndicatorType`.
        canonical_key: Deterministic Step 8A deduplication key
            (``"{type}:{normalized_value}"``).  Unique.
        first_seen_at: When this indicator was first encountered.
        last_seen_at: When this indicator was most recently encountered.
        lookups: The provider lookups performed against this indicator.
    """

    __tablename__ = "threat_intel_indicators"
    __table_args__ = (
        UniqueConstraint(
            "indicator_type",
            "value",
            name="uq_threat_intel_indicators_type_value",
        ),
    )

    value: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        index=True,
        comment=(
            "Indicator value exactly as extracted.  No URL canonicalization "
            "is performed; Step 8A intentionally keeps URLs as-is."
        ),
    )

    indicator_type: Mapped[IndicatorType] = mapped_column(
        Enum(
            IndicatorType,
            name="indicator_type",
            values_callable=_indicator_type_values,
            native_enum=False,
        ),
        nullable=False,
        index=True,
    )

    canonical_key: Mapped[str] = mapped_column(
        String(2200),
        nullable=False,
        unique=True,
        index=True,
        comment=(
            "Deterministic Step 8A deduplication key "
            "`{type}:{normalized_value}`.  Enforces indicator global "
            "uniqueness for the same normalized type+value."
        ),
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # -- Relationships -------------------------------------------------------

    lookups: Mapped[list["ThreatIntelLookup"]] = relationship(  # noqa: F821
        back_populates="indicator",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<ThreatIntelIndicator id={self.id} "
            f"type={self.indicator_type.value} value={self.value!r}>"
        )
