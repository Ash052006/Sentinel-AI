"""Threat-intelligence persistence repository (Step 8C-B).

Provides the database CRUD and query operations used by the persistence
service (:mod:`app.services.threat_intelligence_persistence`) to store a
Step 8B :class:`~app.schemas.threat_intelligence_agent.ThreatIntelligenceAnalysis`
in PostgreSQL.

Contract rules honoured here (defined in 8C-A, see
``docs/development/threat_intelligence_persistence_contract.md``):

* Indicator deduplication is driven by ``canonical_key``
  (``"{type}:{normalized_value}"`` — Step 8A semantics, conservative
  lower-casing of domains/hashes only; no URL canonicalization).
* ``first_seen_at`` is set once on creation and **never** overwritten.
* ``last_seen_at`` only moves forward.
* The repository does **not** commit.  Transaction boundaries are owned by
  the persistence service so that one analysis persists atomically (and a
  failure rolls the whole unit back).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import LookupStatus, ThreatIntelLookup
from app.services.threat_intelligence.types import IndicatorType


def _as_utc(value: datetime) -> datetime:
    """Return *value* normalized to UTC.

    PostgreSQL ``TIMESTAMPTZ`` columns load as timezone-aware datetimes, so
    this is a no-op in production.  Some test/embedded stores (e.g. SQLite)
    return naive UTC instants; this helper interprets those as UTC so
    comparisons never mix aware and naive values.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class ThreatIntelRepository:
    """Data-access layer for threat-intelligence persistence.

    The repository knows nothing about ``ThreatIntelligenceAnalysis`` /
    Step 8B semantics.  It exposes entity- and column-level operations that
    the persistence service composes into a full analysis persistence.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Generic
    # ------------------------------------------------------------------

    def add(self, entity) -> None:
        """Stage *entity* for insertion.  The caller owns the transaction."""
        self.db.add(entity)

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    def get_indicator_by_canonical_key(
        self, canonical_key: str
    ) -> ThreatIntelIndicator | None:
        """Return the global indicator for *canonical_key*, if present."""
        return self.db.scalar(
            select(ThreatIntelIndicator).where(
                ThreatIntelIndicator.canonical_key == canonical_key
            )
        )

    def get_indicator_by_type_and_value(
        self,
        indicator_type: IndicatorType,
        value: str,
    ) -> ThreatIntelIndicator | None:
        """Return the indicator matching *indicator_type* + *value*, if present."""
        return self.db.scalar(
            select(ThreatIntelIndicator).where(
                ThreatIntelIndicator.indicator_type == indicator_type,
                ThreatIntelIndicator.value == value,
            )
        )

    def get_or_create_indicator(
        self,
        *,
        value: str,
        indicator_type: IndicatorType,
        canonical_key: str,
        seen_at: datetime,
    ) -> tuple[ThreatIntelIndicator, bool]:
        """Return ``(indicator, created)`` for the given canonical key.

        When the indicator already exists, ``last_seen_at`` advances to
        *seen_at* only if *seen_at* is more recent.  ``first_seen_at`` is
        never modified.  New indicators are flushed so their UUID is
        available to the caller before commit.

        Args:
            value: The exact extracted value to store on creation.
            indicator_type: The indicator category.
            canonical_key: The Step 8A deterministic deduplication key.
            seen_at: Occurrence timestamp to seed/advance ``last_seen_at``.

        Returns:
            A tuple of the indicator row (created or existing) and whether
            it was newly created.
        """
        existing = self.get_indicator_by_canonical_key(canonical_key)
        if existing is not None:
            if seen_at > _as_utc(existing.last_seen_at):
                existing.last_seen_at = seen_at
                self.db.flush()
            return existing, False

        indicator = ThreatIntelIndicator(
            value=value,
            indicator_type=indicator_type,
            canonical_key=canonical_key,
            first_seen_at=seen_at,
            last_seen_at=seen_at,
        )
        self.db.add(indicator)
        self.db.flush()
        return indicator, True

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def find_existing_lookup(
        self,
        *,
        event_id: uuid.UUID,
        indicator_id: uuid.UUID,
        provider: str,
        status: LookupStatus | None = None,
        performed_at: datetime | None = None,
        error_type: str | None = None,
        error_message: str | None = None,
        retryable: bool | None = None,
    ) -> ThreatIntelLookup | None:
        """Return a lookup row matching the supplied identity attributes.

        Used by the persistence service for idempotency.  The identity of a
        lookup is

        * success: ``(event_id, indicator_id, provider, performed_at)`` —
          re-persisting an identical analysis is a no-op, while the same
          indicator/provider checked again at a different time is a new,
          legitimate historical row;
        * failure : ``(event_id, indicator_id, provider, error_type,
          sanitized error_message, retryable)`` — stable across re-persists
          of the same analysis (failures carry no lookup timestamp).

        Only the attributes that are not ``None`` participate in the match.
        """
        conditions = [
            ThreatIntelLookup.event_id == event_id,
            ThreatIntelLookup.indicator_id == indicator_id,
            ThreatIntelLookup.provider == provider,
        ]
        if status is not None:
            conditions.append(ThreatIntelLookup.status == status)
        if performed_at is not None:
            conditions.append(ThreatIntelLookup.performed_at == performed_at)
        if error_type is not None:
            conditions.append(ThreatIntelLookup.error_type == error_type)
        if error_message is not None:
            conditions.append(ThreatIntelLookup.error_message == error_message)
        if retryable is not None:
            conditions.append(ThreatIntelLookup.retryable == retryable)
        return self.db.scalar(select(ThreatIntelLookup).where(*conditions))

    def get_lookups_for_event(
        self,
        event_id: uuid.UUID,
        *,
        limit: int | None = None,
    ) -> list[ThreatIntelLookup]:
        """Return every lookup executed for *event_id*, most recent first."""
        stmt = (
            select(ThreatIntelLookup)
            .where(ThreatIntelLookup.event_id == event_id)
            .order_by(ThreatIntelLookup.performed_at.desc())
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.db.scalars(stmt))

    def get_lookups_for_indicator(
        self,
        indicator_id: uuid.UUID,
        *,
        limit: int | None = None,
    ) -> list[ThreatIntelLookup]:
        """Return every lookup performed against *indicator_id*, most recent first."""
        stmt = (
            select(ThreatIntelLookup)
            .where(ThreatIntelLookup.indicator_id == indicator_id)
            .order_by(ThreatIntelLookup.performed_at.desc())
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.db.scalars(stmt))

    def get_provider_lookups_for_indicator(
        self,
        indicator_id: uuid.UUID,
        provider: str,
        *,
        limit: int | None = None,
    ) -> list[ThreatIntelLookup]:
        """Return *provider*'s lookups for *indicator_id*, most recent first."""
        stmt = (
            select(ThreatIntelLookup)
            .where(
                ThreatIntelLookup.indicator_id == indicator_id,
                ThreatIntelLookup.provider == provider,
            )
            .order_by(ThreatIntelLookup.performed_at.desc())
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.db.scalars(stmt))

    def get_recent_lookups(
        self,
        *,
        limit: int = 50,
    ) -> list[ThreatIntelLookup]:
        """Return the *limit* most recently performed lookups across all events."""
        return list(
            self.db.scalars(
                select(ThreatIntelLookup)
                .order_by(ThreatIntelLookup.performed_at.desc())
                .limit(limit)
            )
        )