"""Idempotent, clearly-labelled synthetic Threat Intelligence fixtures.

Why this exists
---------------
The Threat Intelligence console (``/threat-intelligence``) renders exactly what
the pipeline **persisted**: indicators extracted by
:class:`~app.agents.threat_intelligence.ThreatIntelligenceAgent` and the provider
lookups recorded against them.  Nothing else.  In a fresh environment that table
is empty -- no event has yet been enriched and no provider has yet been queried
-- so the page legitimately shows zero indicators, zero lookups and zero provider
failures.  Typing an IP into the search box does not change that: the search is a
**substring filter over already-persisted indicators**, never a live lookup (see
:meth:`~app.services.threat_intelligence_query.ThreatIntelQueryService.list_indicators`).

This module provides a *demo* fixture so the read surface can be demonstrated
end to end without pretending the system has done work it has not done.

Honesty rules (non-negotiable)
------------------------------
* **No fabricated real-provider results.**  Every synthetic lookup is written
  under the clearly-invented provider name :data:`DEMO_PROVIDER_NAME`
  (``"demo-fixture"``).  The words ``VirusTotal``, ``abuseipdb`` and
  ``AlienVault OTX`` never appear in, or as, demo data -- a reviewer can always
  tell a fixture from live intelligence by the provider name alone.
* **Labelled evidence.**  Every success row carries
  ``{"synthetic": true, ...}`` in its evidence and metadata, so the UI renders the
  fixture marker verbatim.
* **No verdicts invented.**  Consistent with the rest of Step 8A, no row asserts
  malicious/benign/severity.  The fixtures exercise the read surface's four
  honest states -- provider returned data, provider returned nothing, provider
  failed, provider never queried -- nothing more.
* **Reserved / example values.**  Indicators use documentation and example
  namespaces (RFC 5737 ``192.0.2.0/24`` / ``198.51.100.0/24``, RFC 2606
  ``.example``) plus the public resolver ``1.1.1.1`` used purely as a
  non-malicious lookup example.  None is presented as a real threat.
* **Real writer.**  Fixtures are persisted through the production
  :class:`~app.services.threat_intelligence_persistence.ThreatIntelligencePersistenceService`,
  so the same contracts, deduplication and provenance checks apply.  This module
  never inserts rows directly and never talks to Kafka.

Safety
------
* The seeder **refuses to run when ``ENVIRONMENT=production``**.
* It is **idempotent**: re-running it creates nothing new (fixed event ids and
  fixed lookup timestamps make the persistence layer's identity checks match).
* :func:`cleanup` removes **only** demo-owned rows (``provider == "demo-fixture"``
  with a demo event id) and then demo-key indicators that are left with no
  lookups at all.  It never deletes an indicator that still has a real lookup.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import ThreatIntelLookup
from app.schemas.threat_intelligence_agent import (
    ExtractedIndicator,
    ProviderAssociation,
    ProviderFailure,
    ThreatIntelligenceAnalysis,
)
from app.services.threat_intelligence.base import ThreatIntelResult
from app.services.threat_intelligence.types import IndicatorType, ThreatIndicator
from app.services.threat_intelligence_persistence import (
    ThreatIntelligencePersistenceService,
    canonical_indicator_key,
)

__all__ = [
    "DEMO_PROVIDER_NAME",
    "DEMO_FIXTURE_SOURCE",
    "DemoSeedForbiddenError",
    "DemoSeedResult",
    "DemoCleanupResult",
    "demo_event_ids",
    "demo_canonical_keys",
    "build_demo_analyses",
    "seed",
    "cleanup",
    "demo_row_counts",
]


# ---------------------------------------------------------------------------
# Identity of the demo namespace
# ---------------------------------------------------------------------------

#: The invented provider name every demo lookup is filed under.  Deliberately
#: not a real vendor, so a fixture can never be mistaken for live intelligence.
DEMO_PROVIDER_NAME = "demo-fixture"

#: Marker written into demo evidence/metadata so the fixture is self-describing.
DEMO_FIXTURE_SOURCE = "sentinelai-demo-fixture"

#: Fixed namespace for deterministic demo event ids.  Stable across runs so the
#: seeder is idempotent and cleanup can find exactly the demo's rows.
_DEMO_NAMESPACE = uuid.UUID("d3f17a20-7e5a-4b0e-9c58-5b1a2c3d4e5f")

#: Fixed instants keep timestamps deterministic (a prerequisite for idempotency
#: and for stable ordering on the read surface).
_BASE_TIME = datetime(2026, 2, 1, 9, 0, tzinfo=timezone.utc)

#: A deliberately fake SHA-256-shaped value.  It is obviously not the hash of any
#: real file, so it cannot be confused with a live sample.
_DEMO_SHA256 = "deadbeef" * 8


def _utc(offset_minutes: int) -> datetime:
    from datetime import timedelta

    return _BASE_TIME + timedelta(minutes=offset_minutes)


def demo_event_id(label: str) -> uuid.UUID:
    """Return the deterministic demo event id for *label*."""
    return uuid.uuid5(_DEMO_NAMESPACE, label)


def _fixture_payload(*, indicator: str, indicator_type: IndicatorType) -> dict:
    """The self-describing synthetic evidence attached to a demo success row."""
    return {
        "synthetic": True,
        "fixture_source": DEMO_FIXTURE_SOURCE,
        "note": (
            "Synthetic demo fixture. This is NOT a result returned by VirusTotal, "
            "AbuseIPDB, AlienVault OTX or any real provider."
        ),
        "indicator": indicator,
        "indicator_type": indicator_type.value,
    }


def _extracted(
    value: str,
    indicator_type: IndicatorType,
    *,
    source_field: str,
    source_context: str,
) -> ExtractedIndicator:
    return ExtractedIndicator(
        indicator=value,
        indicator_type=indicator_type,
        source_field=source_field,
        source_context=source_context,
    )


def _demo_fixture_specs() -> list[dict]:
    """Declarative description of the fixture set.

    Kept as data (not control flow) so it is obvious, reviewable and testable.
    Every entry names one event and one indicator, and at most one provider
    outcome.  The set covers all four indicator types and every read-surface
    state.
    """
    return [
        # Provider returned data (ENRICHED).
        {
            "label": "net-enriched",
            "value": "192.0.2.10",
            "type": IndicatorType.IP,
            "source_field": "destination_endpoint.ip",
            "source_context": "destination_endpoint",
            "outcome": "found",
            "minutes": 0,
        },
        # Provider queried, nothing found (NO DATA).  1.1.1.1 is a public,
        # non-malicious resolver used only as a lookup example.
        {
            "label": "net-nomatch",
            "value": "1.1.1.1",
            "type": IndicatorType.IP,
            "source_field": "destination_endpoint.ip",
            "source_context": "destination_endpoint",
            "outcome": "no_match",
            "minutes": 5,
        },
        # Provider returned data (ENRICHED) -- domain.
        {
            "label": "dns-enriched",
            "value": "demo-payload.example",
            "type": IndicatorType.DOMAIN,
            "source_field": "normalized_data.domain",
            "source_context": "normalized_data",
            "outcome": "found",
            "minutes": 10,
        },
        # Provider failed: rate limit.
        {
            "label": "dns-ratelimit",
            "value": "demo-c2.example",
            "type": IndicatorType.DOMAIN,
            "source_field": "normalized_data.domain",
            "source_context": "normalized_data",
            "outcome": "rate_limit",
            "minutes": 15,
        },
        # Provider failed: timeout.
        {
            "label": "web-timeout",
            "value": "https://demo-payload.example/beacon.bin",
            "type": IndicatorType.URL,
            "source_field": "normalized_data.url",
            "source_context": "normalized_data",
            "outcome": "timeout",
            "minutes": 20,
        },
        # Provider failed: generic error.
        {
            "label": "file-error",
            "value": _DEMO_SHA256,
            "type": IndicatorType.HASH,
            "source_field": "file.hash",
            "source_context": "file",
            "outcome": "provider_error",
            "minutes": 25,
        },
        # Extracted but never looked up (no_lookup).
        {
            "label": "recon-nolookup",
            "value": "198.51.100.20",
            "type": IndicatorType.IP,
            "source_field": "source_endpoint.ip",
            "source_context": "source_endpoint",
            "outcome": "no_lookup",
            "minutes": 30,
        },
    ]


def build_demo_analyses() -> list[ThreatIntelligenceAnalysis]:
    """Build the deterministic demo analyses (pure; performs no I/O)."""
    analyses: list[ThreatIntelligenceAnalysis] = []
    for spec in _demo_fixture_specs():
        indicator = _extracted(
            spec["value"],
            spec["type"],
            source_field=spec["source_field"],
            source_context=spec["source_context"],
        )
        event_id = demo_event_id(spec["label"])
        outcome = spec["outcome"]
        stamp = _utc(spec["minutes"])

        results: list[ProviderAssociation] = []
        failures: list[ProviderFailure] = []

        if outcome in ("found", "no_match"):
            found = outcome == "found"
            data = (
                _fixture_payload(
                    indicator=spec["value"], indicator_type=spec["type"]
                )
                if found
                else {}
            )
            result = ThreatIntelResult(
                indicator=ThreatIndicator(
                    indicator_type=spec["type"], value=spec["value"]
                ),
                provider=DEMO_PROVIDER_NAME,
                found=found,
                data=data,
                metadata=None,
                timestamp=stamp,
            )
            results.append(
                ProviderAssociation(
                    indicator=indicator,
                    provider=DEMO_PROVIDER_NAME,
                    result=result,
                )
            )
        elif outcome != "no_lookup":
            message = (
                "Demo fixture: simulated provider rate limit (synthetic)."
                if outcome == "rate_limit"
                else "Demo fixture: simulated provider timeout (synthetic)."
                if outcome == "timeout"
                else "Demo fixture: simulated provider error (synthetic)."
            )
            failures.append(
                ProviderFailure(
                    provider=DEMO_PROVIDER_NAME,
                    indicator=spec["value"],
                    indicator_type=spec["type"],
                    error_type=outcome,
                    message=message,
                    retryable=outcome in ("rate_limit", "timeout"),
                )
            )

        analyses.append(
            ThreatIntelligenceAnalysis(
                event_id=event_id,
                indicators=[indicator],
                results=results,
                failures=failures,
            )
        )
    return analyses


def demo_event_ids() -> frozenset[uuid.UUID]:
    """Every event id the demo owns (deterministic)."""
    return frozenset(demo_event_id(spec["label"]) for spec in _demo_fixture_specs())


def demo_canonical_keys() -> frozenset[str]:
    """Every indicator canonical key the demo owns."""
    return frozenset(
        canonical_indicator_key(spec["type"], spec["value"])
        for spec in _demo_fixture_specs()
    )


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------


class DemoSeedForbiddenError(RuntimeError):
    """Raised when the demo seeder is asked to run somewhere it must not."""


def _assert_not_production() -> None:
    """Refuse to touch a production database, whatever the caller intended."""
    if settings.environment.strip().lower() == "production":
        raise DemoSeedForbiddenError(
            "Refusing to seed demo fixtures while ENVIRONMENT=production. "
            "Demo data is for local/development demonstration only."
        )


# ---------------------------------------------------------------------------
# Seed
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DemoSeedResult:
    """Summary of one :func:`seed` invocation."""

    events: int
    indicators_created: int
    indicators_updated: int
    lookups_created: int
    lookups_skipped: int

    @property
    def created_anything(self) -> bool:
        return bool(self.indicators_created or self.lookups_created)


def seed(
    db: Session,
    *,
    service: ThreatIntelligencePersistenceService | None = None,
    clock: Callable[[], datetime] | None = None,
) -> DemoSeedResult:
    """Persist the demo fixtures through the real persistence service.

    Idempotent: fixed event ids, fixed success timestamps and a fixed clock for
    failures mean a second run creates nothing and reports the rows as skipped.

    Raises:
        DemoSeedForbiddenError: when ``ENVIRONMENT=production``.
    """
    _assert_not_production()
    service = service or ThreatIntelligencePersistenceService(
        clock=clock or (lambda: _BASE_TIME)
    )

    created = updated = lookups_created = lookups_skipped = 0
    analyses = build_demo_analyses()
    for analysis in analyses:
        result = service.persist_analysis(db, analysis)
        created += result.indicators_created
        updated += result.indicators_updated
        lookups_created += result.lookups_created
        lookups_skipped += result.lookups_skipped

    return DemoSeedResult(
        events=len(analyses),
        indicators_created=created,
        indicators_updated=updated,
        lookups_created=lookups_created,
        lookups_skipped=lookups_skipped,
    )


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DemoCleanupResult:
    """Summary of one :func:`cleanup` invocation."""

    lookups_deleted: int
    indicators_deleted: int


def cleanup(db: Session) -> DemoCleanupResult:
    """Delete demo-owned rows only, never a real lookup or indicator.

    Two precise steps, in one transaction:

    1. Delete only lookups whose ``provider`` is :data:`DEMO_PROVIDER_NAME` *and*
       whose ``event_id`` is one of the demo's fixed ids.  A real lookup can
       satisfy neither.
    2. Delete an indicator only when (a) its canonical key is one the demo owns,
       and (b) it has **no** lookups left after step 1.  An indicator any real
       lookup still points at is left untouched.
    """
    _assert_not_production()
    event_ids = list(demo_event_ids())
    keys = list(demo_canonical_keys())

    demo_lookup_ids = list(
        db.scalars(
            select(ThreatIntelLookup.id).where(
                ThreatIntelLookup.provider == DEMO_PROVIDER_NAME,
                ThreatIntelLookup.event_id.in_(event_ids),
            )
        )
    )
    if demo_lookup_ids:
        db.execute(
            delete(ThreatIntelLookup).where(ThreatIntelLookup.id.in_(demo_lookup_ids))
        )

    indicators_deleted = 0
    if keys:
        candidate_ids = list(
            db.scalars(
                select(ThreatIntelIndicator.id).where(
                    ThreatIntelIndicator.canonical_key.in_(keys)
                )
            )
        )
        for indicator_id in candidate_ids:
            remaining = db.scalar(
                select(func.count())
                .select_from(ThreatIntelLookup)
                .where(ThreatIntelLookup.indicator_id == indicator_id)
            )
            if int(remaining or 0) == 0:
                db.execute(
                    delete(ThreatIntelIndicator).where(
                        ThreatIntelIndicator.id == indicator_id
                    )
                )
                indicators_deleted += 1

    db.commit()
    return DemoCleanupResult(
        lookups_deleted=len(demo_lookup_ids),
        indicators_deleted=indicators_deleted,
    )


def demo_row_counts(db: Session) -> dict[str, int]:
    """Return how many demo-owned rows currently exist (for ``--list``)."""
    event_ids = list(demo_event_ids())
    keys = list(demo_canonical_keys())
    lookups = db.scalar(
        select(func.count())
        .select_from(ThreatIntelLookup)
        .where(
            ThreatIntelLookup.provider == DEMO_PROVIDER_NAME,
            ThreatIntelLookup.event_id.in_(event_ids),
        )
    )
    indicators = db.scalar(
        select(func.count())
        .select_from(ThreatIntelIndicator)
        .where(ThreatIntelIndicator.canonical_key.in_(keys))
    )
    return {"lookups": int(lookups or 0), "indicators": int(indicators or 0)}
