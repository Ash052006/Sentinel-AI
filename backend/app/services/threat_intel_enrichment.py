"""Opt-in threat-intelligence enrichment for the runtime ingest pipeline.

This module is the runtime edge for threat intelligence.  The
:class:`~app.agents.threat_intelligence.ThreatIntelligenceAgent` and
:class:`~app.agents.enrichment.EnrichmentAgent` existed and were exercised by
the demo, but the live ingestion paths did not invoke them.  This module wires
them into the *same* governed pipelines used by the Kafka worker and the HTTP
endpoint, without changing the agents, the persistence service, or the pipeline
contract:

    normalize -> detect -> **persist detections** -> enrich -> analyse -> persist TI

Ordering is deliberate and non-negotiable: threat-intelligence enrichment runs
**after** the detection write has committed.  A provider outage, timeout, or
persistence error therefore can never roll back or mask a detection result.

Everything here is opt-in.  The stage is enabled by
``settings.threat_intel_enrichment_enabled`` (default ``False``); when disabled
the ingestion pipeline behaves exactly as it did before this module existed --
no provider client is constructed and no external call is ever made.

This module adds no new analysis logic.  It only wires the *existing*
:class:`~app.agents.enrichment.EnrichmentAgent`,
:class:`~app.agents.threat_intelligence.ThreatIntelligenceAgent`, and
:func:`~app.agents.threat_intelligence.persist_analysis_bound` together, reusing
a single provider registry and agent instances across every event in a worker
run or HTTP upload (a registry rebuild per event would be pure waste).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.agents.enrichment import EnrichmentAgent
from app.agents.threat_intelligence import (
    ThreatIntelligenceAgent,
    persist_analysis_bound,
)
from app.services.threat_intelligence.registry import ProviderRegistry
from app.services.threat_intelligence_persistence import (
    ThreatIntelligencePersistenceService,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sqlalchemy.orm import Session

    from app.schemas.normalized_event import NormalizedSecurityEvent
    from app.schemas.threat_intelligence_agent import ThreatIntelligenceAnalysis

logger = logging.getLogger(__name__)


def build_provider_registry() -> tuple[ProviderRegistry, list[str]]:
    """Build the real provider registry from configured credentials.

    Mirrors the demo's ``ti_registry()`` policy exactly: a provider with no
    API key is *skipped rather than stubbed*, so a missing credential reduces
    coverage instead of inventing a lookup result, and a provider whose
    constructor fails is skipped (its label is reported) instead of aborting
    the run.  The registry is returned even when empty.

    Returns:
        ``(registry, skipped)`` where *skipped* is a list of human-readable
        labels for the providers that could not be built.
    """
    from app.core.config import settings
    from app.services.threat_intelligence.abuseipdb import AbuseIPDBProvider
    from app.services.threat_intelligence.alienvault_otx import (
        AlienVaultOTXProvider,
    )
    from app.services.threat_intelligence.virustotal import VirusTotalProvider

    providers = []
    skipped: list[str] = []
    for label, key, factory in (
        ("virustotal", settings.virustotal_api_key, VirusTotalProvider),
        ("abuseipdb", settings.abuseipdb_api_key, AbuseIPDBProvider),
        ("otx", settings.otx_api_key, AlienVaultOTXProvider),
    ):
        if not key:
            skipped.append(f"{label} (no API key)")
            continue
        try:
            providers.append(factory())
        except Exception as exc:  # noqa: BLE001 - one bad provider must not abort
            skipped.append(f"{label} ({type(exc).__name__})")
    return ProviderRegistry(providers), skipped


class ThreatIntelEnricher:
    """Runs enrichment + threat-intelligence over one already-persisted event.

    The two governed agents are constructed once and reused for the lifetime
    of the enricher, so a worker run pays for them once rather than per event.
    Every collaborator is injectable for testing; no network call is made
    until :meth:`enrich` is invoked, and provider failures are already isolated
    inside :class:`~app.agents.threat_intelligence.ThreatIntelligenceAgent`.

    Args:
        provider_registry: The :class:`ProviderRegistry` used to build the
            threat-intelligence agent when one is not injected.
        enrichment_agent: Optional :class:`EnrichmentAgent`; defaults to a new
            one.
        analysis_agent: Optional :class:`ThreatIntelligenceAgent`; defaults to
            one built from *provider_registry*.
        persistence: Optional
            :class:`~app.services.threat_intelligence_persistence.ThreatIntelligencePersistenceService`;
            defaults to a new one.  It is bound to the caller's session per
            :meth:`enrich` call.
    """

    def __init__(
        self,
        provider_registry: ProviderRegistry,
        *,
        enrichment_agent: EnrichmentAgent | None = None,
        analysis_agent: ThreatIntelligenceAgent | None = None,
        persistence: ThreatIntelligencePersistenceService | None = None,
    ) -> None:
        self._enricher = enrichment_agent or EnrichmentAgent()
        self._analyst = analysis_agent or ThreatIntelligenceAgent(
            provider_registry
        )
        self._persistence = persistence or ThreatIntelligencePersistenceService()

    def enrich(
        self,
        db: Session,
        normalized_event: NormalizedSecurityEvent,
    ) -> ThreatIntelligenceAnalysis:
        """Enrich and analyse *normalized_event*, persisting the analysis.

        Delegates to the existing agents: first
        :class:`EnrichmentAgent` builds the
        :class:`EnrichedSecurityEvent`, then
        :class:`ThreatIntelligenceAgent` analyses it with persistence bound to
        *db*.  Nothing new is computed here.
        """
        enriched = self._enricher.enrich(normalized_event)
        return self._analyst.analyze(
            enriched,
            persistence=persist_analysis_bound(
                db, service=self._persistence
            ),
        )


def build_threat_intel_enricher() -> tuple[ThreatIntelEnricher, list[str]]:
    """Build the runtime enricher from configuration.

    Returns ``(enricher, skipped)``.  *skipped* lists the providers that could
    not be built (normally because their API key is unset); callers should log
    it so an operator can tell reduced coverage from a fault.  The enricher is
    always returned, even when the registry is empty: the local indicator
    extraction still runs, and no lookup is fabricated.
    """
    registry, skipped = build_provider_registry()
    return ThreatIntelEnricher(registry), skipped
