"""Threat Intelligence Agent — Step 8B orchestration.

Implements the execution layer that coordinates external threat-intelligence
providers for an :class:`EnrichedSecurityEvent`.  This agent:

* extracts structurally identifiable indicators from the event using the
  Step 8A contract (:class:`ExtractedIndicator`),
* deduplicates them deterministically via ``canonical_key``,
* selects compatible providers through the existing
  :class:`~app.services.threat_intelligence.registry.ProviderRegistry`
  (never hardcoding a provider list),
* executes provider lookups, isolating each provider's failure,
* converts successful :class:`ThreatIntelResult` objects into
  :class:`EnrichmentResult` objects via the pure Step 8A helper
  :func:`threat_intel_result_to_enrichment`, and
* returns a :class:`ThreatIntelligenceAnalysis` with accurate metadata.

Architecture::

    EnrichedSecurityEvent
        ↓
    ThreatIntelligenceAgent.analyze()
        ↓
    Indicator extraction        (Step 8A ExtractedIndicator)
        ↓
    Deterministic deduplication (canonical_key)
        ↓
    ProviderRegistry
        ↓
    ThreatIntelProvider.lookup()
        ↓
    ThreatIntelResult / ProviderFailure
        ↓
    EnrichmentResult
        ↓
    ThreatIntelligenceAnalysis
        ↓  (optional injected sink, Step 8C-C)
    Persistence Service → PostgreSQL

Design principles:

* **Stateless & deterministic** — same event + same registry always
  produces the same shape of analysis.  Persistence (if any) is an
  injected side-effect sink invoked only *after* the analysis is built;
  the agent never commits, rolls back, or depends on a database.
* **No verdicts** — the agent never assigns a malicious/benign verdict,
  never computes a risk score, and never aggregates confidence.  Provider
  evidence is evidence only.
* **No mutation** — the input :class:`EnrichedSecurityEvent` and its
  nested :class:`NormalizedSecurityEvent` are never modified.
* **Secret-safe** — failures and enrichments never contain API keys,
  authorization headers, or raw HTTP responses.
* **Provider-agnostic** — new providers registered with the registry are
  automatically supported.
"""

from __future__ import annotations

import logging
from typing import Callable, Protocol

from sqlalchemy.orm import Session

from app.schemas.enriched_event import EnrichedSecurityEvent
from app.schemas.normalized_event import NormalizedSecurityEvent
from app.schemas.threat_intelligence_agent import (
    ExtractedIndicator,
    ProviderAssociation,
    ProviderFailure,
    ThreatIntelMetadata,
    ThreatIntelligenceAnalysis,
    threat_intel_result_to_enrichment,
)
from app.services.threat_intelligence.exceptions import (
    InvalidIndicatorError,
    ProviderLookupError,
    RateLimitError,
    ThreatIntelError,
)
from app.services.threat_intelligence.registry import ProviderRegistry
from app.services.threat_intelligence.types import IndicatorType, ThreatIndicator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pluggable persistence boundary (Step 8C-C)
# ---------------------------------------------------------------------------
#
# The agent stays a *pure* orchestration layer: it always builds and returns a
# :class:`ThreatIntelligenceAnalysis` with no side effects.  Persisting that
# analysis is an orthogonal concern, injected as an optional callback so the
# agent never knows about the database.  This keeps the agent stateless and
# deterministic while allowing the pipeline (or tests) to supply whatever
# persistence they need.


class AnalysisPersistence(Protocol):
    """Protocol satisfied by a threat-intelligence persistence sink.

    A conforming callable takes a completed
    :class:`~app.schemas.threat_intelligence_agent.ThreatIntelligenceAnalysis`
    and persists it, returning an opaque summary.  The persistence (service)
    owns its own transaction boundary — the agent never commits or rolls back.
    """

    def __call__(self, analysis: ThreatIntelligenceAnalysis) -> object: ...


#: Type alias for the injected persistence callback accepted by ``analyze()``.
PersistenceCallback = Callable[[ThreatIntelligenceAnalysis], object]


# ---------------------------------------------------------------------------
# Deterministic, key-based extraction of indicators from ``normalized_data``
# ---------------------------------------------------------------------------
#
# The agent only ever reads indicators from *explicitly* present, structurally
# identifiable fields.  For the flexible ``normalized_data`` mapping we use
# explicit, unambiguous key allowlists rather than heuristic value scanning —
# this guarantees no indicator is ever invented from an unrelated field.

#: ``normalized_data`` keys that unambiguously denote an IP address.
_IP_KEYS: frozenset[str] = frozenset(
    {
        "ip",
        "ip_address",
        "source_ip",
        "src_ip",
        "destination_ip",
        "dst_ip",
        "remote_ip",
        "client_ip",
    }
)

#: ``normalized_data`` keys that unambiguously denote a domain.
_DOMAIN_KEYS: frozenset[str] = frozenset(
    {
        "domain",
        "domain_name",
        "host",
        "fqdn",
    }
)

#: ``normalized_data`` keys that unambiguously denote a URL.
_URL_KEYS: frozenset[str] = frozenset(
    {
        "url",
        "uri",
        "request_uri",
        "href",
        "url_full",
    }
)

#: ``normalized_data`` keys that unambiguously denote a file hash.
_HASH_KEYS: frozenset[str] = frozenset(
    {
        "hash",
        "file_hash",
        "md5",
        "sha1",
        "sha256",
        "sha512",
    }
)

class ThreatIntelligenceAgent:
    """Stateless orchestrator for threat-intelligence provider lookups.

    The agent is constructed once with a
    :class:`~app.services.threat_intelligence.registry.ProviderRegistry`
    and is then safe to reuse across many events.  It holds no per-event
    state and makes no network calls itself — providers are responsible
    for their own credentials and HTTP access.
    """

    def __init__(self, registry: ProviderRegistry) -> None:
        if not isinstance(registry, ProviderRegistry):
            raise TypeError(
                "Expected ProviderRegistry, got "
                f"{type(registry).__name__}"
            )
        self._registry = registry

    # -- Public API ----------------------------------------------------------

    def analyze(
        self,
        event: EnrichedSecurityEvent,
        *,
        persistence: PersistenceCallback | None = None,
    ) -> ThreatIntelligenceAnalysis:
        """Run a full threat-intelligence analysis over *event*.

        Extracts indicators, deduplicates them deterministically, selects
        compatible providers from the registry, executes their lookups
        (isolating failures), and returns a complete
        :class:`ThreatIntelligenceAnalysis`.

        When *persistence* is supplied, the completed analysis is handed to
        it before being returned.  Persistence is purely a side-effect sink:
        the analysis is fully built first, the agent never commits/rolls back,
        and a persistence failure is logged and re-raised as-is so the caller
        can decide how to handle it.  With ``persistence=None`` (the default)
        the agent performs no persistence and its behavior is exactly the
        Step 8B behavior.

        Args:
            event: The enriched security event to analyse.  Never mutated.
            persistence: Optional callable invoked with the completed
                :class:`ThreatIntelligenceAnalysis` to persist it.  Defaults
                to ``None`` (no persistence).

        Returns:
            A :class:`ThreatIntelligenceAnalysis` describing the run.
        """
        if not isinstance(event, EnrichedSecurityEvent):
            raise TypeError(
                "Expected EnrichedSecurityEvent, got "
                f"{type(event).__name__}"
            )

        # Every occurrence is kept so that per-source provenance survives;
        # provider lookups are deduplicated by canonical_key.
        extracted_indicators = self._extract_indicators(event)
        lookup_indicators = self._deduplicate(extracted_indicators)

        results: list[ProviderAssociation] = []
        failures: list[ProviderFailure] = []
        enrichments = []

        attempted_providers: set[str] = set()
        succeeded_providers: set[str] = set()
        failed_providers: set[str] = set()

        lookups_attempted = 0
        lookups_succeeded = 0
        lookups_failed = 0

        for indicator in lookup_indicators:
            providers = self._registry.find_providers_for(
                indicator.indicator_type
            )
            threat_indicator = ThreatIndicator(
                indicator_type=indicator.indicator_type,
                value=indicator.indicator,
            )
            for provider in providers:
                name = provider.provider_name
                attempted_providers.add(name)
                lookups_attempted += 1
                try:
                    result = provider.lookup(threat_indicator)
                except Exception as exc:  # noqa: BLE001 — isolate all failures
                    lookups_failed += 1
                    failed_providers.add(name)
                    failures.append(self._to_failure(indicator, name, exc))
                    logger.warning(
                        "Threat-intel lookup failed: provider=%s "
                        "indicator_type=%s indicator=%r error_type=%s",
                        name,
                        indicator.indicator_type.value,
                        indicator.indicator,
                        self._classify(exc)[0],
                    )
                    continue
                lookups_succeeded += 1
                succeeded_providers.add(name)
                results.append(
                    ProviderAssociation(
                        indicator=indicator,
                        provider=name,
                        result=result,
                    )
                )
                enrichments.append(
                    threat_intel_result_to_enrichment(result)
                )

        metadata = ThreatIntelMetadata(
            providers_attempted=len(attempted_providers),
            providers_succeeded=len(succeeded_providers),
            providers_failed=len(failed_providers),
            indicators_extracted=len(lookup_indicators),
            lookups_attempted=lookups_attempted,
            lookups_succeeded=lookups_succeeded,
            lookups_failed=lookups_failed,
        )

        analysis = ThreatIntelligenceAnalysis(
            event_id=event.event_id,
            indicators=extracted_indicators,
            results=results,
            failures=failures,
            enrichments=enrichments,
            metadata=metadata,
        )

        # 8C-C persistence boundary: delegate to the injected sink (if any).
        # The analysis is fully built — the agent has already done all of its
        # deterministic work.  The sink owns its own transaction; we only
        # surface a failure (which the sink has already sanitized) so the
        # caller can react.  The agent itself stays stateless.
        if persistence is not None:
            try:
                persistence(analysis)
            except Exception as exc:  # noqa: BLE001 - surface sanitized error
                logger.warning(
                    "Threat-intel analysis persistence failed for event=%s (%s)",
                    event.event_id,
                    type(exc).__name__,
                )
                raise

        return analysis

    # -- Indicator extraction ------------------------------------------------

    def _extract_indicators(
        self, event: EnrichedSecurityEvent,
    ) -> list[ExtractedIndicator]:
        """Collect every explicitly present, supported indicator.

        Only the field locations defined by the Step 8A contract are read:

        * ``source_endpoint.ip`` and ``destination_endpoint.ip`` → IP,
        * expressly-keyed ``normalized_data`` domain/URL/hash fields,
        * ``file.hash`` → hash.

        No heuristic NLP, no value scanning of arbitrary strings, and no
        fabrication of missing values.
        """
        normalized: NormalizedSecurityEvent = event.normalized_event
        extracted: list[ExtractedIndicator] = []

        # IPs from the strongly-typed network endpoints.
        if (
            normalized.source_endpoint is not None
            and normalized.source_endpoint.ip
        ):
            extracted.append(
                ExtractedIndicator(
                    indicator=normalized.source_endpoint.ip,
                    indicator_type=IndicatorType.IP,
                    source_field="source_endpoint.ip",
                    source_context="source_endpoint",
                )
            )
        if (
            normalized.destination_endpoint is not None
            and normalized.destination_endpoint.ip
        ):
            extracted.append(
                ExtractedIndicator(
                    indicator=normalized.destination_endpoint.ip,
                    indicator_type=IndicatorType.IP,
                    source_field="destination_endpoint.ip",
                    source_context="destination_endpoint",
                )
            )

        # Explicitly-keyed indicators from the flexible normalized_data map.
        # Keys are iterated in sorted order for fully deterministic output.
        for key in sorted(normalized.normalized_data.keys()):
            value = normalized.normalized_data[key]
            if not isinstance(value, str) or not value.strip():
                continue
            source_field = f"normalized_data.{key}"
            if key in _IP_KEYS:
                extracted.append(
                    ExtractedIndicator(
                        indicator=value,
                        indicator_type=IndicatorType.IP,
                        source_field=source_field,
                        source_context="normalized_data",
                    )
                )
            elif key in _DOMAIN_KEYS:
                extracted.append(
                    ExtractedIndicator(
                        indicator=value,
                        indicator_type=IndicatorType.DOMAIN,
                        source_field=source_field,
                        source_context="normalized_data",
                    )
                )
            elif key in _URL_KEYS:
                extracted.append(
                    ExtractedIndicator(
                        indicator=value,
                        indicator_type=IndicatorType.URL,
                        source_field=source_field,
                        source_context="normalized_data",
                    )
                )
            elif key in _HASH_KEYS:
                extracted.append(
                    ExtractedIndicator(
                        indicator=value,
                        indicator_type=IndicatorType.HASH,
                        source_field=source_field,
                        source_context="normalized_data",
                    )
                )

        # The strongly-typed file hash.
        if normalized.file is not None and normalized.file.hash:
            extracted.append(
                ExtractedIndicator(
                    indicator=normalized.file.hash,
                    indicator_type=IndicatorType.HASH,
                    source_field="file.hash",
                    source_context="file",
                )
            )

        return extracted

    @staticmethod
    def _deduplicate(
        indicators: list[ExtractedIndicator],
    ) -> list[ExtractedIndicator]:
        """Return ``indicators`` deduplicated by ``canonical_key``.

        This list drives the provider lookups: indicators with the same
        ``indicator_type`` and normalized value are looked up exactly once.
        The first occurrence of each canonical key is preserved, giving a
        deterministic result regardless of how many fields carried the same
        value.  Distinct indicator types sharing a literal value remain
        distinct (their canonical keys differ).

        Note: deduplication applies to *lookups*; the full occurrence list
        (with each source context) is still kept on the analysis so no
        provenance is lost.
        """
        seen: set[str] = set()
        unique: list[ExtractedIndicator] = []
        for indicator in indicators:
            key = indicator.canonical_key
            if key in seen:
                continue
            seen.add(key)
            unique.append(indicator)
        return unique

    # -- Failure handling ----------------------------------------------------

    def _to_failure(
        self,
        indicator: ExtractedIndicator,
        provider: str,
        exc: Exception,
    ) -> ProviderFailure:
        """Build a secret-safe :class:`ProviderFailure` from *exc*."""
        error_type, retryable, message = self._classify(exc)
        return ProviderFailure(
            provider=provider,
            indicator=indicator.indicator,
            indicator_type=indicator.indicator_type,
            error_type=error_type,
            message=message,
            retryable=retryable,
        )

    @staticmethod
    def _classify(exc: Exception) -> tuple[str, bool, str]:
        """Map an exception to ``(error_type, retryable, message)``.

        Uses the existing provider exception hierarchy where possible.
        The returned message is the (already secret-safe) exception text —
        it never carries API keys, authorization headers, or raw HTTP
        responses.
        """
        if isinstance(exc, RateLimitError):
            return "rate_limit", True, str(exc)
        if isinstance(exc, ProviderLookupError):
            message = str(exc)
            lowered = message.lower()
            if "timeout" in lowered or "timed out" in lowered or (
                "server error" in lowered
            ):
                return "timeout", True, message
            return "provider_error", False, message
        if isinstance(exc, InvalidIndicatorError):
            return "invalid_indicator", False, str(exc)
        if isinstance(exc, ThreatIntelError):
            return "provider_error", False, str(exc)
        return "unexpected", False, f"{type(exc).__name__}: {exc}"


def persist_analysis_bound(
    db: Session,
    *,
    service: ThreatIntelligencePersistenceService | None = None,
) -> PersistenceCallback:
    """Bind a persistence *service* to *db* for injection into ``analyze()``.

    Returns a :class:`PersistenceCallback` that persists a completed
    :class:`~app.schemas.threat_intelligence_agent.ThreatIntelligenceAnalysis`
    through :meth:`ThreatIntelligencePersistenceService.persist_analysis`.

    This is the concrete wiring between the Step 8B agent and the existing
    Step 8C persistence service::

        callback = persist_analysis_bound(session)
        analysis = agent.analyze(event, persistence=callback)

    The service (not the agent) owns the transaction: it commits the whole
    analysis atomically and rolls back on any failure.  The returned callback
    simply forwards the analysis and returns the service's summary.

    Args:
        db: The SQLAlchemy session owned by the caller.
        service: Optional persistence service; defaults to a fresh
            :class:`ThreatIntelligencePersistenceService`.

    Returns:
        A callable accepting a ``ThreatIntelligenceAnalysis``.
    """
    from app.services.threat_intelligence_persistence import (
        ThreatIntelligencePersistenceService,
    )

    sink = service or ThreatIntelligencePersistenceService()

    def _persist(analysis: ThreatIntelligenceAnalysis) -> object:
        return sink.persist_analysis(db, analysis)

    return _persist

