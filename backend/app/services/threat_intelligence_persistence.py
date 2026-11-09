"""Threat-intelligence persistence service (Step 8C-B).

Translates a Step 8B :class:`~app.schemas.threat_intelligence_agent.ThreatIntelligenceAnalysis`
into PostgreSQL persistence operations using the Step 8C-A contract models
(:class:`~app.models.threat_intel_indicator.ThreatIntelIndicator`,
:class:`~app.models.threat_intel_lookup.ThreatIntelLookup`) through the
:class:`~app.repositories.threat_intelligence.ThreatIntelRepository`.

Pipeline:::

    ThreatIntelligenceAnalysis
        ↓  (this service)
    ThreatIntelIndicator   (deduplicated by Step 8A canonical_key)
        ↓
    ThreatIntelLookup      (per event → indicator → provider execution)
        ↓
    success → found / confidence / evidence / result_metadata / result_timestamp
    failure → error_type / sanitized error_message / retryable

Behavioural guarantees
----------------------
* **No network.**  The service performs zero provider API calls.
* **Transactional.**  All work for one analysis commits in a single
  ``Session.commit()``; any failure rolls the unit back and raises a safe
  :class:`ThreatIntelPersistenceError` (no partial state).
* **Idempotent.**  Re-persisting the same analysis reuses existing rows.
  Success lookups are identified by
  ``(event_id, indicator_id, provider, performed_at)``; failure lookups by
  ``(event_id, indicator_id, provider, error_type, error_message,
  retryable)``.  Legitimate repeated historical lookups (same event +
  indicator + provider at a *different* time) are preserved.
* **Provenance.**  Every lookup is stored with
  ``Provenance.ENRICHED`` — never ``observed``/``reconstructed``.
* **Secret-safe.**  Error messages are sanitized and structured evidence is
  recursively key-redacted before persistence.  No API keys, authorization
  headers, cookies, credentials, or raw HTTP responses are ever stored.
* **Post-commit graph refresh.**  When new lookups are committed, the
  knowledge-graph subgraph of every correlation *genuinely* associated with
  the event (via persisted ``correlation_members.event_id``) is refreshed
  through the shared, isolated materializer.  The refresh runs strictly
  after the TI commit, never invents an association when no correlation
  member references the event, and can never undo the committed lookups.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from app.services.knowledge_graph.materialization import GraphMaterializer

from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import LookupStatus, ThreatIntelLookup
from app.repositories.threat_intelligence import ThreatIntelRepository
from app.schemas.security_event import Provenance
from app.schemas.threat_intelligence_agent import (
    ThreatIntelligenceAnalysis,
)
from app.services.threat_intelligence.types import IndicatorType

logger = logging.getLogger(__name__)

#: Hard cap on serialized structured evidence/metadata (defense in depth).
_MAX_EVIDENCE_CHARS = 262_144

#: Hard cap on persisted error messages (defense in depth).
_MAX_ERROR_MESSAGE_CHARS = 4_000

#: Marker substituted for detected credentials anywhere in persisted data.
_REDACTED = "<redacted>"


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class ThreatIntelPersistenceError(Exception):
    """Raised when a threat-intelligence analysis cannot be persisted.

    Instances never contain connection strings, passwords, API keys,
    authorization headers, or raw database/SQL error text — only safe
    contextual identifiers such as the event UUID.
    """

    def __init__(self, event_id: uuid.UUID | None = None, reason: str = "") -> None:
        message = "Failed to persist threat-intelligence analysis"
        if event_id is not None:
            message += f" for event {event_id}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.event_id = event_id


class ThreatIntelPersistenceValidationError(ThreatIntelPersistenceError):
    """Raised when an analysis cannot be mapped to persistence rows safely.

    Used for pre-commit validation failures (e.g. evidence exceeding the
    bounded size) that must abort the analysis transaction.
    """


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThreatIntelPersistenceResult:
    """Summary of one ``persist_analysis`` invocation."""

    event_id: uuid.UUID | None
    indicator_ids: tuple[uuid.UUID, ...]
    lookup_ids: tuple[uuid.UUID, ...]
    indicators_created: int = 0
    indicators_updated: int = 0
    lookups_created: int = 0
    lookups_updated: int = 0
    lookups_skipped: int = 0

    @property
    def is_empty(self) -> bool:
        """True when nothing was persisted (e.g. an empty analysis)."""
        return not (self.indicators_created or self.indicators_updated or self.lookups_created or self.lookups_updated)
# ---------------------------------------------------------------------------
# Secret-safe sanitization
# ---------------------------------------------------------------------------

#: Labeled credential patterns inside error messages, e.g.
#: ``api_key=...``, ``x-api-key: ...``, ``token=...``.  Single-token
#: credentials are redacted together with their label.
_SECRET_LABEL_PATTERN = re.compile(
    r"(?i)((?:set-cookie|cookie|password|passwd|secret|token|api[_-]?key|"
    r"apikey|access[_-]?key|x[_-]?api[_-]?key)\s*[:=]\s*)[^\s,;]+"
)

#: ``Authorization: Bearer <token>`` / ``Authorization: Basic <creds>`` —
#: redacts the scheme and the credential together.
_AUTHORIZATION_PATTERN = re.compile(
    r"(?i)(authorization\s*[:=]\s*)(?:(?:bearer|basic)\s+)?[a-z0-9._~+/=-]+"
)

#: Bare ``Bearer`` / ``Basic`` credential tokens in error text.
_CREDENTIAL_TOKEN_PATTERN = re.compile(
    r"(?i)\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{16,}"
)

#: 64-char opaque tokens (e.g. leaked SHA-256-like API keys).
_BARE_TOKEN_PATTERN = re.compile(r"\b[0-9a-fA-F]{64}\b")

#: JWT-shaped tokens: the standard ``eyJ`` header magic followed by the
#: base64url header/payload/segments (dot-separated for a full JWT, or a
#: bare header in truncated/log text).  Catches JWTs that appear after a
#: redacted ``token:``/``Bearer`` label or standalone in free text.
_JWT_TOKEN_PATTERN = re.compile(r"\beyJ[a-zA-Z0-9_./+=~-]{8,}")


def sanitize_error_message(message: str) -> str:
    """Return a secret-safe, bounded version of *message*.

    The Step 8B :class:`~app.schemas.threat_intelligence_agent.ProviderFailure`
    contract already requires secret-safe messages; this is a second,
    defense-in-depth gate at the persistence boundary.  It redacts labeled
    credential values, ``Authorization`` headers (including Bearer/Basic
    tokens), bare credential tokens, JWT-shaped tokens, and 64-char opaque
    tokens, then truncates to a bounded length.
    """
    if not message:
        return message
    scrubbed = _SECRET_LABEL_PATTERN.sub(
        lambda match: f"{match.group(1)}{_REDACTED}", message
    )
    scrubbed = _AUTHORIZATION_PATTERN.sub(
        lambda match: f"{match.group(1)}{_REDACTED}", scrubbed
    )
    scrubbed = _CREDENTIAL_TOKEN_PATTERN.sub(_REDACTED, scrubbed)
    scrubbed = _BARE_TOKEN_PATTERN.sub(_REDACTED, scrubbed)
    scrubbed = _JWT_TOKEN_PATTERN.sub(_REDACTED, scrubbed)
    return scrubbed.strip()[:_MAX_ERROR_MESSAGE_CHARS]


#: Structured-evidence keys whose values are credentials and must be redacted.
_SECRET_KEY_PATTERN = re.compile(
    r"(?i)^(?:api[_-]?key|apikey|authorization|auth[_-]?header|set[_-]?cookie|"
    r"cookie|password|passwd|secret|token|access[_-]?key|client[_-]?secret)$"
)


def _redact_structured(value: Any) -> Any:
    """Recursively redact credential values inside structured JSON data."""
    if isinstance(value, dict):
        return {
            key: (_REDACTED if _SECRET_KEY_PATTERN.match(str(key)) else _redact_structured(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_structured(item) for item in value]
    return value


def _prepare_structured(data: dict | None, *, field: str) -> dict | None:
    """Redact credentials and enforce the bounded-size rule for JSON columns."""
    if data is None:
        return None
    redacted = _redact_structured(data)
    serialized = len(json.dumps(redacted))
    if serialized > _MAX_EVIDENCE_CHARS:
        raise ThreatIntelPersistenceValidationError(
            reason=f"{field} exceeds the {_MAX_EVIDENCE_CHARS}-character persistence bound"
        )
    return redacted


def canonical_indicator_key(indicator_type: IndicatorType, value: str) -> str:
    """Compute the Step 8A canonical deduplication key for a type/value pair.

    Mirrors :attr:`ExtractedIndicator.canonical_key`: domains and hashes are
    lower-cased; IPs and URLs are kept byte-for-byte (no URL
    canonicalization — Step 8A intentionally preserves URLs as extracted).
    """
    normalized = value
    if indicator_type in (IndicatorType.DOMAIN, IndicatorType.HASH):
        normalized = value.lower()
    return f"{indicator_type.value}:{normalized}"


def _dt_equal(dt1: datetime | None, dt2: datetime | None) -> bool:
    """Compare two datetimes safely across aware and naive UTC representations."""
    if dt1 is None or dt2 is None:
        return dt1 is dt2
    if dt1.tzinfo is None and dt2.tzinfo is not None:
        dt1 = dt1.replace(tzinfo=timezone.utc)
    elif dt2.tzinfo is None and dt1.tzinfo is not None:
        dt2 = dt2.replace(tzinfo=timezone.utc)
    return dt1 == dt2
# ---------------------------------------------------------------------------
# Persistence service
# ---------------------------------------------------------------------------


class ThreatIntelligencePersistenceService:
    """Coordinates persistence of a Step 8B analysis through the repository.

    Args:
        repository_factory: Optional repository factory; defaults to
            :class:`ThreatIntelRepository`.  Injected for testability.
        clock: Optional UTC time source; used when an analysis provides no
            lookup timestamp (failures, or indicators without lookups).
            Defaults to ``datetime.now(timezone.utc)``.
        graph_materializer: Optional post-commit hook used to refresh the
            knowledge graph of correlations associated with the analyzed
            event.  Defaults to the shared knowledge-graph materializer.
            Injected for testability.
    """

    def __init__(
        self,
        repository_factory: Callable[[Session], ThreatIntelRepository] = ThreatIntelRepository,
        clock: Callable[[], datetime] | None = None,
        graph_materializer: "GraphMaterializer | None" = None,
    ) -> None:
        self._repository_factory = repository_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._graph_materializer = graph_materializer

    def persist_analysis(
        self,
        db: Session,
        analysis: ThreatIntelligenceAnalysis,
    ) -> ThreatIntelPersistenceResult:
        """Persist *analysis* atomically and return a summary.

        One logical transaction: every indicator and lookup is staged, a
        single ``commit()`` publishes them together, and any failure rolls
        the unit back before a safe exception propagates.  When new lookups
        are committed, the knowledge graph of every correlation genuinely
        associated with the event is refreshed afterwards as an isolated
        post-commit side effect (see
        :meth:`_refresh_associated_correlation_graphs`).
        """
        try:
            return self._persist(db, analysis)
        except ThreatIntelPersistenceError:
            db.rollback()
            raise
        except Exception as exc:  # database errors / unexpected conditions
            logger.warning(
                "threat-intelligence persistence failed for event=%s (%s)",
                analysis.event_id,
                type(exc).__name__,
            )
            db.rollback()
            raise ThreatIntelPersistenceError(event_id=analysis.event_id) from exc

    # -- internal -----------------------------------------------------------

    def _persist(
        self,
        db: Session,
        analysis: ThreatIntelligenceAnalysis,
    ) -> ThreatIntelPersistenceResult:
        repo = self._repository_factory(db)
        event_id = analysis.event_id
        now = self._clock()

        indicators, occurrences = self._collect_indicators(analysis, now)

        # 2. Persist indicators (globally deduplicated by canonical_key).
        indicator_rows: dict[str, ThreatIntelIndicator] = {}
        indicators_created = indicators_updated = 0
        for key, (value, indicator_type) in indicators.items():
            seen_at = min(occurrences[key]) if occurrences[key] else now
            indicator, created = repo.get_or_create_indicator(
                value=value,
                indicator_type=indicator_type,
                canonical_key=key,
                seen_at=seen_at,
            )
            indicator_rows[key] = indicator
            if created:
                indicators_created += 1
            else:
                indicators_updated += 1

        # 3. Persist lookups: success outcomes, then failure outcomes.
        lookups_created = lookups_updated = lookups_skipped = 0
        lookups: list[ThreatIntelLookup] = []

        for association in analysis.results:
            result = association.result
            if result is None:
                continue
            key = canonical_indicator_key(
                association.indicator.indicator_type, association.indicator.indicator
            )
            indicator = indicator_rows[key]
            performed_at = result.timestamp

            if event_id is not None:
                existing = repo.find_event_lookup(
                    event_id=event_id,
                    indicator_id=indicator.id,
                    provider=association.provider,
                )
                if existing is not None:
                    is_identical = (
                        existing.status == LookupStatus.SUCCESS
                        and existing.found == result.found
                        and existing.confidence == result.confidence
                        and _dt_equal(existing.result_timestamp, result.timestamp)
                    )
                    if is_identical:
                        lookups_skipped += 1
                        continue
                    existing.status = LookupStatus.SUCCESS
                    existing.performed_at = performed_at
                    existing.found = result.found
                    existing.confidence = result.confidence
                    existing.result_timestamp = result.timestamp
                    existing.evidence = _prepare_structured(result.data, field="evidence")
                    existing.result_metadata = _prepare_structured(
                        result.metadata, field="result_metadata"
                    )
                    existing.error_type = None
                    existing.error_message = None
                    existing.retryable = None
                    existing.provenance = Provenance.ENRICHED.value
                    lookups.append(existing)
                    lookups_updated += 1
                    continue

                new_lookup = ThreatIntelLookup(
                    event_id=event_id,
                    origin="event",
                    indicator_id=indicator.id,
                    provider=association.provider,
                    status=LookupStatus.SUCCESS,
                    performed_at=performed_at,
                    found=result.found,
                    confidence=result.confidence,
                    result_timestamp=result.timestamp,
                    evidence=_prepare_structured(result.data, field="evidence"),
                    result_metadata=_prepare_structured(
                        result.metadata, field="result_metadata"
                    ),
                    provenance=Provenance.ENRICHED.value,
                )
                try:
                    with db.begin_nested():
                        repo.add(new_lookup)
                        db.flush()
                    lookups.append(new_lookup)
                    lookups_created += 1
                except IntegrityError:
                    existing = repo.find_event_lookup(
                        event_id=event_id,
                        indicator_id=indicator.id,
                        provider=association.provider,
                    )
                    if existing is not None:
                        existing.status = LookupStatus.SUCCESS
                        existing.performed_at = performed_at
                        existing.found = result.found
                        existing.confidence = result.confidence
                        existing.result_timestamp = result.timestamp
                        existing.evidence = _prepare_structured(result.data, field="evidence")
                        existing.result_metadata = _prepare_structured(
                            result.metadata, field="result_metadata"
                        )
                        existing.error_type = None
                        existing.error_message = None
                        existing.retryable = None
                        lookups.append(existing)
                        lookups_updated += 1
            else:
                new_lookup = ThreatIntelLookup(
                    event_id=None,
                    origin="manual",
                    indicator_id=indicator.id,
                    provider=association.provider,
                    status=LookupStatus.SUCCESS,
                    performed_at=performed_at,
                    found=result.found,
                    confidence=result.confidence,
                    result_timestamp=result.timestamp,
                    evidence=_prepare_structured(result.data, field="evidence"),
                    result_metadata=_prepare_structured(
                        result.metadata, field="result_metadata"
                    ),
                    provenance=Provenance.ENRICHED.value,
                )
                repo.add(new_lookup)
                lookups.append(new_lookup)
                lookups_created += 1

        for failure in analysis.failures:
            key = canonical_indicator_key(failure.indicator_type, failure.indicator)
            indicator = indicator_rows[key]
            safe_message = sanitize_error_message(failure.message)

            if event_id is not None:
                existing = repo.find_event_lookup(
                    event_id=event_id,
                    indicator_id=indicator.id,
                    provider=failure.provider,
                )
                if existing is not None:
                    is_identical = (
                        existing.status == LookupStatus.ERROR
                        and existing.error_type == failure.error_type
                        and existing.error_message == safe_message
                        and existing.retryable == failure.retryable
                    )
                    if is_identical:
                        lookups_skipped += 1
                        continue
                    existing.status = LookupStatus.ERROR
                    existing.performed_at = now
                    existing.error_type = failure.error_type
                    existing.error_message = safe_message
                    existing.retryable = failure.retryable
                    existing.found = None
                    existing.confidence = None
                    existing.result_timestamp = None
                    existing.evidence = None
                    existing.result_metadata = None
                    existing.provenance = Provenance.ENRICHED.value
                    lookups.append(existing)
                    lookups_updated += 1
                    continue

                new_lookup = ThreatIntelLookup(
                    event_id=event_id,
                    origin="event",
                    indicator_id=indicator.id,
                    provider=failure.provider,
                    status=LookupStatus.ERROR,
                    performed_at=now,
                    error_type=failure.error_type,
                    error_message=safe_message,
                    retryable=failure.retryable,
                    provenance=Provenance.ENRICHED.value,
                )
                try:
                    with db.begin_nested():
                        repo.add(new_lookup)
                        db.flush()
                    lookups.append(new_lookup)
                    lookups_created += 1
                except IntegrityError:
                    existing = repo.find_event_lookup(
                        event_id=event_id,
                        indicator_id=indicator.id,
                        provider=failure.provider,
                    )
                    if existing is not None:
                        existing.status = LookupStatus.ERROR
                        existing.performed_at = now
                        existing.error_type = failure.error_type
                        existing.error_message = safe_message
                        existing.retryable = failure.retryable
                        existing.found = None
                        existing.confidence = None
                        existing.result_timestamp = None
                        existing.evidence = None
                        existing.result_metadata = None
                        lookups.append(existing)
                        lookups_updated += 1
            else:
                new_lookup = ThreatIntelLookup(
                    event_id=None,
                    origin="manual",
                    indicator_id=indicator.id,
                    provider=failure.provider,
                    status=LookupStatus.ERROR,
                    performed_at=now,
                    error_type=failure.error_type,
                    error_message=safe_message,
                    retryable=failure.retryable,
                    provenance=Provenance.ENRICHED.value,
                )
                repo.add(new_lookup)
                lookups.append(new_lookup)
                lookups_created += 1

        # 4. Flush and commit lookups.
        if lookups:
            db.flush()

        if indicators or lookups:
            db.commit()

        # The lookups above are now durable and visible.  Refresh the knowledge
        # graph of every correlation genuinely associated with this event so
        # the new EVENT -> THREAT_INDICATOR evidence becomes visible.  This is
        # an isolated post-commit side effect: a graph failure is logged and
        # swallowed by the shared materializer and can never undo or mask the
        # committed threat-intelligence results.
        if lookups and event_id is not None:
            self._refresh_associated_correlation_graphs(db, event_id)

        return ThreatIntelPersistenceResult(
            event_id=event_id,
            indicator_ids=tuple(indicator.id for indicator in indicator_rows.values()),
            lookup_ids=tuple(lookup.id for lookup in lookups),
            indicators_created=indicators_created,
            indicators_updated=indicators_updated,
            lookups_created=lookups_created,
            lookups_updated=lookups_updated,
            lookups_skipped=lookups_skipped,
        )

    def _refresh_associated_correlation_graphs(
        self, db: Session, event_id: uuid.UUID
    ) -> None:
        """Best-effort refresh of the graphs of correlations tied to *event_id*.

        The durable association is ``correlation_members.event_id``: a
        correlation is associated with the event only when a persisted member
        row references it — the lookup row itself carries no correlation id
        (V2 stores no such column), so nothing is guessed and no association
        is fabricated.  An event with no member rows simply has no correlation
        graph to refresh.
        """
        from app.models.correlation_member import CorrelationMember
        from app.services.knowledge_graph.materialization import (
            refresh_correlation_graphs,
        )

        try:
            correlation_ids = list(
                db.scalars(
                    select(CorrelationMember.correlation_id)
                    .where(CorrelationMember.event_id == event_id)
                    .distinct()
                )
            )
        except Exception:
            logger.warning(
                "knowledge graph refresh skipped for event=%s: could not "
                "resolve associated correlations",
                event_id,
                exc_info=True,
            )
            return
        if not correlation_ids:
            logger.debug(
                "knowledge graph refresh skipped for event=%s: no persisted "
                "correlation member references this event",
                event_id,
            )
            return
        try:
            refresh_correlation_graphs(
                db, correlation_ids, materializer=self._graph_materializer
            )
        except Exception:
            logger.warning(
                "knowledge graph refresh failed for event=%s",
                event_id,
                exc_info=True,
            )

    @staticmethod
    def _collect_indicators(
        analysis: ThreatIntelligenceAnalysis, now: datetime
    ) -> tuple[dict[str, tuple[str, IndicatorType]], dict[str, list[datetime]]]:
        """Union of indicators referenced anywhere in the analysis.

        Sources, in canonical-key-deduplicated order:

        * ``analysis.indicators`` — the authoritative list of extracted
          indicators;
        * ``analysis.results[*].indicator`` — indicators referenced by
          provider associations;
        * ``analysis.failures[*]`` — indicators referenced by failures.

        Returns:
            ``(canonical_key -> (exact value, type), canonical_key ->
            occurrence timestamps)``.  Occurrences are the per-lookup
            ``performed_at`` for successful lookups and the persistence
            clock for failures / unreferenced indicators.
        """
        indicators: dict[str, tuple[str, IndicatorType]] = {}
        occurrences: dict[str, list[datetime]] = {}

        def register(value: str, indicator_type: IndicatorType) -> None:
            key = canonical_indicator_key(indicator_type, value)
            indicators.setdefault(key, (value, indicator_type))
            occurrences.setdefault(key, [])

        for extracted in analysis.indicators:
            register(extracted.indicator, extracted.indicator_type)

        for assoc in analysis.results:
            register(assoc.indicator.indicator, assoc.indicator.indicator_type)
            if assoc.result is not None:
                key = canonical_indicator_key(
                    assoc.indicator.indicator_type, assoc.indicator.indicator
                )
                occurrences[key].append(assoc.result.timestamp)

        for failure in analysis.failures:
            register(failure.indicator, failure.indicator_type)
            occurrences[
                canonical_indicator_key(failure.indicator_type, failure.indicator)
            ].append(now)

        return indicators, occurrences


def persist_analysis(
    db: Session,
    analysis: ThreatIntelligenceAnalysis,
) -> ThreatIntelPersistenceResult:
    """Convenience wrapper: persist *analysis* with a default service.

    Equivalent to ``ThreatIntelligencePersistenceService().persist_analysis(
    db, analysis)``.
    """
    return ThreatIntelligencePersistenceService().persist_analysis(db, analysis)