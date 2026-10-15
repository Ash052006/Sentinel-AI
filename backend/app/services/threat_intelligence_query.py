"""Threat Intelligence query layer (Step 8A read surface).

Read-only service over the Step 8C persistence tables.  This is the
companion to :mod:`app.services.threat_intelligence_persistence`, which is
the only writer.  The layering is deliberate and one-directional::

    ThreatIntelligenceAgent  (writes, via the persistence service)
        -> threat_intel_indicators / threat_intel_lookups
        -> ThreatIntelQueryService  (this module, reads only)

Architecture
------------
This module follows the read-only service pattern already established by
:mod:`app.services.detection_query` (Step 9G): validation first, then a
bounded deterministic query, then a mapping into a Step-8A read model.

Design principles
-----------------

* **Read-only, guaranteed** -- no method opens a transaction, calls
  ``add``/``flush``/``commit``/``delete``, or constructs a
  :class:`~app.models.threat_intel_indicator.ThreatIntelIndicator` or
  :class:`~app.models.threat_intel_lookup.ThreatIntelLookup`.  Indicators and
  lookups are created exclusively by the Threat Intelligence Agent.
* **Bounded** -- every query carries an explicit ``LIMIT``, page size is
  capped at :data:`MAX_PAGE_SIZE`, and lookup history and event
  correlation are independently capped.  An unbounded read is impossible.
* **Deterministic** -- indicators order by ``last_seen_at`` descending then
  ``id`` ascending; lookups by ``performed_at`` descending then ``id``
  ascending.  The ``id`` tie-break means two rows sharing a timestamp can
  never swap places between requests, so paging cannot duplicate or drop
  rows.
* **No N+1** -- the list endpoint resolves per-indicator lookup rollups
  with a single grouped aggregate plus a single distinct-provider query for
  the page, regardless of ``page_size``.
* **No fabricated verdicts** -- the service never derives a malicious /
  benign / severity / risk value.  It reports the persisted ``found`` flag,
  the persisted ``confidence`` (which is legitimately null), and the
  persisted lookup ``status``, and it is explicit that a failed lookup is
  not a verdict.
* **Defence in depth on secrets** -- the persistence service already
  sanitizes ``evidence``/``result_metadata``/``error_message`` on write.
  This module re-sanitizes on read using patterns defined *independently*
  of the write path, so a future change to either side cannot silently
  disable the other's redaction.
* **Parameterised only** -- every filter is bound through SQLAlchemy
  expressions.  The one free-text filter (``value_contains``) is passed as
  a bound parameter with an escaped ``LIKE`` pattern; no string is ever
  interpolated into SQL.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import LookupStatus, ThreatIntelLookup
from app.schemas.security_event import Provenance
from app.schemas.threat_intelligence_query import (
    ThreatIntelIndicatorDetail,
    ThreatIntelIndicatorEvents,
    ThreatIntelIndicatorPage,
    ThreatIntelIndicatorRecord,
    ThreatIntelLookupRecord,
)
from app.services.threat_intelligence.types import IndicatorType

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "MAX_LOOKUPS_PER_INDICATOR",
    "MAX_EVENTS_PER_INDICATOR",
    "MAX_INDICATOR_FILTER_LENGTH",
    "ThreatIntelQueryError",
    "ThreatIntelQueryValidationError",
    "ThreatIntelIndicatorNotFoundError",
    "ThreatIntelQueryService",
]


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

#: Rows returned when the caller does not specify a page size.
DEFAULT_PAGE_SIZE = 50

#: Hard cap on a single page.  Guards against unbounded materialization.
MAX_PAGE_SIZE = 200

#: Hard cap on the lookup history returned for one indicator detail.
MAX_LOOKUPS_PER_INDICATOR = 200

#: Hard cap on the event-correlation list returned for one indicator.
MAX_EVENTS_PER_INDICATOR = 200

#: Longest accepted free-text indicator filter.  Matches the widest
#: indicator-ish column (``value``, 2048) with headroom.
MAX_INDICATOR_FILTER_LENGTH = 512

#: ``_like_escape`` is a literal backslash, used to escape ``%``/``_``/``\``.
#: SQLAlchemy renders the ESCAPE clause for us via ``autoescape=True``.
_LIKE_ESCAPE = "\\"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ThreatIntelQueryError(RuntimeError):
    """Base error for the Threat Intelligence query layer."""


class ThreatIntelQueryValidationError(ThreatIntelQueryError):
    """Raised when query input cannot be validated safely.

    Raised *before* any database work: malformed UUIDs, an out-of-range
    page size, an unknown indicator type, and oversized or blank filters all
    land here and surface as HTTP 422.

    Callers construct it with a single ``reason`` keyword, so the reason is
    both the message and a machine-readable attribute -- the transport
    returns the message as the 422 detail rather than re-deriving it.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ThreatIntelIndicatorNotFoundError(ThreatIntelQueryError):
    """Raised when an indicator id does not resolve to a persisted row."""

    def __init__(self, indicator_id: uuid.UUID) -> None:
        super().__init__(f"Indicator {indicator_id} was not found")
        self.indicator_id = indicator_id


# ---------------------------------------------------------------------------
# Read-side secret-safe sanitization
# ---------------------------------------------------------------------------

#: Marker substituted for any value withheld from a response.
_REDACTED = "<redacted>"

#: Keys whose values are credentials.  Mirrors the write-side rule in
#: :mod:`app.services.threat_intelligence_persistence` but is deliberately
#: **broader and independently maintained**: it is anchored only at the end
#: of the key, so vendor-prefixed credentials such as ``x-api-key`` and
#: ``vt_api_key`` are caught too, and it is not imported from the write
#: path, so a regression in either implementation cannot silently open the
#: other.  Failing closed -- over-redacting a benign key is recoverable,
#: leaking a key is not.
_SECRET_KEY_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|apikey|authorization|auth[_-]?header|auth[_-]?token|"
    r"set[_-]?cookie|cookie|password|passwd|secret|token|access[_-]?key|"
    r"client[_-]?secret|credentials?|private[_-]?key|refresh[_-]?token|"
    r"session[_-]?key|access[_-]?token|bearer)$"
)

#: Keys whose values are dropped entirely rather than replaced.  A provider's
#: raw HTTP response envelope must never reach a client, and unlike the
#: credential rule these can legitimately be large, so the whole value goes.
_DROP_KEY_EXACT = frozenset(
    {
        "response_body",
        "response_text",
        "response_raw",
        "response_headers",
        "response_content",
        "response_payload",
        "request_headers",
        "request_body",
        "request_payload",
        "request_raw",
        "headers",
        "header",
        "body",
        "raw",
        "stderr",
        "stdout",
        "traceback",
        "exception",
    }
)

#: Any key beginning with ``raw_``/``raw-``/``raw.`` is a verbatim
#: provider artifact and is dropped.
_DROP_KEY_PREFIXES = ("raw_", "raw-", "raw.")

#: Credential patterns applied to free-text values (error messages only).
#: Evidence values are deliberately *not* run through these: a 64-character
#: SHA-256 in ``evidence`` is legitimate data we want to show, whereas the
#: same shape inside a free-text error message is a probable leak.
_SECRET_LABEL_PATTERN = re.compile(
    r"(?i)((?:set-cookie|cookie|password|passwd|secret|token|api[_-]?key|"
    r"apikey|access[_-]?key|x[_-]?api[_-]?key)\s*[:=]\s*)[^\s,;]+"
)
_AUTHORIZATION_PATTERN = re.compile(
    r"(?i)(authorization\s*[:=]\s*)(?:(?:bearer|basic)\s+)?[a-z0-9._~+/=-]+"
)
_CREDENTIAL_TOKEN_PATTERN = re.compile(r"(?i)\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{16,}")
_BARE_TOKEN_PATTERN = re.compile(r"\b[0-9a-fA-F]{64}\b")
_JWT_TOKEN_PATTERN = re.compile(r"\beyJ[a-zA-Z0-9_./+=~-]{8,}")

#: Display bounds applied to structured provider evidence.
_MAX_SANITIZE_DEPTH = 6
_MAX_EVIDENCE_KEYS = 40
_MAX_EVIDENCE_LIST_ITEMS = 20
_MAX_EVIDENCE_STRING_CHARS = 512
_MAX_ERROR_MESSAGE_CHARS = 4_000


def sanitize_free_text(value: str | None) -> str | None:
    """Return a secret-safe, bounded copy of a free-text value.

    Applies the labeled-credential, ``Authorization`` header, bare
    credential token, opaque 64-character token, and JWT patterns, then
    truncates.
    """
    if value is None:
        return None
    scrubbed = _SECRET_LABEL_PATTERN.sub(lambda m: f"{m.group(1)}{_REDACTED}", value)
    scrubbed = _AUTHORIZATION_PATTERN.sub(lambda m: f"{m.group(1)}{_REDACTED}", scrubbed)
    scrubbed = _CREDENTIAL_TOKEN_PATTERN.sub(_REDACTED, scrubbed)
    scrubbed = _BARE_TOKEN_PATTERN.sub(_REDACTED, scrubbed)
    scrubbed = _JWT_TOKEN_PATTERN.sub(_REDACTED, scrubbed)
    return scrubbed.strip()[:_MAX_ERROR_MESSAGE_CHARS]


def sanitize_structured(value: Any, *, _depth: int = 0) -> Any:
    """Recursively sanitize provider evidence for display.

    Redacts credential-shaped keys, drops raw response envelopes entirely,
    and bounds depth, key count, list length, and string length so a single
    large or deeply nested provider payload cannot bloat a response.
    """
    if _depth > _MAX_SANITIZE_DEPTH:
        return _REDACTED
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_EVIDENCE_KEYS:
                out["_truncated"] = f"further keys omitted after {_MAX_EVIDENCE_KEYS}"
                break
            name = str(key)
            lowered = name.lower()
            if lowered in _DROP_KEY_EXACT or lowered.startswith(_DROP_KEY_PREFIXES):
                continue
            if _SECRET_KEY_PATTERN.search(name):
                out[name] = _REDACTED
                continue
            out[name] = sanitize_structured(item, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        items = [
            sanitize_structured(item, _depth=_depth + 1)
            for item in list(value)[:_MAX_EVIDENCE_LIST_ITEMS]
        ]
        if len(value) > _MAX_EVIDENCE_LIST_ITEMS:
            items.append(f"_truncated: {len(value) - _MAX_EVIDENCE_LIST_ITEMS} more item(s)")
        return items
    if isinstance(value, str):
        return value[:_MAX_EVIDENCE_STRING_CHARS]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    # UUIDs, datetimes and anything else JSON-serialized by the provider.
    return str(value)[:_MAX_EVIDENCE_STRING_CHARS]


def sanitize_evidence(value: dict | None) -> dict | None:
    """Sanitize a stored ``evidence``/``result_metadata`` JSONB column."""
    if value is None:
        return None
    sanitized = sanitize_structured(value)
    return sanitized if isinstance(sanitized, dict) else {"_value": sanitized}


# ---------------------------------------------------------------------------
# Validation + status derivation
# ---------------------------------------------------------------------------


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalize a possibly-naive database instant to a tz-aware UTC value.

    PostgreSQL ``TIMESTAMPTZ`` columns load as timezone-aware datetimes; some
    test/embedded stores return naive UTC instants.  Normalizing at the read
    boundary gives consumers identical records on both.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _coerce_uuid(value: object, *, field: str) -> uuid.UUID:
    """Return *value* as a UUID, rejecting anything that is not one."""
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ThreatIntelQueryValidationError(reason=f"{field} must be a valid UUID") from exc


def _validate_page(page: object, page_size: object) -> tuple[int, int]:
    """Validate 1-based pagination arguments; return corrected integers."""
    try:
        page_int = int(page)  # type: ignore[arg-type]
        page_size_int = int(page_size)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ThreatIntelQueryValidationError(
            reason="page and page_size must be integers"
        ) from exc
    if page_int < 1:
        raise ThreatIntelQueryValidationError(reason="page must be at least 1")
    if page_size_int < 1:
        raise ThreatIntelQueryValidationError(reason="page_size must be at least 1")
    if page_size_int > MAX_PAGE_SIZE:
        raise ThreatIntelQueryValidationError(
            reason=f"page_size must not exceed {MAX_PAGE_SIZE}"
        )
    return page_int, page_size_int


def _coerce_indicator_type(value: object) -> IndicatorType | None:
    """Return *value* as an :class:`IndicatorType`, or None when absent."""
    if value is None:
        return None
    if isinstance(value, IndicatorType):
        return value
    try:
        return IndicatorType(str(value).strip().lower())
    except ValueError as exc:
        allowed = ", ".join(member.value for member in IndicatorType)
        raise ThreatIntelQueryValidationError(
            reason=f"indicator_type must be one of: {allowed}"
        ) from exc


def _validate_indicator_filter(value: object) -> str | None:
    """Return a trimmed, bounded indicator filter, or None when absent."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ThreatIntelQueryValidationError(reason="q must be a string")
    trimmed = value.strip()
    if not trimmed:
        return None
    if len(trimmed) > MAX_INDICATOR_FILTER_LENGTH:
        raise ThreatIntelQueryValidationError(
            reason=f"q must not exceed {MAX_INDICATOR_FILTER_LENGTH} characters"
        )
    return trimmed


def _escape_like(value: str) -> str:
    """Escape ``%``/``_``/backslash so a filter is matched literally.

    Without this, a caller could pass ``%`` and turn the value filter into a
    match-everything scan, or pass ``_`` to widen it to any single character.
    The pattern is still bound as a parameter; this only neutralises the
    wildcard metacharacters inside it.  The escape character itself must be
    doubled first, otherwise escaping the wildcards would corrupt any
    literal backslash the caller supplied.
    """
    return (
        value.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)
        .replace("%", _LIKE_ESCAPE + "%")
        .replace("_", _LIKE_ESCAPE + "_")
    )


def indicator_status(*, lookup_count: int, success_count: int, error_count: int) -> str:
    """Roll persisted lookup counts into one display status.

    ``no_lookup``   -- the indicator exists but was never looked up.
    ``enriched``    -- at least one provider returned data and none failed.
    ``partial``     -- some providers returned data, some failed.
    ``failed``      -- every recorded lookup failed.

    None of these is a malicious or benign verdict; that is a separate
    concern and Step 8A does not persist one.
    """
    if lookup_count == 0:
        return "no_lookup"
    if error_count == 0:
        return "enriched"
    if success_count == 0:
        return "failed"
    return "partial"


def lookup_status_label(
    *, status: LookupStatus, error_type: str | None, provider_result_available: bool
) -> str:
    """Roll a persisted lookup outcome into a human-facing status label.

    Deliberately never returns "malicious".  A failed lookup is reported as
    the failure it is.
    """
    if status == LookupStatus.SUCCESS:
        return "ENRICHED" if provider_result_available else "NO DATA"
    return {
        "rate_limit": "RATE LIMITED",
        "timeout": "TIMED OUT",
        "invalid_indicator": "REJECTED",
        "provider_error": "FAILED",
        "unexpected": "UNAVAILABLE",
    }.get((error_type or "").strip().lower(), "UNAVAILABLE")


# ---------------------------------------------------------------------------
# Row -> read-model mapping
# ---------------------------------------------------------------------------


def _to_lookup_record(row: ThreatIntelLookup) -> ThreatIntelLookupRecord:
    """Map one persisted lookup row onto its read model."""
    evidence = sanitize_evidence(row.evidence)
    result_metadata = sanitize_evidence(row.result_metadata)
    provider_result_available = row.status == LookupStatus.SUCCESS and bool(
        evidence or result_metadata
    )
    return ThreatIntelLookupRecord(
        lookup_id=row.id,
        indicator_id=row.indicator_id,
        event_id=row.event_id,
        provider=row.provider,
        status=row.status.value,
        status_label=lookup_status_label(
            status=row.status,
            error_type=row.error_type,
            provider_result_available=provider_result_available,
        ),
        found=row.found,
        provider_result_available=provider_result_available,
        confidence=row.confidence,
        performed_at=_as_utc(row.performed_at),  # type: ignore[arg-type]
        result_timestamp=_as_utc(row.result_timestamp),
        error_type=row.error_type,
        error_message=sanitize_free_text(row.error_message),
        retryable=row.retryable,
        evidence=evidence,
        result_metadata=result_metadata,
        provenance=Provenance(row.provenance),
        created_at=_as_utc(row.created_at),  # type: ignore[arg-type]
        updated_at=_as_utc(row.updated_at),  # type: ignore[arg-type]
    )


def _to_indicator_record(
    row: ThreatIntelIndicator,
    *,
    providers: list[str],
    lookup_count: int,
    success_count: int,
    error_count: int,
    latest_lookup_at: datetime | None,
) -> ThreatIntelIndicatorRecord:
    """Map one persisted indicator row plus its rollup onto its read model."""
    return ThreatIntelIndicatorRecord(
        indicator_id=row.id,
        indicator_type=IndicatorType(row.indicator_type.value)
        if hasattr(row.indicator_type, "value")
        else IndicatorType(str(row.indicator_type)),
        value=row.value,
        canonical_key=row.canonical_key,
        first_seen=_as_utc(row.first_seen_at),  # type: ignore[arg-type]
        last_seen=_as_utc(row.last_seen_at),  # type: ignore[arg-type]
        providers=providers,
        lookup_count=lookup_count,
        success_count=success_count,
        error_count=error_count,
        latest_lookup_at=latest_lookup_at,
        status=indicator_status(
            lookup_count=lookup_count,
            success_count=success_count,
            error_count=error_count,
        ),
        provenance=Provenance.OBSERVED,
        created_at=_as_utc(row.created_at),  # type: ignore[arg-type]
        updated_at=_as_utc(row.updated_at),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ThreatIntelQueryService:
    """Read-only query surface over persisted threat-intelligence data.

    Every method opens no transaction and writes nothing.  All database
    access is bounded and deterministically ordered.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Indicator list
    # ------------------------------------------------------------------

    def list_indicators(
        self,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        indicator_type: IndicatorType | str | None = None,
        value_filter: str | None = None,
    ) -> ThreatIntelIndicatorPage:
        """Return one bounded, deterministically ordered page of indicators.

        Filters:

        * ``indicator_type`` -- exact match on the persisted type.
        * ``value_filter`` -- case-insensitive substring match against the
          stored ``value``, bound as a parameter with ``%``/``_`` escaped so
          a caller cannot turn it into a wildcard scan.

        Ordering is ``last_seen_at`` descending, ``id`` ascending.  The ``id``
        tie-break is what makes paging deterministic for indicators that
        share a ``last_seen_at``.
        """
        page_int, page_size_int = _validate_page(page, page_size)
        type_filter = _coerce_indicator_type(indicator_type)
        text_filter = _validate_indicator_filter(value_filter)

        statement = select(ThreatIntelIndicator)
        count_statement = select(func.count()).select_from(ThreatIntelIndicator)

        conditions = []
        if type_filter is not None:
            conditions.append(ThreatIntelIndicator.indicator_type == type_filter)
        if text_filter is not None:
            pattern = f"%{_escape_like(text_filter.lower())}%"
            conditions.append(
                or_(
                    func.lower(ThreatIntelIndicator.value).like(pattern, escape=_LIKE_ESCAPE),
                    func.lower(ThreatIntelIndicator.canonical_key).like(
                        pattern, escape=_LIKE_ESCAPE
                    ),
                )
            )
        if conditions:
            statement = statement.where(*conditions)
            count_statement = count_statement.where(*conditions)

        try:
            total = int(self.db.execute(count_statement).scalar_one())
        except Exception as exc:  # noqa: BLE001 - never leak driver detail
            raise ThreatIntelQueryError("Failed to count threat-intel indicators") from exc

        statement = statement.order_by(
            ThreatIntelIndicator.last_seen_at.desc(),
            ThreatIntelIndicator.id.asc(),
        ).limit(page_size_int).offset((page_int - 1) * page_size_int)

        try:
            rows = list(self.db.scalars(statement))
        except Exception as exc:  # noqa: BLE001
            raise ThreatIntelQueryError("Failed to list threat-intel indicators") from exc

        rollups = self._indicator_rollups([row.id for row in rows])
        items = [
            _to_indicator_record(
                row,
                providers=rollups[row.id]["providers"],
                lookup_count=rollups[row.id]["lookup_count"],
                success_count=rollups[row.id]["success_count"],
                error_count=rollups[row.id]["error_count"],
                latest_lookup_at=rollups[row.id]["latest_lookup_at"],
            )
            for row in rows
        ]
        return ThreatIntelIndicatorPage(
            items=items,
            total=total,
            page=page_int,
            page_size=page_size_int,
        )

    # ------------------------------------------------------------------
    # Indicator detail
    # ------------------------------------------------------------------

    def get_indicator(
        self,
        indicator_id: uuid.UUID | str,
        *,
        lookup_limit: int = MAX_LOOKUPS_PER_INDICATOR,
        event_limit: int = MAX_EVENTS_PER_INDICATOR,
    ) -> ThreatIntelIndicatorDetail:
        """Return one indicator with its bounded lookup history and events.

        Raises :class:`ThreatIntelIndicatorNotFoundError` when the id does
        not resolve, which the transport maps to HTTP 404.
        """
        resolved = _coerce_uuid(indicator_id, field="indicator_id")
        limit = min(max(int(lookup_limit), 1), MAX_LOOKUPS_PER_INDICATOR)
        event_cap = min(max(int(event_limit), 1), MAX_EVENTS_PER_INDICATOR)

        row = self.db.scalar(
            select(ThreatIntelIndicator).where(ThreatIntelIndicator.id == resolved)
        )
        if row is None:
            raise ThreatIntelIndicatorNotFoundError(resolved)

        lookups = list(
            self.db.scalars(
                select(ThreatIntelLookup)
                .where(ThreatIntelLookup.indicator_id == resolved)
                .order_by(
                    ThreatIntelLookup.performed_at.desc(),
                    ThreatIntelLookup.id.asc(),
                )
                .limit(limit + 1)
            )
        )
        lookups_truncated = len(lookups) > limit
        lookups = lookups[:limit]

        events, events_truncated = self._events_for_indicator(resolved, event_cap)

        success_count = sum(1 for item in lookups if item.status == LookupStatus.SUCCESS)
        error_count = sum(1 for item in lookups if item.status == LookupStatus.ERROR)
        providers = sorted({item.provider for item in lookups})

        # The rollup counts the whole history, not just the bounded window,
        # so a truncated detail never misreports an indicator as unenriched.
        rollups = self._indicator_rollups([resolved])[resolved]

        return ThreatIntelIndicatorDetail(
            indicator=_to_indicator_record(
                row,
                providers=rollups["providers"] or providers,
                lookup_count=rollups["lookup_count"] or len(lookups),
                success_count=rollups["success_count"] or success_count,
                error_count=rollups["error_count"] or error_count,
                latest_lookup_at=rollups["latest_lookup_at"]
                or (lookups[0].performed_at if lookups else None),
            ),
            lookups=[_to_lookup_record(item) for item in lookups],
            lookups_truncated=lookups_truncated,
            events=events,
            events_truncated=events_truncated,
        )

    def list_indicator_events(
        self,
        indicator_id: uuid.UUID | str,
        *,
        limit: int = MAX_EVENTS_PER_INDICATOR,
    ) -> ThreatIntelIndicatorEvents:
        """Return the bounded set of event ids an indicator was extracted from.

        Supported directly by the persistence model: ``ThreatIntelLookup``
        records the ``event_id`` each lookup ran for, so this reads an
        existing column rather than inventing a relationship.  No
        security-event table exists, so these ids are correlation keys only
        and the response says so.
        """
        resolved = _coerce_uuid(indicator_id, field="indicator_id")
        cap = min(max(int(limit), 1), MAX_EVENTS_PER_INDICATOR)

        exists = self.db.scalar(
            select(ThreatIntelIndicator.id).where(ThreatIntelIndicator.id == resolved)
        )
        if exists is None:
            raise ThreatIntelIndicatorNotFoundError(resolved)

        events, truncated = self._events_for_indicator(resolved, cap)
        return ThreatIntelIndicatorEvents(
            indicator_id=resolved,
            events=events,
            total=self._event_count(resolved),
            truncated=truncated,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _event_count(self, indicator_id: uuid.UUID) -> int:
        """Return the exact number of distinct event ids for one indicator.

        A truncated page still reports the true total rather than ``cap+1``,
        so a caller can tell "201 known" from "1,284 known" instead of
        comparing against a number that silently under-reports.
        """
        statement = select(func.count()).select_from(
            select(ThreatIntelLookup.event_id)
            .where(ThreatIntelLookup.indicator_id == indicator_id)
            .distinct()
            .subquery()
        )
        return int(self.db.scalar(statement) or 0)

    def _events_for_indicator(
        self, indicator_id: uuid.UUID, cap: int
    ) -> tuple[list[uuid.UUID], bool]:
        """Return distinct event ids ordered by their most recent lookup.

        Ordering is ``max(performed_at)`` descending, then ``event_id``
        ascending, so the sequence is stable across requests.
        """
        recent = func.max(ThreatIntelLookup.performed_at).label("last_performed")
        statement: Select[tuple[uuid.UUID, datetime]] = (
            select(ThreatIntelLookup.event_id, recent)
            .where(ThreatIntelLookup.indicator_id == indicator_id)
            .group_by(ThreatIntelLookup.event_id)
            .order_by(recent.desc(), ThreatIntelLookup.event_id.asc())
            .limit(cap + 1)
        )
        pairs = list(self.db.execute(statement))
        truncated = len(pairs) > cap
        return [pair[0] for pair in pairs[:cap]], truncated

    def _indicator_rollups(
        self, indicator_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, dict[str, Any]]:
        """Resolve per-indicator lookup rollups for a page in two queries.

        Returns a default-zero entry for every requested id, so the caller
        can index without a presence check.  Each entry owns its own
        ``providers`` list -- the default is built per id rather than copied
        from a shared literal, so one indicator's providers can never leak
        into another's.  An empty ``indicator_ids`` list issues no query.
        """
        rollups: dict[uuid.UUID, dict[str, Any]] = {
            indicator_id: {
                "providers": [],
                "lookup_count": 0,
                "success_count": 0,
                "error_count": 0,
                "latest_lookup_at": None,
            }
            for indicator_id in indicator_ids
        }
        if not indicator_ids:
            return rollups

        success = func.count(ThreatIntelLookup.id).filter(
            ThreatIntelLookup.status == LookupStatus.SUCCESS
        )
        failure = func.count(ThreatIntelLookup.id).filter(
            ThreatIntelLookup.status == LookupStatus.ERROR
        )
        aggregate = (
            select(
                ThreatIntelLookup.indicator_id.label("indicator_id"),
                func.count(ThreatIntelLookup.id).label("lookup_count"),
                success.label("success_count"),
                failure.label("error_count"),
                func.max(ThreatIntelLookup.performed_at).label("latest_lookup_at"),
            )
            .where(ThreatIntelLookup.indicator_id.in_(indicator_ids))
            .group_by(ThreatIntelLookup.indicator_id)
        )
        for indicator_id, lookup_count, ok, bad, latest in self.db.execute(aggregate):
            rollups[indicator_id].update(
                lookup_count=int(lookup_count or 0),
                success_count=int(ok or 0),
                error_count=int(bad or 0),
                latest_lookup_at=_as_utc(latest),
            )

        distinct = (
            select(
                ThreatIntelLookup.indicator_id,
                ThreatIntelLookup.provider,
            )
            .where(ThreatIntelLookup.indicator_id.in_(indicator_ids))
            .distinct()
            .order_by(ThreatIntelLookup.indicator_id, ThreatIntelLookup.provider)
        )
        for indicator_id, provider in self.db.execute(distinct):
            rollups[indicator_id]["providers"].append(provider)

        return rollups
