"""Event ingestion pipeline: collect -> normalize -> detect -> persist.

This module is the single reusable entry point that wires the existing
V2 pipeline components into one call.  Both the CLI helper
(``scripts/ingest_events.py``) and the HTTP endpoint
(``app/api/routes/ingest.py``) go through :func:`ingest_jsonl`, so the
browser and the terminal can never diverge in behaviour.

The pipeline is deliberately the *governed* one: parsing is done by
:class:`~app.collectors.file_collector.FileLogCollector`, the rule set is
rebuilt through :class:`~app.services.detection_as_code.lifecycle.LifecycleService`
(so source hashes are verified and the set fails closed), and detections
are written by
:class:`~app.services.detection_persistence.DetectionPersistenceService`
(which owns the transaction).

No Kafka is involved: the transport is intentionally omitted so ingestion
can run in environments without a broker, while every other stage remains
the real implementation.

SentinelAI has no security-event store, so the normalized events produced
here are not persisted.  Because the normalization output would otherwise be
discarded the moment detection runs, :func:`ingest_jsonl` returns a bounded
:class:`IngestEventTrace` per event (see :data:`MAX_RETURNED_EVENTS`) so
callers can read back exactly what the pipeline produced.  The trace is
observability, not a second source of truth: the objects it carries are the
same ones the :class:`DetectionAgent` evaluated.
"""

from __future__ import annotations

import json
import logging
import tempfile
import time
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, computed_field
from sqlalchemy.orm import Session

from app.agents.detection import DetectionAgent, persist_analysis_bound
from app.agents.normalization import _DEFAULT_CATEGORY_MAP, NormalizationAgent
from app.collectors.file_collector import FileLogCollector
from app.schemas.normalized_event import (
    EventCategory,
    EventOutcome,
    NormalizedSecurityEvent,
)
from app.schemas.security_event import Provenance, SecurityEvent, SourceType
from app.services.detection_as_code.lifecycle import LifecycleService
from app.services.detection_persistence import DetectionPersistenceService

logger = logging.getLogger(__name__)

#: Maximum accepted upload size.  Anything larger is rejected outright
#: rather than truncated, so a partially-ingested file is never reported
#: as a successful ingest.
MAX_INGEST_BYTES = 10 * 1024 * 1024

#: Upper bound on events processed in a single ingest call.
MAX_EVENTS = 5_000

#: Cap on per-line errors returned to callers.  A file with thousands of
#: malformed lines must not produce an unbounded response payload.
MAX_REPORTED_ERRORS = 50

#: Cap on raw/normalized event pairs returned to callers.  The trace exists
#: so an operator can inspect what normalization produced; it is not a
#: security-event store (SentinelAI has none), so it is bounded exactly like
#: :data:`MAX_REPORTED_ERRORS` rather than growing with the file.
MAX_RETURNED_EVENTS = 50


class IngestRuleSetUnavailableError(RuntimeError):
    """Raised when the governed rule registry cannot be rebuilt.

    The registry fails closed on purpose (missing source file, hash
    mismatch, non-validated state), so ingestion cannot proceed with a
    partial or unverified rule set.  Callers should surface this as an
    operational fault rather than a client error.
    """


class IngestError(BaseModel):
    """A single rejected input line."""

    line_number: int = Field(
        ...,
        description="1-based line number in the submitted file.",
    )
    reason: str = Field(
        ...,
        description="Human-readable reason the line was rejected.",
    )


class IngestEventTrace(BaseModel):
    """One ingested record: the raw input and the normalization output for it.

    Added so a caller (notably the Data Ingest console) can show the real
    ``raw -> normalized`` transformation instead of inventing one.  Both
    halves are the objects the pipeline already produced:

    * ``raw_event`` is :attr:`SecurityEvent.raw_data`, i.e. the untouched
      JSON object :class:`FileLogCollector` read from the line;
    * ``normalized_event`` is the actual
      :class:`NormalizedSecurityEvent` returned by
      :meth:`NormalizationAgent.normalize` and completed by
      :func:`apply_explicit_fields` -- the very object handed to the
      :class:`DetectionAgent`.

    No value is re-derived, reformatted or summarised here, and nothing is
    persisted: SentinelAI still has no security-event store, so this is a
    read-back of the run, not a new source of truth.
    """

    event_id: UUID = Field(
        ...,
        description="Identity assigned by the collector; shared with the normalized event.",
    )
    line_number: int = Field(
        default=0,
        description=(
            "1-based position of the record among the non-blank lines read "
            "by the collector.  Blank lines are dropped before collection, so "
            "this is not always the physical line in the submitted file.  "
            "0 when the collector recorded no position."
        ),
    )
    raw_event: dict[str, Any] = Field(
        ...,
        description="The raw JSON object as received, unmodified.",
    )
    normalized_event: NormalizedSecurityEvent = Field(
        ...,
        description="The NormalizationAgent output evaluated by the DetectionAgent.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provenance(self) -> Provenance:
        """Provenance of this event, read back from the normalized event.

        Derived rather than stored so the reported marker can never drift
        from the event it describes.  Normalization is not a provenance
        change: a collected event is ``observed`` before normalization and
        stays ``observed`` after it.
        """
        return self.normalized_event.provenance


class IngestSummary(BaseModel):
    """Outcome of one ingest run.

    ``detections`` counts only rules that actually *matched*; the engines
    emit one :class:`DetectionResult` per evaluated rule, so the number of
    evaluated rules is deliberately not reported here.
    """

    total_records: int = Field(
        ...,
        description="Total non-empty lines read from the input.",
    )
    accepted_events: int = Field(
        ...,
        description="Lines that produced a valid SecurityEvent.",
    )
    rejected_records: int = Field(
        ...,
        description="Lines that failed validation and were skipped.",
    )
    events_processed: int = Field(
        ...,
        description="Accepted events that were normalized and evaluated.",
    )
    detections: int = Field(
        ...,
        description="Rules that matched at least once across all events.",
    )
    events_with_detections: int = Field(
        ...,
        description="Events for which at least one rule matched.",
    )
    detection_results_created: int = Field(
        ...,
        description="Rows written to detection_results.",
    )
    rule_failures: int = Field(
        ...,
        description="Rule evaluations that errored (fail-closed per rule).",
    )
    active_rule_count: int = Field(
        ...,
        description="Governed rules loaded for this run.",
    )
    errors: list[IngestError] = Field(
        default_factory=list,
        description="Up to MAX_REPORTED_ERRORS rejected lines.",
    )
    truncated_errors: bool = Field(
        ...,
        description="True when more lines were rejected than were reported.",
    )
    events: list[IngestEventTrace] = Field(
        default_factory=list,
        description=(
            "Up to MAX_RETURNED_EVENTS raw/normalized pairs in file order, "
            "so callers can inspect the real normalization output for this "
            "run.  Only events that normalized successfully appear here."
        ),
    )
    truncated_events: bool = Field(
        default=False,
        description="True when more events were normalized than were returned.",
    )
    duration_ms: int = Field(
        ...,
        description="Wall-clock duration of the run in milliseconds.",
    )


class IngestFieldDoc(BaseModel):
    """Documentation for one required JSONL field."""

    name: str
    required: bool
    description: str


class IngestEventTypeDoc(BaseModel):
    """A recognised ``event_type`` and the category it normalises to."""

    event_type: str
    event_category: str


class IngestFormat(BaseModel):
    """Self-describing contract for the JSONL input format.

    Served by ``GET /api/ingest/format`` so the UI never hard-codes the
    field list or the ``SourceType`` enum.
    """

    description: str
    content_type: str
    required_fields: list[IngestFieldDoc]
    optional_fields: list[IngestFieldDoc]
    source_types: list[str]
    event_categories: list[str]
    recognized_event_types: list[IngestEventTypeDoc]
    notes: list[str]
    example_lines: list[str]


FORMAT_DOC = IngestFormat(
    description=(
        "One JSON object per line (JSON Lines / .jsonl). Blank lines are "
        "ignored. Every line must be a complete, self-contained object — "
        "nested or pretty-printed JSON spanning multiple lines is rejected."
    ),
    content_type="application/x-ndjson",
    required_fields=[
        IngestFieldDoc(
            name="timestamp",
            required=True,
            description="ISO-8601 timestamp, timezone-aware (e.g. 2026-09-27T10:00:00+00:00).",
        ),
        IngestFieldDoc(
            name="source",
            required=True,
            description="Originating system or host (e.g. windows, nginx, okta).",
        ),
        IngestFieldDoc(
            name="source_type",
            required=True,
            description="Category of the source; must be one of source_types.",
        ),
        IngestFieldDoc(
            name="event_type",
            required=True,
            description="Event classification (e.g. process_creation, authentication_failure).",
        ),
    ],
    optional_fields=[
        IngestFieldDoc(
            name="actor",
            required=False,
            description="User or principal responsible for the event.",
        ),
        IngestFieldDoc(
            name="action",
            required=False,
            description=(
                "What happened, in free text. Sigma rules match on this "
                "(e.g. 'network logon')."
            ),
        ),
        IngestFieldDoc(
            name="outcome",
            required=False,
            description=(
                f"one of: {', '.join(e.value for e in EventOutcome)}."
            ),
        ),
        IngestFieldDoc(
            name="event_category",
            required=False,
            description=(
                "Overrides the category derived from event_type. One of: "
                f"{', '.join(e.value for e in EventCategory)}."
            ),
        ),
        IngestFieldDoc(
            name="normalized_data",
            required=False,
            description=(
                "Extra structured fields preserved for matching "
                "(e.g. {\"logon_type\": 3})."
            ),
        ),
    ],
    source_types=[value.value for value in SourceType],
    event_categories=[value.value for value in EventCategory],
    recognized_event_types=[
        IngestEventTypeDoc(
            event_type=key,
            event_category=category.value,
        )
        for key, category in sorted(_DEFAULT_CATEGORY_MAP.items())
    ],
    notes=[
        "event_type decides the normalized event_category; only the listed "
        "event_type values map to a specific category, everything else "
        "becomes 'other' and will not match most rules.",
        "action, outcome, event_category and normalized_data are honoured "
        "when you supply them. Use them when your records do not use native "
        "Windows/Linux/firewall field names.",
        "YARA rules need actual file bytes in normalized_data.file_content; "
        "log-only records are reported as 'invalid_target' rule failures, "
        "which is expected and not an error.",
    ],
    example_lines=[
        json.dumps(
            {
                "timestamp": "2026-09-27T10:00:00+00:00",
                "source": "windows-dc01",
                "source_type": "operating_system",
                "event_type": "process_creation",
                "actor": "CONTOSO\\jdoe",
                "action": "powershell.exe -enc SQBFAFgA",
                "outcome": "success",
            }
        ),
        json.dumps(
            {
                "timestamp": "2026-09-27T10:05:12+00:00",
                "source": "vpn-gateway",
                "source_type": "identity",
                "event_type": "authentication_failure",
                "actor": "a.saxena",
                "action": "Failed logon attempt",
                "outcome": "failure",
            }
        ),
    ],
)


def _coerce_outcome(value: object) -> EventOutcome | None:
    """Return *value* as an :class:`EventOutcome`, or None if unrecognised."""
    if isinstance(value, EventOutcome):
        return value
    try:
        return EventOutcome(str(value).strip().lower())
    except ValueError:
        return None


def _coerce_category(value: object) -> EventCategory | None:
    """Return *value* as an :class:`EventCategory`, or None if unrecognised."""
    if isinstance(value, EventCategory):
        return value
    try:
        return EventCategory(str(value).strip().lower())
    except ValueError:
        return None


def apply_explicit_fields(event: SecurityEvent, normalized: NormalizedSecurityEvent) -> NormalizedSecurityEvent:
    """Honour normalized fields the submitter stated explicitly.

    :class:`NormalizationAgent` intentionally maps only *source-specific*
    field names (``TargetUserName``, ``LogonType``, ``action``/``disposition``
    for the linux and firewall sources, ...). Anything else in a record is
    ignored by design, so a generic record that already carries ``action``,
    ``outcome``, ``event_category`` or ``normalized_data`` loses exactly the
    fields Sigma rules match on.

    Ingestion bridges that gap for explicitly supplied values only, and only
    where normalization left the field empty — a source-specific mapping
    always wins. Unrecognised enum values are ignored rather than guessed.

    Provenance is untouched: the event remains ``observed``, and the agent
    itself is not modified.

    Args:
        event: The raw collected event.
        normalized: The agent's output for that event.

    Returns:
        The normalized event, possibly with explicitly supplied fields
        applied. The input is never mutated.
    """
    raw = event.raw_data or {}
    if not isinstance(raw, dict):
        return normalized

    updates: dict[str, object] = {}

    if not normalized.action and isinstance(raw.get("action"), str):
        action = raw["action"].strip()
        if action:
            updates["action"] = action

    if normalized.outcome in (None, EventOutcome.UNKNOWN):
        outcome = _coerce_outcome(raw.get("outcome"))
        if outcome is not None:
            updates["outcome"] = outcome

    category = _coerce_category(raw.get("event_category"))
    if category is not None:
        updates["event_category"] = category

    extra = raw.get("normalized_data")
    if isinstance(extra, dict) and extra:
        updates["normalized_data"] = {**normalized.normalized_data, **extra}

    if not updates:
        return normalized
    return normalized.model_copy(update=updates)


def build_active_registry(db: Session):
    """Rebuild the governed rule registry for this ingest run.

    Delegates to :meth:`LifecycleService.build_deployed_registry`, which
    verifies each deployed rule's source file and hash and refuses to
    build a partial set.

    Raises:
        IngestRuleSetUnavailableError: if the registry cannot be rebuilt.
    """
    try:
        return LifecycleService(db).build_deployed_registry()
    except Exception as exc:  # noqa: BLE001 - converted to a domain error
        logger.error("Ingest rule registry unavailable: %s", type(exc).__name__)
        raise IngestRuleSetUnavailableError(
            "The governed detection rule set could not be loaded. "
            "Ingestion requires a verified, fully deployed rule set."
        ) from exc


def _read_lines(content: str, max_events: int) -> tuple[str, int]:
    """Trim *content* to at most *max_events* data lines.

    Returns the (possibly trimmed) text and the number of lines dropped.
    """
    lines = content.splitlines()
    kept: list[str] = []
    dropped = 0
    for line in lines:
        if not line.strip():
            continue
        if len(kept) >= max_events:
            dropped += 1
            continue
        kept.append(line)
    if dropped:
        logger.warning("Ingest trimmed %d line(s) beyond max_events=%d", dropped, max_events)
    return "\n".join(kept), dropped


def _trace_line_number(event: SecurityEvent) -> int:
    """Return the collector's recorded line number for *event*, else 0.

    :class:`FileLogCollector` stores the line it read in ``metadata``.  A
    missing or non-integer value degrades to 0 -- the same "unknown"
    convention :class:`IngestError` already uses -- rather than failing the
    ingest, since the position is presentational only.
    """
    value = (event.metadata or {}).get("line_number")
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def ingest_jsonl(
    db: Session,
    content: str,
    *,
    max_events: int = MAX_EVENTS,
) -> IngestSummary:
    """Ingest JSON Lines *content* through the full detection pipeline.

    Args:
        db: Session used for the registry snapshot and persistence.
        content: Raw JSON Lines text.
        max_events: Cap on accepted events for this run.

    Returns:
        An :class:`IngestSummary` describing the run, including up to
        :data:`MAX_RETURNED_EVENTS` :class:`IngestEventTrace` entries that
        pair each raw record with the
        :class:`~app.schemas.normalized_event.NormalizedSecurityEvent` the
        pipeline actually produced for it.

    Raises:
        ValueError: if ``content`` exceeds :data:`MAX_INGEST_BYTES`.
        IngestRuleSetUnavailableError: if the rule set cannot be verified.
    """
    started = time.perf_counter()

    encoded = content.encode("utf-8")
    if len(encoded) > MAX_INGEST_BYTES:
        raise ValueError(
            f"Input exceeds the {MAX_INGEST_BYTES // (1024 * 1024)} MB limit."
        )

    text, dropped = _read_lines(content, max_events)

    registry = build_active_registry(db)
    active_rule_count = len(registry.list_rules())

    normalizer = NormalizationAgent()
    agent = DetectionAgent(registry=registry)

    total_records = 0
    accepted = 0
    rejected = 0
    events_processed = 0
    normalized_count = 0
    detections = 0
    events_with_detections = 0
    results_created = 0
    rule_failures = 0
    errors: list[IngestError] = []
    events: list[IngestEventTrace] = []

    # Keep the documented binding (the service owns the transaction) and
    # wrap it only to count the rows it actually created.
    persistence = DetectionPersistenceService()
    bound_persist = persist_analysis_bound(db, service=persistence)

    def _counting_persist(analysis):
        nonlocal results_created
        outcome = bound_persist(analysis)
        results_created += getattr(outcome, "results_created", 0)
        return outcome

    with tempfile.TemporaryDirectory(prefix="sentinel-ingest-") as tmpdir:
        target = Path(tmpdir) / "events.jsonl"
        target.write_text(text, encoding="utf-8")

        collected = FileLogCollector(target).collect()

    total_records = collected.total_records + dropped
    accepted = collected.successful_records
    rejected = collected.failed_records + dropped

    for err in collected.errors:
        if len(errors) < MAX_REPORTED_ERRORS:
            errors.append(
                IngestError(line_number=err.line_number, reason=err.reason)
            )

    for event in collected.events:
        try:
            normalized = normalizer.normalize(event)
            normalized = apply_explicit_fields(event, normalized)

            # The normalized event exists from here on, so the raw/normalized
            # pair is real regardless of what detection does with it.
            # Recorded before evaluation so an evaluation failure cannot hide
            # the normalization the caller asked to see.
            normalized_count += 1
            if len(events) < MAX_RETURNED_EVENTS:
                events.append(
                    IngestEventTrace(
                        event_id=event.event_id,
                        line_number=_trace_line_number(event),
                        raw_event=event.raw_data,
                        normalized_event=normalized,
                    )
                )

            analysis = agent.evaluate(normalized, persistence=_counting_persist)
        except Exception as exc:  # noqa: BLE001 - one bad event must not abort the run
            logger.warning(
                "Ingest skipped event=%s: %s", event.event_id, type(exc).__name__
            )
            if len(errors) < MAX_REPORTED_ERRORS:
                errors.append(
                    IngestError(
                        line_number=0,
                        reason=f"processing failed for event {event.event_id}",
                    )
                )
            rejected += 1
            continue

        events_processed += 1
        matched = [r for r in analysis.results if r.matched]
        rule_failures += len(analysis.failures)

        if matched:
            events_with_detections += 1
            detections += len(matched)
            for result in matched:
                logger.info(
                    "Ingest detection event=%s rule=%s severity=%s",
                    event.event_id,
                    result.rule_id,
                    result.severity,
                )

    duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "Ingest complete records=%d accepted=%d processed=%d detections=%d "
        "failures=%d duration_ms=%d",
        total_records,
        accepted,
        events_processed,
        detections,
        rule_failures,
        duration_ms,
    )

    return IngestSummary(
        total_records=total_records,
        accepted_events=accepted,
        rejected_records=rejected,
        events_processed=events_processed,
        detections=detections,
        events_with_detections=events_with_detections,
        detection_results_created=results_created,
        rule_failures=rule_failures,
        active_rule_count=active_rule_count,
        errors=errors,
        truncated_errors=rejected > len(errors),
        events=events,
        truncated_events=normalized_count > len(events),
        duration_ms=duration_ms,
    )
