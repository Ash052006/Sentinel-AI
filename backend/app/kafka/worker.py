"""Kafka ingestion worker.

Consumes :class:`~app.schemas.security_event.SecurityEvent` messages from the
configured ``security-events`` topic and routes them through the **existing**
SentinelAI pipeline (normalize -> detect -> persist) via
:class:`~app.services.ingest_service.EventIngestPipeline`.  This is the missing
runtime edge: :mod:`app.kafka.consumer` and :mod:`app.kafka.producer` existed
but nothing ever subscribed to the topic.

Delivery and offset semantics
-----------------------------
* Automatic offset commits are **disabled**.  An offset is committed only
  after the corresponding record has been fully handled -- either persisted by
  the pipeline, or successfully republished to the dead-letter topic.
* A record is handled through a bounded, in-process retry loop.  On success
  the offset advances; if the retry budget is exhausted the record is
  dead-lettered and *then* the offset advances, so one poison message cannot
  block its partition forever.
* A crash before commit causes redelivery (at-least-once), never loss.

Idempotency
-----------
The worker checks whether an event's detections or failures are already
persisted before processing it, so a redelivered event does not create
duplicate rows.  See :meth:`KafkaIngestionWorker._default_already_processed`
and ``docs/development/kafka.md`` for the precise guarantee and its one
limitation (an event that produces *no* matches and *no* failures persists
nothing, so a redelivery of such an event re-runs detection once more -- it
still writes nothing, so the store stays duplicate-free).
"""

from __future__ import annotations

import logging
import time

from app.services.ingest_service import EventIngestPipeline

logger = logging.getLogger(__name__)


class IngestionWorkerReport:
    """Immutable summary of one :meth:`KafkaIngestionWorker.run`."""

    __slots__ = (
        "poll_cycles",
        "records_consumed",
        "events_processed",
        "events_skipped_duplicate",
        "detection_results_created",
        "invalid_messages",
        "processing_failures",
        "dead_lettered",
    )

    def __init__(self, **kwargs: int) -> None:
        for field in self.__slots__:
            setattr(self, field, int(kwargs.get(field, 0)))

    def as_dict(self) -> dict[str, int]:
        return {field: getattr(self, field) for field in self.__slots__}


class _Counters:
    """Mutable run counters; frozen into an :class:`IngestionWorkerReport`."""

    __slots__ = (
        "poll_cycles",
        "records_consumed",
        "events_processed",
        "events_skipped_duplicate",
        "detection_results_created",
        "invalid_messages",
        "processing_failures",
        "dead_lettered",
    )

    def __init__(self) -> None:
        for field in self.__slots__:
            setattr(self, field, 0)

    def as_dict(self) -> dict[str, int]:
        return {field: getattr(self, field) for field in self.__slots__}


class KafkaIngestionWorker:
    """Consumes security events and routes them through the ingest pipeline.

    All collaborators are injected so the worker is unit-testable without a
    broker or database:

    Args:
        consumer: A :class:`~app.kafka.consumer.KafkaEventConsumer`.
        dead_letter: An object with ``publish(**envelope)`` (see
            :class:`~app.kafka.dlq.KafkaDeadLetterPublisher`).
        session_factory: Callable returning a SQLAlchemy ``Session`` usable as
            a context manager (e.g. ``SessionLocal``).
        registry: The governed :class:`DetectionRuleRegistry`, built once.
        pipeline_factory: Builds the per-event pipeline from ``(db, registry)``.
            Defaults to :class:`EventIngestPipeline`.
        already_processed: ``(db, event_id) -> bool`` idempotency predicate.
        max_retries: In-process attempts per event before dead-lettering.
        retry_backoff_seconds: Base backoff; attempt *n* waits ``n * base``.
        sleep: Injectable sleep (tests pass a no-op).
        poll_timeout_ms: Broker poll timeout per cycle.
    """

    def __init__(
        self,
        *,
        consumer,
        dead_letter,
        session_factory,
        registry,
        pipeline_factory=EventIngestPipeline,
        already_processed=None,
        max_retries: int = 3,
        retry_backoff_seconds: float = 1.0,
        sleep=None,
        poll_timeout_ms: int = 1000,
    ) -> None:
        if max_retries < 1:
            raise ValueError("max_retries must be >= 1")
        self._consumer = consumer
        self._dead_letter = dead_letter
        self._session_factory = session_factory
        self._registry = registry
        self._pipeline_factory = pipeline_factory
        self._already_processed = already_processed or self._default_already_processed
        self._max_retries = max_retries
        self._retry_backoff_seconds = retry_backoff_seconds
        self._sleep = sleep or time.sleep
        self._poll_timeout_ms = poll_timeout_ms
        self._stopping = False
        self._previous_handlers: dict[int, object] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """Request a graceful shutdown at the next loop boundary."""
        self._stopping = True

    def close(self) -> None:
        """Close the consumer and dead-letter publisher.

        Both are attempted even if one fails, so a ``finally`` block always
        releases as much as possible.
        """
        errors: list[BaseException] = []
        for resource in (self._consumer, self._dead_letter):
            close = getattr(resource, "close", None)
            if callable(close):
                try:
                    close()
                except BaseException as exc:  # noqa: BLE001 - close all
                    errors.append(exc)
        if errors:
            logger.warning(
                "Worker resource close failed: %s", type(errors[0]).__name__
            )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(
        self,
        *,
        max_messages: int | None = None,
        install_signal_handlers: bool = True,
    ) -> IngestionWorkerReport:
        """Consume and process until stopped, or until *max_messages* records.

        Args:
            max_messages: Stop after this many consumed records (useful for
                bounded runs and tests).  ``None`` runs until stopped.
            install_signal_handlers: Install SIGINT/SIGTERM handlers for
                graceful shutdown (skipped when not on the main thread).

        Returns:
            An :class:`IngestionWorkerReport` describing the run.
        """
        if install_signal_handlers:
            self._install_signal_handlers()

        counters = _Counters()
        try:
            while not self._stopping:
                if max_messages is not None and counters.records_consumed >= max_messages:
                    break
                records = self._consumer.consume_records(
                    timeout_ms=self._poll_timeout_ms
                )
                counters.poll_cycles += 1
                for record in records:
                    if self._stopping:
                        break
                    if max_messages is not None and counters.records_consumed >= max_messages:
                        break
                    counters.records_consumed += 1
                    self._handle_record(record, counters)
        finally:
            if install_signal_handlers:
                self._restore_signal_handlers()

        return IngestionWorkerReport(**counters.as_dict())

    # ------------------------------------------------------------------
    # Record handling
    # ------------------------------------------------------------------

    def _handle_record(self, record, counters: _Counters) -> None:
        """Handle one consumed record and advance its offset.

        The offset is committed **only** after the record is fully handled, so
        an exception here leaves it uncommitted for redelivery.
        """
        if record.error is not None or record.event is None:
            counters.invalid_messages += 1
            self._dead_letter_record(record, record.error or "undeserialisable")
            counters.dead_lettered += 1
            self._consumer.commit(record.topic, record.partition, record.offset)
            return

        try:
            status, result = self._process_with_retries(record)
        except Exception as exc:  # noqa: BLE001 - retries exhausted
            counters.processing_failures += 1
            logger.error(
                "Processing failed after %d attempt(s): event=%s error=%s",
                self._max_retries,
                record.event.event_id,
                type(exc).__name__,
            )
            self._dead_letter_record(record, f"{type(exc).__name__}: {exc}")
            counters.dead_lettered += 1
            self._consumer.commit(record.topic, record.partition, record.offset)
            return

        if status == "duplicate":
            counters.events_skipped_duplicate += 1
        else:
            counters.events_processed += 1
            if result is not None:
                counters.detection_results_created += result.detection_results_created

        self._consumer.commit(record.topic, record.partition, record.offset)

    def _process_with_retries(self, record) -> tuple[str, object]:
        """Process the record's event with a bounded retry loop.

        Returns ``("processed", EventIngestResult)`` or ``("duplicate", None)``.
        Raises the last exception once the retry budget is exhausted.
        """
        event = record.event
        last_exc: BaseException | None = None

        for attempt in range(1, self._max_retries + 1):
            try:
                with self._session_factory() as db:
                    if self._already_processed(db, event.event_id):
                        return "duplicate", None
                    pipeline = self._pipeline_factory(db, self._registry)
                    return "processed", pipeline.process(event)
            except Exception as exc:  # noqa: BLE001 - retried then surfaced
                last_exc = exc
                logger.warning(
                    "Processing attempt %d/%d failed: event=%s error=%s",
                    attempt,
                    self._max_retries,
                    event.event_id,
                    type(exc).__name__,
                )
                if attempt < self._max_retries:
                    self._sleep(self._retry_backoff_seconds * attempt)

        assert last_exc is not None
        raise last_exc

    # ------------------------------------------------------------------
    # Idempotency
    # ------------------------------------------------------------------

    @staticmethod
    def _default_already_processed(db, event_id) -> bool:
        """Return True when *event_id* already has persisted detections.

        The detection persistence layer keys matches by ``detection_id`` -- a
        fresh uuid4 per evaluation -- so it does **not** itself deduplicate a
        redelivered event.  This guard does: if any matched result or rule
        failure is already stored for the event, the event has been handled and
        is skipped.  Imported lazily so importing this module never pulls the
        ORM layer.
        """
        from app.repositories.detection import DetectionRepository

        repo = DetectionRepository(db)
        return (
            repo.count_results_for_event(event_id) > 0
            or repo.count_failures_for_event(event_id) > 0
        )

    # ------------------------------------------------------------------
    # Dead-lettering
    # ------------------------------------------------------------------

    def _dead_letter_record(self, record, error: str) -> None:
        """Republish *record*'s original bytes to the dead-letter topic.

        Raises if the broker does not acknowledge, so the caller does not
        commit an offset for a message that was never preserved.
        """
        self._dead_letter.publish(
            topic=record.topic,
            partition=record.partition,
            offset=record.offset,
            key=record.key,
            raw_value=record.raw_value,
            error=error,
        )

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------

    def _install_signal_handlers(self) -> None:
        import signal as _signal

        def _handler(signum, _frame):
            logger.info("Shutdown signal received (%d); draining...", signum)
            self._stopping = True

        for sig in (_signal.SIGINT, _signal.SIGTERM):
            try:
                self._previous_handlers[sig] = _signal.getsignal(sig)
                _signal.signal(sig, _handler)
            except (ValueError, OSError):
                # Not the main thread, or the signal is unsupported here.
                self._previous_handlers.pop(sig, None)

    def _restore_signal_handlers(self) -> None:
        import signal as _signal

        for sig, handler in self._previous_handlers.items():
            try:
                _signal.signal(sig, handler)
            except (ValueError, OSError, TypeError):
                pass
        self._previous_handlers.clear()
