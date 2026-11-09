"""Kafka event consumer for SentinelAI.

Consumes messages from the ``security-events`` Kafka topic and
reconstructs validated :class:`SecurityEvent` objects for downstream
processing agents.

Design principles:

* Every consumed message is validated via :class:`SecurityEvent` before
  being returned to the caller.
* Malformed JSON and schema-invalid events are logged and skipped —
  they never reach the caller.
* The consumer is a transport-layer component only: it does **not**
  normalise, enrich, reconstruct, or detect.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from kafka import KafkaConsumer as _KafkaConsumer
from kafka.errors import KafkaError
from kafka.structs import OffsetAndMetadata, TopicPartition

from app.kafka.serialization import deserialize_event
from app.schemas.security_event import SecurityEvent

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ConsumedRecord:
    """One message fetched from Kafka, with the coordinates needed to commit it.

    ``event`` is the validated :class:`SecurityEvent` when the payload is
    well-formed and schema-valid.  When deserialization fails ``event`` is
    ``None`` and ``error`` carries a sanitized reason; ``raw_value`` always
    preserves the original bytes so a dead-letter publisher can keep the
    message without loss.  The caller decides how to handle each case and
    commits the offset only once the record is handled.
    """

    topic: str
    partition: int
    offset: int
    key: str | None
    raw_value: bytes
    event: SecurityEvent | None
    error: str | None


class KafkaEventConsumer:
    """Consumes :class:`SecurityEvent` objects from a Kafka topic.

    Usage::

        consumer = KafkaEventConsumer(
            "localhost:9092", "security-events", "sentinelai-development",
        )
        event = consumer.consume(timeout_ms=5000)
        if event is not None:
            # process event …
        consumer.close()

    Also usable as a context manager::

        with KafkaEventConsumer(...) as consumer:
            event = consumer.consume()
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        group_id: str,
        *,
        auto_offset_reset: str = "earliest",
        enable_auto_commit: bool = False,
    ) -> None:
        self._topic = topic
        self._consumer = _KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            auto_offset_reset=auto_offset_reset,
            enable_auto_commit=enable_auto_commit,
            value_deserializer=lambda v: v,
            key_deserializer=lambda k: k.decode("utf-8") if k is not None else None,
        )
        logger.info(
            "Kafka consumer initialised: servers=%s topic=%s group=%s",
            bootstrap_servers,
            topic,
            group_id,
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "KafkaEventConsumer":
        return self

    def __exit__(self, exc_type: type | None, exc_val: BaseException | None, exc_tb: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def consume(self, timeout_ms: int = 1000) -> SecurityEvent | None:
        """Poll for a single message and return a validated
        :class:`SecurityEvent`.

        Returns ``None`` if no message was available within the timeout.

        Malformed or schema-invalid messages are logged at warning level
        and skipped — the next call will fetch the following message.
        """
        try:
            records = self._consumer.poll(timeout_ms=timeout_ms)
        except KafkaError as exc:
            logger.error("Kafka poll error: %s", type(exc).__name__)
            raise

        for _tp, messages in records.items():
            for message in messages:
                try:
                    event = deserialize_event(message.value)
                    logger.debug(
                        "Event consumed: topic=%s partition=%d offset=%d",
                        message.topic,
                        message.partition,
                        message.offset,
                    )
                    return event
                except Exception as exc:
                    logger.warning(
                        "Skipping invalid message: topic=%s partition=%d "
                        "offset=%d error=%s",
                        message.topic,
                        message.partition,
                        message.offset,
                        type(exc).__name__,
                    )
                    continue

        return None

    def consume_records(self, timeout_ms: int = 1000) -> list[ConsumedRecord]:
        """Poll once and return every fetched message as a record envelope.

        Unlike :meth:`consume`, this does not stop at the first valid event
        and does not hide invalid ones: it returns exactly what the broker
        delivered, in order, tagging each record with whether it deserialized
        successfully.  No offset is committed here -- the caller commits only
        after it has fully handled the record, so a crash mid-processing
        causes redelivery (at-least-once) rather than loss.
        """
        try:
            records = self._consumer.poll(timeout_ms=timeout_ms)
        except KafkaError as exc:
            logger.error("Kafka poll error: %s", type(exc).__name__)
            raise

        collected: list[ConsumedRecord] = []
        for _tp, messages in records.items():
            for message in messages:
                raw = message.value
                try:
                    event = deserialize_event(raw)
                    logger.debug(
                        "Event consumed: topic=%s partition=%d offset=%d",
                        message.topic,
                        message.partition,
                        message.offset,
                    )
                    collected.append(
                        ConsumedRecord(
                            topic=message.topic,
                            partition=message.partition,
                            offset=message.offset,
                            key=message.key,
                            raw_value=raw,
                            event=event,
                            error=None,
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - surfaced, never dropped
                    reason = f"{type(exc).__name__}: {exc}"
                    logger.warning(
                        "Invalid message: topic=%s partition=%d offset=%d error=%s",
                        message.topic,
                        message.partition,
                        message.offset,
                        type(exc).__name__,
                    )
                    collected.append(
                        ConsumedRecord(
                            topic=message.topic,
                            partition=message.partition,
                            offset=message.offset,
                            key=message.key,
                            raw_value=raw,
                            event=None,
                            error=reason,
                        )
                    )

        return collected

    def commit(self, topic: str, partition: int, offset: int) -> None:
        """Commit ``offset + 1`` for a single (topic, partition).

        Should be called only after the record at *offset* has been fully
        handled (persisted, or dead-lettered).  Committing ``offset + 1``
        marks that offset as processed without advancing past a record that
        has not yet been handled.
        """
        try:
            self._consumer.commit(
                {
                    TopicPartition(topic, partition): OffsetAndMetadata(
                        offset + 1, None
                    )
                }
            )
        except KafkaError as exc:
            logger.error(
                "Kafka commit error: topic=%s partition=%d offset=%d error=%s",
                topic,
                partition,
                offset,
                type(exc).__name__,
            )
            raise

    def close(self) -> None:
        """Close the consumer and release resources."""
        try:
            self._consumer.close()
            logger.info("Kafka consumer closed: topic=%s", self._topic)
        except Exception:
            logger.exception("Error closing Kafka consumer")
            raise