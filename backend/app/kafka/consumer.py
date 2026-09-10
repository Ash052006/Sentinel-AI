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

from kafka import KafkaConsumer as _KafkaConsumer
from kafka.errors import KafkaError

from app.kafka.serialization import deserialize_event
from app.schemas.security_event import SecurityEvent

logger = logging.getLogger(__name__)


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

    def close(self) -> None:
        """Close the consumer and release resources."""
        try:
            self._consumer.close()
            logger.info("Kafka consumer closed: topic=%s", self._topic)
        except Exception:
            logger.exception("Error closing Kafka consumer")
            raise