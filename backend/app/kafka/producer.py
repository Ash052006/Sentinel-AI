"""Kafka event producer for SentinelAI.

Publishes validated :class:`SecurityEvent` objects to the
``security-events`` Kafka topic.

Design principles:

* Accepts only validated :class:`SecurityEvent` objects — callers
  cannot bypass the contract.
* Uses ``event_id`` as the Kafka message key for deterministic
  partitioning.
* Waits for broker acknowledgement before returning
  (``acks=all``).
* Logs operational events without exposing sensitive event content.
"""

from __future__ import annotations

import logging
from typing import Any

from kafka import KafkaProducer
from kafka.errors import KafkaError

from app.kafka.serialization import serialize_event
from app.schemas.security_event import SecurityEvent

logger = logging.getLogger(__name__)


class KafkaEventProducer:
    """Publishes :class:`SecurityEvent` objects to a Kafka topic.

    Usage::

        producer = KafkaEventProducer("localhost:9092", "security-events")
        producer.publish(event)
        producer.close()

    The producer is safe to use as a context manager::

        with KafkaEventProducer("localhost:9092", "security-events") as prod:
            prod.publish(event)
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        *,
        acks: str = "all",
        linger_ms: int = 0,
        max_retries: int = 3,
    ) -> None:
        self._topic = topic
        self._producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: v,  # already bytes from serialize_event
            key_serializer=lambda k: k.encode("utf-8") if isinstance(k, str) else k,
            acks=acks,
            linger_ms=linger_ms,
            retries=max_retries,
            retry_backoff_ms=100,
        )
        logger.info(
            "Kafka producer initialised: servers=%s topic=%s",
            bootstrap_servers,
            topic,
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "KafkaEventProducer":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish(self, event: SecurityEvent) -> None:
        """Publish a single :class:`SecurityEvent` to the configured topic.

        The ``event_id`` is used as the Kafka message key, providing
        deterministic partition assignment and enabling downstream
        consumers to identify events.

        Raises ``KafkaError`` if the broker does not acknowledge the
        message within the configured timeout.
        """
        key = str(event.event_id)
        value = serialize_event(event)

        future = self._producer.send(self._topic, key=key, value=value)

        try:
            record_metadata = future.get(timeout=10)
            logger.debug(
                "Event published: topic=%s partition=%d offset=%d",
                record_metadata.topic,
                record_metadata.partition,
                record_metadata.offset,
            )
        except KafkaError as exc:
            logger.error(
                "Failed to publish event: topic=%s key=%s error=%s",
                self._topic,
                key,
                type(exc).__name__,
            )
            raise

    def close(self) -> None:
        """Flush pending messages and close the producer."""
        try:
            self._producer.flush(timeout=10)
            self._producer.close(timeout=10)
            logger.info("Kafka producer closed: topic=%s", self._topic)
        except Exception:
            logger.exception("Error closing Kafka producer")
            raise