"""Dead-letter publishing for the Kafka ingestion worker.

The worker never drops a message.  A payload that cannot be deserialized
(malformed JSON / schema-invalid) or an event whose processing exhausts the
retry budget is republished, verbatim, to a configured dead-letter topic so an
operator can inspect and replay it.

The original message value is preserved byte-for-byte using base64 so arbitrary
(non-UTF-8) payloads survive the round-trip.  The dead-letter envelope is JSON
and carries only operational metadata plus the encoded original value; it never
contains credentials.

The publisher deliberately does **not** reuse
:class:`~app.kafka.producer.KafkaEventProducer`: that class accepts only a
validated :class:`~app.schemas.security_event.SecurityEvent`, whereas a
dead-letter message is by definition *not* a valid event.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from kafka import KafkaProducer
from kafka.errors import KafkaError

logger = logging.getLogger(__name__)


class KafkaDeadLetterPublisher:
    """Publishes raw dead-letter envelopes to a Kafka topic.

    Usable as a context manager::

        with KafkaDeadLetterPublisher("localhost:9092", "security-events-dlq") as dlq:
            dlq.publish(topic="security-events", partition=0, offset=7,
                        key="…", raw_value=b"{bad", error="JSONDecodeError: …")
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        *,
        acks: str = "all",
        max_retries: int = 3,
    ) -> None:
        self._topic = topic
        self._producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            key_serializer=lambda k: k.encode("utf-8") if isinstance(k, str) else k,
            value_serializer=lambda v: v,  # already bytes
            acks=acks,
            linger_ms=0,
            retries=max_retries,
            retry_backoff_ms=100,
        )
        logger.info(
            "Kafka dead-letter publisher initialised: servers=%s topic=%s",
            bootstrap_servers,
            topic,
        )

    def __enter__(self) -> "KafkaDeadLetterPublisher":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Envelope
    # ------------------------------------------------------------------

    @staticmethod
    def build_payload(
        *,
        topic: str,
        partition: int,
        offset: int,
        key: str | None,
        raw_value: bytes,
        error: str,
    ) -> bytes:
        """Build the JSON dead-letter envelope for one original message.

        The original value is base64-encoded under ``value`` (with
        ``value_encoding="base64"``) so a non-UTF-8 payload is preserved
        exactly.
        """
        envelope = {
            "error": error,
            "source_topic": topic,
            "source_partition": partition,
            "source_offset": offset,
            "key": key,
            "value_encoding": "base64",
            "value": base64.b64encode(raw_value).decode("ascii"),
        }
        return json.dumps(envelope).encode("utf-8")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish(
        self,
        *,
        topic: str,
        partition: int,
        offset: int,
        key: str | None,
        raw_value: bytes,
        error: str,
    ) -> None:
        """Publish one dead-letter envelope and wait for acknowledgement.

        Raises ``KafkaError`` if the broker does not acknowledge the message,
        so the caller can decide **not** to commit the source offset.
        """
        payload = self.build_payload(
            topic=topic,
            partition=partition,
            offset=offset,
            key=key,
            raw_value=raw_value,
            error=error,
        )
        future = self._producer.send(self._topic, key=key, value=payload)
        try:
            future.get(timeout=10)
            logger.warning(
                "Dead-lettered message: source=%s[%d]@%d key=%s",
                topic,
                partition,
                offset,
                key,
            )
        except KafkaError as exc:
            logger.error(
                "Failed to dead-letter message: source=%s[%d]@%d error=%s",
                topic,
                partition,
                offset,
                type(exc).__name__,
            )
            raise

    def close(self) -> None:
        """Flush pending messages and close the producer."""
        try:
            self._producer.flush(timeout=10)
            self._producer.close(timeout=10)
            logger.info("Kafka dead-letter publisher closed: topic=%s", self._topic)
        except Exception:
            logger.exception("Error closing Kafka dead-letter publisher")
            raise
