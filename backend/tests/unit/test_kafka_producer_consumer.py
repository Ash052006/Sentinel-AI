"""Unit tests for the Kafka producer and consumer components.

These tests use mocks so they run without a live Kafka broker.  They
verify error handling and the validation boundary:

* ``KafkaEventProducer`` raises on Kafka-unavailable / publish failure.
* ``KafkaEventConsumer`` rejects malformed JSON and schema-invalid
  events, exposing only valid SecurityEvents to the caller.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from kafka.errors import KafkaError, NoBrokersAvailable

from app.kafka.consumer import KafkaEventConsumer
from app.kafka.producer import KafkaEventProducer
from app.kafka.serialization import serialize_event
from app.schemas.security_event import Provenance, SecurityEvent, SourceType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**overrides) -> SecurityEvent:
    defaults = {
        "timestamp": datetime(2025, 7, 20, 8, 0, 0, tzinfo=timezone.utc),
        "source": "unit-test-host",
        "source_type": SourceType.OPERATING_SYSTEM,
        "event_type": "unit_test",
        "raw_data": {"unit": True},
        "provenance": Provenance.OBSERVED,
        "metadata": {"collector": "unit_test"},
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


def _mock_message(value: bytes, topic: str = "security-events",
                  partition: int = 0, offset: int = 0):
    msg = MagicMock()
    msg.value = value
    msg.topic = topic
    msg.partition = partition
    msg.offset = offset
    return msg


# ---------------------------------------------------------------------------
# Producer
# ---------------------------------------------------------------------------

class TestProducerUnavailable:
    """Producer raises gracefully when Kafka is unavailable."""

    @patch("app.kafka.producer.KafkaProducer")
    def test_constructor_raises_no_brokers(self, mock_cls):
        mock_cls.side_effect = NoBrokersAvailable()
        with pytest.raises(NoBrokersAvailable):
            KafkaEventProducer("localhost:9092", "security-events")

    @patch("app.kafka.producer.KafkaProducer")
    def test_publish_failure_propagates_kafka_error(self, mock_cls):
        mock_producer = MagicMock()
        future = MagicMock()
        future.get.side_effect = KafkaError("publish failed")
        mock_producer.send.return_value = future
        mock_cls.return_value = mock_producer

        producer = KafkaEventProducer("localhost:9092", "security-events")
        with pytest.raises(KafkaError):
            producer.publish(_make_event())

    @patch("app.kafka.producer.KafkaProducer")
    def test_publish_uses_event_id_as_key(self, mock_cls):
        mock_producer = MagicMock()
        future = MagicMock()
        metadata = MagicMock()
        metadata.topic = "security-events"
        metadata.partition = 0
        metadata.offset = 5
        future.get.return_value = metadata
        mock_producer.send.return_value = future
        mock_cls.return_value = mock_producer

        event = _make_event()
        producer = KafkaEventProducer("localhost:9092", "security-events")
        producer.publish(event)

        # The event_id (as string) must be used as the Kafka message key.
        args, kwargs = mock_producer.send.call_args
        assert args[0] == "security-events"
        assert kwargs["key"] == str(event.event_id)
        # Value is the serialized event.
        assert kwargs["value"] == serialize_event(event)


# ---------------------------------------------------------------------------
# Consumer
# ---------------------------------------------------------------------------

class TestConsumerValidation:
    """Consumer rejects malformed and schema-invalid messages."""

    def _make_consumer_with_records(self, records) -> KafkaEventConsumer:
        mock_consumer = MagicMock()
        mock_consumer.poll.return_value = records
        with patch("app.kafka.consumer._KafkaConsumer", return_value=mock_consumer):
            consumer = KafkaEventConsumer(
                "localhost:9092", "security-events", "test-group",
            )
        return consumer

    def test_rejects_malformed_json(self):
        """Malformed JSON is skipped and no event is returned."""
        bad_msg = _mock_message(b"{ not valid json")
        consumer = self._make_consumer_with_records({(0, 0): [bad_msg]})
        result = consumer.consume(timeout_ms=100)
        assert result is None

    def test_rejects_schema_invalid_event(self):
        """A valid-JSON-but-schema-invalid message is skipped."""
        invalid = {
            "event_id": str(uuid.uuid4()),
            # missing required fields (timestamp, source, source_type, ...)
        }
        invalid_msg = _mock_message(json.dumps(invalid).encode("utf-8"))
        consumer = self._make_consumer_with_records({(0, 0): [invalid_msg]})
        result = consumer.consume(timeout_ms=100)
        assert result is None

    def test_rejects_naive_timestamp(self):
        """A timezone-naive timestamp is rejected by the schema."""
        event = _make_event()
        raw = json.loads(serialize_event(event))
        raw["timestamp"] = "2025-07-20T08:00:00"  # naive
        msg = _mock_message(json.dumps(raw).encode("utf-8"))
        consumer = self._make_consumer_with_records({(0, 0): [msg]})
        result = consumer.consume(timeout_ms=100)
        assert result is None

    def test_valid_event_returned(self):
        """A valid message is deserialized and returned as SecurityEvent."""
        event = _make_event()
        msg = _mock_message(serialize_event(event))
        consumer = self._make_consumer_with_records({(0, 0): [msg]})
        result = consumer.consume(timeout_ms=100)
        assert isinstance(result, SecurityEvent)
        assert result.event_id == event.event_id

    def test_skips_invalid_then_returns_valid(self):
        """Invalid messages are skipped, then a valid one is returned."""
        event = _make_event()
        bad_msg = _mock_message(b"garbage")
        good_msg = _mock_message(serialize_event(event))
        mock_consumer = MagicMock()
        mock_consumer.poll.side_effect = [
            {(0, 0): [bad_msg]},
            {(0, 0): [good_msg]},
        ]
        with patch("app.kafka.consumer._KafkaConsumer", return_value=mock_consumer):
            consumer = KafkaEventConsumer(
                "localhost:9092", "security-events", "test-group",
            )
        assert consumer.consume(timeout_ms=100) is None
        result = consumer.consume(timeout_ms=100)
        assert isinstance(result, SecurityEvent)
        assert result.event_id == event.event_id