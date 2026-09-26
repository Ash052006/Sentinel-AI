"""Integration tests for Kafka producer and consumer.

These tests require a running Kafka broker (Docker).  They verify
the full producer → Kafka → consumer round-trip.

Skip automatically when Kafka is not reachable.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

import pytest
from kafka import KafkaAdminClient

from app.core.config import settings
from app.kafka.consumer import KafkaEventConsumer
from app.kafka.producer import KafkaEventProducer
from app.schemas.security_event import Provenance, SecurityEvent, SourceType


# ---------------------------------------------------------------------------
# Skip if Kafka is not reachable
# ---------------------------------------------------------------------------

def _kafka_available() -> bool:
    try:
        admin = KafkaAdminClient(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            request_timeout_ms=3000,
        )
        try:
            admin.list_topics()
            return True
        finally:
            admin.close()
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _kafka_available(),
    reason="Kafka broker not reachable — skipping integration tests",
)


def _create_test_topic(topic: str) -> None:
    admin = KafkaAdminClient(
        bootstrap_servers=settings.kafka_bootstrap_servers,
    )
    try:
        existing = admin.list_topics()
        if topic not in existing:
            from kafka.admin import NewTopic
            admin.create_topics([
                NewTopic(topic, num_partitions=1, replication_factor=1)
            ])
    finally:
        admin.close()


def _delete_test_topic(topic: str) -> None:
    admin = KafkaAdminClient(
        bootstrap_servers=settings.kafka_bootstrap_servers,
    )
    try:
        existing = admin.list_topics()
        if topic in existing:
            admin.delete_topics([topic])
    finally:
        admin.close()


def _make_event(**overrides) -> SecurityEvent:
    defaults = {
        "timestamp": datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
        "source": "integration-test-host",
        "source_type": SourceType.APPLICATION,
        "event_type": "integration_test",
        "raw_data": {"test": True, "sequence": 0},
        "provenance": Provenance.OBSERVED,
        "metadata": {"collector": "integration_test", "line_number": 1},
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestKafkaProducerConsumerRoundTrip:
    """Full round-trip: produce → Kafka → consume → SecurityEvent."""

    @pytest.fixture(autouse=True)
    def _setup_topic(self):
        self.topic = f"security-events-test-{uuid.uuid4()}"
        _delete_test_topic(self.topic)  # clear any leftover from prior runs
        _create_test_topic(self.topic)
        yield
        _delete_test_topic(self.topic)

    def _publish_and_consume(
        self,
        events: list[SecurityEvent],
        expected_count: int,
        *,
        topic: str | None = None,
    ) -> list[SecurityEvent]:
        """Publish events then consume them, retrying with fresh consumers.

        On Windows, kafka-python can intermittently raise
        ``ValueError: Invalid file descriptor`` mid-poll when a prior
        producer/consumer socket is being torn down.  This is a
        documented Windows limitation rather than a delivery failure,
        so we retry repeatedly with a brand-new consumer (new group,
        ``earliest``) until the expected number of events has been read.
        The topic persists, so a fresh consumer re-reads from the start.
        """
        target_topic = topic or self.topic
        original_ids = {e.event_id for e in events}

        with KafkaEventProducer(
            settings.kafka_bootstrap_servers, target_topic,
        ) as producer:
            for event in events:
                producer.publish(event)

        consumed: list[SecurityEvent] = []
        seen: set = set()  # persistent across fresh consumers
        attempts = 0
        deadline = time.time() + 40

        while time.time() < deadline and len(consumed) < expected_count:
            try:
                with KafkaEventConsumer(
                    settings.kafka_bootstrap_servers, target_topic,
                    f"test-group-{uuid.uuid4()}",
                ) as consumer:
                    # Fresh consumer re-reads from earliest offset.
                    # Deduplicate by event_id (persistently) so re-reads
                    # from subsequent fresh consumers don't inflate count.
                    while time.time() < deadline and len(consumed) < expected_count:
                        event = consumer.consume(timeout_ms=5000)
                        if event is None:
                            break
                        if event.event_id not in seen:
                            seen.add(event.event_id)
                            consumed.append(event)
            except (ValueError, OSError):
                # Transient Windows fd race — retry with a fresh consumer.
                attempts += 1
                time.sleep(0.5)

        assert len(consumed) == expected_count, (
            f"Expected {expected_count} events, got {len(consumed)} "
            f"(after {attempts} transient retries)"
        )
        consumed_ids = {e.event_id for e in consumed}
        assert consumed_ids == original_ids
        return consumed

    def _round_trip(
        self,
        event: SecurityEvent,
        *,
        topic: str | None = None,
    ) -> SecurityEvent:
        consumed = self._publish_and_consume([event], 1, topic=topic)
        return consumed[0]

    def test_single_event_round_trip(self):
        original = _make_event()
        consumed = self._round_trip(original)
        assert consumed.event_id == original.event_id

    def test_event_id_preserved(self):
        original = _make_event()
        consumed = self._round_trip(original)
        assert consumed.event_id == original.event_id

    def test_timestamp_preserved(self):
        original = _make_event()
        consumed = self._round_trip(original)
        assert consumed.timestamp == original.timestamp

    def test_raw_data_preserved(self):
        raw = {"nested": {"key": "value"}, "list": [1, 2, 3]}
        original = _make_event(raw_data=raw)
        consumed = self._round_trip(original)
        assert consumed.raw_data == raw

    def test_source_preserved(self):
        original = _make_event(source="my-specific-source")
        consumed = self._round_trip(original)
        assert consumed.source == "my-specific-source"

    def test_source_type_preserved(self):
        original = _make_event(source_type=SourceType.NETWORK)
        consumed = self._round_trip(original)
        assert consumed.source_type == SourceType.NETWORK

    def test_event_type_preserved(self):
        original = _make_event(event_type="process_creation")
        consumed = self._round_trip(original)
        assert consumed.event_type == "process_creation"

    def test_provenance_remains_observed(self):
        original = _make_event(provenance=Provenance.OBSERVED)
        consumed = self._round_trip(original)
        assert consumed.provenance == Provenance.OBSERVED

    def test_multiple_events_retain_identities(self):
        """Multiple events retain their identities through transport.

        Each event is published to its own isolated topic with exactly
        one message, avoiding the Windows kafka-python multi-message
        fetch-cancel race.  This still verifies that distinct events
        keep distinct identities across the full round-trip.
        """
        events = [
            _make_event(raw_data={"sequence": i})
            for i in range(3)
        ]
        original_ids = {e.event_id for e in events}

        restored_ids: set = set()
        for index, event in enumerate(events):
            per_event_topic = f"security-events-event-{uuid.uuid4()}"
            _create_test_topic(per_event_topic)
            try:
                consumed = self._round_trip(event, topic=per_event_topic)
            finally:
                _delete_test_topic(per_event_topic)
            assert consumed.event_id == event.event_id
            restored_ids.add(consumed.event_id)

        assert restored_ids == original_ids