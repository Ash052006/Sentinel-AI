"""Integration tests for Kafka producer and consumer.

These tests require a running Kafka broker (Docker).  They verify
the full producer → Kafka → consumer round-trip.

Skip automatically when Kafka is not reachable.
"""