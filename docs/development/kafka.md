# Kafka Event Streaming (Step 5C)

This document describes the Kafka event transport layer introduced in
Step 5C. Kafka decouples event **collection** from downstream
**processing** in SentinelAI.

## Architecture

```
Log Source
    ↓
FileLogCollector
    ↓
SecurityEvent
    ↓
KafkaProducer  ──▶  Kafka Topic (security-events)  ──▶  KafkaConsumer
                                                              ↓
                                                        SecurityEvent
                                                              ↓
                                                    Future Processing Agents
```

The collector produces validated `SecurityEvent` objects. The producer
publishes them to Kafka. The consumer reads them back as validated
`SecurityEvent` objects. Storage, normalization, enrichment, detection,
etc. are **separate future steps** and are deliberately not part of this
layer.

> The collector does **not** call agents directly, and the consumer does
> **not** normalise, enrich, reconstruct, or detect. Transport + schema
> validation only.

## Starting Kafka locally

Kafka runs in Docker Compose (KRaft mode — a single combined
broker+controller, no Zookeeper).

```bash
docker compose up -d kafka
```

Verify it is running:

```bash
docker ps --filter name=sentinelai-kafka
docker logs --tail 50 sentinelai-kafka   # look for "Kafka Server started"
```

The default broker is reachable at `localhost:9092`.

## Topic

| Topic             | Purpose                                    |
| ----------------- | ------------------------------------------ |
| `security-events` | Stream of validated `SecurityEvent` objects |

The topic is configured via `KAFKA_SECURITY_EVENTS_TOPIC`
(default `security-events`). Broker-level auto-creation is disabled in
the compose file, but the topic is created on demand by the producer or
admin tooling during development.

## Environment variables

| Variable                      | Default              | Description                          |
| ----------------------------- | -------------------- | ------------------------------------ |
| `KAFKA_BOOTSTRAP_SERVERS`     | `localhost:9092`     | Kafka broker address(es)             |
| `KAFKA_SECURITY_EVENTS_TOPIC` | `security-events`    | Topic carrying security events       |
| `KAFKA_CONSUMER_GROUP`        | `sentinelai-development` | Default consumer group for dev   |

These are defined in `backend/app/core/config.py` and can be overridden
via `.env`. No credentials are stored in source code; for production,
configure SASL/TLS credentials through environment variables only.

## Producer design

`backend/app/kafka/producer.py` — `KafkaEventProducer`

- Accepts only validated `SecurityEvent` objects (`publish(event)`).
- Uses `event_id` as the Kafka message **key** for deterministic
  partitioning/order semantics.
- Uses `acks=all` — waits for the broker to acknowledge the message
  before returning; does not report success on failure.
- Serializes via `serialize_event` (shared serialization module).
- Implemented as a context manager (`with` block) for clean resource
  handling.
- Raises `KafkaError` (e.g. `NoBrokersAvailable`) on connect/publish
  failure — callers handle errors explicitly.

## Consumer design

`backend/app/kafka/consumer.py` — `KafkaEventConsumer`

- Subscribes to the configured topic.
- Deserializes each message and validates it against `SecurityEvent`
  before returning it to the caller.
- Malformed JSON and schema-invalid messages are logged and **skipped**
  — they never reach the caller as valid events.
- Transport + validation only; no processing added.
- Consumer group is configurable via `group_id`, so future consumers
  can use `normalization-group`, `detection-group`, etc.

## Serialization format

Format: UTF-8 JSON, produced by Pydantic's `model_dump_json`
(`backend/app/kafka/serialization.py`). Every field — including
`raw_data`, `event_id`, `timestamp`, `source`, `source_type`,
`event_type`, `provenance`, and `metadata` — survives the round-trip
unchanged. Enums serialize as their string values
(e.g. `Provenance.OBSERVED` → `"observed"`).

```
SecurityEvent ──serialize──▶ JSON bytes ──▶ Kafka message
SecurityEvent ◀─deserialize── JSON bytes ◀─ Kafka message
```

Deserialization always validates via the `SecurityEvent` schema — it is
never bypassed.

## Delivery semantics

- **At-least-once** is the practical baseline (acks=all + consumer
  auto-commit disabled in tests; dev consumer defaults to manual). We
  do **not** claim exactly-once semantics.
- The producer waits for broker acknowledgement (`acks=all`) before
  reporting success.
- Message **keys** are the `event_id`, so ordering per key/partition is
  preserved.

## Error handling

| Scenario               | Behavior                                            |
| ---------------------- | --------------------------------------------------- |
| Kafka unavailable      | Producer/consumer raise `KafkaError`/`NoBrokersAvailable`; callers handle it |
| Publish failure        | `publish` raises `KafkaError`; no false success     |
| Serialization failure  | Raised by Pydantic during `model_dump_json`         |
| Malformed JSON         | Consumer logs warning, skips message                |
| Schema-invalid event   | Consumer logs warning, skips message (validation is enforced) |
| Consumer errors        | Poll raises `KafkaError`; caller handles it         |

Credentials and secrets are never logged. Sensitive event content is
not logged unnecessarily; only operational metadata (topic, partition,
offset) is emitted.

## Health check

`GET /api/health/kafka` reports broker connectivity independently of
application/database health. A Kafka outage does **not** fail the main
application health endpoint — it only marks the Kafka dependency check
as unhealthy. No credentials are exposed in the response.

## Running the Kafka integration test

The integration tests require the Docker Kafka broker to be running.

```bash
docker compose up -d kafka
cd backend
.venv\Scripts\python -m pytest tests/integration/test_kafka_integration.py
```

These tests verify a real producer → Kafka → consumer round-trip. They
skip automatically when Kafka is unreachable, so the full unit suite
runs fine without a broker.

Unit tests (`tests/unit/test_kafka_serialization.py`,
`tests/unit/test_kafka_producer_consumer.py`) run without Kafka.

## Development limitations

- The `apache/kafka` image is configured in KRaft mode (no Zookeeper).
- On Windows, the kafka-python client can intermittently raise
  `ValueError: Invalid file descriptor` during rapid connect/disconnect
  cycles in tests. The integration tests retry with fresh consumers to
  ride out these transient, non-delivery races. This is a kafka-python
  + Windows limitation, not a data-loss condition.
- Broker auto-creation is disabled; topics are created explicitly or via
  admin tooling during development.

