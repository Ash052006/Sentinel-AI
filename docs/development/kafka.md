# Kafka Event Streaming

This document describes the Kafka event pipeline in SentinelAI. Kafka
decouples event **collection** from downstream **processing**: the
collector publishes validated events, and the ingestion worker consumes
them and runs the full normalize -> detect -> persist pipeline.

## Architecture

```
Log Source
    ↓
FileLogCollector
    ↓
SecurityEvent
    ↓
KafkaProducer  ──▶  Kafka Topic (security-events)  ──▶  KafkaEventConsumer
                                                              ↓
                                                     KafkaIngestionWorker
                                                              ↓
                                            EventIngestPipeline
                                         normalize → detect → persist
                                                              ↓
                                             (on failure) security-events-dlq
```

The collector produces validated `SecurityEvent` objects. The producer
publishes them to Kafka. The **ingestion worker** reads them back,
re-validates them, and drives each one through the existing
`EventIngestPipeline` — the same governed path used by the CLI and HTTP
ingest entrypoints. Normalization, detection, and persistence are the
real implementations; the transport stays optional.

> The consumer class itself still only does transport + schema validation.
> The **worker** is the component that wires the consumer to the pipeline.

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

| Topic                 | Purpose                                             |
| --------------------- | --------------------------------------------------- |
| `security-events`     | Stream of validated `SecurityEvent` objects         |
| `security-events-dlq` | Dead-letter queue for messages the worker cannot process |

The main topic is configured via `KAFKA_SECURITY_EVENTS_TOPIC`
(default `security-events`); the DLQ via `KAFKA_SECURITY_EVENTS_DLQ_TOPIC`
(default `security-events-dlq`). Broker-level auto-creation is disabled in
the compose file, so the worker provisions both topics explicitly at
startup via `app.kafka.topics.ensure_topics` (idempotent; tolerates a topic
that a concurrent process just created). Pass `--no-create-topics` to the
worker if topics are provisioned out-of-band.

## Environment variables

| Variable                           | Default                  | Description                          |
| ---------------------------------- | ------------------------ | ------------------------------------ |
| `KAFKA_BOOTSTRAP_SERVERS`          | `localhost:9092`         | Kafka broker address(es)             |
| `KAFKA_SECURITY_EVENTS_TOPIC`      | `security-events`        | Topic carrying security events       |
| `KAFKA_SECURITY_EVENTS_DLQ_TOPIC`  | `security-events-dlq`    | Dead-letter topic for failed messages |
| `KAFKA_CONSUMER_GROUP`             | `sentinelai-development` | Default consumer group for dev       |
| `KAFKA_CONSUMER_MAX_RETRIES`       | `3`                      | Processing attempts before dead-lettering |
| `KAFKA_CONSUMER_RETRY_BACKOFF_SECONDS` | `1.0`                | Delay between processing retries     |
| `THREAT_INTEL_ENRICHMENT_ENABLED`  | `false`                  | Opt-in post-detection enrichment (see below) |

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

## Consumer design (transport)

`backend/app/kafka/consumer.py` — `KafkaEventConsumer`

- Subscribes to `KAFKA_SECURITY_EVENTS_TOPIC` in `KAFKA_CONSUMER_GROUP`.
- Reads one message at a time with `consume()`; returns a validated
  `SecurityEvent` or `None` (no message within the poll timeout).
- Malformed JSON and schema-invalid messages are logged and **skipped**
  — `consume()` never raises for a single bad message.
- `auto_offset_reset` defaults to `latest` (configurable) and
  `enable_auto_commit` is disabled; the caller decides when to advance
  the offset.
- Exposes `consume_records()` (returns every polled message wrapped in a
  `ConsumedRecord` — valid or invalid — with topic/partition/offset) and
  `commit(topic, partition, offset)` for manual, per-message offset
  advancement. This is what the ingestion worker uses.
- Transport + validation only; no processing added here.

## Ingestion worker

`backend/app/kafka/worker.py` — `KafkaIngestionWorker`

The worker is the runnable entrypoint that connects the consumer to the
processing pipeline. For each polled record it:

1. Validates the payload (the consumer has already attached a parsed
   `SecurityEvent` or an `error`).
2. Skips an **invalid** message: it is dead-lettered and its offset is
   committed (a malformed message will never succeed on redelivery).
3. Runs the event through `EventIngestPipeline.process()` — normalize,
   detect, persist — with bounded retries (`KAFKA_CONSUMER_MAX_RETRIES`,
   `KAFKA_CONSUMER_RETRY_BACKOFF_SECONDS`).
4. On success commits the offset; on exhausted retries dead-letters the
   message and commits the offset so the partition does not stall.
5. Skips events already processed (idempotency guard — see below).

It is fully dependency-injected (`consumer`, `dead_letter`,
`session_factory`, `registry`, `pipeline_factory`, `already_processed`,
`sleep`), so it can be unit-tested without a broker or database. In
production it installs SIGINT/SIGTERM handlers and drains cleanly on
`stop()`.

### Starting the worker

```bash
cd backend
.venv/bin/python -m app.cli consume-events
# bounded batch with a JSON summary:
.venv/bin/python -m app.cli consume-events --max-messages 100 --json
```

| Flag                 | Purpose                                             |
| -------------------- | --------------------------------------------------- |
| `--group`            | Consumer group (default `KAFKA_CONSUMER_GROUP`)     |
| `--max-messages`     | Stop after N records (default: run until signalled) |
| `--no-create-topics` | Do not provision `security-events`/DLQ at startup   |
| `--json`             | Emit the run report as JSON instead of text         |

The worker provisions the topics first (unless `--no-create-topics`),
then polls until `--max-messages` is reached or a signal arrives.

### Dead-lettering

`backend/app/kafka/dlq.py` — `KafkaDeadLetterPublisher`

Failed or malformed messages are republished to
`KAFKA_SECURITY_EVENTS_DLQ_TOPIC` with a JSON envelope containing the
original value (base64-encoded so arbitrary bytes survive round-trip),
the error type/message, the source topic/partition/offset, and a
timestamp. No credentials are added.

### Idempotency limitation

Detection engines assign a **fresh `detection_id` on every evaluation**,
so persistence is idempotent per *evaluation*, not per *event*. The worker
therefore guards against duplicate rows with an event-level check
(`count_results_for_event` / `count_failures_for_event` on the detection
repository): if an event already produced detection rows, redelivery is
skipped. This is an application-level guard, not a transactional
exactly-once guarantee — see "Delivery semantics".

### Threat-intelligence enrichment (opt-in)

`backend/app/services/threat_intel_enrichment.py` — `ThreatIntelEnricher`

By default the worker does detection only. Setting
`THREAT_INTEL_ENRICHMENT_ENABLED=true` adds a **post-detection** stage that
runs the existing `EnrichmentAgent` and `ThreatIntelligenceAgent` over each
event and writes indicators/lookups through the existing persistence service.

- **Ordering.** For each event the worker runs normalize → detect → persist
  detections, and only *after* detection persistence has committed does it
  enrich and persist threat intelligence. `EventIngestPipeline` invokes the
  collaborator exactly once per processed event.
- **Reuse.** The provider registry and both agents are built once at worker
  startup (`_run_kafka_consumer`) and reused for every event via a bound
  pipeline factory; they are never rebuilt per event. The worker's
  `(db, registry)` factory contract is unchanged.
- **Failure isolation.** A provider failure, timeout, or persistence error is
  caught inside the pipeline, logged with the exception *type* only, and
  swallowed. Detection results are already committed and are never rolled
  back, and the worker still commits the offset — so an unavailable external
  provider degrades coverage, never ingestion.
- **Credentials.** Providers are built only from configured keys
  (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`); a provider with
  no key is *skipped, not stubbed*, and the run report lists skipped
  providers. No key values are ever logged. This mirrors the demo's provider
  policy.
- **Latency limitation.** Provider lookups are **synchronous and blocking**
  with per-request timeouts and no client-side cache or rate limiter, so
  enrichment adds per-event latency to the poll loop; size provider timeouts
  and the retry budget accordingly. Enrichment applies to the Kafka path only;
  the HTTP/file ingestion path (`ingest_jsonl`) is unchanged and performs no
  threat-intelligence lookup.
- **Testing offline.** With the setting left at its `false` default, no
  provider client is constructed and no network call is made; the unit tests
  in `tests/unit/test_threat_intel_enrichment.py` run fully offline
  (`--noconftest`).

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
  auto-commit disabled; offsets are committed manually by the worker). We
  do **not** claim exactly-once semantics.
- The producer waits for broker acknowledgement (`acks=all`) before
  reporting success.
- Message **keys** are the `event_id`, so ordering per key/partition is
  preserved.
- The worker commits an offset **only after** the event is persisted or
  dead-lettered, so a crash mid-processing causes redelivery (at-least-once).
  The event-level idempotency guard absorbs the resulting duplicates.

## Error handling

| Scenario               | Behavior                                            |
| ---------------------- | --------------------------------------------------- |
| Kafka unavailable      | Producer/consumer raise `KafkaError`/`NoBrokersAvailable`; callers handle it |
| Publish failure        | `publish` raises `KafkaError`; no false success     |
| Serialization failure  | Raised by Pydantic during `model_dump_json`         |
| Malformed JSON         | Consumer logs warning, skips message; the worker dead-letters and commits it |
| Schema-invalid event   | Consumer logs warning, skips message (validation is enforced); worker dead-letters |
| Processing failure     | Worker retries up to `KAFKA_CONSUMER_MAX_RETRIES`, then dead-letters and commits |
| Consumer errors        | Poll raises `KafkaError`; caller handles it         |
| DLQ publish failure    | Worker does **not** commit the offset, so the message is retried next poll |

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
`tests/unit/test_kafka_producer_consumer.py`,
`tests/unit/test_kafka_ingestion_worker.py`) run without Kafka or a
database — use `pytest --noconftest` for the worker tests so the
session-scoped DB fixture is not triggered.

## Development limitations

- The `apache/kafka` image is configured in KRaft mode (no Zookeeper).
- On Windows, the kafka-python client can intermittently raise
  `ValueError: Invalid file descriptor` during rapid connect/disconnect
  cycles in tests. The integration tests retry with fresh consumers to
  ride out these transient, non-delivery races. This is a kafka-python
  + Windows limitation, not a data-loss condition.
- Broker auto-creation is disabled; topics are created explicitly or via
  admin tooling during development.

