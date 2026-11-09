"""Unit tests for the Kafka ingestion worker and the per-event pipeline.

Everything runs with fakes/injected collaborators -- no broker, no database,
no live registry -- so the suite runs under ``--noconftest`` and never touches
the conftest autouse fixture that migrates a database.

Covered behaviours:

* a valid event is processed and its offset committed only afterwards;
* a malformed payload is dead-lettered and the offset advanced;
* a transient failure is retried, then succeeds with a single commit;
* an event that exhausts the retry budget is dead-lettered, not lost;
* a redelivered (already-persisted) event is skipped (idempotency);
- an offset is not committed if the dead-letter publish itself fails;
- graceful shutdown returns without draining forever;
- :class:`EventIngestPipeline` reuses the existing normalization/detection
  services rather than re-implementing them.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from kafka.errors import TopicAlreadyExistsError

from app.cli import main as cli_main
from app.kafka.consumer import ConsumedRecord
from app.kafka.topics import ensure_topics
from app.kafka.worker import KafkaIngestionWorker
from app.schemas.security_event import Provenance, SecurityEvent, SourceType
from app.services import ingest_service
from app.services.ingest_service import EventIngestResult


# ---------------------------------------------------------------------------
# Fixtures / fakes
# ---------------------------------------------------------------------------


def _event(event_id: uuid.UUID | None = None) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id or uuid.uuid4(),
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        source="test-source",
        source_type=SourceType.OPERATING_SYSTEM,
        event_type="process_creation",
        raw_data={"action": "test"},
        provenance=Provenance.OBSERVED,
    )


def _record(event=None, error=None, offset=0, partition=0) -> ConsumedRecord:
    return ConsumedRecord(
        topic="security-events",
        partition=partition,
        offset=offset,
        key="key-1",
        raw_value=b'{"raw": true}',
        event=event,
        error=error,
    )


class FakeConsumer:
    def __init__(self, batches, on_empty=None):
        self._batches = list(batches)
        self._on_empty = on_empty
        self.commits: list[tuple[str, int, int]] = []
        self.closed = False

    def consume_records(self, timeout_ms: int = 1000):
        if self._batches:
            return self._batches.pop(0)
        if self._on_empty is not None:
            self._on_empty()
        return []

    def commit(self, topic, partition, offset):
        self.commits.append((topic, partition, offset))

    def close(self):
        self.closed = True


class FakeDeadLetter:
    def __init__(self, fail: bool = False):
        self.published: list[dict] = []
        self.fail = fail
        self.closed = False

    def publish(self, **envelope):
        if self.fail:
            raise RuntimeError("dead-letter broker down")
        self.published.append(envelope)

    def close(self):
        self.closed = True


class FakeSession:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def session_factory():
    return FakeSession()


class PipelineRecorder:
    """Records pipeline invocations; can fail the first N attempts."""

    def __init__(self, fail_times: int = 0, fail_exc: Exception | None = None, result=None):
        self.calls = 0
        self.fail_times = fail_times
        self.fail_exc = fail_exc or RuntimeError("boom")
        self.result = result

    def factory(self, db, registry):
        recorder = self

        class _Pipeline:
            def process(self, event):
                recorder.calls += 1
                if recorder.calls <= recorder.fail_times:
                    raise recorder.fail_exc
                return recorder.result

        return _Pipeline()


def _result(detections=1, created=1, failures=0) -> EventIngestResult:
    return EventIngestResult(
        event_id=uuid.uuid4(),
        detections=detections,
        detection_results_created=created,
        rule_failures=failures,
    )


def _worker(consumer, dead_letter, recorder, *, already_processed=None, **kwargs):
    return KafkaIngestionWorker(
        consumer=consumer,
        dead_letter=dead_letter,
        session_factory=session_factory,
        registry=object(),
        pipeline_factory=recorder.factory,
        already_processed=already_processed or (lambda db, event_id: False),
        sleep=lambda _seconds: None,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_valid_event_processed_and_committed():
    consumer = FakeConsumer([[_record(event=_event(), offset=0)]])
    dead_letter = FakeDeadLetter()
    recorder = PipelineRecorder(result=_result(detections=1, created=2))
    worker = _worker(consumer, dead_letter, recorder)

    report = worker.run(max_messages=1, install_signal_handlers=False)

    assert recorder.calls == 1
    assert consumer.commits == [("security-events", 0, 0)]
    assert dead_letter.published == []
    assert report.events_processed == 1
    assert report.detection_results_created == 2
    assert report.invalid_messages == 0
    assert report.dead_lettered == 0


def test_batch_processes_and_commits_each_record():
    events = [_event(), _event()]
    consumer = FakeConsumer([[ _record(event=events[0], offset=0),
                             _record(event=_event(), offset=1) ]])
    dead_letter = FakeDeadLetter()
    recorder = PipelineRecorder(result=_result())
    worker = _worker(consumer, dead_letter, recorder)

    report = worker.run(max_messages=2)

    assert recorder.calls == 2
    assert consumer.commits == [("security-events", 0, 0), ("security-events", 0, 1)]
    assert report.records_consumed == 2
    assert report.events_processed == 2


# ---------------------------------------------------------------------------
# Malformed payloads
# ---------------------------------------------------------------------------


def test_malformed_message_is_dead_lettered_and_committed():
    consumer = FakeConsumer([[_record(event=None, error="JSONDecodeError: bad", offset=3)]])
    dead_letter = FakeDeadLetter()
    recorder = PipelineRecorder(result=_result())
    worker = _worker(consumer, dead_letter, recorder)

    report = worker.run(max_messages=1, install_signal_handlers=False)

    assert recorder.calls == 0
    assert len(dead_letter.published) == 1
    assert dead_letter.published[0]["raw_value"] == b'{"raw": true}'
    assert dead_letter.published[0]["offset"] == 3
    assert consumer.commits == [("security-events", 0, 3)]
    assert report.invalid_messages == 1
    assert report.dead_lettered == 1
    assert report.events_processed == 0


def test_offset_not_committed_when_dead_letter_publish_fails():
    consumer = FakeConsumer([[_record(event=None, error="bad", offset=5)]])
    dead_letter = FakeDeadLetter(fail=True)
    recorder = PipelineRecorder(result=_result())
    worker = _worker(consumer, dead_letter, recorder)

    with pytest.raises(RuntimeError):
        worker.run(max_messages=1, install_signal_handlers=False)

    assert consumer.commits == []


# ---------------------------------------------------------------------------
# Retries
# ---------------------------------------------------------------------------


def test_retry_then_success_commits_once():
    consumer = FakeConsumer([[_record(event=_event(), offset=0)]])
    dead_letter = FakeDeadLetter()
    recorder = PipelineRecorder(fail_times=1, result=_result())
    worker = _worker(consumer, dead_letter, recorder, max_retries=3)

    report = worker.run(max_messages=1, install_signal_handlers=False)

    assert recorder.calls == 2
    assert dead_letter.published == []
    assert consumer.commits == [("security-events", 0, 0)]
    assert report.events_processed == 1


def test_exhausted_retries_dead_letters_and_commits():
    consumer = FakeConsumer([[_record(event=_event(), offset=9)]])
    dead_letter = FakeDeadLetter()
    recorder = PipelineRecorder(fail_times=99, result=_result())
    sleeps: list[float] = []
    worker = KafkaIngestionWorker(
        consumer=consumer,
        dead_letter=dead_letter,
        session_factory=session_factory,
        registry=object(),
        pipeline_factory=recorder.factory,
        already_processed=lambda db, event_id: False,
        max_retries=3,
        retry_backoff_seconds=0.5,
        sleep=sleeps.append,
    )

    report = worker.run(max_messages=1, install_signal_handlers=False)

    assert recorder.calls == 3
    assert len(dead_letter.published) == 1
    assert consumer.commits == [("security-events", 0, 9)]
    assert report.processing_failures == 1
    assert report.dead_lettered == 1
    assert report.events_processed == 0
    # Backoff is applied between attempts only (max_retries - 1 times).
    assert sleeps == [0.5, 1.0]


def test_max_retries_must_be_positive():
    with pytest.raises(ValueError):
        KafkaIngestionWorker(
            consumer=FakeConsumer([]),
            dead_letter=FakeDeadLetter(),
            session_factory=session_factory,
            registry=object(),
            max_retries=0,
        )


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_duplicate_event_is_skipped():
    event = _event()
    consumer = FakeConsumer([[_record(event=event, offset=1)]])
    dead_letter = FakeDeadLetter()
    recorder = PipelineRecorder(result=_result())
    worker = _worker(
        consumer,
        dead_letter,
        recorder,
        already_processed=lambda db, event_id: event_id == event.event_id,
    )

    report = worker.run(max_messages=1, install_signal_handlers=False)

    assert recorder.calls == 0
    assert consumer.commits == [("security-events", 0, 1)]
    assert report.events_skipped_duplicate == 1
    assert report.events_processed == 0


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_graceful_shutdown_stops_loop():
    consumer = FakeConsumer([[_record(event=_event(), offset=0)]])
    dead_letter = FakeDeadLetter()
    recorder = PipelineRecorder(result=_result())
    worker = _worker(consumer, dead_letter, recorder)
    consumer._on_empty = worker.stop

    report = worker.run(install_signal_handlers=False)

    assert report.records_consumed == 1
    assert report.events_processed == 1


def test_close_releases_resources():
    consumer = FakeConsumer([])
    dead_letter = FakeDeadLetter()
    recorder = PipelineRecorder()
    worker = _worker(consumer, dead_letter, recorder)

    worker.close()

    assert consumer.closed is True
    assert dead_letter.closed is True


# ---------------------------------------------------------------------------
# EventIngestPipeline reuses the existing services
# ---------------------------------------------------------------------------


def test_event_ingest_pipeline_reuses_existing_services(monkeypatch):
    calls: dict[str, object] = {}

    class FakeNormalizer:
        def normalize(self, event):
            calls["normalized_input"] = event
            return "NORMALIZED"

    monkeypatch.setattr(ingest_service, "NormalizationAgent", lambda: FakeNormalizer())
    monkeypatch.setattr(
        ingest_service,
        "apply_explicit_fields",
        lambda event, normalized: normalized,
    )

    class FakeDetectionAgent:
        def __init__(self, registry=None):
            calls["registry"] = registry

        def evaluate(self, normalized, persistence=None):
            calls["evaluated"] = normalized
            persistence("ANALYSIS")
            return SimpleNamespace(
                results=[SimpleNamespace(matched=True), SimpleNamespace(matched=False)],
                failures=["f1"],
            )

    monkeypatch.setattr(ingest_service, "DetectionAgent", FakeDetectionAgent)

    persisted: dict[str, object] = {}
    outcome = SimpleNamespace(results_created=7)

    def _fake_persist_bound(db, service=None):
        def _persist(analysis):
            persisted["analysis"] = analysis
            return outcome

        return _persist

    monkeypatch.setattr(
        ingest_service, "persist_analysis_bound", _fake_persist_bound
    )

    pipeline = ingest_service.EventIngestPipeline(
        db=None, registry="REGISTRY", persistence="PERSISTENCE"
    )
    event = _event()
    result = pipeline.process(event)

    assert calls["normalized_input"] is event
    assert calls["evaluated"] == "NORMALIZED"
    assert calls["registry"] == "REGISTRY"
    assert persisted["analysis"] == "ANALYSIS"
    assert result.event_id == event.event_id
    assert result.detections == 1  # only the matched result counts
    assert result.detection_results_created == 7
    assert result.rule_failures == 1


# ---------------------------------------------------------------------------
# Topic provisioning
# ---------------------------------------------------------------------------


@patch("app.kafka.topics.KafkaAdminClient")
def test_ensure_topics_creates_only_missing(mock_admin_cls):
    admin = MagicMock()
    admin.list_topics.return_value = ["security-events"]
    mock_admin_cls.return_value = admin

    created = ensure_topics(
        "localhost:9092", ["security-events", "security-events-dlq"]
    )

    assert created == ["security-events-dlq"]
    admin.create_topics.assert_called_once()
    admin.close.assert_called_once()


@patch("app.kafka.topics.KafkaAdminClient")
def test_ensure_topics_noop_when_all_exist(mock_admin_cls):
    admin = MagicMock()
    admin.list_topics.return_value = ["security-events", "security-events-dlq"]
    mock_admin_cls.return_value = admin

    created = ensure_topics(
        "localhost:9092", ["security-events", "security-events-dlq"]
    )

    assert created == []
    admin.create_topics.assert_not_called()


@patch("app.kafka.topics.KafkaAdminClient")
def test_ensure_topics_tolerates_concurrent_creation(mock_admin_cls):
    admin = MagicMock()
    admin.list_topics.return_value = []
    admin.create_topics.side_effect = TopicAlreadyExistsError()
    mock_admin_cls.return_value = admin

    created = ensure_topics("localhost:9092", ["security-events"])

    assert created == []
    admin.close.assert_called_once()


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_cli_registers_consume_events(monkeypatch):
    captured: dict[str, object] = {}

    def fake_runner(args):
        captured["max_messages"] = args.max_messages
        captured["group"] = args.group
        captured["no_create_topics"] = args.no_create_topics
        return {"records_consumed": 0}

    monkeypatch.setattr("app.cli._run_kafka_consumer", fake_runner)

    rc = cli_main(
        ["consume-events", "--max-messages", "5", "--group", "g1", "--json"]
    )

    assert rc == 0
    assert captured == {
        "max_messages": 5,
        "group": "g1",
        "no_create_topics": False,
    }
