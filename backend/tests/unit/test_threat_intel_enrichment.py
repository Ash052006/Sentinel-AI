"""Unit tests for the opt-in threat-intelligence enrichment stage (F-10).

Everything runs with injected fakes/monkeypatched collaborators -- no broker,
no database, no provider network call -- so the suite runs under
``--noconftest`` and never triggers the conftest autouse database fixture.

Covered behaviours:

* the provider registry skips keyless providers (never fabricates a lookup);
* ``ThreatIntelEnricher`` delegates to the existing EnrichmentAgent and
  ThreatIntelligenceAgent, in that order, and persists through the existing
  bound persistence callback;
* the registry and both agents are built once and reused across events;
* the pipeline invokes enrichment exactly once, *after* detection persistence;
* an enrichment failure is isolated (detection result still returned);
* a detection failure skips enrichment entirely;
* the Kafka worker still commits (and records success) when enrichment fails;
* a retried event invokes enrichment only on the attempt that succeeds.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from functools import partial
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.kafka.consumer import ConsumedRecord
from app.kafka.worker import KafkaIngestionWorker
from app.schemas.security_event import Provenance, SecurityEvent, SourceType
from app.services import ingest_service
from app.services import threat_intel_enrichment as tie
from app.services.ingest_service import EventIngestResult
from app.services.threat_intelligence.base import ThreatIntelProvider
from app.services.threat_intelligence.types import IndicatorType


# ---------------------------------------------------------------------------
# Fakes / helpers
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


class FakeProvider(ThreatIntelProvider):
    """Minimal in-memory provider (never dialled in these tests)."""

    def __init__(self, name: str = "Fake") -> None:
        self._name = name

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def supported_indicator_types(self) -> frozenset[IndicatorType]:
        return frozenset({IndicatorType.IP})

    def lookup(self, indicator):  # pragma: no cover - not exercised here
        raise AssertionError("no lookup should be performed")


def _install_pipeline_fakes(monkeypatch, *, fail_evaluations: int = 0):
    """Replace the pipeline's real stages with deterministic fakes.

    Returns a ``state`` dict recording evaluation/persistence counts and the
    ordered sequence of stage events, mirroring the existing worker test's
    patching approach.
    """
    state = {"evaluate_calls": 0, "persist_calls": 0, "order": []}

    class FakeNormalizer:
        def normalize(self, event):
            return SimpleNamespace(
                event_id=event.event_id, timestamp=event.timestamp
            )

    class FakeDetectionAgent:
        def __init__(self, registry=None):
            self._registry = registry

        def evaluate(self, normalized, persistence=None):
            state["evaluate_calls"] += 1
            state["order"].append("evaluate")
            if state["evaluate_calls"] <= fail_evaluations:
                raise RuntimeError("detection boom")
            persistence("ANALYSIS")
            return SimpleNamespace(
                results=[SimpleNamespace(matched=True)],
                failures=[],
            )

    def _fake_persist_bound(db, service=None):
        def _persist(analysis):
            state["persist_calls"] += 1
            state["order"].append("persist")
            return SimpleNamespace(results_created=1)

        return _persist

    monkeypatch.setattr(ingest_service, "NormalizationAgent", FakeNormalizer)
    monkeypatch.setattr(
        ingest_service,
        "apply_explicit_fields",
        lambda event, normalized: normalized,
    )
    monkeypatch.setattr(ingest_service, "DetectionAgent", FakeDetectionAgent)
    monkeypatch.setattr(
        ingest_service, "persist_analysis_bound", _fake_persist_bound
    )
    return state


class RecordingEnricher:
    def __init__(self, *, fail: bool = False, order: list | None = None,
                 result: object = "TI_ANALYSIS") -> None:
        self.fail = fail
        self.calls = 0
        self.events = []
        self.dbs = []
        self._order = order if order is not None else []
        self._result = result

    def enrich(self, db, event):
        self.calls += 1
        self.events.append(event)
        self.dbs.append(db)
        self._order.append("enrich")
        if self.fail:
            raise RuntimeError("ti boom")
        return self._result


# ---------------------------------------------------------------------------
# Provider registry builder
# ---------------------------------------------------------------------------


def test_build_provider_registry_skips_keyless_providers(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "")
    monkeypatch.setattr(settings, "abuseipdb_api_key", "")
    monkeypatch.setattr(settings, "otx_api_key", "")

    built = []

    def _explode_ctor():
        built.append(True)
        raise AssertionError("keyless provider must not be constructed")

    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.VirusTotalProvider",
        _explode_ctor,
    )
    monkeypatch.setattr(
        "app.services.threat_intelligence.abuseipdb.AbuseIPDBProvider",
        _explode_ctor,
    )
    monkeypatch.setattr(
        "app.services.threat_intelligence.alienvault_otx.AlienVaultOTXProvider",
        _explode_ctor,
    )

    registry, skipped = tie.build_provider_registry()

    assert registry.list_providers() == []
    assert built == []
    assert skipped == [
        "virustotal (no API key)",
        "abuseipdb (no API key)",
        "otx (no API key)",
    ]


def test_build_provider_registry_constructs_only_configured(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "vt-key")
    monkeypatch.setattr(settings, "abuseipdb_api_key", "")
    monkeypatch.setattr(settings, "otx_api_key", "")

    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.VirusTotalProvider",
        lambda: FakeProvider("VirusTotal"),
    )

    registry, skipped = tie.build_provider_registry()

    assert [p.provider_name for p in registry.list_providers()] == ["VirusTotal"]
    assert skipped == ["abuseipdb (no API key)", "otx (no API key)"]


def test_build_provider_registry_tolerates_failing_constructor(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "vt-key")
    monkeypatch.setattr(settings, "abuseipdb_api_key", "")
    monkeypatch.setattr(settings, "otx_api_key", "")

    def _boom():
        raise RuntimeError("bad credentials format")

    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.VirusTotalProvider", _boom
    )

    registry, skipped = tie.build_provider_registry()

    assert registry.list_providers() == []
    assert skipped == [
        "virustotal (RuntimeError)",
        "abuseipdb (no API key)",
        "otx (no API key)",
    ]


# ---------------------------------------------------------------------------
# ThreatIntelEnricher delegation and reuse
# ---------------------------------------------------------------------------


def test_enricher_delegates_to_existing_agents_in_order(monkeypatch):
    calls: list[tuple] = []
    enriched = object()
    analysis = object()
    bound: dict[str, object] = {}

    class FakeEnrichmentAgent:
        def enrich(self, event):
            calls.append(("enrich", event))
            return enriched

    class FakeAnalyst:
        def __init__(self, registry):
            calls.append(("analyst_init", registry))

        def analyze(self, event, persistence=None):
            calls.append(("analyze", event, persistence))
            persistence("ANALYSIS")
            return analysis

    def _fake_bound(db, *, service=None):
        def _persist(analysis_arg):
            bound["db"] = db
            bound["analysis"] = analysis_arg

        return _persist

    monkeypatch.setattr(tie, "persist_analysis_bound", _fake_bound)

    registry = object()
    enricher = tie.ThreatIntelEnricher(
        registry,
        enrichment_agent=FakeEnrichmentAgent(),
        analysis_agent=FakeAnalyst(registry),
    )
    event = SimpleNamespace(event_id=uuid.uuid4())

    result = enricher.enrich(db="DB", normalized_event=event)

    assert result is analysis
    assert [c[0] for c in calls] == ["analyst_init", "enrich", "analyze"]
    assert calls[1][1] is event
    assert calls[2][1] is enriched
    assert bound["db"] == "DB"
    assert bound["analysis"] == "ANALYSIS"


def test_enricher_builds_agents_once_and_reuses_them(monkeypatch):
    constructions = {"enrichment": 0, "analyst": 0, "persistence": 0}

    class FakeEnrichmentAgent:
        def __init__(self):
            constructions["enrichment"] += 1

        def enrich(self, event):
            return event

    class FakeAnalyst:
        def __init__(self, registry):
            constructions["analyst"] += 1

        def analyze(self, event, persistence=None):
            return "A"

    class FakePersistence:
        def __init__(self):
            constructions["persistence"] += 1

    monkeypatch.setattr(tie, "EnrichmentAgent", FakeEnrichmentAgent)
    monkeypatch.setattr(tie, "ThreatIntelligenceAgent", FakeAnalyst)
    monkeypatch.setattr(tie, "ThreatIntelligencePersistenceService", FakePersistence)
    monkeypatch.setattr(
        tie, "persist_analysis_bound", lambda db, service=None: (lambda a: None)
    )

    enricher = tie.ThreatIntelEnricher("REGISTRY")

    assert constructions == {"enrichment": 1, "analyst": 1, "persistence": 1}

    for _ in range(3):
        enricher.enrich("DB", SimpleNamespace(event_id=uuid.uuid4()))

    assert constructions == {"enrichment": 1, "analyst": 1, "persistence": 1}


def test_build_threat_intel_enricher_wires_registry(monkeypatch):
    seen: dict[str, object] = {}

    def _fake_registry_builder():
        seen["built"] = True
        return "REGISTRY", ["virustotal (no API key)"]

    class FakeEnricher:
        def __init__(self, registry):
            seen["registry"] = registry

    monkeypatch.setattr(tie, "build_provider_registry", _fake_registry_builder)
    monkeypatch.setattr(tie, "ThreatIntelEnricher", FakeEnricher)

    enricher, skipped = tie.build_threat_intel_enricher()

    assert isinstance(enricher, FakeEnricher)
    assert seen == {"built": True, "registry": "REGISTRY"}
    assert skipped == ["virustotal (no API key)"]


# ---------------------------------------------------------------------------
# EventIngestPipeline enrichment hook
# ---------------------------------------------------------------------------


def test_pipeline_disabled_by_default_does_not_enrich(monkeypatch):
    _install_pipeline_fakes(monkeypatch)

    pipeline = ingest_service.EventIngestPipeline(db=None, registry="REGISTRY")

    result = pipeline.process(_event())

    assert isinstance(result, EventIngestResult)
    assert result.detection_results_created == 1


def test_pipeline_enrichment_runs_after_detection_persistence(monkeypatch):
    state = _install_pipeline_fakes(monkeypatch)
    enricher = RecordingEnricher(order=state["order"])

    pipeline = ingest_service.EventIngestPipeline(
        db="SESSION", registry="REGISTRY", enrichment=enricher
    )
    event = _event()

    result = pipeline.process(event)

    assert state["order"] == ["evaluate", "persist", "enrich"]
    assert enricher.calls == 1
    assert enricher.dbs == ["SESSION"]
    assert enricher.events[0].event_id == event.event_id
    assert result.event_id == event.event_id
    assert result.detection_results_created == 1


def test_pipeline_enrichment_failure_is_isolated(monkeypatch):
    state = _install_pipeline_fakes(monkeypatch)
    enricher = RecordingEnricher(fail=True, order=state["order"])

    pipeline = ingest_service.EventIngestPipeline(
        db="SESSION", registry="REGISTRY", enrichment=enricher
    )

    result = pipeline.process(_event())

    # Detection result still returned; enrichment was attempted and failed.
    assert enricher.calls == 1
    assert state["persist_calls"] == 1
    assert result.detections == 1
    assert result.detection_results_created == 1


def test_pipeline_detection_failure_skips_enrichment(monkeypatch):
    _install_pipeline_fakes(monkeypatch, fail_evaluations=1)
    enricher = RecordingEnricher()

    pipeline = ingest_service.EventIngestPipeline(
        db="SESSION", registry="REGISTRY", enrichment=enricher
    )

    with pytest.raises(RuntimeError, match="detection boom"):
        pipeline.process(_event())

    assert enricher.calls == 0


def test_partial_factory_preserves_worker_contract(monkeypatch):
    """The CLI wires enrichment via ``partial``; the worker signature is intact."""
    _install_pipeline_fakes(monkeypatch)
    enricher = RecordingEnricher()

    factory = partial(ingest_service.EventIngestPipeline, enrichment=enricher)
    pipeline = factory("DB", "REGISTRY")  # exactly how the worker calls it

    pipeline.process(_event())

    assert enricher.calls == 1


# ---------------------------------------------------------------------------
# Kafka worker integration
# ---------------------------------------------------------------------------


class FakeConsumer:
    def __init__(self, batches):
        self._batches = list(batches)
        self.commits: list[tuple[str, int, int]] = []
        self.closed = False

    def consume_records(self, timeout_ms: int = 1000):
        return self._batches.pop(0) if self._batches else []

    def commit(self, topic, partition, offset):
        self.commits.append((topic, partition, offset))

    def close(self):
        self.closed = True


class FakeDeadLetter:
    def __init__(self):
        self.published: list[dict] = []

    def publish(self, **envelope):
        self.published.append(envelope)

    def close(self):
        pass


class FakeSession:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _record(event, offset=0) -> ConsumedRecord:
    return ConsumedRecord(
        topic="security-events",
        partition=0,
        offset=offset,
        key="key-1",
        raw_value=b"{}",
        event=event,
        error=None,
    )


def _worker(consumer, dead_letter, enricher):
    return KafkaIngestionWorker(
        consumer=consumer,
        dead_letter=dead_letter,
        session_factory=lambda: FakeSession(),
        registry=object(),
        pipeline_factory=partial(
            ingest_service.EventIngestPipeline, enrichment=enricher
        ),
        already_processed=lambda db, event_id: False,
        sleep=lambda _seconds: None,
    )


def test_worker_commits_when_enrichment_fails(monkeypatch):
    _install_pipeline_fakes(monkeypatch)
    enricher = RecordingEnricher(fail=True)

    consumer = FakeConsumer([[_record(_event(), offset=0)]])
    dead_letter = FakeDeadLetter()
    worker = _worker(consumer, dead_letter, enricher)

    report = worker.run(max_messages=1, install_signal_handlers=False)

    assert enricher.calls == 1
    assert consumer.commits == [("security-events", 0, 0)]
    assert dead_letter.published == []
    assert report.events_processed == 1
    assert report.processing_failures == 0
    assert report.dead_lettered == 0
    assert report.detection_results_created == 1


def test_worker_enriches_once_only_on_the_successful_attempt(monkeypatch):
    # First attempt fails detection (before enrichment); the retry succeeds and
    # must invoke enrichment exactly once -- never twice for one record.
    _install_pipeline_fakes(monkeypatch, fail_evaluations=1)
    enricher = RecordingEnricher()

    consumer = FakeConsumer([[_record(_event(), offset=0)]])
    dead_letter = FakeDeadLetter()
    worker = _worker(consumer, dead_letter, enricher)

    report = worker.run(max_messages=1, install_signal_handlers=False)

    assert enricher.calls == 1
    assert consumer.commits == [("security-events", 0, 0)]
    assert report.events_processed == 1
    assert report.processing_failures == 0
