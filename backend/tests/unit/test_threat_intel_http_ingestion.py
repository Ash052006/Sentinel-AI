"""Opt-in threat-intelligence enrichment for the HTTP ingestion path.

The HTTP endpoint calls :func:`app.services.ingest_service.ingest_jsonl`
directly (the Kafka worker uses :class:`EventIngestPipeline` instead), so these
tests pin the HTTP-specific wiring:

* enrichment is not requested while ``threat_intel_enrichment_enabled`` is off;
* it is built once per request and injected when the flag is on;
* the enricher runs once per successfully persisted event, after detection;
* an enrichment/provider failure cannot reject or roll back detection;
* missing/skipped providers still allow local enrichment metadata to run;
* a detection failure skips enrichment.

Everything is fixture-independent (no live database, no provider network
call).  Run with::

    python -m pytest tests/unit/test_threat_intel_http_ingestion.py --noconftest
"""

from __future__ import annotations

import io
import json
import uuid
from types import SimpleNamespace

import pytest

from app.api.routes import ingest as ingest_route
from app.services import ingest_service

WINDOWS_LOGON_EVENT = {
    "timestamp": "2026-09-27T10:00:00+00:00",
    "source": "windows-dc01",
    "source_type": "operating_system",
    "event_type": "logon",
    "action": "network logon attempt",
    "outcome": "failure",
    "actor": "CONTOSO\\jdoe",
    "TargetUserName": "jdoe",
}


def _jsonl(*records: dict) -> str:
    return "\n".join(json.dumps(record) for record in records) + "\n"


def _install_ingest_fakes(monkeypatch, *, fail_detection: bool = False) -> dict:
    """Replace only the governed detection edges, keeping real normalization."""
    state: dict[str, object] = {"order": [], "persist_calls": 0}

    class _Registry:
        def list_rules(self):
            return []

    class _DetectionAgent:
        def __init__(self, registry=None):
            self._registry = registry

        def evaluate(self, normalized, persistence=None):
            state["order"].append("evaluate")
            if fail_detection:
                raise RuntimeError("detection boom")
            persistence("ANALYSIS")
            return SimpleNamespace(
                results=[
                    SimpleNamespace(
                        matched=True, rule_id="rule-1", severity="high"
                    )
                ],
                failures=[],
            )

    def _persist_bound(db, service=None):
        def _persist(analysis):
            state["order"].append("persist")
            state["persist_calls"] += 1
            return SimpleNamespace(results_created=1)

        return _persist

    monkeypatch.setattr(
        ingest_service, "build_active_registry", lambda db: _Registry()
    )
    monkeypatch.setattr(ingest_service, "DetectionAgent", _DetectionAgent)
    monkeypatch.setattr(ingest_service, "persist_analysis_bound", _persist_bound)
    return state


class RecordingEnricher:
    def __init__(self, *, fail: bool = False, order: list | None = None) -> None:
        self.fail = fail
        self.calls = 0
        self.dbs: list[object] = []
        self.events: list[object] = []
        self._order = order if order is not None else []

    def enrich(self, db, event):
        self.calls += 1
        self.dbs.append(db)
        self.events.append(event)
        self._order.append("enrich")
        if self.fail:
            raise RuntimeError("provider unavailable")
        return object()


class _Upload:
    def __init__(self, content: str, name: str = "events.jsonl") -> None:
        self.filename = name
        self.file = io.BytesIO(content.encode("utf-8"))


def _request() -> SimpleNamespace:
    return SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))


def _user() -> SimpleNamespace:
    return SimpleNamespace(id=uuid.uuid4())


def _summary() -> SimpleNamespace:
    return SimpleNamespace(
        total_records=1,
        accepted_events=1,
        rejected_records=0,
        detections=1,
    )


# ---------------------------------------------------------------------------
# ingest_jsonl: the enricher hook used by the HTTP endpoint
# ---------------------------------------------------------------------------


def test_http_ingest_enriches_after_detection_persistence(monkeypatch):
    state = _install_ingest_fakes(monkeypatch)
    enricher = RecordingEnricher(order=state["order"])

    summary = ingest_service.ingest_jsonl(
        "DB", _jsonl(WINDOWS_LOGON_EVENT), enrichment=enricher
    )

    assert state["order"] == ["evaluate", "persist", "enrich"]
    assert summary.events_processed == 1
    assert summary.detections == 1
    assert summary.detection_results_created == 1
    assert enricher.calls == 1
    assert enricher.dbs == ["DB"]
    assert enricher.events[0].event_id == summary.events[0].event_id


def test_http_ingest_without_enrichment_keeps_old_behaviour(monkeypatch):
    state = _install_ingest_fakes(monkeypatch)

    summary = ingest_service.ingest_jsonl("DB", _jsonl(WINDOWS_LOGON_EVENT))

    assert state["order"] == ["evaluate", "persist"]
    assert summary.events_processed == 1
    assert summary.detections == 1


def test_http_ingest_enrichment_failure_does_not_reject_event(monkeypatch):
    state = _install_ingest_fakes(monkeypatch)
    enricher = RecordingEnricher(fail=True, order=state["order"])

    summary = ingest_service.ingest_jsonl(
        "DB", _jsonl(WINDOWS_LOGON_EVENT), enrichment=enricher
    )

    assert state["order"] == ["evaluate", "persist", "enrich"]
    assert summary.events_processed == 1
    assert summary.rejected_records == 0
    assert summary.detections == 1
    assert summary.detection_results_created == 1
    assert enricher.calls == 1


def test_http_ingest_enriches_once_per_accepted_event(monkeypatch):
    state = _install_ingest_fakes(monkeypatch)
    enricher = RecordingEnricher(order=state["order"])

    summary = ingest_service.ingest_jsonl(
        "DB",
        _jsonl(WINDOWS_LOGON_EVENT, WINDOWS_LOGON_EVENT),
        enrichment=enricher,
    )

    assert enricher.calls == 2
    assert summary.events_processed == 2
    assert [event.event_id for event in enricher.events] == [
        trace.event_id for trace in summary.events
    ]


def test_detection_failure_skips_enrichment(monkeypatch):
    state = _install_ingest_fakes(monkeypatch, fail_detection=True)
    enricher = RecordingEnricher(order=state["order"])

    summary = ingest_service.ingest_jsonl(
        "DB", _jsonl(WINDOWS_LOGON_EVENT), enrichment=enricher
    )

    assert state["order"] == ["evaluate"]
    assert enricher.calls == 0
    assert summary.events_processed == 0
    assert summary.rejected_records == 1


# ---------------------------------------------------------------------------
# HTTP route: flag handling and one-shot construction per request
# ---------------------------------------------------------------------------


def test_http_route_end_to_end_enriches_upload(monkeypatch):
    state = _install_ingest_fakes(monkeypatch)
    enricher = RecordingEnricher(order=state["order"])

    monkeypatch.setattr(
        ingest_route.settings, "threat_intel_enrichment_enabled", True
    )
    monkeypatch.setattr(
        ingest_route,
        "build_threat_intel_enricher",
        lambda: (enricher, []),
    )
    monkeypatch.setattr(ingest_route, "log_action", lambda **kwargs: None)

    summary = ingest_route.ingest_events(
        request=_request(),
        file=_Upload(_jsonl(WINDOWS_LOGON_EVENT)),
        db="DB",
        current_user=_user(),
    )

    assert state["order"] == ["evaluate", "persist", "enrich"]
    assert summary.events_processed == 1
    assert summary.detections == 1
    assert enricher.calls == 1
    assert enricher.events[0].event_id == summary.events[0].event_id


def test_http_route_builds_and_injects_enricher_when_enabled(monkeypatch):
    enricher = RecordingEnricher()
    built: list[bool] = []
    captured: dict[str, object] = {}

    def _build():
        built.append(True)
        return enricher, ["virustotal (no API key)"]

    def _ingest(db, content, *, enrichment=None):
        captured.update(db=db, content=content, enrichment=enrichment)
        return _summary()

    monkeypatch.setattr(
        ingest_route.settings, "threat_intel_enrichment_enabled", True
    )
    monkeypatch.setattr(ingest_route, "build_threat_intel_enricher", _build)
    monkeypatch.setattr(ingest_route, "ingest_jsonl", _ingest)
    monkeypatch.setattr(ingest_route, "log_action", lambda **kwargs: None)

    ingest_route.ingest_events(
        request=_request(),
        file=_Upload(_jsonl(WINDOWS_LOGON_EVENT)),
        db="DB",
        current_user=_user(),
    )

    assert built == [True]
    assert captured["db"] == "DB"
    assert captured["enrichment"] is enricher
    assert json.loads(captured["content"]) == WINDOWS_LOGON_EVENT


def test_http_route_does_not_build_enricher_when_disabled(monkeypatch):
    captured: dict[str, object] = {}
    built: list[bool] = []

    def _build():
        built.append(True)
        return RecordingEnricher(), []

    def _ingest(db, content, *, enrichment=None):
        captured["enrichment"] = enrichment
        return _summary()

    monkeypatch.setattr(
        ingest_route.settings, "threat_intel_enrichment_enabled", False
    )
    monkeypatch.setattr(ingest_route, "build_threat_intel_enricher", _build)
    monkeypatch.setattr(ingest_route, "ingest_jsonl", _ingest)
    monkeypatch.setattr(ingest_route, "log_action", lambda **kwargs: None)

    ingest_route.ingest_events(
        request=_request(),
        file=_Upload(_jsonl(WINDOWS_LOGON_EVENT)),
        db="DB",
        current_user=_user(),
    )

    assert built == []
    assert captured["enrichment"] is None


def test_http_route_keeps_ingesting_when_enricher_construction_fails(monkeypatch):
    captured: dict[str, object] = {}

    def _build():
        raise RuntimeError("bad provider configuration")

    def _ingest(db, content, *, enrichment=None):
        captured["enrichment"] = enrichment
        return _summary()

    monkeypatch.setattr(
        ingest_route.settings, "threat_intel_enrichment_enabled", True
    )
    monkeypatch.setattr(ingest_route, "build_threat_intel_enricher", _build)
    monkeypatch.setattr(ingest_route, "ingest_jsonl", _ingest)
    monkeypatch.setattr(ingest_route, "log_action", lambda **kwargs: None)

    result = ingest_route.ingest_events(
        request=_request(),
        file=_Upload(_jsonl(WINDOWS_LOGON_EVENT)),
        db="DB",
        current_user=_user(),
    )

    assert result.accepted_events == 1
    assert captured["enrichment"] is None


def test_http_route_runs_local_enrichment_when_providers_are_skipped(monkeypatch):
    enricher = RecordingEnricher()
    captured: dict[str, object] = {}

    def _build():
        return enricher, [
            "virustotal (no API key)",
            "abuseipdb (no API key)",
            "otx (RuntimeError)",
        ]

    def _ingest(db, content, *, enrichment=None):
        captured["enrichment"] = enrichment
        return _summary()

    monkeypatch.setattr(
        ingest_route.settings, "threat_intel_enrichment_enabled", True
    )
    monkeypatch.setattr(ingest_route, "build_threat_intel_enricher", _build)
    monkeypatch.setattr(ingest_route, "ingest_jsonl", _ingest)
    monkeypatch.setattr(ingest_route, "log_action", lambda **kwargs: None)

    result = ingest_route.ingest_events(
        request=_request(),
        file=_Upload(_jsonl(WINDOWS_LOGON_EVENT)),
        db="DB",
        current_user=_user(),
    )

    assert result.accepted_events == 1
    assert captured["enrichment"] is enricher
