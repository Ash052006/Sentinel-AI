"""Ingest service response-contract tests.

:func:`app.services.ingest_service.ingest_jsonl` returns an
:class:`~app.services.ingest_service.IngestSummary`.  This file pins the
raw/normalized trace that summary now carries, because that trace is what
the Data Ingest console renders:

* it pairs each raw record with the *real*
  :class:`~app.schemas.normalized_event.NormalizedSecurityEvent` the
  :class:`~app.agents.normalization.NormalizationAgent` produced;
* the object it exposes is the same object the
  :class:`~app.agents.detection.DetectionAgent` evaluated -- no re-derivation;
* provenance is read back from the normalized event and is never upgraded
  merely because an event was normalized;
* the trace is bounded, and an ingest that normalized nothing returns none.

The collector, the normalization agent and :func:`apply_explicit_fields`
all run for real.  Only the two governed edges are stubbed -- the deployed
rule registry (which needs a live deployment table) and detection
evaluation (which would open a transaction) -- so these tests stay about
normalization, not about rule deployment or persistence.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.agents.normalization import NormalizationAgent
from app.collectors.file_collector import FileLogCollector
from app.schemas.normalized_event import EventCategory, EventOutcome
from app.schemas.security_event import Provenance
from app.services.ingest_service import (
    MAX_RETURNED_EVENTS,
    IngestEventTrace,
    IngestSummary,
    apply_explicit_fields,
    ingest_jsonl,
)

SAMPLE_EVENTS = Path(__file__).resolve().parents[2] / "sample_events.jsonl"

WINDOWS_PROCESS_EVENT = {
    "timestamp": "2026-09-27T10:09:02+00:00",
    "source": "windows-ws07",
    "source_type": "operating_system",
    "event_type": "process_creation",
    "action": "powershell.exe -nop -enc SQBFAFg",
    "outcome": "success",
    "actor": "CONTOSO\\jdoe",
    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -nop -enc SQBFAFg",
}


class _StubRegistry:
    """Minimal stand-in for the governed detection registry."""

    def list_rules(self) -> list[object]:
        return []


@pytest.fixture
def stub_registry(monkeypatch):
    """Bypass the deployed-rule-set rebuild with an empty registry."""
    monkeypatch.setattr(
        "app.services.ingest_service.build_active_registry",
        lambda db: _StubRegistry(),
    )


@pytest.fixture
def evaluated(monkeypatch):
    """Replace detection evaluation and record what it was handed.

    Returns the list of ``NormalizedSecurityEvent`` objects passed to
    ``evaluate``, so a test can assert the trace exposes exactly those.
    """
    seen: list[object] = []

    class _StubDetectionAgent:
        def __init__(self, registry=None):
            self.registry = registry

        def evaluate(self, event, persistence=None):
            seen.append(event)
            return SimpleNamespace(results=[], failures=[])

    monkeypatch.setattr(
        "app.services.ingest_service.DetectionAgent", _StubDetectionAgent
    )
    return seen


@pytest.fixture
def run(stub_registry, evaluated):
    """Ingest JSONL text through the real collector + real normalizer."""

    def _run(text: str, **kwargs) -> IngestSummary:
        return ingest_jsonl(None, text, **kwargs)  # type: ignore[arg-type]

    return _run


def _lines(*records: dict) -> str:
    return "\n".join(json.dumps(record) for record in records) + "\n"


# ---------------------------------------------------------------------------
# Response contract
# ---------------------------------------------------------------------------

class TestSummaryContract:
    def test_summary_exposes_trace_fields(self):
        fields = IngestSummary.model_fields
        assert "events" in fields
        assert "truncated_events" in fields

    def test_trace_defaults_to_empty_and_untruncated(self):
        summary = IngestSummary(
            total_records=0,
            accepted_events=0,
            rejected_records=0,
            events_processed=0,
            detections=0,
            events_with_detections=0,
            detection_results_created=0,
            rule_failures=0,
            active_rule_count=0,
            truncated_errors=False,
            duration_ms=0,
        )
        assert summary.events == []
        assert summary.truncated_events is False

    def test_trace_serialises_expected_top_level_keys(self, tmp_path):
        trace = _trace_for(WINDOWS_PROCESS_EVENT, tmp_path)
        payload = json.loads(trace.model_dump_json())
        assert set(payload) == {
            "event_id",
            "line_number",
            "raw_event",
            "normalized_event",
            "provenance",
        }

    def test_summary_serialises_provenance_as_its_string_value(self, tmp_path):
        trace = _trace_for(WINDOWS_PROCESS_EVENT, tmp_path)
        payload = json.loads(trace.model_dump_json())
        assert payload["provenance"] == "observed"
        assert payload["normalized_event"]["provenance"] == "observed"


# ---------------------------------------------------------------------------
# Provenance semantics
# ---------------------------------------------------------------------------

class TestTraceProvenance:
    def test_derived_from_the_normalized_event(self, tmp_path):
        normalized = NormalizationAgent().normalize(
            _collected(WINDOWS_PROCESS_EVENT, tmp_path)
        )
        enriched = normalized.model_copy(update={"provenance": Provenance.ENRICHED})
        trace = IngestEventTrace(
            event_id=normalized.event_id,
            raw_event=dict(WINDOWS_PROCESS_EVENT),
            normalized_event=enriched,
        )
        assert trace.provenance is Provenance.ENRICHED

    def test_collected_event_stays_observed(self, run):
        summary = run(_lines(WINDOWS_PROCESS_EVENT))
        trace = summary.events[0]
        assert trace.provenance is Provenance.OBSERVED
        assert trace.normalized_event.provenance is Provenance.OBSERVED

    def test_normalization_does_not_upgrade_provenance(self, tmp_path):
        collected = _collected(WINDOWS_PROCESS_EVENT, tmp_path)
        before = collected.provenance
        after = NormalizationAgent().normalize(collected).provenance
        assert before is Provenance.OBSERVED
        assert after is before

    def test_apply_explicit_fields_leaves_provenance_untouched(self, tmp_path):
        collected = _collected(
            {**WINDOWS_PROCESS_EVENT, "event_category": "process"}, tmp_path
        )
        normalized = NormalizationAgent().normalize(collected)
        patched = apply_explicit_fields(collected, normalized)
        assert patched.provenance is Provenance.OBSERVED


# ---------------------------------------------------------------------------
# The trace carries the real pipeline output
# ---------------------------------------------------------------------------

class TestTraceIsRealPipelineOutput:
    def test_matches_an_independent_normalization_of_the_same_line(self, run, tmp_path):
        summary = run(_lines(WINDOWS_PROCESS_EVENT))
        expected = apply_explicit_fields(
            _collected(WINDOWS_PROCESS_EVENT, tmp_path),
            NormalizationAgent().normalize(_collected(WINDOWS_PROCESS_EVENT, tmp_path)),
        )
        # The collector mints a fresh event_id per run, so identity is
        # compared separately; every other field must match exactly.
        assert _without_event_id(summary.events[0].normalized_event) == _without_event_id(
            expected
        )

    def test_exposes_the_object_detection_evaluated(self, run, evaluated):
        summary = run(_lines(WINDOWS_PROCESS_EVENT))
        assert len(evaluated) == 1
        assert summary.events[0].normalized_event is evaluated[0]

    def test_raw_event_is_the_untouched_record(self, run):
        summary = run(_lines(WINDOWS_PROCESS_EVENT))
        assert summary.events[0].raw_event == WINDOWS_PROCESS_EVENT

    def test_event_id_is_shared_by_both_halves(self, run):
        trace = run(_lines(WINDOWS_PROCESS_EVENT)).events[0]
        assert str(trace.event_id) == str(trace.normalized_event.event_id)

    def test_line_number_is_reported(self, run):
        summary = run(_lines(WINDOWS_PROCESS_EVENT, {**WINDOWS_PROCESS_EVENT, "source": "ws02"}))
        assert [trace.line_number for trace in summary.events] == [1, 2]

    def test_nested_entities_are_carried_through(self, run):
        trace = run(_lines(WINDOWS_PROCESS_EVENT)).events[0]
        process = trace.normalized_event.process
        assert process is not None
        assert process.name == WINDOWS_PROCESS_EVENT["NewProcessName"]
        assert process.command_line == WINDOWS_PROCESS_EVENT["CommandLine"]

    def test_normalized_data_keeps_explicit_extras(self, run):
        record = {
            "timestamp": "2026-09-27T10:00:00+00:00",
            "source": "windows-dc01",
            "source_type": "operating_system",
            "event_type": "logon",
            "normalized_data": {"logon_type": 3},
            "TargetUserName": "jdoe",
        }
        normalized = run(_lines(record)).events[0].normalized_event
        assert normalized.normalized_data == {"logon_type": 3}
        assert normalized.actor is not None
        assert normalized.actor.username == "jdoe"
        assert normalized.event_category is EventCategory.AUTHENTICATION
        assert normalized.outcome is EventOutcome.UNKNOWN

    def test_sample_file_produces_a_trace_per_line(self, run):
        records = [
            line
            for line in SAMPLE_EVENTS.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        summary = run(SAMPLE_EVENTS.read_text(encoding="utf-8"))
        assert len(records) == 6
        assert len(summary.events) == 6
        assert summary.events_processed == 6
        assert all(trace.provenance is Provenance.OBSERVED for trace in summary.events)
        assert all(trace.raw_event for trace in summary.events)

    def test_categories_come_from_the_agent(self, run):
        summary = run(SAMPLE_EVENTS.read_text(encoding="utf-8"))
        categories = [t.normalized_event.event_category for t in summary.events]
        assert categories == [
            EventCategory.AUTHENTICATION,
            EventCategory.AUTHENTICATION,
            EventCategory.PROCESS,
            EventCategory.AUTHENTICATION,
            EventCategory.NETWORK,
            EventCategory.FILE,
        ]


# ---------------------------------------------------------------------------
# Bounded / empty results
# ---------------------------------------------------------------------------

class TestTraceBounds:
    def test_truncated_when_more_events_normalize_than_are_returned(self, run):
        summary = run(_lines(*[dict(WINDOWS_PROCESS_EVENT) for _ in range(MAX_RETURNED_EVENTS + 5)]))
        assert len(summary.events) == MAX_RETURNED_EVENTS
        assert summary.truncated_events is True

    def test_not_truncated_at_the_cap(self, run):
        summary = run(_lines(*[dict(WINDOWS_PROCESS_EVENT) for _ in range(MAX_RETURNED_EVENTS)]))
        assert len(summary.events) == MAX_RETURNED_EVENTS
        assert summary.truncated_events is False

    def test_empty_input_returns_no_traces(self, run):
        summary = run("\n\n")
        assert summary.total_records == 0
        assert summary.events_processed == 0
        assert summary.events == []
        assert summary.truncated_events is False

    def test_rejected_line_produces_no_trace(self, run):
        summary = run('{"timestamp": "2026-09-27T10:00:00+00:00"}\n')
        assert summary.rejected_records == 1
        assert summary.events == []

    def test_malformed_json_is_skipped_without_losing_valid_traces(self, run):
        content = "{not json}\n" + _lines(WINDOWS_PROCESS_EVENT)
        summary = run(content)
        assert summary.rejected_records == 1
        assert len(summary.events) == 1

    def test_events_that_normalize_then_fail_detection_are_still_traced(self, run, monkeypatch):
        def _explode(self, event, persistence=None):
            raise RuntimeError("engine unavailable")

        monkeypatch.setattr(
            "app.services.ingest_service.DetectionAgent.evaluate", _explode
        )
        summary = run(_lines(WINDOWS_PROCESS_EVENT))
        assert len(summary.events) == 1
        assert summary.events[0].normalized_event.event_category is EventCategory.PROCESS
        assert summary.events_processed == 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _trace_for(record: dict, tmp_path: Path) -> IngestEventTrace:
    collected = _collected(record, tmp_path)
    normalized = apply_explicit_fields(collected, NormalizationAgent().normalize(collected))
    return IngestEventTrace(
        event_id=collected.event_id,
        line_number=1,
        raw_event=collected.raw_data,
        normalized_event=normalized,
    )


def _collected(record: dict, tmp_path: Path):
    """Run one record through the real FileLogCollector."""
    return FileLogCollector(_write(_lines(record), tmp_path)).collect().events[0]


def _write(text: str, tmp_path: Path) -> Path:
    path = tmp_path / f"events-{len(list(tmp_path.iterdir()))}.jsonl"
    path.write_text(text, encoding="utf-8")
    return path


def _without_event_id(normalized):
    return {k: v for k, v in normalized.model_dump(mode="json").items() if k != "event_id"}
