"""Tests for the FileLogCollector.

These are pure unit tests that exercise the collector against temporary
files on disk.  No database connection is required.
"""

import json
import os
import sys
import uuid
from pathlib import Path

import pytest

from app.collectors.file_collector import FileLogCollector
from app.collectors.base import CollectionResult
from app.schemas.security_event import Provenance, SecurityEvent


# ---------------------------------------------------------------------------
# Fixtures — synthetic test data
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_log(tmp_path: Path) -> Path:
    """Return a path to a temporary log file (empty by default)."""
    return tmp_path / "events.jsonl"


def _write(path: Path, *lines: str) -> None:
    """Write lines to *path*, one per line, with trailing newlines."""
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _valid_record(**overrides) -> dict:
    """Return a minimal valid event record with optional overrides."""
    base = {
        "timestamp": "2026-09-04T10:30:00Z",
        "source": "windows",
        "source_type": "operating_system",
        "event_type": "authentication",
        "data": {"user": "testuser", "action": "login", "result": "success"},
    }
    base.update(overrides)
    return base


def _record_line(record: dict | None = None, **overrides) -> str:
    """Return a single JSON line string for a valid record."""
    if record is None:
        record = _valid_record(**overrides)
    return json.dumps(record)


# ---------------------------------------------------------------------------
# 1. Collector successfully reads valid records
# ---------------------------------------------------------------------------

class TestReadsValidRecords:
    def test_single_valid_record(self, tmp_log: Path):
        _write(tmp_log, _record_line())
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        assert isinstance(result, CollectionResult)
        assert result.successful_records == 1
        assert len(result.events) == 1


# ---------------------------------------------------------------------------
# 2. Valid records become SecurityEvent objects
# ---------------------------------------------------------------------------

class TestRecordsBecomeEvents:
    def test_returns_security_event_instances(self, tmp_log: Path):
        _write(tmp_log, _record_line())
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        event = result.events[0]
        assert isinstance(event, SecurityEvent)
        assert event.source == "windows"
        assert event.source_type.value == "operating_system"
        assert event.event_type == "authentication"
        assert event.timestamp is not None


# ---------------------------------------------------------------------------
# 3. Every collected event receives a unique event_id
# ---------------------------------------------------------------------------

class TestUniqueEventIDs:
    def test_each_event_has_unique_id(self, tmp_log: Path):
        lines = [_record_line() for _ in range(5)]
        _write(tmp_log, *lines)
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        ids = {e.event_id for e in result.events}
        assert len(ids) == 5


# ---------------------------------------------------------------------------
# 4. Valid events have OBSERVED provenance
# ---------------------------------------------------------------------------

class TestObservedProvenance:
    def test_all_events_are_observed(self, tmp_log: Path):
        _write(tmp_log, _record_line())
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        assert result.events[0].provenance == Provenance.OBSERVED


# ---------------------------------------------------------------------------
# 5. raw_data preserves the original input record
# ---------------------------------------------------------------------------

class TestRawDataPreservation:
    def test_raw_data_matches_original(self, tmp_log: Path):
        original = _valid_record()
        _write(tmp_log, _record_line(original))
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        assert result.events[0].raw_data == original

    def test_raw_data_not_transformed(self, tmp_log: Path):
        original = _valid_record(
            data={"nested": {"deep": [1, 2, 3]}, "flag": True}
        )
        _write(tmp_log, _record_line(original))
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        assert result.events[0].raw_data["data"]["nested"]["deep"] == [1, 2, 3]
        assert result.events[0].raw_data["data"]["flag"] is True


# ---------------------------------------------------------------------------
# 6. Multiple valid records are collected
# ---------------------------------------------------------------------------

class TestMultipleRecords:
    def test_collects_all_valid_records(self, tmp_log: Path):
        records = [
            _valid_record(event_type="authentication"),
            _valid_record(event_type="network_connection"),
            _valid_record(event_type="process_creation"),
        ]
        lines = [_record_line(r) for r in records]
        _write(tmp_log, *lines)
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        assert result.total_records == 3
        assert result.successful_records == 3
        assert len(result.events) == 3
        event_types = {e.event_type for e in result.events}
        assert event_types == {
            "authentication", "network_connection", "process_creation",
        }


# ---------------------------------------------------------------------------
# 7. Malformed JSON is rejected without stopping collection
# ---------------------------------------------------------------------------

class TestMalformedJSON:
    def test_bad_json_skipped(self, tmp_log: Path):
        good = _record_line(_valid_record(event_type="authentication"))
        bad = "this is not json {{{"
        good2 = _record_line(_valid_record(event_type="network_connection"))
        _write(tmp_log, good, bad, good2)
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        assert result.total_records == 3
        assert result.successful_records == 2
        assert result.failed_records == 1
        assert len(result.events) == 2
        # Error references line 2
        assert result.errors[0].line_number == 2
        assert "Invalid JSON" in result.errors[0].reason


# ---------------------------------------------------------------------------
# 8. Schema validation failures are rejected without stopping collection
# ---------------------------------------------------------------------------

class TestSchemaValidationFailures:
    def test_missing_timestamp_rejected(self, tmp_log: Path):
        good = _record_line(_valid_record())
        bad = json.dumps({
            "source": "linux",
            "source_type": "operating_system",
            "event_type": "auth",
        })
        good2 = _record_line(_valid_record(event_type="process_creation"))
        _write(tmp_log, good, bad, good2)
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        assert result.total_records == 3
        assert result.successful_records == 2
        assert result.failed_records == 1
        assert result.errors[0].line_number == 2

    def test_invalid_source_type_rejected(self, tmp_log: Path):
        bad_record = _valid_record(source_type="invalid_cat")
        _write(tmp_log, _record_line(bad_record))
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        assert result.failed_records == 1
        assert result.successful_records == 0


# ---------------------------------------------------------------------------
# 9. Empty lines are handled safely
# ---------------------------------------------------------------------------

class TestEmptyLines:
    def test_blank_lines_skipped(self, tmp_log: Path):
        good = _record_line(_valid_record())
        _write(tmp_log, good, "", "  ", "", good)
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        assert result.total_records == 2
        assert result.successful_records == 2
        assert result.failed_records == 0

    def test_empty_file_returns_empty_result(self, tmp_log: Path):
        _write(tmp_log)
        collector = FileLogCollector(tmp_log)
        result = collector.collect()
        assert result.total_records == 0
        assert result.successful_records == 0
        assert result.failed_records == 0
        assert len(result.events) == 0


# ---------------------------------------------------------------------------
# 10. Missing file is handled correctly
# ---------------------------------------------------------------------------

class TestMissingFile:
    def test_file_not_found_raises(self, tmp_path: Path):
        collector = FileLogCollector(tmp_path / "nonexistent.jsonl")
        with pytest.raises(FileNotFoundError):
            collector.collect()


# ---------------------------------------------------------------------------
# 11. File permission/open failure is handled appropriately
# ---------------------------------------------------------------------------

class TestFilePermissionError:
    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows does not enforce POSIX-style file permissions via chmod",
    )
    def test_permission_error_propagates(self, tmp_log: Path):
        _write(tmp_log, _record_line())
        try:
            os.chmod(tmp_log, 0o000)
            collector = FileLogCollector(tmp_log)
            with pytest.raises(PermissionError):
                collector.collect()
        finally:
            os.chmod(tmp_log, 0o644)


# ---------------------------------------------------------------------------
# 12. Collection statistics are correct
# ---------------------------------------------------------------------------

class TestCollectionStatistics:
    def test_statistics_all_valid(self, tmp_log: Path):
        lines = [_record_line() for _ in range(4)]
        _write(tmp_log, *lines)
        result = FileLogCollector(tmp_log).collect()
        assert result.total_records == 4
        assert result.successful_records == 4
        assert result.failed_records == 0
        assert len(result.errors) == 0

    def test_statistics_mixed(self, tmp_log: Path):
        good = _record_line()
        bad = "not-json"
        _write(tmp_log, good, bad, good, bad, good)
        result = FileLogCollector(tmp_log).collect()
        assert result.total_records == 5
        assert result.successful_records == 3
        assert result.failed_records == 2
        assert len(result.errors) == 2

    def test_statistics_consistency(self, tmp_log: Path):
        """successful + failed must always equal total."""
        good = _record_line()
        bad = "!!!invalid"
        _write(tmp_log, good, bad, good, bad, good, bad)
        result = FileLogCollector(tmp_log).collect()
        assert result.successful_records + result.failed_records == result.total_records


# ---------------------------------------------------------------------------
# 13. Valid + invalid + valid still returns both valid events
# ---------------------------------------------------------------------------

class TestMixedValidInvalid:
    def test_sandwich_pattern(self, tmp_log: Path):
        valid1 = _record_line(_valid_record(event_type="authentication"))
        bad = "}invalid json{"
        valid2 = _record_line(_valid_record(event_type="network_connection"))
        _write(tmp_log, valid1, bad, valid2)
        result = FileLogCollector(tmp_log).collect()
        assert result.successful_records == 2
        assert len(result.events) == 2
        event_types = {e.event_type for e in result.events}
        assert event_types == {"authentication", "network_connection"}


# ---------------------------------------------------------------------------
# 14. No enrichment occurs
# ---------------------------------------------------------------------------

class TestNoEnrichment:
    def test_no_enrichment_fields_added(self, tmp_log: Path):
        original = _valid_record()
        _write(tmp_log, _record_line(original))
        event = FileLogCollector(tmp_log).collect().events[0]
        assert set(event.raw_data.keys()) == set(original.keys())
        assert not hasattr(event, "enriched_data")
        assert not hasattr(event, "normalised_data")


# ---------------------------------------------------------------------------
# 15. No reconstruction occurs
# ---------------------------------------------------------------------------

class TestNoReconstruction:
    def test_provenance_never_reconstructed(self, tmp_log: Path):
        _write(tmp_log, _record_line())
        event = FileLogCollector(tmp_log).collect().events[0]
        assert event.provenance == Provenance.OBSERVED
        assert event.provenance != Provenance.RECONSTRUCTED


# ---------------------------------------------------------------------------
# 16. No normalization occurs
# ---------------------------------------------------------------------------

class TestNoNormalization:
    def test_field_values_not_normalised(self, tmp_log: Path):
        original = _valid_record(
            source="MyWindowsHost",
            event_type="LoginAttempt",
        )
        _write(tmp_log, _record_line(original))
        event = FileLogCollector(tmp_log).collect().events[0]
        assert event.source == "MyWindowsHost"
        assert event.event_type == "LoginAttempt"


# ---------------------------------------------------------------------------
# 17. Metadata contains collector info
# ---------------------------------------------------------------------------

class TestCollectorMetadata:
    def test_metadata_has_collector_name_and_line(self, tmp_log: Path):
        _write(tmp_log, _record_line())
        event = FileLogCollector(tmp_log).collect().events[0]
        assert event.metadata is not None
        assert event.metadata["collector"] == "file_collector"
        assert event.metadata["line_number"] == 1

    def test_line_numbers_are_accurate(self, tmp_log: Path):
        good = _record_line()
        bad = "not-json"
        _write(tmp_log, good, bad, good)
        result = FileLogCollector(tmp_log).collect()
        line_numbers = [e.metadata["line_number"] for e in result.events]
        assert line_numbers == [1, 3]