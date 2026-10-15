"""Ingest API layer tests for the raw/normalized trace.

Exercises ``POST /api/ingest/events`` through the full stack the project
already uses for API tests (JWT -> ``TestClient(app)`` -> route ->
:func:`ingest_jsonl`) and pins what reaches the browser:

* the response still carries every pre-existing
  :class:`~app.services.ingest_service.IngestSummary` counter, so the
  console's summary panel is unchanged;
* it now also carries ``events``/``truncated_events``, each entry pairing
  ``raw_event`` with the real ``normalized_event`` and a ``provenance``
  read back from it;
* RBAC, size/encoding rejection and the empty-file 422 are unaffected;
* an ingest that normalized nothing returns an empty trace, not an error.

The governed rule registry and detection evaluation are stubbed (see
``tests/unit/test_ingest_service.py`` for the service-level contract); the
collector and the normalization agent are the real ones.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_header

ENDPOINT = "/api/ingest/events"

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


class _StubRegistry:
    def list_rules(self) -> list[object]:
        return []


@pytest.fixture(autouse=True)
def stub_detection_pipeline(monkeypatch):
    """Bypass the deployed rule registry and the detection transaction."""
    monkeypatch.setattr(
        "app.services.ingest_service.build_active_registry",
        lambda db: _StubRegistry(),
    )

    class _StubDetectionAgent:
        def __init__(self, registry=None):
            self.registry = registry

        def evaluate(self, event, persistence=None):
            return SimpleNamespace(results=[], failures=[])

    monkeypatch.setattr(
        "app.services.ingest_service.DetectionAgent", _StubDetectionAgent
    )


def _upload(content: str, name: str = "events.jsonl") -> tuple[bytes, str]:
    return content.encode("utf-8"), name


def _post(client: TestClient, token: str, content: str):
    body, name = _upload(content)
    return client.post(
        ENDPOINT,
        files={"file": (name, body, "application/x-ndjson")},
        headers=auth_header(token),
    )


@pytest.mark.usefixtures("stub_detection_pipeline")
class TestIngestResponseContract:
    def test_returns_normalized_event_for_each_ingested_record(
        self, client: TestClient, analyst_token: str
    ):
        response = _post(client, analyst_token, json.dumps(WINDOWS_LOGON_EVENT) + "\n")
        assert response.status_code == 200
        payload = response.json()

        assert len(payload["events"]) == 1
        trace = payload["events"][0]
        assert set(trace) == {
            "event_id",
            "line_number",
            "raw_event",
            "normalized_event",
            "provenance",
        }
        assert trace["raw_event"] == WINDOWS_LOGON_EVENT
        assert trace["line_number"] == 1

        normalized = trace["normalized_event"]
        assert normalized["event_id"] == trace["event_id"]
        assert normalized["event_category"] == "authentication"
        assert normalized["outcome"] == "failure"
        assert normalized["action"] == "network logon attempt"
        assert normalized["source"] == "windows-dc01"
        assert normalized["source_type"] == "operating_system"
        assert normalized["actor"] == {
            "user_id": None,
            "username": "jdoe",
            "domain": None,
        }
        assert normalized["timestamp"].startswith("2026-09-27T10:00:00")

    def test_reports_observed_provenance_not_a_normalization_marker(
        self, client: TestClient, analyst_token: str
    ):
        payload = _post(
            client, analyst_token, json.dumps(WINDOWS_LOGON_EVENT) + "\n"
        ).json()
        assert payload["events"][0]["provenance"] == "observed"
        assert payload["events"][0]["normalized_event"]["provenance"] == "observed"

    def test_preserves_existing_summary_counters(
        self, client: TestClient, analyst_token: str
    ):
        payload = _post(
            client, analyst_token, json.dumps(WINDOWS_LOGON_EVENT) + "\n"
        ).json()
        for key in (
            "total_records",
            "accepted_events",
            "rejected_records",
            "events_processed",
            "detections",
            "events_with_detections",
            "detection_results_created",
            "rule_failures",
            "active_rule_count",
            "errors",
            "truncated_errors",
            "duration_ms",
        ):
            assert key in payload, key
        assert payload["total_records"] == 1
        assert payload["events_processed"] == 1
        assert payload["truncated_events"] is False

    def test_keeps_nested_structures_readable(
        self, client: TestClient, analyst_token: str
    ):
        record = {
            **WINDOWS_LOGON_EVENT,
            "source": "firewall-edge-01",
            "source_type": "network",
            "event_type": "firewall",
            "action": "deny",
            "src_ip": "10.20.30.40",
            "dst_ip": "203.0.113.9",
            "dst_port": 4444,
        }
        payload = _post(client, analyst_token, json.dumps(record) + "\n").json()
        normalized = payload["events"][0]["normalized_event"]
        assert normalized["source_endpoint"] == {
            "ip": "10.20.30.40",
            "hostname": None,
            "port": None,
            "protocol": None,
        }
        assert normalized["destination_endpoint"] == {
            "ip": "203.0.113.9",
            "hostname": None,
            "port": 4444,
            "protocol": None,
        }
        assert normalized["event_category"] == "network"
        assert normalized["outcome"] == "denied"

    def test_all_lines_rejected_returns_empty_trace(
        self, client: TestClient, analyst_token: str
    ):
        response = _post(client, analyst_token, "{not json}\n{also not json}\n")
        assert response.status_code == 200
        payload = response.json()
        assert payload["accepted_events"] == 0
        assert payload["events_processed"] == 0
        assert payload["events"] == []
        assert payload["truncated_events"] is False
        assert len(payload["errors"]) == 2

    def test_rejected_line_is_reported_without_a_trace(
        self, client: TestClient, analyst_token: str
    ):
        content = json.dumps(WINDOWS_LOGON_EVENT) + "\n" + "{not json}\n"
        payload = _post(client, analyst_token, content).json()
        assert payload["rejected_records"] == 1
        assert len(payload["events"]) == 1
        assert payload["errors"]


class TestIngestEndpointUnaffected:
    def test_still_requires_authentication(self, client: TestClient):
        body, name = _upload(json.dumps(WINDOWS_LOGON_EVENT))
        response = client.post(
            ENDPOINT, files={"file": (name, body, "application/x-ndjson")}
        )
        assert response.status_code in (401, 403)

    def test_still_rejects_a_whitespace_only_file(
        self, client: TestClient, analyst_token: str
    ):
        response = _post(client, analyst_token, "   \n")
        assert response.status_code == 422
        assert response.json()["detail"] == "File is empty."
