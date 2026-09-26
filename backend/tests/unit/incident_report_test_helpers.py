"""Shared SQLite adapters and seed builders for the V2.20 incident-report suite.

Mirrors :mod:`tests.unit.threat_hunt_test_helpers`: bolts the PostgreSQL
models onto an in-memory SQLite engine (JSONB -> JSON, UUID -> CHAR(32)) so
the read-only context builder, generator and service run against the exact
persistence contracts without touching the live database.

The builders here extend the V2.19 threat-hunt seeds with approval-request
and SOAR-execution rows (the two execution-adjacent sources a report must
present as observed records, never as triggers), plus a complete canonical
model output used to drive generator tests.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from tests.unit.threat_hunt_test_helpers import (  # noqa: F401  (SQLite patches)
    NOW,
    TZ,
    ACTOR_ID,
    a_audit,
    a_correlation,
    a_detection,
    a_indicator,
    a_lookup,
    a_memory,
    a_risk,
    seed_actor,
)

# SQLite patches for JSONB / UUID are installed by the import above.
from app.models.approval_request import ApprovalRequestRow
from app.models.soar_execution import SoarExecutionRow
from app.schemas.incident_report import IncidentReportAI


def a_approval(
    db,
    *,
    approval_id: uuid.UUID,
    policy_decision_id: uuid.UUID,
    correlation_id: uuid.UUID,
    status: str = "approved",
    requested_at: datetime = NOW,
    by: uuid.UUID = ACTOR_ID,
    by_role: str = "analyst",
) -> ApprovalRequestRow:
    row = ApprovalRequestRow(
        approval_id=approval_id,
        policy_decision_id=policy_decision_id,
        correlation_id=correlation_id,
        action_type="block_ip",
        target="192.0.2.10",
        status=status,
        reason="Policy rule X required a human decision.",
        policy_rule_id="rule-021",
        risk_level="high",
        risk_score=0.81,
        confidence=0.7,
        evidence=[],
        decision={},
        requested_by=by,
        requested_by_role=by_role,
        requested_at=requested_at,
        expires_at=requested_at + timedelta(hours=1),
        resolved_at=requested_at + timedelta(minutes=5) if status != "pending" else None,
        resolved_by=by if status != "pending" else None,
        resolution_reason="Approved by test harness." if status != "pending" else None,
    )
    db.add(row)
    db.flush()
    return row


def a_soar_execution(
    db,
    *,
    execution_id: uuid.UUID,
    policy_decision_id: uuid.UUID,
    correlation_id: uuid.UUID,
    status: str = "succeeded",
    started_at: datetime = NOW,
    by: uuid.UUID = ACTOR_ID,
    by_role: str = "analyst",
) -> SoarExecutionRow:
    row = SoarExecutionRow(
        execution_id=execution_id,
        idempotency_key=f"ir-{uuid.uuid4().hex}",
        policy_decision_id=policy_decision_id,
        correlation_id=correlation_id,
        approval_id=None,
        response_id=uuid.uuid4(),
        playbook_id="response-block-ip",
        playbook_version="1",
        primary_action="block_ip",
        target="192.0.2.10",
        status=status,
        failure_policy="stop_on_failure",
        simulated=False,
        error_code=None,
        started_at=started_at,
        completed_at=started_at + timedelta(minutes=2),
        created_by=by,
        created_by_role=by_role,
        execution_metadata={},
    )
    db.add(row)
    db.flush()
    return row


def canonical_model_output(**overrides) -> str:
    """A strictly-valid, catalog-citing model output (raw LLM text)."""
    payload = {
        "title": "Correlated network intrusion",
        "executive_summary": "Multiple high-severity detections correlated.",
        "incident_overview": "Persisted detections point to a coordinated sweep.",
        "investigation_summary": "No persisted investigation store exists.",
        "attribution_summary": "No attribution assessment exists in V2.20.",
        "threat_hunting_summary": "A completed hunt overlapped the incident window.",
        "response_summary": "An approval was granted; no execution is proven.",
        "findings": [
            {
                "title": "High-severity detection",
                "summary": "A high-severity SIGMA rule matched.",
                "evidence_references": [],
            }
        ],
        "limitations": ["No security-event telemetry persisted."],
        "recommended_follow_up": ["Review the correlated detections."],
    }
    payload.update(overrides)
    return json.dumps(payload)


VALID_AI = IncidentReportAI(
    title="Correlated network intrusion",
    executive_summary="Multiple high-severity detections correlated.",
    incident_overview="Persisted detections point to a coordinated sweep.",
    investigation_summary="No persisted investigation store exists.",
    attribution_summary="No attribution assessment exists in V2.20.",
    threat_hunting_summary="A completed hunt overlapped the incident window.",
    response_summary="An approval was granted; no execution is proven.",
    findings=[],
    limitations=["No security-event telemetry persisted."],
    recommended_follow_up=["Review the correlated detections."],
)


class FakeReportLLM:
    """Deterministic in-memory report LLM for tests (never hits the network)."""

    model_name = "fake-report-model"

    def __init__(self, text: str | None = None, *, callable=None) -> None:
        self._text = text if text is not None else canonical_model_output()
        self._callable = callable
        self.calls: list[str] = []

    def generate(self, prompt) -> str:
        self.calls.append(prompt.content if hasattr(prompt, "content") else str(prompt))
        if self._callable is not None:
            return self._callable(prompt)
        return self._text


__all__ = [
    "NOW",
    "TZ",
    "ACTOR_ID",
    "a_audit",
    "a_correlation",
    "a_detection",
    "a_indicator",
    "a_lookup",
    "a_memory",
    "a_risk",
    "a_approval",
    "a_soar_execution",
    "seed_actor",
    "canonical_model_output",
    "VALID_AI",
    "FakeReportLLM",
]