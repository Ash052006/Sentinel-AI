"""V2.20 incident-report AI output contract tests (category D).

Strict model-output parsing, the Gemini client's report-specific payload
composition (inherited transport, report output schema), and the prompt
builder's context handoff.  No network calls are made.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.services.reporting.model_output import (
    INCIDENT_REPORT_MODEL_JSON_SCHEMA,
    parse_model_output,
)
from app.services.reporting.errors import ReportValidationError
from app.services.reporting.llm import IncidentReportGeminiClient
from app.services.reporting.prompt import IncidentReportPrompt, ReportPromptBuilder

from tests.unit.incident_report_test_helpers import canonical_model_output


class TestParseModelOutput:
    def test_accepts_canonical_output(self):
        parsed = parse_model_output(canonical_model_output())
        assert parsed.title == "Correlated network intrusion"
        assert parsed.findings[0].provenance.value == "ai_generated"

    def test_rejects_malformed_json(self):
        with pytest.raises(ReportValidationError):
            parse_model_output("{not json")

    def test_rejects_non_object_root(self):
        with pytest.raises(ReportValidationError):
            parse_model_output("[1, 2, 3]")

    def test_rejects_unknown_fields(self):
        payload = json.loads(canonical_model_output())
        payload["actor_id"] = "attacker"
        with pytest.raises(ReportValidationError):
            parse_model_output(json.dumps(payload))

    def test_rejects_oversized_prose(self):
        payload = json.loads(canonical_model_output())
        payload["incident_overview"] = "x" * 20001
        with pytest.raises(ReportValidationError):
            parse_model_output(json.dumps(payload))

    def test_rejects_invalid_reference_type(self):
        payload = json.loads(canonical_model_output())
        payload["findings"] = [
            {
                "title": "t",
                "summary": "s",
                "evidence_references": ["not-a-uuid"],
            }
        ]
        with pytest.raises(ReportValidationError):
            parse_model_output(json.dumps(payload))


class TestJsonSchema:
    def test_schema_sends_report_output_contract(self):
        assert INCIDENT_REPORT_MODEL_JSON_SCHEMA["type"] == "OBJECT"
        assert "title" in INCIDENT_REPORT_MODEL_JSON_SCHEMA["properties"]
        assert "findings" in INCIDENT_REPORT_MODEL_JSON_SCHEMA["properties"]
        assert "correlation_id" not in INCIDENT_REPORT_MODEL_JSON_SCHEMA["properties"]

    def test_schema_requires_all_prose_fields(self):
        required = INCIDENT_REPORT_MODEL_JSON_SCHEMA["required"]
        for field in (
            "title",
            "executive_summary",
            "incident_overview",
            "investigation_summary",
            "attribution_summary",
            "threat_hunting_summary",
            "response_summary",
            "findings",
            "limitations",
            "recommended_follow_up",
        ):
            assert field in required


class TestGeminiClientPayload:
    def test_build_payload_uses_report_schema(self):
        from app.agents.investigation.prompt import InvestigationPrompt

        prompt = IncidentReportPrompt(
            prompt=InvestigationPrompt(
                system_instruction="sys",
                content="report task with context",
            )
        )
        client = IncidentReportGeminiClient(
            api_key="k",
            model="gemini-2.0-flash",
            temperature=0.0,
            max_retries=0,
            http_client=httpx.Client(),
        )
        payload = client._build_payload(prompt.prompt)
        assert payload["generationConfig"]["responseSchema"] == INCIDENT_REPORT_MODEL_JSON_SCHEMA
        assert "temperature" in payload["generationConfig"]
        assert payload["systemInstruction"]["parts"][0]["text"] == "sys"

    def test_generate_requires_report_prompt(self):
        from app.agents.investigation.prompt import InvestigationPrompt

        client = IncidentReportGeminiClient(
            api_key="k",
            model="m",
            temperature=0.0,
            max_retries=0,
            http_client=httpx.Client(),
        )
        try:
            client.generate(InvestigationPrompt(system_instruction="s", content="c"))
        except TypeError:
            pass
        else:
            raise AssertionError("expected TypeError for wrong prompt type")


class TestPromptBuilder:
    def test_build_returns_delimited_context(self):
        from app.schemas.incident_report import (
            IncidentReportContext,
            IncidentFactContext,
        )

        # Minimal empty-but-valid context (all sources empty).
        from app.schemas.investigation_context import (
            CorrelationContext,
            InputAvailability,
        )
        from app.schemas.security_event import Provenance
        from app.schemas.correlation import CorrelationStatus
        from app.schemas.incident_report import ReportSourceAvailability
        from datetime import datetime, timezone as tz

        ts = datetime(2026, 9, 24, 12, 0, 0, tzinfo=tz.utc)
        correlation = CorrelationContext(
            correlation_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            status=CorrelationStatus.ACTIVE,
            confidence=0.5,
            members=[],
            evidence={},
            timestamp=ts,
            provenance=Provenance.CORRELATED,
        )
        availability = ReportSourceAvailability(
            correlation=InputAvailability.PROVIDED,
            detections=InputAvailability.NOT_PROVIDED,
            threat_intelligence=InputAvailability.NONE_FOUND,
            risk_assessment=InputAvailability.NOT_PROVIDED,
            investigation=InputAvailability.NOT_PROVIDED,
            attribution=InputAvailability.NOT_PROVIDED,
            incident_memory=InputAvailability.NONE_FOUND,
            threat_hunts=InputAvailability.NONE_FOUND,
            policy_decisions=InputAvailability.NONE_FOUND,
            soar_executions=InputAvailability.NONE_FOUND,
            security_events=InputAvailability.NOT_PROVIDED,
        )
        context = IncidentReportContext(
            incident=IncidentFactContext(
                correlation_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                status=CorrelationStatus.ACTIVE,
                confidence=0.5,
                established_at=ts,
                member_count=0,
                resolved_detection_count=0,
                unresolved_detection_count=0,
                distinct_event_reference_count=0,
                earliest_member_timestamp=None,
                latest_member_timestamp=None,
                provenance=Provenance.CORRELATED,
            ),
            correlation=correlation,
            security_event_references=[],
            evidence_catalog=[],
            availability=availability,
        )
        prompt = ReportPromptBuilder().build(context)
        assert "INCIDENT_CONTEXT" in (prompt.prompt.content + prompt.prompt.system_instruction)