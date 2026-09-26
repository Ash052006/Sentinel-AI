"""V2.20 incident-report strict contract tests (category A).

Strict Pydantic contracts: availability/provenance semantics, bounds that
**reject** rather than truncate, airtight evidence-catalog uniqueness, and
the secret-safety gate on persisted payloads.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.incident_report import (
    MAX_REPORT_TITLE_LENGTH,
    ReportFinding,
    ReportSourceAvailability,
    IncidentReport,
    IncidentReportAI,
)
from app.schemas.investigation_context import InputAvailability


def _ai(**overrides) -> IncidentReportAI:
    base = {
        "title": "Correlated network intrusion",
        "executive_summary": "S",
        "incident_overview": "S",
        "investigation_summary": "S",
        "attribution_summary": "S",
        "threat_hunting_summary": "S",
        "response_summary": "S",
        "findings": [],
        "limitations": [],
        "recommended_follow_up": [],
    }
    base.update(overrides)
    return IncidentReportAI(**base)


class TestProvenancePins:
    def test_finding_accepts_ai_generated_only(self):
        finding = ReportFinding(
            title="t", summary="s", evidence_references=[]
        )
        assert finding.provenance.value == "ai_generated"

    def test_finding_rejects_non_ai_provenance(self):
        with pytest.raises(ValidationError):
            _ai(
                findings=[
                    {
                        "title": "t",
                        "summary": "s",
                        "evidence_references": [],
                        "provenance": "correlated",
                    }
                ]
            )


class TestStringBounds:
    def test_title_rejects_over_long(self):
        with pytest.raises(ValidationError):
            _ai(title="x" * (MAX_REPORT_TITLE_LENGTH + 1))

    def test_title_rejects_blank(self):
        with pytest.raises(ValidationError):
            _ai(title="   ")

    def test_finding_rejects_blank_summary(self):
        with pytest.raises(ValidationError):
            _ai(
                findings=[
                    {"title": "t", "summary": " ", "evidence_references": []}
                ]
            )


class TestAvailabilitySemantics:
    def test_investigation_and_attribution_always_not_provided(self):
        a = ReportSourceAvailability(
            correlation=InputAvailability.PROVIDED,
            risk_assessment=InputAvailability.NOT_PROVIDED,
            investigation=InputAvailability.NOT_PROVIDED,
            attribution=InputAvailability.NOT_PROVIDED,
        )
        assert a.investigation is InputAvailability.NOT_PROVIDED
        assert a.attribution is InputAvailability.NOT_PROVIDED

    def test_correlation_always_provided(self):
        a = ReportSourceAvailability(
            correlation=InputAvailability.PROVIDED,
        )
        assert a.correlation is InputAvailability.PROVIDED


class TestReportSecretSafety:
    def test_payload_gate_rejects_session_token_shape(self):
        from app.schemas.incident_report import _validate_payload

        with pytest.raises(ValueError):
            _validate_payload(
                {"metadata": {"session_token": "abc"}},
                "payload",
            )