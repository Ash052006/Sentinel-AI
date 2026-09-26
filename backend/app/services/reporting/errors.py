"""AI Incident Report error model (V2.20).

A closed hierarchy of domain errors that report generation may terminate
with.  Each error maps onto a sanitized ``error_code`` / ``error_message``
pair persisted on a failed report row and surfaced to the API.  Messages
are sanitized and never contain credentials, raw provider internals, full
prompts, or source telemetry.
"""

from __future__ import annotations


class IncidentReportError(Exception):
    """Base class for all incident-report domain errors."""

    code: str = "report.error"
    message: str = "Incident report error"

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.message
        super().__init__(self.message)


def sanitize(message: str) -> str:
    """Bound a message for persistence (never raw payloads / secrets)."""
    return " ".join(message.split())[:500]


class ReportNotFoundError(IncidentReportError):
    code = "REPORT_NOT_FOUND"
    message = "Report not found"


class ReportCorrelationNotFoundError(IncidentReportError):
    code = "CORRELATION_NOT_FOUND"
    message = "The correlation does not exist"

    def __init__(self, correlation_id) -> None:
        super().__init__(f"The correlation {correlation_id} does not exist")


class ReportValidationError(IncidentReportError):
    """The request, context, or model output failed validation."""

    code = "REPORT_INVALID"
    message = "Incident report is not valid"

    def __init__(self, reason: str) -> None:
        super().__init__(reason or "Incident report is not valid")


class ReportBoundError(ReportValidationError):
    """A documented report bound was exceeded; the report was refused."""

    code = "REPORT_BOUND_EXCEEDED"

    def __init__(self, reason: str) -> None:
        super().__init__(reason or "A report bound was exceeded")


class ReportContextError(IncidentReportError):
    """A source query failed while assembling the report context."""

    code = "REPORT_CONTEXT_UNAVAILABLE"
    message = "Report source data is unavailable"

    def __init__(self, reason: str) -> None:
        super().__init__(reason or "Report source data is unavailable")


class ReportSecretSafetyError(IncidentReportError):
    """Credential-shaped content was detected; the report failed closed."""

    code = "REPORT_SECRET_DETECTED"
    message = "No report generated: credential-shaped content was detected"


class ReportEvidenceError(IncidentReportError):
    """A model citation did not resolve to an existing catalog reference."""

    code = "REPORT_EVIDENCE_INVALID"
    message = "No report generated: an evidence reference did not resolve"

    def __init__(self, reason: str) -> None:
        super().__init__(reason or "An evidence reference did not resolve")


class ReportProviderError(IncidentReportError):
    """The AI provider call failed (sanitized)."""

    code = "REPORT_PROVIDER_UNAVAILABLE"
    message = "The report provider is unavailable"

    def __init__(self, reason: str) -> None:
        super().__init__(reason or "The report provider is unavailable")


class ReportUnexpectedError(IncidentReportError):
    """An unexpected internal defect (mapped to 500)."""

    code = "REPORT_INTERNAL"
    message = "Incident report failed internally"


__all__ = [
    "IncidentReportError",
    "sanitize",
    "ReportNotFoundError",
    "ReportCorrelationNotFoundError",
    "ReportValidationError",
    "ReportBoundError",
    "ReportContextError",
    "ReportSecretSafetyError",
    "ReportEvidenceError",
    "ReportProviderError",
    "ReportUnexpectedError",
]