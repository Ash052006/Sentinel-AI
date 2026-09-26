"""V2.20 AI Incident Report Generator — service package.

The public faces of the feature:

* ``context`` — read-only, bounded, deterministic context + timeline builder.
* ``prompt`` — deterministic prompt construction over the validated context.
* ``llm`` — Gemini structured-output provider for the report writer.
* ``model_output`` — strict model-output contract + parser.
* ``generator`` — end-to-end orchestration (build -> prompt -> LLM -> parse
  -> cite-check -> assemble).
* ``service`` — persistence/audit facade the transport calls.

``errors`` is the closed incident-report error hierarchy; every terminal
failure is a documented error code persisted on the failed report row.
"""

from app.services.reporting.context import (
    ReportContextBuild,
    ReportContextBuilder,
    ReportQuerySources,
    derive_source_limitations,
)
from app.services.reporting.errors import (
    IncidentReportError,
    ReportBoundError,
    ReportContextError,
    ReportCorrelationNotFoundError,
    ReportEvidenceError,
    ReportNotFoundError,
    ReportProviderError,
    ReportSecretSafetyError,
    ReportUnexpectedError,
    ReportValidationError,
    sanitize,
)
from app.services.reporting.generator import IncidentReportGenerator
from app.services.reporting.llm import (
    IncidentReportGeminiClient,
    default_report_llm,
)
from app.services.reporting.model_output import (
    INCIDENT_REPORT_MODEL_JSON_SCHEMA,
    IncidentReportModelOutput,
    parse_model_output,
)
from app.services.reporting.prompt import (
    IncidentReportPrompt,
    ReportPromptBuilder,
)
from app.services.reporting.service import IncidentReportService

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
    "ReportContextBuild",
    "ReportContextBuilder",
    "ReportQuerySources",
    "derive_source_limitations",
    "INCIDENT_REPORT_MODEL_JSON_SCHEMA",
    "IncidentReportModelOutput",
    "parse_model_output",
    "IncidentReportPrompt",
    "ReportPromptBuilder",
    "IncidentReportGeminiClient",
    "default_report_llm",
    "IncidentReportGenerator",
    "IncidentReportService",
]