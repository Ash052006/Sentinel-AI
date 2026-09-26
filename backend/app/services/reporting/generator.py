"""End-to-end incident report generation orchestration (V2.20).

``IncidentReportGenerator`` is the single, pure orchestration of one
generation:

    build context (read-only) -> build prompt (secret-scanned)
        -> call the report LLM -> strictly parse the model output
        -> resolve every evidence citation against the catalog
        -> assemble the authoritative IncidentReport (final secret scan)

It performs **no writes** and never touches execution/policy/approval/SOAR
paths — it only reads already-persisted records and produces the report
payload.  Persistence, audit and failed-row handling are owned by
:class:`~app.services.reporting.service.IncidentReportService`.

Failure semantics (all fail closed; nothing is silently repaired):

* context/bound failures -> ``ReportCorrelationNotFoundError`` /
  ``ReportBoundError`` / ``ReportContextError`` / ``ReportValidationError``;
* credential-shaped content -> ``ReportSecretSafetyError`` (never sent to or
  accepted from the provider);
* provider/transport failures -> ``ReportProviderError`` (sanitized);
* malformed / contract-violating model output -> ``ReportValidationError``;
* a citation that does not resolve to a catalog reference ->
  ``ReportEvidenceError`` (the whole output is rejected).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.agents.investigation._safety import assert_no_secrets
from app.agents.investigation.exceptions import (
    InvestigationConfigurationError,
    InvestigationModelOutputError,
    InvestigationProviderError,
    InvestigationSecretSafetyError,
)
from app.models.user import User
from app.schemas.incident_report import (
    REPORT_SCHEMA_VERSION,
    IncidentReport,
    IncidentReportAI,
)
from app.services.reporting.context import (
    ReportContextBuild,
    ReportContextBuilder,
)
from app.services.reporting.errors import (
    ReportEvidenceError,
    ReportProviderError,
    ReportSecretSafetyError,
    ReportValidationError,
    sanitize,
)
from app.services.reporting.llm import IncidentReportGeminiClient
from app.services.reporting.model_output import (
    IncidentReportModelOutput,
    parse_model_output,
)
from app.services.reporting.prompt import IncidentReportPrompt, ReportPromptBuilder

logger = logging.getLogger(__name__)


class IncidentReportGenerator:
    """Orchestrates one read-only, evidence-grounded report generation.

    Parameters:
        builder_factory: Optional factory ``(actor) -> ReportContextBuilder``;
            defaults to a builder with the actor set (so hunts read with the
            correct caller).  Tests inject fakes here.
        prompt_builder: Optional :class:`ReportPromptBuilder`; defaults to the
            deterministic builder.
        llm: Optional report LLM client; defaults to the configured Gemini
            client.  Tests inject a fake returning canned raw text.
        parse: Optional strict model-output parser; defaults to
            :func:`parse_model_output`.
        now: Optional ``() -> datetime`` clock for ``generated_at``.
        report_id_factory: Optional ``() -> uuid.UUID`` identity source.
    """

    def __init__(
        self,
        *,
        builder_factory: Callable[[User], ReportContextBuilder] | None = None,
        prompt_builder: ReportPromptBuilder | None = None,
        llm: IncidentReportGeminiClient | object | None = None,
        parse: Callable[[str], IncidentReportModelOutput] = parse_model_output,
        now: Callable[[], datetime] | None = None,
        report_id_factory: Callable[[], uuid.UUID] | None = None,
    ) -> None:
        self._builder_factory = builder_factory or (
            lambda actor: ReportContextBuilder(actor=actor)
        )
        self._prompt_builder = prompt_builder or ReportPromptBuilder()
        if llm is None:
            from app.services.reporting.llm import default_report_llm

            llm = default_report_llm()
        self._llm = llm
        self._parse = parse
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._report_id_factory = report_id_factory or uuid.uuid4

    @property
    def model_name(self) -> str:
        """Configured model identifier for the report payload (safe to log)."""
        name = getattr(self._llm, "model_name", None)
        return str(name) if name else "unknown"

    def generate(
        self,
        db: Session,
        *,
        actor: User,
        correlation_id: uuid.UUID,
    ) -> IncidentReport:
        """Generate and return one validated incident report (no writes).

        Raises:
            ReportCorrelationNotFoundError: the correlation does not exist.
            ReportBoundError / ReportContextError / ReportValidationError:
                context or model output violated a contract.
            ReportSecretSafetyError: credential-shaped content detected.
            ReportEvidenceError: a model citation is not in the catalog.
            ReportProviderError: the provider call failed (sanitized).
            ReportUnexpectedError: an unexpected internal defect.
        """
        builder = self._builder_factory(actor)
        built: ReportContextBuild = builder.build(db, correlation_id)

        try:
            prompt = self._build_prompt(built)
        except InvestigationSecretSafetyError as exc:
            raise ReportSecretSafetyError() from exc
        raw = self._call_llm(prompt)
        model_output = self._parse(raw)

        self._validate_citations(model_output, built)

        ai = self._assemble_ai(model_output)
        report = self._assemble_report(
            built, ai=ai, actor=actor, correlation_id=correlation_id
        )
        self._final_secret_scan(report)
        return report

    # ------------------------------------------------------------------
    # Pipeline steps
    # ------------------------------------------------------------------

    def _build_prompt(self, built: ReportContextBuild) -> IncidentReportPrompt:
        return self._prompt_builder.build(built.context)

    def _call_llm(self, prompt: IncidentReportPrompt) -> str:
        """Call the provider, translating its failures to report errors."""
        try:
            return self._llm.generate(prompt)
        except InvestigationSecretSafetyError as exc:
            raise ReportSecretSafetyError() from exc
        except InvestigationConfigurationError as exc:
            raise ReportProviderError(sanitize(str(exc))) from exc
        except InvestigationProviderError as exc:
            raise ReportProviderError(sanitize(str(exc))) from exc
        except InvestigationModelOutputError as exc:
            raise ReportValidationError(sanitize(str(exc))) from exc
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Report provider failure (unknown): %s", type(exc).__name__)
            raise ReportProviderError(
                "the report provider call failed"
            ) from exc

    @staticmethod
    def _validate_citations(
        model_output: IncidentReportModelOutput,
        built: ReportContextBuild,
    ) -> None:
        """Reject any evidence citation that does not resolve to a catalog id.

        The evidence catalog is the authoritative set of reference ids the
        model may cite; a dangling or fabricated id fails the whole output.
        """
        catalog_ids = {
            ref.reference_id for ref in built.context.evidence_catalog
        }
        for finding in model_output.findings:
            for ref_id in finding.evidence_references:
                if ref_id not in catalog_ids:
                    raise ReportEvidenceError(
                        "a finding cited evidence_reference "
                        f"{ref_id} that is not present in the evidence catalog"
                    )

    @staticmethod
    def _assemble_ai(model_output: IncidentReportModelOutput) -> IncidentReportAI:
        """Wrap the validated model output as the report's AI block."""
        return IncidentReportAI(**model_output.model_dump())

    def _assemble_report(
        self,
        built: ReportContextBuild,
        *,
        ai: IncidentReportAI,
        actor: User,
        correlation_id: uuid.UUID,
    ) -> IncidentReport:
        """Assemble the authoritative report from context + validated AI prose."""
        context = built.context
        role = actor.role.name if actor.role is not None else "unknown"
        return IncidentReport(
            schema_version=REPORT_SCHEMA_VERSION,
            report_id=self._report_id_factory(),
            correlation_id=correlation_id,
            generated_at=self._now(),
            generated_by=actor.id,
            generated_by_role=role,
            model=self.model_name,
            availability=context.availability,
            incident=context.incident,
            correlation=context.correlation,
            detections=context.detections,
            threat_intelligence=context.threat_intelligence,
            risk_assessment=context.risk_assessment,
            incident_memories=context.incident_memories,
            threat_hunts=context.threat_hunts,
            approvals=context.approvals,
            soar_executions=context.soar_executions,
            timeline=built.timeline,
            evidence_catalog=context.evidence_catalog,
            source_limitations=built.source_limitations,
            ai=ai,
        )

    @staticmethod
    def _final_secret_scan(report: IncidentReport) -> None:
        """Re-scan the assembled serialized report before anyone persists it."""
        try:
            assert_no_secrets(report.model_dump_json(), "incident report")
        except ValueError as exc:
            raise ReportSecretSafetyError() from exc


__all__ = ["IncidentReportGenerator"]