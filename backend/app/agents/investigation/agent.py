"""The Step 12C AI Investigation Agent.

``InvestigationAgent`` orchestrates::

    InvestigationAgent
        |  build deterministic prompt
        v
    InvestigationPromptBuilder
        |  send prompt (raw text back)
        v
    InvestigationLLMClient (concrete: GeminiClient)
        |  strict JSON parse
        v
    InvestigationModelOutput (bounded contract)
        |  evidence-reference resolution against the supplied context
        v
    InvestigationResult (Step 12A contract)

The agent is a **reasoning-only** component:

* It consumes only a validated :class:`InvestigationContext` (12B); it
  never queries databases, message buses, vector stores, graph stores,
  threat-intelligence providers, the filesystem, or external websites.
* The LLM is an investigator, NOT a source of security evidence.  Every
  ``InvestigationEvidence`` on the result originates from the supplied
  context (copied verbatim, with its original provenance); the model may
  only *reference* existing ``evidence_id`` values.
* The agent owns the authoritative fields: the result ``investigation_id``
  (injectable factory), the final ``timestamp`` (injectable clock), the
  pinned ``AI_GENERATED`` provenance, and every evidence record.
* Result and findings are pinned ``AI_GENERATED`` by the Step 12A
  contract; AI-generated observations are explicitly labelled
  ``AI_GENERATED`` (never observed).
* It never persists anything, never exposes an API, never performs
  response/mitigation, never creates incidents, never edits
  detection/correlation/risk data, and never invokes external security
  tools.
* No side effects beyond the configured provider request.

Fail-closed rules: malformed model output is rejected, never repaired;
invalid output-contract payloads are rejected, never truncated; dangling or
fabricated evidence references reject the **entire** output; credential-
shaped content anywhere fails closed; an investigation failure never becomes
an empty result unless the model explicitly returned a valid empty output.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from pydantic import ValidationError

from app.agents.investigation._safety import assert_no_secrets
from app.agents.investigation.exceptions import (
    InvestigationAgentError,
    InvestigationContextError,
    InvestigationEvidenceError,
    InvestigationInternalError,
    InvestigationModelOutputError,
    InvestigationModelValidationError,
    InvestigationSecretSafetyError,
)
from app.agents.investigation.gemini import GeminiClient
from app.agents.investigation.llm_client import InvestigationLLMClient
from app.agents.investigation.model_output import (
    MAX_MODEL_OUTPUT_BYTES,
    InvestigationModelOutput,
)
from app.agents.investigation.prompt import (
    InvestigationPromptBuilder,
)
from app.schemas.investigation import (
    InvestigationFinding,
    InvestigationObservation,
    InvestigationResult,
)
from app.schemas.investigation_context import InvestigationContext
from app.schemas.knowledge_context import InvestigationKnowledgeContext
from app.schemas.security_event import Provenance

logger = logging.getLogger(__name__)

_AGENT_PROVIDER_KEY = "provider"
_AGENT_MODEL_KEY = "model"


def _default_timestamp() -> datetime:
    return datetime.now(timezone.utc)


class InvestigationAgent:
    """Reasoning-only agent that turns a context into a validated result."""

    agent_name = "sentinelai.investigation_agent"

    def __init__(
        self,
        *,
        llm_client: InvestigationLLMClient | None = None,
        prompt_builder: InvestigationPromptBuilder | None = None,
        investigation_id_factory: Callable[[], uuid.UUID] | None = None,
        result_timestamp_factory: Callable[[], datetime] | None = None,
    ) -> None:
        self._llm_client: InvestigationLLMClient = (
            llm_client if llm_client is not None else GeminiClient()
        )
        if not isinstance(self._llm_client, InvestigationLLMClient):
            raise TypeError(
                "llm_client must implement InvestigationLLMClient; "
                f"received {type(self._llm_client).__name__}"
            )

        self._prompt_builder: InvestigationPromptBuilder = (
            prompt_builder
            if prompt_builder is not None
            else InvestigationPromptBuilder()
        )
        if not hasattr(self._prompt_builder, "build"):
            raise TypeError(
                "prompt_builder must provide a build(context) method; "
                f"received {type(self._prompt_builder).__name__}"
            )

        self._investigation_id_factory: Callable[[], uuid.UUID] = (
            investigation_id_factory
            if investigation_id_factory is not None
            else uuid.uuid4
        )
        if not callable(self._investigation_id_factory):
            raise TypeError("investigation_id_factory must be callable")

        self._result_timestamp_factory: Callable[[], datetime] = (
            result_timestamp_factory
            if result_timestamp_factory is not None
            else _default_timestamp
        )
        if not callable(self._result_timestamp_factory):
            raise TypeError("result_timestamp_factory must be callable")

    @property
    def provider_name(self) -> str:
        return self._llm_client.provider_name

    # -- Public entry point ---------------------------------------------------

    def investigate(
        self,
        context: InvestigationContext,
        knowledge_context: InvestigationKnowledgeContext | None = None,
    ) -> InvestigationResult:
        """Run one investigation over :class:`InvestigationContext`.

        Args:
            context: The validated 12B investigation context.
            knowledge_context: Optional retrieved security knowledge (Step
                13).  It is supplied to the model strictly as background
                reference material; the result never treats it as evidence.

        Raises:
            InvestigationContextError: input is not an InvestigationContext,
                or knowledge_context is not an InvestigationKnowledgeContext.
            InvestigationSecretSafetyError: unsafe context or model output.
            InvestigationProviderError / subclasses: provider failures.
            InvestigationModelOutputError: malformed (non-JSON) output.
            InvestigationModelValidationError: valid JSON failing the
                output contract.
            InvestigationEvidenceError: dangling/fabricated evidence refs.
            InvestigationInternalError: unexpected internal failure.
        """
        if not isinstance(context, InvestigationContext):
            raise InvestigationContextError(
                "an investigation requires a validated InvestigationContext "
                "input; received "
                f"{type(context).__name__}"
            )
        if knowledge_context is not None and not isinstance(
            knowledge_context, InvestigationKnowledgeContext
        ):
            raise InvestigationContextError(
                "retrieved knowledge must be an "
                "InvestigationKnowledgeContext; received "
                f"{type(knowledge_context).__name__}"
            )

        correlation_id = context.correlation.correlation_id
        logger.info(
            "%s.starting investigation for correlation %s via provider=%s "
            "(retrieved knowledge items=%d)",
            self.agent_name,
            correlation_id,
            self.provider_name,
            (
                len(knowledge_context.items)
                if knowledge_context is not None
                else 0
            ),
        )

        prompt = self._prompt_builder.build(context, knowledge_context)

        start = time.monotonic()
        raw_text = self._invoke_provider(prompt)
        duration = time.monotonic() - start

        parsed = self._parse_strict(raw_text)
        output = self._validate_output(parsed)
        self._assert_output_secret_free(output)

        evidence_ids = {item.evidence_id for item in context.evidence}
        self._validate_evidence_references(output, evidence_ids)

        result = self._build_result(context, output)
        logger.info(
            "%s.completed investigation for correlation %s in %.3fs "
            "(%d findings, %d observations)",
            self.agent_name,
            correlation_id,
            duration,
            len(result.findings),
            len(result.observations),
        )
        return result

    # -- Steps ----------------------------------------------------------------

    def _invoke_provider(self, prompt: Any) -> str:
        try:
            return self._llm_client.generate(prompt)
        except InvestigationAgentError:
            raise
        except Exception as exc:  # pragma: no cover - defensive boundary
            raise InvestigationInternalError(
                "unexpected provider failure while contacting the "
                "investigation LLM"
            ) from exc

    @staticmethod
    def _parse_strict(raw_text: str) -> dict[str, Any]:
        """Strict JSON parse: no fences, no prose, no multiple objects.

        Malformed output is rejected, never "repaired".
        """
        text = raw_text.strip()
        if not text:
            raise InvestigationModelOutputError(
                "model output is empty; the output is rejected "
                "rather than treated as an investigation"
            )
        if len(text.encode("utf-8")) > MAX_MODEL_OUTPUT_BYTES:
            raise InvestigationModelOutputError(
                f"model output exceeds MAX_MODEL_OUTPUT_BYTES="
                f"{MAX_MODEL_OUTPUT_BYTES}; the output is rejected "
                "rather than truncated"
            )
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InvestigationModelOutputError(
                "model output is not strict JSON (fenced, prose-wrapped, "
                "or malformed output is never accepted): "
                f"{exc.msg}"
            ) from exc
        if not isinstance(parsed, dict):
            raise InvestigationModelOutputError(
                "model output must be a single JSON object; "
                f"received {type(parsed).__name__}"
            )
        return parsed

    @staticmethod
    def _validate_output(parsed: dict[str, Any]) -> InvestigationModelOutput:
        try:
            return InvestigationModelOutput.model_validate(parsed)
        except ValidationError as exc:
            raise InvestigationModelValidationError(
                f"model output failed the output contract "
                f"({len(exc.errors())} issue(s)); the output is rejected "
                "rather than truncated"
            ) from exc

    @staticmethod
    def _assert_output_secret_free(
        output: InvestigationModelOutput,
    ) -> None:
        try:
            assert_no_secrets(output.model_dump_json(), "model output")
        except ValueError as exc:
            raise InvestigationSecretSafetyError(
                "refusing to accept model output that contains "
                "credential-shaped content"
            ) from exc

    @staticmethod
    def _validate_evidence_references(
        output: InvestigationModelOutput,
        evidence_ids: set[uuid.UUID],
    ) -> None:
        for finding in output.findings:
            for reference in finding.evidence_ids:
                if reference not in evidence_ids:
                    raise InvestigationEvidenceError(
                        f"finding references evidence_id {reference} which "
                        "does not exist in the supplied InvestigationContext; "
                        "the entire model output is rejected"
                    )

    def _build_result(
        self,
        context: InvestigationContext,
        output: InvestigationModelOutput,
    ) -> InvestigationResult:
        timestamp = self._result_timestamp_factory()
        if timestamp.tzinfo is None or timestamp.tzinfo.utcoffset(timestamp) is None:
            raise InvestigationInternalError(
                "the result timestamp factory returned a naive (timezone-"
                "unaware) timestamp"
            )

        findings = [
            InvestigationFinding(
                finding_type=finding.finding_type,
                title=finding.title,
                summary=finding.summary,
                confidence=finding.confidence,
                evidence_ids=list(finding.evidence_ids),
            )
            for finding in output.findings
        ]
        observations = [
            InvestigationObservation(
                observation_type=obs.observation_type,
                observation_text=obs.observation_text,
                provenance=Provenance.AI_GENERATED,
            )
            for obs in output.observations
        ]

        metadata: dict[str, Any] = {_AGENT_PROVIDER_KEY: self.provider_name}
        model_name = self._llm_client.model_name
        if model_name:
            metadata[_AGENT_MODEL_KEY] = model_name

        try:
            return InvestigationResult(
                investigation_id=self._investigation_id_factory(),
                correlation_id=context.correlation.correlation_id,
                risk_assessment_id=(
                    context.risk_assessment.risk_assessment_id
                    if context.risk_assessment is not None
                    else None
                ),
                findings=findings,
                evidence=[
                    item.model_copy(deep=True) for item in context.evidence
                ],
                observations=observations,
                metadata=metadata,
                timestamp=timestamp,
            )
        except ValidationError as exc:
            raise InvestigationInternalError(
                "the investigation agent produced an invalid domain result"
            ) from exc