"""Step 12C — AI Investigation Agent.

Reasoning-only component: consumes a validated
:class:`~app.schemas.investigation_context.InvestigationContext` (12B),
constructs a deterministic prompt, sends it through a provider boundary
(``InvestigationLLMClient``; concrete ``GeminiClient``), strictly validates
the structured model output, resolves every evidence reference against the
supplied context, and produces a validated Step 12A ``InvestigationResult``.

The LLM is an investigator, never a source of security evidence.
"""

from app.agents.investigation.agent import InvestigationAgent
from app.agents.investigation.exceptions import (
    InvestigationAgentError,
    InvestigationConfigurationError,
    InvestigationContextError,
    InvestigationEvidenceError,
    InvestigationInternalError,
    InvestigationModelOutputError,
    InvestigationModelValidationError,
    InvestigationProviderError,
    InvestigationProviderTimeoutError,
    InvestigationProviderUnavailableError,
    InvestigationSecretSafetyError,
)
from app.agents.investigation.gemini import GeminiClient
from app.agents.investigation.llm_client import InvestigationLLMClient
from app.agents.investigation.model_output import (
    INVESTIGATION_MODEL_JSON_SCHEMA,
    MAX_MODEL_EVIDENCE_REFERENCES,
    MAX_MODEL_FINDINGS,
    MAX_MODEL_OBSERVATIONS,
    MAX_MODEL_OUTPUT_BYTES,
    MAX_MODEL_STRING_LENGTH,
    InvestigationModelOutput,
    ModelFindingOutput,
    ModelObservationOutput,
)
from app.agents.investigation.prompt import (
    CONTEXT_DATA_END,
    CONTEXT_DATA_START,
    SYSTEM_INSTRUCTIONS,
    InvestigationPrompt,
    InvestigationPromptBuilder,
)

__all__ = [
    "InvestigationAgent",
    "InvestigationAgentError",
    "InvestigationConfigurationError",
    "InvestigationContextError",
    "InvestigationEvidenceError",
    "InvestigationInternalError",
    "InvestigationModelOutputError",
    "InvestigationModelValidationError",
    "InvestigationProviderError",
    "InvestigationProviderTimeoutError",
    "InvestigationProviderUnavailableError",
    "InvestigationSecretSafetyError",
    "InvestigationLLMClient",
    "GeminiClient",
    "InvestigationPrompt",
    "InvestigationPromptBuilder",
    "SYSTEM_INSTRUCTIONS",
    "CONTEXT_DATA_START",
    "CONTEXT_DATA_END",
    "InvestigationModelOutput",
    "ModelFindingOutput",
    "ModelObservationOutput",
    "INVESTIGATION_MODEL_JSON_SCHEMA",
    "MAX_MODEL_FINDINGS",
    "MAX_MODEL_OBSERVATIONS",
    "MAX_MODEL_EVIDENCE_REFERENCES",
    "MAX_MODEL_STRING_LENGTH",
    "MAX_MODEL_OUTPUT_BYTES",
]