"""Threat Attribution Engine — Step 15.

``ThreatAttributionEngine`` is the deterministic, evidence-grounded entry
point that consumes the Step 14 contract and produces validated
:class:`~app.schemas.threat_attribution.AttributionAssessment` objects
through a pluggable, dependency-light strategy pipeline.

Responsibilities:

* **Input validation** — rejects inputs that are not the documented
  :class:`~app.services.threat_attribution.input.ThreatAttributionInput`
  contract, plus any input that would exceed the engine-level bounds
  (oversized claims, oversized prepared evidence metadata).
* **Secret safety, fail-closed** — the whole input is serialized and
  scanned for secrets.  Any match raises :class:`AttributionSafetyError`;
  nothing dangerous is ever redacted or emitted.
* **Dependency-light orchestration** — a single strategy (default:
  :class:`~app.services.threat_attribution.policy.DeterministicAttributionStrategy`)
  computes the assessment; the engine never calls an LLM, never queries RAG,
  never hits a database, an API, or any external service; it only consults
  the structured claims in the input.
* **Determinism** — the timestamp (default ``datetime.now(timezone.utc)``,
  matching the ``CorrelationAgent`` convention) and the UUID factory
  (default ``uuid.uuid4``) are injectable, so identical inputs and injected
  sources produce byte-identical outputs.
* **Output re-validation (fail-closed)** — the strategy result must be an
  :class:`AttributionAssessment` and is re-validated through the Step 14
  contract's ``model_validate``.  A malformed output raises
  :class:`AttributionOutputValidationError`.
* **Clean error taxonomy** — distinct exception types for invalid input,
  unsupported signals, safety violations, strategy failure, output
  validation failure, and evidence-reference failure.  Messages are
  sanitized and never expose raw input, targets, secrets, or stacks.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Callable

from app.schemas.threat_attribution import (
    AttributionAssessment,
    AttributionTargetType,
    MAX_ATTRIBUTION_HYPOTHESES,
    MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES,
)
from app.services.threat_attribution.exceptions import (
    AttributionEvidenceReferenceError,
    AttributionOutputValidationError,
    AttributionSafetyError,
    AttributionStrategyError,
    InvalidAttributionInputError,
    UnsupportedAttributionSignalError,
)
from app.services.threat_attribution.input import (
    AttributionRelation,
    ThreatAttributionInput,
)
from app.services.threat_attribution.policy import (
    AttributionStrategy,
    DeterministicAttributionStrategy,
)

# Secret markers scanned against payloads (mirrors the SentinelAI pattern;
# false positives reject harder, never leak).
_SENSITIVE_KEYS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "credential_value",
    "secret_value",
)

_SECRET_VALUE_PATTERNS: tuple[str, ...] = (
    "AKIA[0-9A-Z]{16}",
    "ASIA[0-9A-Z]{16}",
    "ghp_[0-9A-Za-z]{36}",
    "gho_[0-9A-Za-z]{36}",
    "sk-[0-9A-Za-z]{20,}",
    "AIza[0-9A-Za-z_\\-]{35}",
    "xox[baprs]-[0-9A-Za-z-]{10,}",
    "[A-Za-z0-9_\\-]{32,}:\\S+",
)


class ThreatAttributionEngine:
    """Deterministic, evidence-grounded threat attribution orchestrator."""

    def __init__(self, strategy: AttributionStrategy | None = None) -> None:
        if strategy is not None and not callable(getattr(strategy, "assess", None)):
            raise TypeError(
                "ThreatAttributionEngine requires a strategy exposing a "
                "callable 'assess(input_data, *, timestamp, uuid_factory)'"
            )
        self._strategy: AttributionStrategy = (
            strategy if strategy is not None else DeterministicAttributionStrategy()
        )

    @property
    def strategy(self) -> AttributionStrategy:
        """The strategy in use (read-only accessor)."""
        return self._strategy

    def assess(
        self,
        input_data: ThreatAttributionInput,
        *,
        clock: datetime | None = None,
        uuid_factory: Callable[[], uuid.UUID] | None = None,
    ) -> AttributionAssessment:
        """Assemble a validated attribution assessment for *input_data*.

        Args:
            input_data: The explicit structured attribution input contract.
            clock: Timestamp to stamp the assessment; defaults to
                ``datetime.now(timezone.utc)`` (matching the
                ``CorrelationAgent`` convention).  Must be timezone-aware.
            uuid_factory: Callable returning a fresh UUID for every
                identifier; defaults to ``uuid.uuid4``.

        Returns:
            A valid Step 14 :class:`AttributionAssessment`.

        Raises:
            InvalidAttributionInputError: Input is not the documented
                contract, is oversized, or the supplied clock is naive.
            UnsupportedAttributionSignalError: Input declares a claim
                targeting the unsupported ``unknown`` category.
            AttributionSafetyError: Any secret material is present anywhere
                in the input.
            AttributionEvidenceReferenceError: The strategy produced
                evidence/reference inconsistencies.
            AttributionStrategyError: The strategy itself failed.
            AttributionOutputValidationError: The strategy result is not a
                valid :class:`AttributionAssessment`.
        """
        self._validate_input(input_data)
        self._assert_no_secrets(input_data)

        now = clock if clock is not None else datetime.now(timezone.utc)
        if not isinstance(now, datetime):
            raise InvalidAttributionInputError(
                "attribution clock must be a datetime; "
                f"received {type(now).__module__}.{type(now).__qualname__}"
            )
        if now.tzinfo is None or now.utcoffset() is None:
            raise InvalidAttributionInputError(
                "attribution clock must be timezone-aware"
            )
        ids = uuid_factory if uuid_factory is not None else uuid.uuid4

        try:
            assessment = self._strategy.assess(
                input_data,
                timestamp=now,
                uuid_factory=ids,
            )
        except InvalidAttributionInputError:
            raise
        except UnsupportedAttributionSignalError:
            raise
        except AttributionEvidenceReferenceError:
            raise
        except AttributionSafetyError:
            raise
        except Exception as exc:
            raise AttributionStrategyError(
                "the attribution strategy failed; the engine refuses to "
                "fall back to fabricated output"
            ) from exc

        if not isinstance(assessment, AttributionAssessment):
            raise AttributionOutputValidationError(
                "the attribution strategy returned a result that is not an "
                "AttributionAssessment"
            )

        try:
            revalidated = AttributionAssessment.model_validate_json(
                assessment.model_dump_json()
            )
        except Exception as exc:
            raise AttributionOutputValidationError(
                "the attribution strategy returned an assessment that fails "
                "Step 14 contract validation"
            ) from exc

        return revalidated

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    def _validate_input(self, input_data: object) -> None:
        if not isinstance(input_data, ThreatAttributionInput):
            raise InvalidAttributionInputError(
                "attribution engine requires a ThreatAttributionInput; "
                "received "
                f"{type(input_data).__module__}.{type(input_data).__qualname__}"
            )

        for claim in input_data.claims:
            merged_metadata = dict(claim.metadata)
            merged_metadata["claim_id"] = str(claim.claim_id)
            if (
                len(json.dumps(merged_metadata))
                > MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES
            ):
                raise InvalidAttributionInputError(
                    "claim evidence metadata exceeds the Step 14 serialized "
                    "size bound of "
                    f"{MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES} bytes"
                )

        for claim in input_data.claims:
            for reference_name in (
                "event_id",
                "detection_id",
                "correlation_id",
                "risk_assessment_id",
                "investigation_id",
            ):
                value = getattr(claim, reference_name)
                if value is not None and not isinstance(value, uuid.UUID):
                    raise InvalidAttributionInputError(
                        f"claim {reference_name} must reference a UUID"
                    )

        supported_candidates = {
            (claim.target_type.value, claim.target_identifier)
            for claim in input_data.claims
            if claim.target_type is not AttributionTargetType.UNKNOWN
            and claim.relationship is AttributionRelation.SUPPORTS
        }
        if len(supported_candidates) > MAX_ATTRIBUTION_HYPOTHESES:
            raise InvalidAttributionInputError(
                "attribution input declares more distinct supported targets "
                f"than the Step 14 hypothesis bound of "
                f"{MAX_ATTRIBUTION_HYPOTHESES}"
            )

    # ------------------------------------------------------------------
    # Secret scan — fail-closed
    # ------------------------------------------------------------------

    def _assert_no_secrets(self, input_data: ThreatAttributionInput) -> None:
        """Serialise the whole input and scan for secrets.

        Scan payloads exactly as the rest of SentinelAI does: any sensitive
        key *or* secret-value pattern rejects the entire input with
        :class:`AttributionSafetyError`.  The engine never redacts, never
        emits a partial result, and never provides a way to continue with a
        sanitized copy.
        """
        for claim in input_data.claims:
            payload = json.dumps(
                {
                    "target_identifier": claim.target_identifier,
                    "evidence_type": claim.evidence_type,
                    "metadata": claim.metadata,
                    "claim_id": str(claim.claim_id),
                }
            )
            if _matches_secret_pattern(payload):
                raise AttributionSafetyError(
                    "attribution input contains secret material; refusal"
                )
            for key in claim.metadata:
                low = str(key).lower()
                if any(marker in low for marker in _SENSITIVE_KEYS):
                    raise AttributionSafetyError(
                        "attribution input metadata contains a sensitive "
                        "key; refusal"
                    )

        if input_data.context is not None and _matches_secret_pattern(
            json.dumps(input_data.context.model_dump(mode="json"))
        ):
            raise AttributionSafetyError(
                "attribution context contains secret material; refusal"
            )


def _matches_secret_pattern(payload: str) -> bool:
    lowered = payload.lower()
    if any(marker in lowered for marker in _SENSITIVE_KEYS):
        return True
    for pattern in _SECRET_VALUE_PATTERNS:
        if re.search(pattern, payload):
            return True
    return False