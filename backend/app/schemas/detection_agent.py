"""Detection Agent contract — Step 9E.

Defines the **unified output** of the Detection Agent, which orchestrates
the existing Sigma and YARA detection engines against a single
:class:`~app.schemas.normalized_event.NormalizedSecurityEvent`.

Design principles:

* **Contract only** — no detection logic, no engine execution, no
  database tables, no API endpoints.
* **Engine-agnostic results** — ``DetectionResult`` objects from both
  Sigma and YARA engines are collected without reinterpretation.
* **Unified failures** — ``DetectionFailure`` normalises the
  engine-specific ``SigmaRuleFailure`` / ``YaraRuleFailure`` objects
  into a single representation that carries an ``engine`` field.
* **Deterministic** — given the same event, rules, and engine state,
  the analysis produces the same ordered output.
* **Provenance-aware** — the analysis carries ``DETECTED`` provenance.
* **No fabrication** — no risk scores, no verdicts, no MITRE mapping.
* **No secrets** — the schema never stores credentials or API keys.

Relationship to the pipeline::

    NormalizedSecurityEvent
        -> DetectionAgent
            -> SigmaDetectionEngine / YaraDetectionEngine
                -> DetectionAnalysis (this module)
                    -> [future: correlation, risk, investigation]
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.schemas.detection import DetectionResult
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Unified failure
# ---------------------------------------------------------------------------


class DetectionFailure(BaseModel):
    """Engine-agnostic representation of a rule-level or engine-level failure.

    Both ``SigmaRuleFailure`` and ``YaraRuleFailure`` carry the same logical
    fields (``rule_id``, ``error_type``, ``message``).  This model adds an
    ``engine`` discriminator so that downstream consumers can determine the
    source engine without relying on exception class identity.

    Attributes:
        engine: Which detection engine produced this failure (``"sigma"``
            or ``"yara"``).
        rule_id: The ``rule_id`` of the rule that failed, or a sentinel
            value (e.g. ``"<event>"``) for engine-level failures.
        error_type: Machine-readable failure category, e.g.
            ``"malformed_rule"``, ``"unsupported_feature"``,
            ``"invalid_target"``, ``"internal_error"``.
        message: Human-readable description.  Must never contain secrets,
            credentials, or raw event payloads.
    """

    engine: str = Field(
        ...,
        min_length=1,
        description='Detection engine that produced this failure ("sigma" or "yara").',
    )
    rule_id: str = Field(
        ...,
        min_length=1,
        description="Rule ID that failed, or a sentinel for engine-level failures.",
    )
    error_type: str = Field(
        ...,
        min_length=1,
        description="Machine-readable failure category.",
    )
    message: str = Field(
        ...,
        description="Human-readable failure description.  Must not contain secrets.",
    )

    @field_validator("message")
    @classmethod
    def _ensure_no_secrets(cls, v: str) -> str:
        """Reject messages containing common secret patterns."""
        lowered = v.lower()
        forbidden = ("api_key", "authorization", "bearer", "secret")
        for pattern in forbidden:
            if pattern in lowered:
                raise ValueError(
                    f"failure message must not contain secrets ('{pattern}' detected)"
                )
        return v


# ---------------------------------------------------------------------------
# Analysis metadata
# ---------------------------------------------------------------------------


class DetectionAnalysisMetadata(BaseModel):
    """Aggregate metadata about a unified detection analysis.

    All fields are deterministically derivable from the engine outputs.
    No risk scores, severity aggregation, or threat verdicts are
    included — those belong to later SentinelAI phases.
    """

    engines_executed: int = Field(
        ...,
        ge=0,
        description="Number of detection engines that were executed.",
    )
    sigma_rules_evaluated: int = Field(
        default=0,
        ge=0,
        description="Number of Sigma rules evaluated.",
    )
    sigma_rules_ignored: int = Field(
        default=0,
        ge=0,
        description="Number of Sigma rules ignored (e.g. disabled).",
    )
    yara_rules_evaluated: int = Field(
        default=0,
        ge=0,
        description="Number of YARA rules evaluated.",
    )
    yara_rules_ignored: int = Field(
        default=0,
        ge=0,
        description="Number of YARA rules ignored (e.g. disabled).",
    )
    total_results: int = Field(
        default=0,
        ge=0,
        description="Total detection results (matches) across all engines.",
    )
    sigma_results: int = Field(
        default=0,
        ge=0,
        description="Number of Sigma detection results (matches).",
    )
    yara_results: int = Field(
        default=0,
        ge=0,
        description="Number of YARA detection results (matches).",
    )
    total_failures: int = Field(
        default=0,
        ge=0,
        description="Total failures across all engines.",
    )
    sigma_failures: int = Field(
        default=0,
        ge=0,
        description="Number of Sigma failures.",
    )
    yara_failures: int = Field(
        default=0,
        ge=0,
        description="Number of YARA failures.",
    )
    execution_time_ms: float | None = Field(
        default=None,
        ge=0.0,
        description="Wall-clock time of the full detection analysis in milliseconds.",
    )


# ---------------------------------------------------------------------------
# Unified analysis
# ---------------------------------------------------------------------------


class DetectionAnalysis(BaseModel):
    """Unified detection analysis produced by the Detection Agent.

    Aggregates all ``DetectionResult`` objects (matches) and
    ``DetectionFailure`` objects (failures) from the Sigma and YARA
    engines into a single, engine-agnostic report.

    The analysis preserves full traceability:

    * Every ``DetectionResult`` retains its original ``detection_id``,
      ``event_id``, ``rule_id``, ``severity``, ``confidence``,
      ``evidence``, ``metadata``, and ``provenance``.
    * Every ``DetectionFailure`` identifies the originating engine.
    * ``DetectionResult`` objects already carry engine identification
      in their ``evidence.detection_context`` or ``metadata.extra``
      dictionaries — the agent does not overwrite this information.

    The analysis is **immutable by convention**: consumers must not
    modify the result lists or metadata after creation.

    Attributes:
        event_id: UUID of the evaluated event.  Preserved from the
            input ``NormalizedSecurityEvent`` — never regenerated.
        results: All detection matches from both engines, in engine
            order (Sigma first, then YARA) with deterministic ordering
            within each engine (by ``rule_id``).
        failures: All rule-level and engine-level failures from both
            engines, in engine order with deterministic ordering.
        metadata: Aggregate counts and timing information.
        timestamp: Timezone-aware timestamp of when the analysis was
            performed.
        provenance: Always ``DETECTED`` — a detection analysis is a
            derived analytical conclusion.
    """

    event_id: uuid.UUID = Field(
        ...,
        description=(
            "UUID of the evaluated event.  Preserved from the input "
            "NormalizedSecurityEvent — never regenerated."
        ),
    )
    results: list[DetectionResult] = Field(
        default_factory=list,
        description=(
            "All detection matches from both engines.  Engine order: "
            "Sigma results first, then YARA results.  Within each "
            "engine, results follow the deterministic rule ordering."
        ),
    )
    failures: list[DetectionFailure] = Field(
        default_factory=list,
        description=(
            "All rule-level and engine-level failures from both engines.  "
            "Engine order: Sigma failures first, then YARA failures."
        ),
    )
    metadata: DetectionAnalysisMetadata = Field(
        default_factory=lambda: DetectionAnalysisMetadata(
            engines_executed=0,
        ),
        description="Aggregate metadata about the detection analysis.",
    )
    timestamp: datetime = Field(
        ...,
        description="Timezone-aware timestamp of when the analysis was performed.",
    )
    provenance: Provenance = Field(
        default=Provenance.DETECTED,
        description=(
            "Provenance marker.  Detection analyses are derived analytical "
            "conclusions and default to DETECTED."
        ),
    )

    # -- Validators ----------------------------------------------------------

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        """Reject naive (timezone-unaware) timestamps."""
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "timestamp must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v

    @field_validator("results")
    @classmethod
    def _ensure_results_match_true(
        cls, v: list[DetectionResult]
    ) -> list[DetectionResult]:
        """Every result in the unified analysis should be a match.

        Non-matching evaluations that complete successfully produce no
        result object (the engines only emit results for matches).
        """
        for result in v:
            if not result.matched:
                raise ValueError(
                    f"DetectionResult for rule '{result.rule_id}' has "
                    "matched=False; only matched results belong in the "
                    "unified analysis"
                )
        return v
