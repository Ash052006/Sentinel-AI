"""Detection Contract — Step 9A.

Defines the validated internal schema for **detection** results in
SentinelAI.  Detection evaluates structured rules (Sigma, YARA) against
enriched security events and produces deterministic, auditable results.

Design principles:

* **Contract only** — no rule execution, no Sigma/YARA engine
  invocation, no database tables, no API endpoints, no orchestration.
* **Structured evidence** — every match produces machine-readable
  evidence (matched fields, matched values, detection context) rather
  than free-form human text.  No LLM is required or assumed.
* **Deterministic** — given the same event and rule, the detection
  evaluation must produce the same structured evidence every time.
* **Provenance-aware** — detection results carry ``DETECTED``
  provenance, distinguishing them from observed, enriched, or
  reconstructed information.  A detection result is an analytical
  conclusion, not a direct observation.
* **No fabrication** — this module defines *how* detection results are
  represented, not *how* rules are executed.  Sigma and YARA engines
  are separate future steps.
* **No verdicts** — severity and confidence are properties of the
  detection result, not aggregated risk scores.  Correlation,
  risk scoring, and investigation are explicit future steps.
* **Extensible** — new rule types, evidence structures, and metadata
  fields can be added without breaking the contract.
* **No secrets** — the schema must never require or store credentials,
  API keys, authorization headers, or arbitrary code execution fields.

Relationship to the pipeline::

    SecurityEvent
        → NormalizedSecurityEvent
            → EnrichedSecurityEvent
                → ThreatIntelligenceAnalysis  (Step 8)
                → DetectionResult             (Step 9A — this module)

A DetectionResult references its source event by ``event_id`` and
identifies the rule that was evaluated by ``rule_id``.  The rule
definition (:class:`DetectionRule`) is a separate schema that describes
what should be evaluated; it does not carry results.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RuleType(str, Enum):
    """Detection rule engine type.

    Each value corresponds to a supported detection rule language.
    New rule engines can be added here in later versions without
    breaking the contract.
    """

    SIGMA = "sigma"
    YARA = "yara"


class DetectionSeverity(str, Enum):
    """Severity assigned by a detection rule.

    Severity reflects the *rule author's* assessment of the finding's
    potential impact.  It is independent of confidence (how sure the
    engine is that the rule matched) and of any downstream risk score.

    Values intentionally mirror common SIEM/SOAR conventions.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Structured Evidence
# ---------------------------------------------------------------------------


class DetectionEvidence(BaseModel):
    """Machine-readable evidence produced by a detection evaluation.

    Evidence is **structured** data — it never requires an LLM or
    free-form explanation.  Fields are designed to accommodate both
    Sigma and YARA match semantics without over-restricting either
    engine:

    * ``matched_conditions`` — the rule conditions that evaluated to
      true (e.g. Sigma detection IDs, YARA rule names or strings).
    * ``matched_fields`` — field to value mappings extracted from the
      event that contributed to the match (e.g.
      ``{"CommandLine": "powershell -enc ...", "User": "admin"}``).
    * ``rule_references`` — supplementary rule information such as
      Sigma logsource mappings or YARA meta references (e.g.
      ``{"attack": "T1059.001", "cve": "CVE-2023-1234"}``).
    * ``detection_context`` — additional engine-specific context
      that does not fit the above categories.  Must be
      JSON-serializable and must never contain secrets.

    The schema is intentionally permissive for future engine
    compatibility.  Downstream consumers should check for the
    presence of specific keys rather than requiring all keys.
    """

    matched_conditions: list[str] = Field(
        default_factory=list,
        description=(
            "Rule conditions that evaluated to true, e.g. Sigma detection "
            "IDs ('detection_id_1'), YARA rule names ('APT_backdoor')."
        ),
    )
    matched_fields: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Field to value mappings from the event that contributed to "
            "the match, e.g. {'CommandLine': 'powershell -enc ...'}."
        ),
    )
    rule_references: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Supplementary rule references (e.g. MITRE ATT&CK IDs, CVEs, "
            "Sigma logsource categories).  Not required by all engines."
        ),
    )
    detection_context: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Engine-specific context that does not fit the above fields. "
            "Must be JSON-serializable and must never contain secrets."
        ),
    )

    # -- Validators ----------------------------------------------------------

    @field_validator("matched_fields")
    @classmethod
    def _ensure_matched_fields_json_compatible(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        """Ensure matched_fields is strictly JSON-serializable."""
        try:
            json.dumps(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"matched_fields must be JSON-compatible: {exc}"
            ) from exc
        return v

    @field_validator("rule_references")
    @classmethod
    def _ensure_rule_references_json_compatible(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        """Ensure rule_references is strictly JSON-serializable."""
        try:
            json.dumps(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"rule_references must be JSON-compatible: {exc}"
            ) from exc
        return v

    @field_validator("detection_context")
    @classmethod
    def _ensure_detection_context_json_compatible(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        """Ensure detection_context is strictly JSON-serializable."""
        try:
            json.dumps(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"detection_context must be JSON-compatible: {exc}"
            ) from exc
        return v


# ---------------------------------------------------------------------------
# Detection Metadata
# ---------------------------------------------------------------------------


class DetectionMetadata(BaseModel):
    """Flexible metadata about a detection evaluation.

    Carries operational information about *how* the evaluation was
    performed without encoding domain-specific verdicts.  New fields
    can be added in later versions without breaking the contract.
    """

    rule_version: str | None = Field(
        default=None,
        description="Version of the rule that was evaluated.",
    )
    engine_version: str | None = Field(
        default=None,
        description="Version of the detection engine used.",
    )
    execution_time_ms: float | None = Field(
        default=None,
        description="Wall-clock time of the detection evaluation in milliseconds.",
    )
    total_rules_evaluated: int | None = Field(
        default=None,
        description="Total number of rules evaluated against the event.",
    )
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Open-ended structured metadata.  Must be JSON-serializable "
            "and must never contain secrets, API keys, or credentials."
        ),
    )

    # -- Validators ----------------------------------------------------------

    @field_validator("execution_time_ms")
    @classmethod
    def _ensure_non_negative(cls, v: float | None) -> float | None:
        """Execution time must be non-negative when provided."""
        if v is not None and v < 0:
            raise ValueError("execution_time_ms must be non-negative")
        return v

    @field_validator("extra")
    @classmethod
    def _ensure_extra_json_compatible(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        """Ensure extra metadata is strictly JSON-serializable."""
        try:
            json.dumps(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"extra metadata must be JSON-compatible: {exc}"
            ) from exc
        return v


# ---------------------------------------------------------------------------
# Detection Rule
# ---------------------------------------------------------------------------


class DetectionRule(BaseModel):
    """A detection rule definition.

    Represents the authoritative definition of a rule to be evaluated
    against security events.  A rule is a **static definition** — it
    does not carry results.  Results are represented by
    :class:`DetectionResult`.

    ``rule_id`` is the stable, unique identifier for this rule across
    the system.  ``version`` tracks rule content changes so that
    detection results can be traced to the exact rule that produced
    them.
    """

    rule_id: str = Field(
        ...,
        min_length=1,
        description=(
            "Stable, unique identifier for this rule, e.g. "
            "'sigma-credential-access-001', 'yara-apt-backdoor-v2'."
        ),
    )
    name: str = Field(
        ...,
        min_length=1,
        description="Human-readable name of the rule.",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="What the rule detects and why it matters.",
    )
    rule_type: RuleType = Field(
        ...,
        description="Engine type this rule is written for.",
    )
    severity: DetectionSeverity = Field(
        ...,
        description=(
            "Rule author's assessment of the potential impact if this "
            "rule matches."
        ),
    )
    enabled: bool = Field(
        default=True,
        description=(
            "Whether this rule should be evaluated.  Disabled rules "
            "are skipped by the detection engine."
        ),
    )
    version: str = Field(
        default="1.0.0",
        min_length=1,
        description=(
            "Semantic version of the rule content.  Updated when the "
            "rule logic changes."
        ),
    )
    metadata: DetectionMetadata = Field(
        default_factory=DetectionMetadata,
        description="Optional metadata about the rule definition.",
    )

    tags: list[str] = Field(
        default_factory=list,
        description=(
            "Freeform tags for rule classification "
            "(e.g. 'attack.t1059', 'windows', 'lateral_movement')."
        ),
    )

    content: dict | str | None = Field(
        default=None,
        description=(
            "Raw Sigma (YAML string or parsed dict) or YARA rule "
            "definition.  The detection engine parses this to evaluate "
            "the rule against events."
        ),
    )

    # -- Validators ----------------------------------------------------------

    @field_validator("rule_id")
    @classmethod
    def _ensure_rule_id_format(cls, v: str) -> str:
        """Rule IDs must be non-empty after stripping whitespace."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("rule_id must not be blank")
        return stripped

    @field_validator("name")
    @classmethod
    def _ensure_name_not_blank(cls, v: str) -> str:
        """Name must be non-empty after stripping whitespace."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("name must not be blank")
        return stripped


# ---------------------------------------------------------------------------
# Detection Result
# ---------------------------------------------------------------------------


class DetectionResult(BaseModel):
    """Result of evaluating a detection rule against a security event.

    A DetectionResult is a **derived analytical conclusion** — it is
    not an observation of the event itself.  The ``provenance`` field
    is therefore ``DETECTED``, distinguishing it from observed,
    enriched, or reconstructed information.

    The ``matched`` boolean is the primary outcome: ``True`` means the
    rule matched the event, ``False`` means the rule was evaluated but
    did not match.  Even non-matching results are recorded so that
    the full evaluation is auditable.

    The ``evidence`` field carries structured, machine-readable data
    about *why* the rule matched (or did not).  It never contains
    secrets, API keys, or arbitrary code.

    ``severity`` and ``confidence`` are independent:
    * ``severity`` comes from the rule definition (potential impact).
    * ``confidence`` reflects the engine's certainty that the rule
      correctly matched (or did not match) this specific event.
    """

    detection_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description=(
            "Unique identifier for this detection result.  "
            "Auto-generated when not supplied."
        ),
    )
    event_id: uuid.UUID = Field(
        ...,
        description=(
            "Identity of the security event that was evaluated.  "
            "Preserved from the source event — never regenerated."
        ),
    )
    rule_id: str = Field(
        ...,
        min_length=1,
        description=(
            "Identity of the rule that was evaluated.  Traceable to a "
            "DetectionRule definition."
        ),
    )
    rule_type: RuleType = Field(
        ...,
        description="Engine type of the evaluated rule.",
    )
    matched: bool = Field(
        ...,
        description=(
            "Whether the rule matched the event.  True = match found; "
            "False = rule evaluated but did not match."
        ),
    )
    severity: DetectionSeverity = Field(
        ...,
        description=(
            "Severity assigned by the rule.  Reflects potential impact, "
            "not confidence."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Engine's confidence that this evaluation result is correct. "
            "Constrained to [0.0, 1.0].  Independent of severity."
        ),
    )
    evidence: DetectionEvidence = Field(
        default_factory=DetectionEvidence,
        description="Structured evidence of the evaluation outcome.",
    )
    timestamp: datetime = Field(
        ...,
        description="Timezone-aware timestamp of when the evaluation was performed.",
    )
    metadata: DetectionMetadata = Field(
        default_factory=DetectionMetadata,
        description="Flexible metadata about the detection evaluation.",
    )
    provenance: Provenance = Field(
        default=Provenance.DETECTED,
        description=(
            "Provenance marker.  Detection results are derived analytical "
            "conclusions and default to DETECTED.  The source event's own "
            "provenance (OBSERVED, RECONSTRUCTED, etc.) is preserved in "
            "the event record identified by event_id."
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

    @field_validator("evidence")
    @classmethod
    def _ensure_evidence_no_secrets(
        cls, v: DetectionEvidence
    ) -> DetectionEvidence:
        """Reject evidence containing common secret patterns.

        This is a defence-in-depth check; the primary protection is
        that evidence is structured (not raw HTTP responses).
        """
        serialized = v.model_dump_json().lower()
        forbidden = ("api_key", "authorization", "bearer", "secret")
        for pattern in forbidden:
            if pattern in serialized:
                raise ValueError(
                    f"evidence must not contain secrets ('{pattern}' detected)"
                )
        return v

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_no_secrets(
        cls, v: DetectionMetadata
    ) -> DetectionMetadata:
        """Reject metadata containing common secret patterns."""
        serialized = v.model_dump_json().lower()
        forbidden = ("api_key", "authorization", "bearer", "secret")
        for pattern in forbidden:
            if pattern in serialized:
                raise ValueError(
                    f"metadata must not contain secrets ('{pattern}' detected)"
                )
        return v

