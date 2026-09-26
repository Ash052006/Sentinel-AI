"""Risk Assessment Domain Contract — Step 11A.

Defines the foundational **domain contract** for the future Risk Scoring
subsystem: the validated Pydantic representation of a single risk
assessment produced over a correlated security situation.

Detection answers *"what individual detection rules matched this event?"*,
correlation answers *"which detections/events are related?"*, and risk
scoring will eventually answer *"how dangerous does the correlated
situation appear, and how confident is SentinelAI in that assessment?"*.
This module defines the objects the future Risk Scoring Agent will
produce.  It **does not answer the question** — it contains no scoring
algorithm, no weights, no thresholds, and no formula of any kind.

Design principles:

* **Contract only** — no scoring engine, no risk formulas, no weights, no
  scoring rules, no thresholds, no ML/statistical/heuristic scoring, no
  threat-intelligence scoring, no severity/confidence multiplication, no
  persistence, no query service, no API, no incidents, no response, no
  MITRE ATT&CK, no threat attribution, no AI/LLM, no database, no message
  bus.  A future Risk Scoring Agent will consume correlation output and
  produce ``RiskAssessment`` objects shaped by this contract.
* **Referencing, not duplicating** — a risk assessment references the
  correlation it evaluates by ``correlation_id``.  It never stores a whole
  ``CorrelationResult`` (or its members); the correlation subsystem remains
  the source of truth for correlation data.  No correlation/detection
  object is copied into the risk contract.
* **Risk vs confidence** — ``score`` / ``level`` answer *"how dangerous
  does the situation appear?"*; ``confidence`` answers *"how confident is
  SentinelAI in this assessment?"*.  These are independent concepts: the
  contract never derives one from the other and contains no formula
  linking them.
* **Bounded risk score** — ``score`` is a normalized scalar constrained to
  ``[0.0, 1.0]``.  The bounds are enforced by the schema.  The score is
  never *calculated* here.
* **Controlled risk level** — ``level`` is a controlled
  :class:`RiskLevel` enumeration (no arbitrary strings), mirroring the
  categorical ladder already used by detection severity.
* **Provenance-aware** — a risk assessment is a derived analytical
  conclusion and carries ``Provenance.RISK_ASSESSED`` (an additive member
  of the existing global ``Provenance`` enum).  It is never labelled
  observed / enriched / reconstructed / detected / correlated.
* **Structured & secret-safe** — evidence and metadata are strict
  JSON-compatible payloads that reject credential-shaped content.
* **Deterministic & non-mutating** — the contract generates no score, no
  evidence, no factors, never reorders input, and never mutates its
  sources.
* **No verdicts** — a risk assessment is not a verdict.  It never asserts
  ``malicious`` / ``benign`` / ``confirmed attack``; it creates no
  incidents and implies no response.

Relationship to the pipeline::

    CorrelationResult                (Step 10A)
        -> [future Correlation Query / Risk Scoring Input]
            -> [future Risk Scoring Agent (11B)]
                -> RiskAssessment     (Step 11A — this module)
                    -> [future Risk Persistence / Query / API]

The final architecture after 11A remains::

    Detection
        -> Correlation
            -> 11A Risk Assessment Domain Contract
                -> [Future Risk Scoring Agent]
                -> [Future Risk Persistence / Query / API]
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
# Secret-safety helpers (mirror the Step 9A / 9I / 10A contract patterns)
# ---------------------------------------------------------------------------

#: Forbidden credential-shaped strings re-checked at the risk boundary.
#: Kept in lock-step with ``app/schemas/detection.py`` /
#: ``app/schemas/correlation.py``.
_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret")


def _assert_json_compatible(value: Any, field: str) -> None:
    """Raise ValueError when *value* is not strictly JSON-serializable."""
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{field} must be JSON-compatible: {exc}"
        ) from exc


def _assert_no_secrets(value: Any, field: str) -> None:
    """Raise ValueError when *value* contains common secret patterns.

    Defence-in-depth: the primary protection is that evidence/metadata are
    structured payloads.  This re-check keeps credential-shaped keys
    (API keys, authorization headers, bearer tokens, JWTs) out of the risk
    contract.
    """
    serialized = json.dumps(value).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"{field} must not contain secrets ('{pattern}' detected)"
            )


def _json_clone(value: dict[str, Any]) -> dict[str, Any]:
    """Return an independent, JSON-compatible deep copy of *value*.

    Guarantees the contract never shares mutable state with the caller,
    regardless of how an object is constructed.
    """
    return json.loads(json.dumps(value))


def _require_non_blank(value: str, field: str) -> str:
    """Reject blank strings in structured labels."""
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field} must not be blank")
    return stripped


# ---------------------------------------------------------------------------
# Risk level
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    """Categorical representation of a risk assessment's severity.

    The ladder mirrors the categorical severity scale already established
    by detection severity (``LOW``/``MEDIUM``/``HIGH``/``CRITICAL``) so the
    system has a single, comprehensible severity vocabulary.  It is a
    **category**, not a score: the contract never maps a numeric ``score``
    to a ``level`` (score -> level mapping is a scoring rule that belongs
    to the future Risk Scoring Agent).
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Structured evidence
# ---------------------------------------------------------------------------


class RiskEvidence(BaseModel):
    """One structured observation that contributed to a risk assessment.

    Evidence is **structured and machine-readable** — it never requires an
    LLM or free-form explanation text.  Each item names the kind of
    observation that influenced the assessment (``observation_type``) and
    may reference the exact detection/event that supplied it.  It does not
    invent factors or scores; a future engine decides what evidence means.
    """

    observation_type: str = Field(
        ...,
        min_length=1,
        description=(
            "Machine-readable label of the observation that contributed, "
            "e.g. 'detection_severity', 'correlation_confidence', "
            "'correlation_size'.  Structured, not free-form prose."
        ),
    )
    detection_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Optional reference to the exact detection that supplied this "
            "observation.  A reference only — never an embedded detection "
            "record."
        ),
    )
    event_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Optional reference to the exact source event.  A reference "
            "only — never an embedded event record."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured details about this observation.  Must be "
            "JSON-compatible and must never contain secrets."
        ),
    )

    # -- Validators ----------------------------------------------------------

    @field_validator("observation_type")
    @classmethod
    def _ensure_observation_type_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "observation_type")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        _assert_json_compatible(v, "evidence metadata")
        _assert_no_secrets(v, "evidence metadata")
        return _json_clone(v)


# ---------------------------------------------------------------------------
# Risk factor
# ---------------------------------------------------------------------------


class RiskFactor(BaseModel):
    """A named contributor to a risk assessment.

    A factor describes *what kind of consideration* influenced the
    assessment and (optionally) its numeric contribution.  The schema
    validates and preserves factors; it never computes them.  Contribution
    values are produced by the future Risk Scoring Agent, bounded to
    ``[0.0, 1.0]`` when present.
    """

    factor_type: str = Field(
        ...,
        min_length=1,
        description=(
            "Machine-readable label of the factor, e.g. 'detection_volume', "
            "'severity_impact', 'correlation_extent'.  Structured, not "
            "free-form prose."
        ),
    )
    contribution: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Optional numeric contribution of this factor to the "
            "assessment, bounded to [0.0, 1.0].  Produced by the future "
            "Risk Scoring Agent — never calculated by this contract."
        ),
    )
    evidence: list[RiskEvidence] = Field(
        default_factory=list,
        description=(
            "Structured observations supporting this factor.  The contract "
            "defines no factor semantics; the future engine decides what a "
            "factor means."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Open-ended JSON-compatible metadata about the factor.  Must "
            "never contain secrets."
        ),
    )

    # -- Validators ----------------------------------------------------------

    @field_validator("factor_type")
    @classmethod
    def _ensure_factor_type_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "factor_type")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        _assert_json_compatible(v, "factor metadata")
        _assert_no_secrets(v, "factor metadata")
        return _json_clone(v)


# ---------------------------------------------------------------------------
# Risk assessment
# ---------------------------------------------------------------------------


class RiskAssessment(BaseModel):
    """A structured assessment of the security risk associated with a
    correlated security situation.

    ``RiskAssessment`` is the **output contract** of the future Risk
    Scoring subsystem.  It represents *what a risk assessment IS*:

    * ``risk_assessment_id`` — stable domain identity (never a database row
      id, never the evaluated correlation's id).
    * ``correlation_id`` — the exact identity of the correlation being
      evaluated (a reference; the correlation itself is never embedded).
    * ``score`` — normalized risk score in ``[0.0, 1.0]``, representing how
      dangerous the situation appears.
    * ``level`` — controlled categorical risk level.
    * ``confidence`` — how confident SentinelAI is in this assessment,
      bounded to ``[0.0, 1.0]`` and independent of ``score``/``level``.
    * ``factors`` / ``evidence`` — structured, explainable reasons for the
      assessment; optional and defined by the future engine.
    * ``metadata`` — JSON-compatible, secret-free bookkeeping.
    * ``timestamp`` — timezone-aware instant of the assessment.
    * ``provenance`` — always ``RISK_ASSESSED``.

    It asserts **no formula**: the contract never derives ``score``,
    ``level``, ``confidence``, factors, or evidence from correlation
    inputs.  It only validates and preserves an engine-produced assessment.
    """

    risk_assessment_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description=(
            "Stable identity of this risk assessment.  Distinct from "
            "correlation_id, detection_id, event_id, and incident_id.  "
            "Auto-generated when not supplied; generating the identity is "
            "identity generation, not risk scoring."
        ),
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description=(
            "Identity of the correlation this assessment evaluates.  A "
            "reference — the correlation subsystem stays authoritative and "
            "no correlation/detection object is duplicated here."
        ),
    )
    score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Normalized risk score, bounded to [0.0, 1.0].  Answers 'how "
            "dangerous does the situation appear?'.  Never calculated by "
            "this contract."
        ),
    )
    level: RiskLevel = Field(
        ...,
        description=(
            "Controlled categorical risk level (low / medium / high / "
            "critical).  Independent of score and confidence; a precise "
            "score->level mapping is a future scoring rule."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "How confident SentinelAI is in this assessment, bounded to "
            "[0.0, 1.0].  Independent of score/level — never derived from "
            "them, never a risk score."
        ),
    )
    factors: list[RiskFactor] = Field(
        default_factory=list,
        description=(
            "Named contributors to the assessment, if the future engine "
            "enumerated any.  Never computed here."
        ),
    )
    evidence: list[RiskEvidence] = Field(
        default_factory=list,
        description=(
            "Structured observations supporting the assessment.  The "
            "contract defines no evidence semantics; the future engine "
            "decides what evidence means."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Open-ended JSON-compatible metadata about the assessment.  "
            "Must never encode verdicts or future-layer decisions and "
            "must never contain secrets."
        ),
    )
    timestamp: datetime = Field(
        ...,
        description=(
            "Timezone-aware instant at which the assessment was produced.  "
            "Descriptive bookkeeping, not evidence."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.RISK_ASSESSED,
        description=(
            "Provenance marker.  Risk assessments are derived analytical "
            "conclusions and are always RISK_ASSESSED; they are never "
            "observed / enriched / reconstructed / detected / correlated "
            "telemetry."
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

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Metadata must be JSON-compatible, secret-free, and independent."""
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _json_clone(v)

    @field_validator("factors")
    @classmethod
    def _ensure_factors_secret_free(
        cls, v: list[RiskFactor]
    ) -> list[RiskFactor]:
        """Defence-in-depth: the serialized factor set is secret-screened.

        Factor metadata is already validated per item; this re-scan catches
        any secret-shaped content that might otherwise slip through labels.
        """
        _assert_no_secrets([factor.model_dump(mode="json") for factor in v], "factors")
        return v

    @field_validator("evidence")
    @classmethod
    def _ensure_evidence_secret_free(
        cls, v: list[RiskEvidence]
    ) -> list[RiskEvidence]:
        """Defence-in-depth: the serialized evidence set is secret-screened."""
        _assert_no_secrets(
            [item.model_dump(mode="json") for item in v], "evidence"
        )
        return v

    @field_validator("provenance")
    @classmethod
    def _ensure_risk_assessed_provenance(
        cls, v: Provenance
    ) -> Provenance:
        """A risk assessment is always a derived analytical conclusion.

        Mirroring the Step 9I / 10A boundaries (which enforce ``DETECTED`` /
        ``CORRELATED``), the risk contract enforces ``RISK_ASSESSED``: a
        risk assessment is never observed, enriched, reconstructed,
        detected, or correlated telemetry.
        """
        if v is not Provenance.RISK_ASSESSED:
            raise ValueError(
                "risk assessments are derived analytical conclusions "
                "and must carry RISK_ASSESSED provenance; got "
                f"{v.value!r}"
            )
        return v