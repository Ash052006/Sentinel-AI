"""Investigation Domain Contract — Step 12A.

Defines the foundational **domain contract** for the future AI
Investigation subsystem: the validated Pydantic representation of a single
investigation output (``InvestigationResult``) together with its supporting
structures — structured conclusions (``InvestigationFinding``),
source-backed support (``InvestigationEvidence``), and contextual
statements (``InvestigationObservation``).

Detection answers *"what individual detection rules matched this event?"*,
correlation answers *"which detections/events are related?"*, risk answers
*"how dangerous does the correlated situation appear?"*, and the future AI
Investigation Agent will answer *"what can SentinelAI conclude about this
correlated, risk-assessed situation?"*.  This module defines the objects
that agent will produce.  It **does not answer the question** — it contains
no investigation agent, no LLM, no prompts, no model calls, no context
builder, no reasoning, and no inference of any kind.

Design principles:

* **Contract only, the most important rule of this step** — no AI
  investigation agent, no LLM/Ollama/LangChain/LangGraph, no prompts, no
  model calls, no embeddings, no vector database, no context builder, no
  adapters from CorrelationResult/RiskAssessment, no persistence
  (SQLAlchemy models, repositories, migrations, tables, queries), no API
  (routes, endpoints, dependencies), no incidents, no MITRE ATT&CK, no
  response, no message bus.  The future Investigation Context Builder
  (12B) and Investigation Agent (12C) consume and produce objects shaped
  by this contract.
* **Referencing, not duplicating** — an investigation result references
  the correlation it investigates by ``correlation_id`` and (when
  applicable) the risk assessment it used by ``risk_assessment_id``.
  Evidence references existing SentinelAI identities
  (``detection_id`` / ``event_id`` / ``correlation_id`` /
  ``risk_assessment_id``) — never invented IDs and never embedded copies of
  detection/correlation/risk records; those subsystems stay authoritative.
  Threat-intelligence context is *not* given a fabricated reference id:
  it flows into an investigation as ``ENRICHED`` evidence referencing the
  enriched ``event_id`` (threat intelligence is an enrichment source in
  this pipeline, and the existing domain contracts expose no
  threat-intelligence UUID reference).
* **Provenance honesty (hallucination safety)** — the contract keeps
  observed / enriched / reconstructed / detected / correlated /
  risk-assessed information structurally distinct from AI-generated
  conclusions.  Each concept maps onto the global ``Provenance`` enum; a
  seventh additive member, ``Provenance.AI_GENERATED``, was introduced for
  investigation-produced conclusions.  Evidence must be source-backed and
  therefore **may never** carry ``AI_GENERATED`` provenance; findings and
  the overall result are conclusions of the investigation process and are
  **pinned** to ``AI_GENERATED``.  An AI inference can never be silently
  serialized as an ``OBSERVED`` fact.
* **Evidence vs finding vs observation** — ``evidence`` is *"what
  information (from a referenced source) supports the investigation"*;
  ``finding`` is *"what conclusion the investigation derived"*; an
  ``observation`` is *"what structured contextual statement is being
  represented"*.  These are separate structures and are never
  interchangeable.
* **Independent confidence** — ``confidence`` is bounded to ``[0.0, 1.0]``
  and is *how strongly the investigation supports its finding* — a
  different concept from risk score/level or detection severity, and never
  derived from them.  The contract contains no formula linking them.
* **Structured & secret-safe** — metadata everywhere is strict
  JSON-compatible payload, deeply validated, deeply cloned, and rejects
  credential-shaped content.  No secrets are ever logged or preserved.
* **Deterministic & non-mutating** — the contract generates no findings,
  no evidence, no observations, never reorders input, never deduplicates,
  and never mutates its sources.
* **No verdicts** — an investigation result is not a verdict: it creates
  no incidents, maps no MITRE ATT&CK, asserts no attribution, and implies
  no response.

Relationship to the pipeline::

    CorrelationResult                (Step 10A)
        + RiskAssessment             (Step 11A)
        + Detection evidence         (Step 9A)
        + Threat-intelligence context
        -> [future Investigation Context Builder (12B)]
            -> [future AI Investigation Agent (12C)]
                -> InvestigationResult   (Step 12A — this module)
                    -> [future Investigation Persistence / Query / API]

The final architecture after 12A remains::

    Pipeline-derived context
        -> 12A Investigation Domain Contract
        -> [Future Context Builder (12B)]
        -> [Future AI Investigation Agent (12C)]
        -> [Future Persistence / Query / API]
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Secret-safety helpers (mirror the Step 9A / 10A / 11A contract patterns)
# ---------------------------------------------------------------------------

#: Forbidden credential-shaped strings re-checked at the investigation
#: boundary.  Kept in lock-step with ``app/schemas/detection.py`` /
#: ``app/schemas/correlation.py`` / ``app/schemas/risk.py``.
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

    Defence-in-depth: the primary protection is that metadata are
    structured payloads.  This re-check keeps credential-shaped keys
    (API keys, authorization headers, bearer tokens, JWTs, database
    credentials) out of the investigation contract.
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
# Investigation evidence
# ---------------------------------------------------------------------------


class InvestigationEvidence(BaseModel):
    """One source-backed item of information supporting an investigation.

    Evidence answers *"what information supports the investigation?"*.  It
    is **source-backed**: an evidence record must reference the exact
    existing SentinelAI identity that supplies it (a detection, an event, a
    correlation, or a risk assessment) and must declare the provenance of
    that information.  The provenance-to-reference link is **enforced**:

    * ``OBSERVED`` / ``ENRICHED`` / ``RECONSTRUCTED`` evidence must
      reference ``event_id`` (the information lives on the event).
    * ``DETECTED`` evidence must reference ``detection_id``.
    * ``CORRELATED`` evidence must reference ``correlation_id``.
    * ``RISK_ASSESSED`` evidence must reference ``risk_assessment_id``.

    Evidence is a **machine-readable record**, not free-form prose:
    ``evidence_type`` is a controlled label and structured details live in
    ``metadata``.  It never embeds a copy of the referenced detection /
    event / correlation / risk record.

    ``Provenance.AI_GENERATED`` is **forbidden** on evidence: an
    AI-generated conclusion is a finding, and evidence must trace to an
    actual pipeline source (a reference and a provenance that back it).
    This makes fabricated/unsupported "evidence invented by the model"
    structurally impossible to represent.
    """

    evidence_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description=(
            "Stable identity of this evidence record within the "
            "investigation.  Referenced by InvestigationFinding.evidence_ids "
            "so conclusions can point at their supporting information.  "
            "Auto-generated when not supplied; generating the identity is "
            "identity generation, not investigation logic."
        ),
    )
    evidence_type: str = Field(
        ...,
        min_length=1,
        description=(
            "Machine-readable label of the evidence, e.g. "
            "'detection_match', 'correlation_membership', "
            "'risk_factor', 'event_field'.  Structured, not free-form "
            "prose."
        ),
    )
    provenance: Provenance = Field(
        ...,
        description=(
            "Provenance of the information.  MUST be one of OBSERVED / "
            "ENRICHED / RECONSTRUCTED / DETECTED / CORRELATED / "
            "RISK_ASSESSED and MUST match a present reference.  "
            "AI_GENERATED is never valid for evidence."
        ),
    )
    detection_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Reference to the exact detection that supplied this "
            "evidence (required when provenance is DETECTED).  A "
            "reference only — never an embedded detection record."
        ),
    )
    event_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Reference to the exact security event that supplied this "
            "evidence (required when provenance is OBSERVED, ENRICHED, "
            "or RECONSTRUCTED).  A reference only — never an embedded "
            "event record."
        ),
    )
    correlation_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Reference to the exact correlation that supplied this "
            "evidence (required when provenance is CORRELATED).  A "
            "reference only — never an embedded correlation record."
        ),
    )
    risk_assessment_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Reference to the exact risk assessment that supplied this "
            "evidence (required when provenance is RISK_ASSESSED).  A "
            "reference only — never an embedded risk record."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured details about this evidence.  Must be "
            "JSON-compatible and must never contain secrets."
        ),
    )

    # -- Validators ----------------------------------------------------------

    @field_validator("evidence_type")
    @classmethod
    def _ensure_evidence_type_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "evidence_type")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        _assert_json_compatible(v, "evidence metadata")
        _assert_no_secrets(v, "evidence metadata")
        return _json_clone(v)

    @model_validator(mode="after")
    def _ensure_source_backed_and_coherent(self) -> "InvestigationEvidence":
        """Evidence must be source-backed and provenance-coherent.

        An AI-generated inference is never acceptable as evidence (either
        as ``ai_generated`` reasoning or as an ``attribution_assessed``
        hypothesis): investigation evidence is source-backed and an
        attribution hypothesis is a conclusion, not a source.  The declared
        provenance must be backed by the matching reference so a
        provenance category can never be silently attached to the wrong
        kind of information.
        """
        if self.provenance in (
            Provenance.AI_GENERATED,
            Provenance.ATTRIBUTION_ASSESSED,
        ):
            raise ValueError(
                "investigation evidence is source-backed; it must not carry "
                "AI_GENERATED or ATTRIBUTION_ASSESSED provenance (analytical "
                "content is a finding, not evidence)"
            )
        required = {
            Provenance.OBSERVED: "event_id",
            Provenance.ENRICHED: "event_id",
            Provenance.RECONSTRUCTED: "event_id",
            Provenance.DETECTED: "detection_id",
            Provenance.CORRELATED: "correlation_id",
            Provenance.RISK_ASSESSED: "risk_assessment_id",
        }
        needed = required.get(self.provenance)
        if needed is not None and getattr(self, needed) is None:
            raise ValueError(
                f"{self.provenance.value} evidence must reference a "
                f"{needed}; an analytical provenance cannot be attached "
                "without the matching source identity"
            )
        return self


# ---------------------------------------------------------------------------
# Investigation observation
# ---------------------------------------------------------------------------


class InvestigationObservation(BaseModel):
    """One structured contextual observation used by the investigation.

    An observation answers *"what structured contextual statement is being
    represented?"*.  Unlike ``InvestigationFinding`` it carries **no
    conclusion**; unlike ``InvestigationEvidence`` it carries **no source
    reference** — it is a declared statement about context.

    The provenance distinction is the entire point of this structure:

    * A **source-backed** observation (a contextual summary of something
      actually retrieved from the pipeline) must declare ``OBSERVED`` /
      ``ENRICHED`` / ``RECONSTRUCTED`` (or the derived source categories).
    * An **AI-generated** observation (reasoning produced by the
      investigation process) must declare ``AI_GENERATED`` — never
      ``OBSERVED``.  The model that generates an observation must attest to
      what it produced; the schema guarantees an AI inference can never be
      dropped into the ``observed`` bucket.
    """

    observation_type: str = Field(
        ...,
        min_length=1,
        description=(
            "Machine-readable label of the observation, e.g. "
            "'context_summary', 'timeline_note', 'ai_reasoning'.  "
            "Structured, not free-form prose."
        ),
    )
    observation_text: str = Field(
        ...,
        min_length=1,
        description=(
            "The structured contextual statement itself.  Kept explicit so "
            "an observation is never a hidden dump of unlabelled telemetry."
        ),
    )
    provenance: Provenance = Field(
        ...,
        description=(
            "Whether this observation is source-backed or AI-generated.  "
            "AI-generated observations MUST declare AI_GENERATED and must "
            "never be labelled observed."
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

    @field_validator("observation_text")
    @classmethod
    def _ensure_observation_text_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "observation_text")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        _assert_json_compatible(v, "observation metadata")
        _assert_no_secrets(v, "observation metadata")
        return _json_clone(v)


# ---------------------------------------------------------------------------
# Investigation finding
# ---------------------------------------------------------------------------


class InvestigationFinding(BaseModel):
    """One structured conclusion derived by the investigation.

    A finding answers *"what did the investigation conclude?"*.  It is a
    **conclusion** — never observed telemetry and never a disguised piece
    of evidence.  Findings carry machine-readable fields
    (``finding_type``, ``title``), an optional short ``summary``, a
    confidence bounded to ``[0.0, 1.0]``, references to the evidence that
    support the conclusion (``evidence_ids``), and structured metadata.

    Findings are conclusions of the investigation process and are therefore
    always ``AI_GENERATED`` — the schema **pins** the provenance so an
    AI-generated conclusion can never be silently serialized as
    ``OBSERVED`` telemetry.  Evidence (and its own provenance) is kept
    separate: a finding *references* evidence; it never absorbs it.
    """

    finding_type: str = Field(
        ...,
        min_length=1,
        description=(
            "Machine-readable type of the conclusion, e.g. "
            "'activity_pattern', 'escalation', 'exoneration', "
            "'insufficient_evidence'.  Controlled by the future agent; "
            "structured, not free-form prose."
        ),
    )
    title: str = Field(
        ...,
        min_length=1,
        description=(
            "Concise human-readable label of the conclusion.  A label, "
            "not a free-form evidence dump."
        ),
    )
    summary: str | None = Field(
        default=None,
        description=(
            "Optional short structured summary of the conclusion.  The "
            "contract never relies *entirely* on prose: finding_type and "
            "title carry the machine-readable semantics."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "How strongly the investigation supports this finding, bounded "
            "to [0.0, 1.0].  Independent of risk score/level and detection "
            "severity — never derived from them, never a risk score."
        ),
    )
    evidence_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description=(
            "References to the evidence records (on the same "
            "InvestigationResult) that support this conclusion.  Each id "
            "must resolve to an evidence record on the result.  Order is "
            "preserved; duplicates are preserved as-is."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Open-ended JSON-compatible metadata about the finding.  Must "
            "never contain secrets."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.AI_GENERATED,
        description=(
            "Provenance marker.  Findings are conclusions produced by the "
            "investigation process and are always AI_GENERATED; they are "
            "never observed / enriched / reconstructed / detected / "
            "correlated / risk_assessed telemetry."
        ),
    )

    # -- Validators ----------------------------------------------------------

    @field_validator("finding_type")
    @classmethod
    def _ensure_finding_type_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "finding_type")

    @field_validator("title")
    @classmethod
    def _ensure_title_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "title")

    @field_validator("summary")
    @classmethod
    def _ensure_summary_not_blank(
        cls, v: str | None
    ) -> str | None:
        if v is None:
            return None
        return _require_non_blank(v, "summary")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        _assert_json_compatible(v, "finding metadata")
        _assert_no_secrets(v, "finding metadata")
        return _json_clone(v)

    @field_validator("provenance")
    @classmethod
    def _ensure_ai_generated_provenance(
        cls, v: Provenance
    ) -> Provenance:
        """A finding is always a conclusion of the investigation process.

        Pinning findings to ``AI_GENERATED`` (mirroring how the detection /
        correlation / risk boundaries pin their outputs) makes it
        structurally impossible for an AI-generated conclusion to serialize
        as observed telemetry.
        """
        if v is not Provenance.AI_GENERATED:
            raise ValueError(
                "findings are conclusions produced by the investigation "
                "process and must carry AI_GENERATED provenance; got "
                f"{v.value!r}"
            )
        return v


# ---------------------------------------------------------------------------
# Investigation result
# ---------------------------------------------------------------------------


class InvestigationResult(BaseModel):
    """The complete validated output of one future investigation.

    ``InvestigationResult`` represents *what a completed investigation
    output IS*:

    * ``investigation_id`` — stable domain identity (never a database row
      id, never the investigated correlation's id).  Unique per
      investigation result.
    * ``correlation_id`` — the exact identity of the correlation being
      investigated (a reference; the correlation itself is never embedded).
      One correlation may legitimately produce multiple historical
      investigations — the contract does not assume a 1:1 mapping and
      every result carries its own ``investigation_id`` and ``timestamp``.
    * ``risk_assessment_id`` — the exact identity of the risk assessment
      used by the investigation, when one was used (a reference; optional).
    * ``confidence`` — optional overall confidence in the investigation
      output, bounded to ``[0.0, 1.0]`` and independent of risk score.
    * ``findings`` / ``evidence`` / ``observations`` — the structured
      conclusions, source-backed support, and contextual statements.
    * ``metadata`` — JSON-compatible, secret-free bookkeeping.
    * ``timestamp`` — timezone-aware instant the investigation was
      produced (bookkeeping, not evidence).
    * ``provenance`` — always ``AI_GENERATED``: the complete output of the
      investigation process is a generated conclusion, never observed
      telemetry.

    The result asserts **no reasoning**: it never derives findings,
    evidence, observations, or confidence, and it contains no
    investigation algorithm.  It only validates and preserves an
    agent-produced output.
    """

    investigation_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description=(
            "Stable identity of this investigation result.  Distinct from "
            "correlation_id, risk_assessment_id, detection_id, event_id, "
            "and incident_id.  Auto-generated when not supplied; "
            "generating the identity is identity generation, not "
            "investigation logic."
        ),
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description=(
            "Identity of the correlation being investigated.  A reference "
            "— the correlation subsystem stays authoritative and no "
            "correlation/detection/risk object is duplicated here.  One "
            "correlation may have multiple historical investigations."
        ),
    )
    risk_assessment_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Identity of the risk assessment used by the investigation, "
            "when one was used.  Optional and a reference only."
        ),
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Overall confidence in the investigation output, bounded to "
            "[0.0, 1.0].  Independent of the risk score/level and of "
            "detection severity — never derived from them.  Absent when "
            "the agent produced no numeric confidence."
        ),
    )
    findings: list[InvestigationFinding] = Field(
        default_factory=list,
        description=(
            "Structured conclusions of the investigation, in the order "
            "supplied.  Never computed here."
        ),
    )
    evidence: list[InvestigationEvidence] = Field(
        default_factory=list,
        description=(
            "Structured source-backed support used by the investigation, "
            "in the order supplied.  Never computed here."
        ),
    )
    observations: list[InvestigationObservation] = Field(
        default_factory=list,
        description=(
            "Structured contextual observations used by the investigation, "
            "in the order supplied.  Never computed here."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Open-ended JSON-compatible metadata about the investigation "
            "output.  Must never encode verdicts or future-layer decisions "
            "and must never contain secrets."
        ),
    )
    timestamp: datetime = Field(
        ...,
        description=(
            "Timezone-aware instant at which the investigation output was "
            "produced.  Descriptive bookkeeping, not evidence."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.AI_GENERATED,
        description=(
            "Provenance marker.  An investigation output is a conclusion "
            "produced by the investigation process and is always "
            "AI_GENERATED; it is never observed / enriched / "
            "reconstructed / detected / correlated / risk_assessed "
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

    @field_validator("findings")
    @classmethod
    def _ensure_findings_secret_free(
        cls, v: list[InvestigationFinding]
    ) -> list[InvestigationFinding]:
        """Defence-in-depth: the serialized finding set is secret-screened.

        Finding metadata/labels are already validated per item; this
        re-scan catches any secret-shaped content that might otherwise
        slip through labels.
        """
        _assert_no_secrets(
            [item.model_dump(mode="json") for item in v], "findings"
        )
        return v

    @field_validator("evidence")
    @classmethod
    def _ensure_evidence_secret_free(
        cls, v: list[InvestigationEvidence]
    ) -> list[InvestigationEvidence]:
        """Defence-in-depth: the serialized evidence set is secret-screened."""
        _assert_no_secrets(
            [item.model_dump(mode="json") for item in v], "evidence"
        )
        return v

    @field_validator("observations")
    @classmethod
    def _ensure_observations_secret_free(
        cls, v: list[InvestigationObservation]
    ) -> list[InvestigationObservation]:
        """Defence-in-depth: the serialized observation set is secret-screened."""
        _assert_no_secrets(
            [item.model_dump(mode="json") for item in v], "observations"
        )
        return v

    @field_validator("provenance")
    @classmethod
    def _ensure_ai_generated_provenance(
        cls, v: Provenance
    ) -> Provenance:
        """An investigation output is always a generated conclusion.

        Mirroring the Step 9I / 10A / 11A boundaries, the investigation
        contract pins ``AI_GENERATED``: the complete output of the
        investigation process is never observed, enriched, reconstructed,
        detected, correlated, or risk-assessed telemetry.
        """
        if v is not Provenance.AI_GENERATED:
            raise ValueError(
                "investigation results are conclusions produced by the "
                "investigation process and must carry AI_GENERATED "
                f"provenance; got {v.value!r}"
            )
        return v

    @model_validator(mode="after")
    def _ensure_evidence_references_resolve(self) -> "InvestigationResult":
        """Finding evidence references must resolve to this result's evidence.

        A finding's ``evidence_ids`` are references *into* the result's
        evidence list; an unresolvable reference would be a dangling or
        fabricated citation, so it is rejected deterministically.  Order of
        findings/evidence/observations and duplicates in ``evidence_ids``
        are preserved exactly.
        """
        known = {item.evidence_id for item in self.evidence}
        for finding in self.findings:
            missing = [
                reference
                for reference in finding.evidence_ids
                if reference not in known
            ]
            if missing:
                raise ValueError(
                    "finding evidence references must resolve to evidence "
                    "records on the result; unresolved: "
                    + ", ".join(str(reference) for reference in missing)
                )
        return self