"""Security Event contract.

Defines the validated internal schema for security events flowing through
SentinelAI.  Future collectors, normalization, enrichment, and detection
agents will all operate on this contract.

No database table, API endpoint, or message-bus integration is introduced
here — this module is purely the data contract.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Provenance(str, Enum):
    """Where the information in an event (or field) originated.

    Semantic meaning:

    * ``observed``  — directly present in the original collected event.
    * ``enriched``  — added by an external or internal enrichment source.
    * ``reconstructed`` — inferred because the original was incomplete.
    * ``detected``  — derived analytical result produced by a detection
      evaluation (e.g. Sigma or YARA rule match).  A detected result is
      **not** an observation of the event itself; it is an analytical
      conclusion derived from evaluating a rule against event data.
    * ``correlated`` — derived analytical result produced by a correlation
      evaluation.  A correlated result is **not** a detection and it is
      not an observation; it is an analytical conclusion about the
      *relationship between* detections/events (e.g. that they belong to
      the same activity or attack sequence).
    * ``risk_assessed`` — derived analytical result produced by a risk
      assessment evaluation.  A risk-assessed result is **not** a
      correlation, a detection, or an observation; it is an analytical
      conclusion about *how dangerous a correlated situation appears* and
      how confident SentinelAI is in that assessment.  It carries no
      verdict (the activity is not branded malicious/benign) and no
      incident/response state.

    Each of the ``detected`` / ``correlated`` / ``risk_assessed`` values
    was added **additively and backward-compatibly**: no existing value was
    redefined, and existing consumers that compare against ``observed`` /
    ``enriched`` / ``reconstructed`` / ``detected`` / ``correlated`` behave
    identically.

    A **reconstructed** value must never silently appear as if it were an
    observed fact.  A **detected**, **correlated**, or **risk assessed**
    value must never be confused with direct observation.  The schema
    enforces this distinction so downstream agents can make appropriate
    trust decisions.

    ``ai_generated`` (added additively by the Step 12A Investigation
    contract) marks a conclusion **generated or inferred by an AI
    investigation process** — an analytical observation produced by an
    investigation agent rather than information retrieved from the
    pipeline.  It is the reverse of ``observed`` and must never be used for
    telemetry that was actually collected from the environment.  The
    Step 12A contract forbids ``ai_generated`` on source-backed evidence
    and pins investigation *output* (results and findings) to this value so
    that an AI inference can never be silently serialized as an observed
    fact.

    ``attribution_assessed`` (added additively by the Step 14 Threat
    Attribution contract) marks a conclusion **produced by a threat
    attribution assessment** — an analytical hypothesis about *who or what*
    may be responsible for correlated activity, together with the overall
    assessment over those hypotheses.  An attribution assessment is
    reasoning *over* available evidence; it is never observed telemetry.
    The Step 14 contract forbids ``attribution_assessed`` on source-backed
    evidence (attribution hypotheses are conclusions, not evidence) and
    pins attribution *output* (hypotheses and the assessment) to this
    value.

    ``recalled`` (added additively by the Step 16 Incident Memory
    foundation) marks a **historical memory / reusable context record**
    assembled from completed investigations or incidents.  A recalled
    memory is never current telemetry: it is the *history* of an incident,
    explicitly represented as memory rather than as a raw observation.
    The Step 16 contract pins IncidentMemory output to this value and
    forbids it on memory *source references*, which always retain the
    original provenance (``observed`` / ``enriched`` / ``reconstructed`` /
    ``detected`` / ``correlated`` / ``risk_assessed`` / ``ai_generated`` /
    ``attribution_assessed``) of the information they cite.  A memory can
    therefore never silently masquerade as observed evidence, and a
    previously-noted provenance is never silently converted into another.

    ``learned`` (added additively by the Step 22 Incident Memory Learning
    & Consolidation foundation) marks a **derived historical learning /
    consolidation record** produced deterministically by the learning layer
    from explicitly available ``recalled`` incident memories.  A learned
    record is never current telemetry and never original memory: it is a
    structured, evidence-grounded consolidation *over* historical memory
    (a recurring pattern, repeated technique/action/outcome, a repeated
    source-provenance relationship, with occurrence counts, first/last
    occurrence, and support-derived confidence).  The Step 22 contract
    pins IncidentMemoryLearning output to this value and forbids it both on
    current-evidence constructs and on memory *source references*, which
    always retain the original provenance of the information they cite.  A
    learned record can therefore never masquerade as an observed fact, as
    evidence, or as an original recalled memory.

    ``policy_decided`` (added additively by the Step 24 Policy Decision
    contract) marks a conclusion **produced by the deterministic Policy
    Decision Engine** — an auditable ALLOWED / DENIED / REQUIRES_APPROVAL
    outcome derived by evaluating declarative policy rules over structured
    Risk / Investigation / Attribution context.  A policy decision is a
    decision *about* whether a proposed response action may proceed; it is
    never telemetry, never an investigation finding, never a risk
    assessment, and never an executed response.  The Step 24 contract pins
    PolicyDecision output to this value and forbids reusing any prior value
    (a policy decision must never masquerade as a detection, correlation,
    risk assessment, AI investigation, attribution, recalled memory, or
    learned pattern).

    ``response_executed`` (added additively by the Step 25 Response &
    Mitigation contract) marks the **auditable result of a response
    execution attempt** — a structured EXECUTED / FAILED / SKIPPED /
    REJECTED outcome produced deterministically by the Response layer from
    a permitted policy decision and a validated, simulated/adaptable
    provider.  A response result is never observed telemetry, never a
    detection, correlation, risk assessment, investigation, attribution,
    recalled memory, learned pattern, or policy decision: it records *what
    the response layer attempted and what happened to it*.  The Step 25
    contract pins ResponseResult output to this value and forbids reusing
    any prior value.

    ``approval_reviewed`` (added additively by the Step 16 / V2.16 Human-
    in-the-Loop approval workflow) marks the **auditable record of a human
    approval decision**.  An approval record is a human governance action
    over a REQUIRES_APPROVAL policy decision — it is never observed
    telemetry, a detection, correlation, risk assessment, investigation,
    attribution, recalled memory, learned pattern, AI text, a policy
    decision, or a response result, and it never executes anything itself.
    The V2.16 approval contract pins ApprovalRecord output to this value
    and forbids reusing any prior value.

    Each of the ``detected`` / ``correlated`` / ``risk_assessed`` /
    ``ai_generated`` / ``attribution_assessed`` / ``recalled`` /
    ``learned`` / ``policy_decided`` / ``response_executed`` /
    ``approval_reviewed`` values was added **additively and
    backward-compatibly**: no existing value was redefined, and existing
    consumers that compare against ``observed`` / ``enriched`` /
    ``reconstructed`` / ``detected`` / ``correlated`` / ``risk_assessed`` /
    ``ai_generated`` / ``attribution_assessed`` / ``recalled`` /
    ``learned`` / ``policy_decided`` / ``response_executed`` behave
    identically.
    """

    OBSERVED = "observed"
    ENRICHED = "enriched"
    RECONSTRUCTED = "reconstructed"
    DETECTED = "detected"
    CORRELATED = "correlated"
    RISK_ASSESSED = "risk_assessed"
    AI_GENERATED = "ai_generated"
    ATTRIBUTION_ASSESSED = "attribution_assessed"
    RECALLED = "recalled"
    LEARNED = "learned"
    POLICY_DECIDED = "policy_decided"
    RESPONSE_EXECUTED = "response_executed"
    APPROVAL_REVIEWED = "approval_reviewed"


class SourceType(str, Enum):
    """High-level category for the origin of a security event.

    The set of values is intentionally broad to accommodate future
    collectors.  New values can be added in later versions without
    breaking the contract.
    """

    OPERATING_SYSTEM = "operating_system"
    NETWORK = "network"
    APPLICATION = "application"
    CLOUD = "cloud"
    IDENTITY = "identity"
    SECURITY_DEVICE = "security_device"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Security Event
# ---------------------------------------------------------------------------

class SecurityEvent(BaseModel):
    """Validated, internally canonical representation of a security event.

    The schema is designed around clear separation of concerns so that
    future processing stages (normalisation → enrichment → synthetic
    reconstruction → detection → correlation → investigation) can add
    information without overwriting original event data::

        raw_data            ← immutable, forensic-grade
        normalised_data     ← (future) normalised representation
        enriched_data       ← (future) added by enrichment
        provenance          ← event-level trust/provenance marker

    Field-level provenance can be added later via an optional mapping
    without redesigning this schema.
    """

    event_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Unique identifier for this event. Auto-generated when not supplied.",
    )

    timestamp: datetime = Field(
        ...,
        description="Timezone-aware timestamp of when the event occurred.",
    )

    source: str = Field(
        ...,
        min_length=1,
        description=(
            "Specific origin of the event, e.g. 'windows', 'linux', "
            "'firewall', 'application'."
        ),
    )

    source_type: SourceType = Field(
        ...,
        description="High-level category of the event source.",
    )

    event_type: str = Field(
        ...,
        min_length=1,
        description=(
            "What kind of event occurred, e.g. 'authentication', "
            "'process_creation', 'network_connection', 'file_activity'."
        ),
    )

    raw_data: dict[str, Any] = Field(
        ...,
        description=(
            "Original collected event data.  Preserved as-is for forensic "
            "integrity; must not be silently transformed downstream."
        ),
    )

    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional structured information associated with collection.",
    )

    provenance: Provenance = Field(
        ...,
        description=(
            "Whether this event's information was directly observed, "
            "enriched, or reconstructed."
        ),
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

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
