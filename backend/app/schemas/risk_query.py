"""Risk Query Layer read models — Step 11D.

Read-only views over the Step 11C persistence contract
(:class:`~app.models.risk_assessment.RiskAssessment`).  These are **read
models**: they describe *what the risk query layer returns*, not what the
Step 11A ``RiskAssessment`` authoring contract holds or what the Step 11B
agent produces.

Design principles:

* **Read models only** — no writes, no persistence code, no API endpoints.
  Consumers build these from persisted rows via the read-only
  :class:`~app.services.risk_query.RiskQueryService`.
* **Persisted view** — a record mirrors a database row: the structured
  JSONB ``factors`` / ``evidence`` come back as plain lists of dicts and
  ``assessment_metadata`` as a plain ``dict`` payload, ``score`` /
  ``confidence`` are ``0.0..1.0`` floats persisted exactly as produced,
  ``level`` is the controlled :class:`~app.schemas.risk.RiskLevel`
  enumeration, ``provenance`` is the ``RISK_ASSESSED`` marker every
  persisted row carries, and timestamps are timezone-aware UTC instants.
  No derived/aggregate fields are invented — the query layer is a
  retrieval layer, never a risk engine.
* **Assessment field mapping** — the Step 11A ``metadata`` is persisted to
  the ``assessment_metadata`` column (Step 11C-A) and surfaces here as
  ``RiskAssessmentRecord.assessment_metadata``, following the Detection
  (``result_metadata``) and Correlation (``result_metadata``) read-model
  convention that the record field names the persisted column.
* **Bounded pagination** — list operations return a 1-based page envelope
  (``items`` + ``total`` + requested ``page``/``page_size``) so callers can
  reconstruct state without an unbounded cursor.
* **No secrets** — the layer never fabricates data and only surfaces what
  the persistence contract already stored (factors/evidence/metadata were
  redacted by the Step 11C-B service *before* write).

Relationship to the pipeline::

    RiskPersistenceService                   (Step 11C-B, writes)
        -> risk_assessments                  (Step 11C-A model)
            -> RiskQueryService              (Step 11D, read-only)
                -> RiskAssessmentRecord / RiskAssessmentPage
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Persisted-view record
# ---------------------------------------------------------------------------


class RiskAssessmentRecord(BaseModel):
    """Read-only view of one persisted ``risk_assessments`` row.

    Attribute names mirror the Step 11C-A persistence contract columns; the
    structured JSONB ``factors``/``evidence`` payloads are exposed as plain
    lists of dicts and ``assessment_metadata`` as a plain dictionary.
    ``score``/``confidence`` are the exact Step 11B-produced values (bounded
    to ``[0.0, 1.0]`` by DB CHECK constraints), ``level`` is the persisted
    ``RiskLevel`` enumeration, and ``provenance`` is always ``RISK_ASSESSED``.
    Nothing is recalculated or re-derived on read.
    """

    id: uuid.UUID = Field(
        ...,
        description="Primary-key UUID of the persisted risk_assessments row.",
    )
    risk_assessment_id: uuid.UUID = Field(
        ...,
        description=(
            "Step 11A RiskAssessment.risk_assessment_id.  Unique identity "
            "of the persisted assessment — the query key."
        ),
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description=(
            "The evaluated correlation (Step 10A correlation identity).  "
            "Not unique at rest — one correlation may carry several "
            "historical assessments."
        ),
    )
    score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Step 11B risk score in [0.0, 1.0], persisted exactly.",
    )
    level: RiskLevel = Field(
        ...,
        description=(
            "Controlled risk level (low / medium / high / critical), "
            "persisted exactly as scored.  Never re-derived from score."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Step 11B assessment confidence in [0.0, 1.0].  Independent of "
            "score/level; persisted exactly."
        ),
    )
    factors: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured Step 11A risk factors (JSONB), preserved exactly.",
    )
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured Step 11A risk evidence (JSONB), preserved exactly.",
    )
    assessment_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Safe, non-secret Step 11A assessment metadata as stored (JSONB); "
            "the persisted form of ``RiskAssessment.metadata``."
        ),
    )
    timestamp: datetime = Field(
        ...,
        description=(
            "When the assessment was produced (Step 11A result timestamp, "
            "UTC, timezone-aware)."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.RISK_ASSESSED,
        description="Assessment provenance; always RISK_ASSESSED for persisted rows.",
    )
    created_at: datetime = Field(
        ...,
        description="When the row was first persisted (UTC, timezone-aware).",
    )
    updated_at: datetime = Field(
        ...,
        description="When the row was last modified (UTC, timezone-aware).",
    )


# ---------------------------------------------------------------------------
# Pagination envelope
# ---------------------------------------------------------------------------


class RiskAssessmentPage(BaseModel):
    """One 1-based page of persisted risk assessments."""

    items: list[RiskAssessmentRecord] = Field(
        ...,
        description="The page's assessment records, newest first.",
    )
    total: int = Field(
        ...,
        ge=0,
        description="Total number of persisted assessments matching the query.",
    )
    page: int = Field(
        ...,
        ge=1,
        description="Requested 1-based page number.",
    )
    page_size: int = Field(
        ...,
        ge=1,
        description="Requested maximum number of items per page.",
    )