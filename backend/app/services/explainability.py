"""Evidence-grounded Explainability service.

Answers *"why does SentinelAI conclude this about a correlation?"* by joining
two independent halves:

1. **Deterministic explanation** — assembled by the platform from
   already-persisted records (correlation, its detections, its risk assessment,
   its approval requests and SOAR executions).  Every dimension is either
   ``grounded`` in a real record, ``none_found`` (the source exists but holds
   nothing for this correlation), or ``unavailable`` (the platform persists no
   such source).  The AI never authors these.
2. **AI narrative (optional)** — the existing Step 12C
   :class:`~app.agents.investigation.agent.InvestigationAgent` reasons over a
   Step 12B :class:`~app.schemas.investigation_context.InvestigationContext`
   built from the same records.  It produces Step 12A findings that may only
   *reference* context evidence; ungrounded findings are flagged.

Trust boundary / design rules:

* **Read-only** — the service never writes, never mutates the session, and
  never calls a provider except through the injected agent factory.
* **No fabrication** — deterministic dimensions come only from persisted
  values; a missing source is reported, never invented.  The AI cannot add
  evidence.
* **Reuse, don't reinvent** — provider selection reuses
  :func:`app.agents.investigation.provider.build_investigation_agent`; the
  context reuses :class:`InvestigationContextBuilder`; the narrative reuses the
  Step 12A result contract.
* **Graceful degradation** — an AI/provider failure yields
  ``ai_unavailable`` with the deterministic dimensions intact, never a 5xx and
  never a fabricated narrative.
* **Bounded** — every read is capped; a documented bound violation fails closed
  rather than silently truncating.
* **Secret-safe** — records were vetted at write; the contracts re-validate
  secret-free payloads at this boundary.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.agents.investigation.agent import InvestigationAgent
from app.agents.investigation.exceptions import (
    InvestigationAgentError,
    InvestigationConfigurationError,
    InvestigationModelOutputError,
    InvestigationModelValidationError,
    InvestigationProviderError,
    InvestigationProviderTimeoutError,
    InvestigationProviderUnavailableError,
)
from app.models.approval_request import ApprovalRequestRow
from app.models.soar_execution import SoarExecutionRow
from app.repositories.approval import ApprovalRepository
from app.repositories.soar import SoarRepository
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
)
from app.schemas.correlation_query import CorrelationResultRecord
from app.schemas.detection_correlation import (
    DetectionCorrelationBatch,
    DetectionCorrelationBatchMetadata,
    to_correlation_input,
)
from app.schemas.detection_query import DetectionResultRecord
from app.schemas.explainability import (
    DimensionCoverage,
    DimensionExplanation,
    ExplanationClaim,
    ExplanationDimension,
    ExplanationStatus,
    ExplainabilityResult,
)
from app.schemas.incident_memory_query import IncidentMemoryRecord
from app.schemas.investigation import InvestigationResult
from app.schemas.investigation_context import (
    InvestigationContext,
    InvestigationContextBuilder,
)
from app.schemas.risk import (
    RiskAssessment,
    RiskEvidence,
    RiskFactor,
)
from app.schemas.risk_query import RiskAssessmentRecord
from app.schemas.security_event import Provenance
from app.services.correlation_query import CorrelationQueryService
from app.services.detection_query import DetectionQueryService
from app.services.incident_memory_query import IncidentMemoryQueryService
from app.services.risk_query import RiskQueryService

logger = logging.getLogger(__name__)

#: Deterministic namespace for explanation evidence ids local to this service.
#: (Deterministic dimensions reference the context's evidence ids instead;
#: this namespace is reserved for future per-dimension synthetic ids.)
DEFAULT_MAX_DETECTIONS = 500
DEFAULT_MAX_MEMORIES = 100
DEFAULT_MAX_APPROVALS = 100
DEFAULT_MAX_SOAR_EXECUTIONS = 100


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ExplainabilityError(Exception):
    """Base error for the explanation service (sanitized messages only)."""


class ExplainabilityNotFoundError(ExplainabilityError):
    """The correlation to explain does not exist."""

    def __init__(self, correlation_id: uuid.UUID) -> None:
        super().__init__(f"correlation {correlation_id} was not found")
        self.correlation_id = correlation_id


class ExplainabilityValidationError(ExplainabilityError):
    """The supplied correlation id is malformed."""


class ExplainabilityContextError(ExplainabilityError):
    """A persisted record could not be assembled into a valid context."""


class ExplainabilityBoundError(ExplainabilityError):
    """A documented bound was exceeded (fail closed; never truncate)."""


# ---------------------------------------------------------------------------
# Safe helpers
# ---------------------------------------------------------------------------


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _coerce_uuid(value: object, *, field: str = "id") -> uuid.UUID:
    try:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ExplainabilityValidationError(
            f"{field} must be a valid UUID"
        ) from exc


# ---------------------------------------------------------------------------
# Domain adapters (read model -> Step 10A / 11A domain contract)
# ---------------------------------------------------------------------------


def _to_domain_correlation(record: CorrelationResultRecord) -> CorrelationResult:
    """Reconstruct the Step 10A domain ``CorrelationResult`` from its read model.

    The persisted evidence and result-metadata are carried verbatim; members are
    restored in ``member_order`` so the domain contract sees the same
    membership the correlation engine produced.  The Step 10A contract
    re-validates timestamps and secret-freedom, so a corrupted row fails closed
    here rather than reaching the agent.
    """
    if not record.members:
        raise ExplainabilityContextError(
            f"correlation {record.correlation_id} has no members; it cannot be "
            "explained"
        )
    ordered = sorted(record.members, key=lambda m: (m.member_order, m.id))
    try:
        members = [
            CorrelationMember(
                detection_id=_coerce_uuid(member.detection_id),
                event_id=_coerce_uuid(member.event_id),
                timestamp=_as_utc(member.timestamp),
            )
            for member in ordered
        ]
        return CorrelationResult(
            correlation_id=_coerce_uuid(record.correlation_id),
            members=members,
            status=record.status,
            confidence=record.confidence,
            evidence=dict(record.evidence or {}),
            metadata=dict(record.result_metadata or {}),
            timestamp=_as_utc(record.timestamp),
            provenance=record.provenance,
        )
    except ExplainabilityError:
        raise
    except Exception as exc:
        raise ExplainabilityContextError(
            f"correlation {record.correlation_id} could not be reconstructed "
            "as a valid correlation result"
        ) from exc


def _to_domain_risk(record: RiskAssessmentRecord) -> RiskAssessment:
    """Reconstruct the Step 11A domain ``RiskAssessment`` from its read model."""
    try:
        factors = [RiskFactor.model_validate(f) for f in (record.factors or [])]
        evidence = [RiskEvidence.model_validate(e) for e in (record.evidence or [])]
    except Exception as exc:  # pydantic ValidationError and friends
        raise ExplainabilityContextError(
            f"risk assessment {record.risk_assessment_id} carries an "
            "unparseable factor/evidence payload"
        ) from exc
    try:
        return RiskAssessment(
            risk_assessment_id=_coerce_uuid(record.risk_assessment_id),
            correlation_id=_coerce_uuid(record.correlation_id),
            score=record.score,
            level=record.level,
            confidence=record.confidence,
            factors=factors,
            evidence=evidence,
            metadata=dict(record.assessment_metadata or {}),
            timestamp=_as_utc(record.timestamp),
            provenance=record.provenance,
        )
    except ExplainabilityError:
        raise
    except Exception as exc:
        raise ExplainabilityContextError(
            f"risk assessment {record.risk_assessment_id} could not be "
            "reconstructed as a valid risk assessment"
        ) from exc


# ---------------------------------------------------------------------------
# Injectable sources (testable without a database)
# ---------------------------------------------------------------------------


class ExplainabilitySources:
    """Replaceable read sources and AI seam for :class:`ExplainabilityService`.

    Every default is the production implementation; tests inject fakes to run
    without a database or a provider key.  All reads are strictly read-only.
    """

    def __init__(
        self,
        *,
        correlation_service: CorrelationQueryService | None = None,
        detection_service: DetectionQueryService | None = None,
        risk_service: RiskQueryService | None = None,
        memory_service: IncidentMemoryQueryService | None = None,
        approval_repository_factory: Callable[[Session], ApprovalRepository] = ApprovalRepository,
        soar_repository_factory: Callable[[Session], SoarRepository] = SoarRepository,
        context_builder: InvestigationContextBuilder | None = None,
        agent_factory: Callable[[], InvestigationAgent] | None = None,
    ) -> None:
        self.correlation_service = correlation_service or CorrelationQueryService()
        self.detection_service = detection_service or DetectionQueryService()
        self.risk_service = risk_service or RiskQueryService()
        self.memory_service = memory_service or IncidentMemoryQueryService()
        self.approval_repository_factory = approval_repository_factory
        self.soar_repository_factory = soar_repository_factory
        self.context_builder = context_builder or InvestigationContextBuilder()
        self.agent_factory = agent_factory


class ExplainabilityService:
    """Read-only explanation of one correlation's persisted reasoning."""

    def __init__(
        self,
        sources: ExplainabilitySources | None = None,
        *,
        max_detections: int = DEFAULT_MAX_DETECTIONS,
        max_memories: int = DEFAULT_MAX_MEMORIES,
        max_approvals: int = DEFAULT_MAX_APPROVALS,
        max_soar_executions: int = DEFAULT_MAX_SOAR_EXECUTIONS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.sources = sources or ExplainabilitySources()
        self._max_detections = max_detections
        self._max_memories = max_memories
        self._max_approvals = max_approvals
        self._max_soar = max_soar_executions
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def explain_correlation(
        self,
        db: Session,
        correlation_id: uuid.UUID | str,
        *,
        use_ai: bool = True,
    ) -> ExplainabilityResult:
        """Explain the correlation identified by *correlation_id*.

        Args:
            db: Caller-owned session.  Never mutated by this service.
            correlation_id: The correlation to explain.
            use_ai: When ``False`` only the deterministic dimensions are
                produced (status ``insufficient_evidence``).

        Raises:
            ExplainabilityValidationError: malformed correlation id.
            ExplainabilityNotFoundError: the correlation does not exist.
            ExplainabilityContextError: a persisted record was unusable.
            ExplainabilityBoundError: a documented bound was exceeded.
        """
        cid = _coerce_uuid(correlation_id, field="correlation_id")

        record = self._load_correlation(db, cid)
        if record is None:
            raise ExplainabilityNotFoundError(cid)

        correlation = _to_domain_correlation(record)
        detections, detection_records = self._load_detections(db, record)
        risk_record = self._load_risk(db, record)
        risk = _to_domain_risk(risk_record) if risk_record is not None else None
        memories = self._load_memories(db, record)
        approvals = self._load_approvals(db, record)
        soar_rows = self._load_soar(db, record)

        context = self._build_context(
            correlation=correlation,
            risk=risk,
            detections=detections,
            memories=memories,
        )

        dimensions, limitations = self._build_dimensions(
            record=record,
            detection_records=detection_records,
            risk_record=risk_record,
            approvals=approvals,
            soar_rows=soar_rows,
            context=context,
        )

        narrative: list = []
        observations: list = []
        evidence = list(context.evidence)
        unsupported: list[str] = []
        ai_provider: str | None = None
        ai_model: str | None = None
        status = ExplanationStatus.INSUFFICIENT_EVIDENCE

        if use_ai:
            investigation, ai_note = self._run_ai(context)
            if investigation is not None:
                narrative = investigation.findings
                observations = investigation.observations
                evidence = investigation.evidence or evidence
                ai_provider = investigation.metadata.get("provider")
                ai_model = investigation.metadata.get("model")
                unsupported = [
                    finding.title
                    for finding in investigation.findings
                    if not finding.evidence_ids
                ]
                status = ExplanationStatus.EXPLAINED
            else:
                status = ExplanationStatus.AI_UNAVAILABLE
                limitations.append(ai_note or "AI narrative was unavailable.")

        return ExplainabilityResult(
            correlation_id=cid,
            generated_at=self._clock(),
            status=status,
            dimensions=dimensions,
            ai_provider=ai_provider,
            ai_model=ai_model,
            narrative=narrative,
            observations=observations,
            evidence=evidence,
            unsupported_claims=unsupported,
            limitations=limitations,
            metadata={
                "investigation_context_id": str(context.investigation_id),
                "detection_count": len(detection_records),
                "uses_ai": use_ai,
            },
        )

    # ------------------------------------------------------------------
    # Loaders (read-only)
    # ------------------------------------------------------------------

    def _load_correlation(
        self, db: Session, correlation_id: uuid.UUID
    ) -> CorrelationResultRecord | None:
        try:
            return self.sources.correlation_service.get_correlation(db, correlation_id)
        except ExplainabilityError:
            raise
        except Exception as exc:
            raise ExplainabilityContextError(
                "failed to load the correlation"
            ) from exc

    def _load_detections(
        self, db: Session, record: CorrelationResultRecord
    ) -> tuple[DetectionCorrelationBatch, list[DetectionResultRecord]]:
        ordered = sorted(record.members, key=lambda m: (m.member_order, m.id))
        seen: set[uuid.UUID] = set()
        inputs = []
        resolved: list[DetectionResultRecord] = []
        for member in ordered:
            detection_id = _coerce_uuid(member.detection_id)
            if detection_id in seen:
                continue
            seen.add(detection_id)
            if len(resolved) >= self._max_detections:
                raise ExplainabilityBoundError(
                    f"resolved detections exceed the bound "
                    f"({self._max_detections}); the explanation was refused "
                    "rather than truncated"
                )
            row = self._get_detection(db, detection_id)
            if row is None:
                continue
            try:
                inputs.append(to_correlation_input(row))
            except Exception as exc:
                raise ExplainabilityContextError(
                    f"detection {detection_id} could not cross into the "
                    "correlation boundary"
                ) from exc
            resolved.append(row)
        batch = DetectionCorrelationBatch(
            detections=inputs,
            metadata=DetectionCorrelationBatchMetadata(record_count=len(inputs)),
        )
        return batch, resolved

    def _get_detection(
        self, db: Session, detection_id: uuid.UUID
    ) -> DetectionResultRecord | None:
        try:
            return self.sources.detection_service.get_result(db, detection_id)
        except ExplainabilityError:
            raise
        except Exception as exc:
            raise ExplainabilityContextError(
                "failed to resolve a member detection"
            ) from exc

    def _load_risk(
        self, db: Session, record: CorrelationResultRecord
    ) -> RiskAssessmentRecord | None:
        try:
            page = self.sources.risk_service.list_assessments_for_correlation(
                db, record.correlation_id, page=1, page_size=1
            )
        except ExplainabilityError:
            raise
        except Exception as exc:
            raise ExplainabilityContextError(
                "failed to load risk assessments"
            ) from exc
        return page.items[0] if page.items else None

    def _load_memories(
        self, db: Session, record: CorrelationResultRecord
    ) -> list[IncidentMemoryRecord]:
        try:
            page = self.sources.memory_service.list_memories_for_correlation(
                db,
                record.correlation_id,
                page=1,
                page_size=self._max_memories,
            )
        except ExplainabilityError:
            raise
        except Exception as exc:
            raise ExplainabilityContextError(
                "failed to load incident memories"
            ) from exc
        return list(page.items)

    def _load_approvals(
        self, db: Session, record: CorrelationResultRecord
    ) -> list[ApprovalRequestRow]:
        try:
            rows = self.sources.approval_repository_factory(db).list_for_correlation(
                record.correlation_id, limit=self._max_approvals
            )
        except ExplainabilityError:
            raise
        except Exception as exc:
            raise ExplainabilityContextError(
                "failed to load approval requests"
            ) from exc
        return list(rows)

    def _load_soar(
        self, db: Session, record: CorrelationResultRecord
    ) -> list[SoarExecutionRow]:
        try:
            rows = self.sources.soar_repository_factory(db).list_for_correlation(
                record.correlation_id, limit=self._max_soar
            )
        except ExplainabilityError:
            raise
        except Exception as exc:
            raise ExplainabilityContextError(
                "failed to load SOAR executions"
            ) from exc
        return list(rows)

    # ------------------------------------------------------------------
    # Context + dimensions
    # ------------------------------------------------------------------

    def _build_context(
        self,
        *,
        correlation: CorrelationResult,
        risk: RiskAssessment | None,
        detections: DetectionCorrelationBatch,
        memories: list[IncidentMemoryRecord],
    ) -> InvestigationContext:
        try:
            return self.sources.context_builder.build(
                correlation=correlation,
                risk_assessment=risk,
                detections=detections,
                historical_memories=memories,
            )
        except ExplainabilityError:
            raise
        except Exception as exc:
            raise ExplainabilityContextError(
                "failed to build the investigation context"
            ) from exc

    def _evidence_ids_by_provenance(
        self, context: InvestigationContext
    ) -> dict[Provenance, list[uuid.UUID]]:
        grouped: dict[Provenance, list[uuid.UUID]] = {}
        for item in context.evidence:
            grouped.setdefault(item.provenance, []).append(item.evidence_id)
        return grouped

    def _build_dimensions(
        self,
        *,
        record: CorrelationResultRecord,
        detection_records: list[DetectionResultRecord],
        risk_record: RiskAssessmentRecord | None,
        approvals: list[ApprovalRequestRow],
        soar_rows: list[SoarExecutionRow],
        context: InvestigationContext,
    ) -> tuple[list[DimensionExplanation], list[str]]:
        evidence = self._evidence_ids_by_provenance(context)
        dimensions = [
            self._correlation_dimension(record, evidence),
            self._detection_dimension(detection_records, evidence),
            self._risk_dimension(risk_record, evidence),
            self._mitre_dimension(detection_records),
            self._policy_dimension(approvals),
            self._response_dimension(approvals, soar_rows),
            self._audit_dimension(),
        ]
        limitations = [
            f"{dim.dimension.value}: {dim.unavailable_reason}"
            for dim in dimensions
            if dim.coverage is DimensionCoverage.UNAVAILABLE
        ]
        limitations += [
            f"{dim.dimension.value}: none_found"
            for dim in dimensions
            if dim.coverage is DimensionCoverage.NONE_FOUND
        ]
        return dimensions, limitations

    @staticmethod
    def _correlation_dimension(
        record: CorrelationResultRecord,
        evidence: dict[Provenance, list[uuid.UUID]],
    ) -> DimensionExplanation:
        member_count = len(record.members)
        distinct_detections = len({_coerce_uuid(m.detection_id) for m in record.members})
        evidence_ids = evidence.get(Provenance.CORRELATED, [])
        claims = [
            ExplanationClaim(
                text=f"Correlation status is {record.status.value}",
                evidence_ids=evidence_ids,
            ),
            ExplanationClaim(
                text=(
                    f"The correlation references {member_count} member(s) "
                    f"across {distinct_detections} distinct detection(s)"
                ),
                evidence_ids=[],
            ),
        ]
        if record.confidence is not None:
            claims.append(
                ExplanationClaim(
                    text=f"Correlation confidence is {record.confidence:.2f}",
                    evidence_ids=evidence_ids,
                )
            )
        return DimensionExplanation(
            dimension=ExplanationDimension.CORRELATION,
            coverage=DimensionCoverage.GROUNDED,
            title="Correlation",
            summary=(
                "How the detections were grouped, reconstructed from the "
                "persisted correlation result."
            ),
            provenance=Provenance.CORRELATED,
            claims=claims,
            reference_ids=[_coerce_uuid(record.correlation_id)],
        )

    @staticmethod
    def _detection_dimension(
        detection_records: list[DetectionResultRecord],
        evidence: dict[Provenance, list[uuid.UUID]],
    ) -> DimensionExplanation:
        evidence_ids = evidence.get(Provenance.DETECTED, [])
        if not detection_records:
            return DimensionExplanation(
                dimension=ExplanationDimension.DETECTION,
                coverage=DimensionCoverage.NONE_FOUND,
                title="Detections",
                summary="No persisted detection record resolved for this correlation.",
                provenance=Provenance.DETECTED,
                claims=[],
                reference_ids=[],
            )
        rules = sorted({row.rule_id for row in detection_records})
        severities = sorted({row.severity.value for row in detection_records})
        claims = [
            ExplanationClaim(
                text=(
                    f"{len(detection_records)} detection(s) matched, spanning "
                    f"{len(rules)} rule(s)"
                ),
                evidence_ids=[],
            ),
            ExplanationClaim(
                text="Matched rules: " + ", ".join(rules),
                evidence_ids=evidence_ids,
            ),
            ExplanationClaim(
                text="Severities observed: " + ", ".join(severities),
                evidence_ids=[],
            ),
        ]
        return DimensionExplanation(
            dimension=ExplanationDimension.DETECTION,
            coverage=DimensionCoverage.GROUNDED,
            title="Detections",
            summary="The persisted detection matches that form this correlation.",
            provenance=Provenance.DETECTED,
            claims=claims,
            reference_ids=[_coerce_uuid(r.detection_id) for r in detection_records],
        )

    @staticmethod
    def _risk_dimension(
        risk_record: RiskAssessmentRecord | None,
        evidence: dict[Provenance, list[uuid.UUID]],
    ) -> DimensionExplanation:
        if risk_record is None:
            return DimensionExplanation(
                dimension=ExplanationDimension.RISK,
                coverage=DimensionCoverage.NONE_FOUND,
                title="Risk",
                summary="This correlation has no persisted risk assessment.",
                provenance=Provenance.RISK_ASSESSED,
                claims=[],
                reference_ids=[],
            )
        evidence_ids = evidence.get(Provenance.RISK_ASSESSED, [])
        claims = [
            ExplanationClaim(
                text=(
                    f"Risk level {risk_record.level.value} with score "
                    f"{risk_record.score:.2f}"
                ),
                evidence_ids=evidence_ids,
            )
        ]
        if risk_record.confidence is not None:
            claims.append(
                ExplanationClaim(
                    text=f"Assessment confidence is {risk_record.confidence:.2f}",
                    evidence_ids=evidence_ids,
                )
            )
        factor_types = [
            f.get("factor_type")
            for f in (risk_record.factors or [])
            if isinstance(f, dict) and f.get("factor_type")
        ]
        if factor_types:
            claims.append(
                ExplanationClaim(
                    text="Contributing factors: " + ", ".join(map(str, factor_types)),
                    evidence_ids=evidence_ids,
                )
            )
        return DimensionExplanation(
            dimension=ExplanationDimension.RISK,
            coverage=DimensionCoverage.GROUNDED,
            title="Risk",
            summary="The persisted risk assessment of this correlation.",
            provenance=Provenance.RISK_ASSESSED,
            claims=claims,
            reference_ids=[_coerce_uuid(risk_record.risk_assessment_id)],
        )

    @staticmethod
    def _mitre_dimension(
        detection_records: list[DetectionResultRecord],
    ) -> DimensionExplanation:
        """MITRE ATT&CK mapping is only grounded when detections carry it.

        The platform persists no ATT&CK mapping table and the detection
        contract defines no MITRE field, so this dimension is *unavailable*
        unless a detection's own structured metadata happens to name a
        technique — in which case only that observed label is reported.
        """
        techniques: dict[str, list[uuid.UUID]] = {}
        for row in detection_records:
            meta = row.result_metadata or {}
            label = None
            if isinstance(meta, dict):
                label = meta.get("mitre_technique") or meta.get("technique_id")
            if isinstance(label, str) and label.strip():
                techniques.setdefault(label.strip(), []).append(
                    _coerce_uuid(row.detection_id)
                )
        if not techniques:
            return DimensionExplanation(
                dimension=ExplanationDimension.MITRE,
                coverage=DimensionCoverage.UNAVAILABLE,
                title="MITRE ATT&CK",
                summary="No MITRE ATT&CK mapping is available for this correlation.",
                provenance=Provenance.DETECTED,
                claims=[],
                reference_ids=[],
                unavailable_reason=(
                    "the platform persists no ATT&CK mapping and the "
                    "detection contract defines no technique field, so no "
                    "grounded mapping can be shown"
                ),
            )
        claims = [
            ExplanationClaim(
                text=f"Technique {label} reported by detections",
                evidence_ids=[],
            )
            for label in sorted(techniques)
        ]
        refs: list[uuid.UUID] = []
        for ids in techniques.values():
            refs.extend(ids)
        return DimensionExplanation(
            dimension=ExplanationDimension.MITRE,
            coverage=DimensionCoverage.GROUNDED,
            title="MITRE ATT&CK",
            summary="Technique labels reported by the persisted detections.",
            provenance=Provenance.DETECTED,
            claims=claims,
            reference_ids=sorted(set(refs)),
        )

    @staticmethod
    def _policy_dimension(
        approvals: list[ApprovalRequestRow],
    ) -> DimensionExplanation:
        """Policy decisions are persisted only as fields on approval requests."""
        if not approvals:
            return DimensionExplanation(
                dimension=ExplanationDimension.POLICY,
                coverage=DimensionCoverage.UNAVAILABLE,
                title="Policy",
                summary="No policy decision is persisted for this correlation.",
                provenance=Provenance.POLICY_DECIDED,
                claims=[],
                reference_ids=[],
                unavailable_reason=(
                    "policy decisions are persisted only as fields on approval "
                    "requests, and none exist for this correlation"
                ),
            )
        claims: list[ExplanationClaim] = []
        refs: list[uuid.UUID] = []
        for row in approvals:
            refs.append(_coerce_uuid(row.approval_id))
            rule = getattr(row, "policy_rule_id", None) or "unknown rule"
            claims.append(
                ExplanationClaim(
                    text=(
                        f"Policy rule {rule} required approval for action "
                        f"{row.action_type} on {row.target}"
                    ),
                    evidence_ids=[],
                )
            )
        return DimensionExplanation(
            dimension=ExplanationDimension.POLICY,
            coverage=DimensionCoverage.GROUNDED,
            title="Policy",
            summary="Policy rules carried by this correlation's approval requests.",
            provenance=Provenance.POLICY_DECIDED,
            claims=claims,
            reference_ids=sorted(set(refs)),
        )

    @staticmethod
    def _response_dimension(
        approvals: list[ApprovalRequestRow],
        soar_rows: list[SoarExecutionRow],
    ) -> DimensionExplanation:
        if not approvals and not soar_rows:
            return DimensionExplanation(
                dimension=ExplanationDimension.RESPONSE,
                coverage=DimensionCoverage.NONE_FOUND,
                title="Response",
                summary="No response action or approval exists for this correlation.",
                provenance=Provenance.RESPONSE_EXECUTED,
                claims=[],
                reference_ids=[],
            )
        claims: list[ExplanationClaim] = []
        refs: list[uuid.UUID] = []
        for row in approvals:
            refs.append(_coerce_uuid(row.approval_id))
            claims.append(
                ExplanationClaim(
                    text=(
                        f"Approval {row.status} for action {row.action_type} "
                        f"on {row.target}"
                    ),
                    evidence_ids=[],
                )
            )
        for row in soar_rows:
            refs.append(_coerce_uuid(row.execution_id))
            claims.append(
                ExplanationClaim(
                    text=(
                        f"SOAR playbook {row.playbook_id} ran action "
                        f"{row.primary_action} on {row.target} "
                        f"(status {row.status}, simulated={bool(row.simulated)})"
                    ),
                    evidence_ids=[],
                )
            )
        return DimensionExplanation(
            dimension=ExplanationDimension.RESPONSE,
            coverage=DimensionCoverage.GROUNDED,
            title="Response",
            summary="The human-in-the-loop approvals and SOAR executions recorded.",
            provenance=Provenance.RESPONSE_EXECUTED,
            claims=claims,
            reference_ids=sorted(set(refs)),
        )

    @staticmethod
    def _audit_dimension() -> DimensionExplanation:
        """Audit entries are not correlation-scoped in the persisted audit log."""
        return DimensionExplanation(
            dimension=ExplanationDimension.AUDIT,
            coverage=DimensionCoverage.UNAVAILABLE,
            title="Audit",
            summary="No correlation-scoped audit trail is available.",
            provenance=Provenance.OBSERVED,
            claims=[],
            reference_ids=[],
            unavailable_reason=(
                "the audit log records actor/action entries by resource name "
                "and is not keyed by correlation, so it cannot be filtered to "
                "this correlation without inventing an association"
            ),
        )

    # ------------------------------------------------------------------
    # AI narrative
    # ------------------------------------------------------------------

    def _run_ai(
        self, context: InvestigationContext
    ) -> tuple[InvestigationResult | None, str | None]:
        """Run the configured agent; degrade gracefully on any failure.

        Returns ``(result, None)`` on success and ``(None, note)`` on failure.
        The note is a sanitized, human-readable degradation statement.
        """
        if self.sources.agent_factory is None:
            return None, "AI narrative was not requested (no agent configured)."
        try:
            agent = self.sources.agent_factory()
            return agent.investigate(context), None
        except InvestigationConfigurationError:
            logger.info("explainability: AI provider is not configured")
            return None, (
                "AI narrative unavailable: the reasoning provider is not "
                "configured."
            )
        except (
            InvestigationProviderTimeoutError,
            InvestigationProviderUnavailableError,
            InvestigationModelOutputError,
            InvestigationModelValidationError,
            InvestigationProviderError,
        ) as exc:
            logger.info("explainability: AI provider degraded (%s)", type(exc).__name__)
            return None, (
                "AI narrative unavailable: the reasoning provider could not "
                "produce a valid, evidence-grounded narrative."
            )
        except InvestigationAgentError as exc:
            logger.info("explainability: AI agent error (%s)", type(exc).__name__)
            return None, "AI narrative unavailable: the investigation agent failed."
        except Exception:
            logger.exception("explainability: unexpected AI failure")
            return None, "AI narrative unavailable: an unexpected error occurred."


__all__ = [
    "ExplainabilityError",
    "ExplainabilityNotFoundError",
    "ExplainabilityValidationError",
    "ExplainabilityContextError",
    "ExplainabilityBoundError",
    "ExplainabilitySources",
    "ExplainabilityService",
    "DEFAULT_MAX_DETECTIONS",
    "DEFAULT_MAX_MEMORIES",
    "DEFAULT_MAX_APPROVALS",
    "DEFAULT_MAX_SOAR_EXECUTIONS",
]
