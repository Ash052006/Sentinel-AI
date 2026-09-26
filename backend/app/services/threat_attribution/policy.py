"""Threat Attribution deterministic policy — Step 15.

Defines the :class:`AttributionStrategy` contract and the baseline
:class:`DeterministicAttributionStrategy` that implements the documented,
deterministic attribution policy consumed by the
:class:`~app.services.threat_attribution.engine.ThreatAttributionEngine`.

The policy is deliberately conservative and symmetric with the rest of
SentinelAI's deterministic engines (Step 11B risk scoring):

* **Evidence-grounded only** — every candidate target MUST originate from a
  structured :class:`AttributionClaim` (``input.py``).  The policy never
  invents a target, never reads prose, is never influenced by risk level,
  detection severity, investigation confidence, or RAG relevance, and never
  calls any external service or AI.
* **Explicit uncertainty** — status is derived from the *evidence state*
  (claim count, supported targets, conflicting evidence) and is never
  derived from the computed confidence number.  See :func:`assess_status`.
* **Conflicting evidence preserved** — a target supported and contradicted
  simultaneously is emitted as one hypothesis carrying both supporting and
  conflicting evidence references (the Step 14 contract preserves both
  sides and the engine never hides the conflict).  Two or more distinct
  supported targets also produce ``CONFLICTING``: with no relationship
  semantics available, the deterministic engine must not silently pick one
  candidate over another.
* **Confidence policy** — hypothesis confidence is computed ONLY from the
  target's own supporting/conflicting *signal counts* via a documented
  closed-form::

      confidence = (s / (s + c)) * min(s, CONFIDENCE_SATURATION) / CONFIDENCE_SATURATION

  where ``s`` is the supporting-signal count and ``c`` the
  conflicting-signal count for the target.  It is monotone in ``s``,
  decreasing in ``c``, saturates at ``CONFIDENCE_SATURATION`` supporting
  signals, and is computed with ``Fraction`` arithmetic so published values
  are exact and reproducible.  It is never a transformed risk/detection/
  investigation/RAG value.
* **Sufficiency** — a hypothesis is only emitted when a target has at least
  ``MIN_SUPPORTING_SIGNALS`` (1) supporting claim; a target with zero
  supporting claims is never hypothesized.  The policy never fabricates a
  hypothesis just because a signal "sounded useful".
* **Bounded** — the number of hypotheses is capped by the Step 14
  ``MAX_ATTRIBUTION_HYPOTHESES`` (10); inputs that would exceed it are
  rejected by the engine.  Evidence count is bounded by the Step 14
  ``MAX_ATTRIBUTION_EVIDENCE_ITEMS`` (250), which equals the input claim
  cap.
* **Deterministic & non-mutating** — claims are grouped in a single pass
  over input order (O(n)); candidate ordering is by
  ``(target_type.value, target_identifier)`` so identical input always
  yields identical hypotheses; inputs are never mutated.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from fractions import Fraction
from typing import Callable, Protocol

from app.schemas.threat_attribution import (
    AttributionAssessment,
    AttributionEvidence,
    AttributionHypothesis,
    AttributionStatus,
    AttributionTargetType,
    MAX_ATTRIBUTION_EVIDENCE_ITEMS,
    MAX_ATTRIBUTION_HYPOTHESES,
)
from app.services.threat_attribution.exceptions import (
    AttributionEvidenceReferenceError,
    UnsupportedAttributionSignalError,
)
from app.services.threat_attribution.input import (
    AttributionRelation,
    ThreatAttributionInput,
)

# ---------------------------------------------------------------------------
# Policy constants — single source of truth (documented + tested)
# ---------------------------------------------------------------------------

#: Policy label recorded in every assessment's metadata.
POLICY_NAME = "deterministic_attribution_signals_v1"

#: Confidence precision shared by every published confidence value.
CONFIDENCE_DECIMALS = 6

#: Minimum supporting signals required before a target becomes a hypothesis.
MIN_SUPPORTING_SIGNALS = 1

#: Supporting signals at which a single uncontested target is ATTRIBUTED.
ATTRIBUTED_MIN_SUPPORTING_SIGNALS = 2

#: Supporting-signal count at which the support contribution saturates.
CONFIDENCE_SATURATION = 3

#: Decision-path labels recorded in assessment metadata (explainability).
DECISION_NO_CLAIMS = "no_attribution_claims"
DECISION_NO_SUPPORTED_TARGET = "no_supported_target"
DECISION_SINGLE_SUPPORTED_CONFLICTED = "single_supported_target_conflicted"
DECISION_MULTI_SUPPORTED_TARGETS = "multiple_supported_targets"
DECISION_ATTRIBUTED = "single_supported_target_attributed"
DECISION_PARTIALLY_SUPPORTED = "single_supported_target_partial"


# ---------------------------------------------------------------------------
# Pure policy helpers (each tested directly)
# ---------------------------------------------------------------------------


def attribution_confidence(supporting: int, conflicting: int) -> float:
    """Compute target confidence purely from its signal counts.

    ``confidence = (s / (s + c)) * min(s, SATURATION) / SATURATION`` using
    exact ``Fraction`` arithmetic, rounded to ``CONFIDENCE_DECIMALS``.

    Raises:
        ValueError: if *supporting* < 1 (a confidence is only defined for a
            supported target) or *conflicting* < 0.
    """
    if supporting < 1:
        raise ValueError("confidence is only defined for a supported target")
    if conflicting < 0:
        raise ValueError("conflicting must be non-negative")
    proportion = Fraction(supporting, supporting + conflicting)
    saturation = Fraction(min(supporting, CONFIDENCE_SATURATION), CONFIDENCE_SATURATION)
    return round(float(proportion * saturation), CONFIDENCE_DECIMALS)


def assess_status(
    *,
    claim_count: int,
    supported_targets: tuple[tuple[str, int, int], ...],
) -> AttributionStatus:
    """Derive the categorical assessment status from the evidence state.

    Order of checks (documented policy):

    1. ``claim_count == 0`` → ``INSUFFICIENT_EVIDENCE`` (no evidence).
    2. no supported target → ``UNATTRIBUTED`` (evidence existed but nothing
       supported a candidate).
    3. any target with conflicting claims → ``CONFLICTING`` (that candidate
       is both supported and contradicted).
    4. two or more distinct supported targets → ``CONFLICTING`` (the policy
       must not silently pick between candidates).
    5. otherwise: the single uncontested supported target → ``ATTRIBUTED``
       when it has at least ``ATTRIBUTED_MIN_SUPPORTING_SIGNALS`` supporting
       claims, else ``PARTIALLY_SUPPORTED``.

    ``supported_targets`` is a deterministic sequence of
    ``(target_key, supporting_count, conflicting_count)`` tuples.
    """
    if claim_count == 0:
        return AttributionStatus.INSUFFICIENT_EVIDENCE
    if not supported_targets:
        return AttributionStatus.UNATTRIBUTED
    if any(conflicting > 0 for _, _, conflicting in supported_targets):
        return AttributionStatus.CONFLICTING
    if len(supported_targets) >= 2:
        return AttributionStatus.CONFLICTING
    supporting = supported_targets[0][1]
    if supporting >= ATTRIBUTED_MIN_SUPPORTING_SIGNALS:
        return AttributionStatus.ATTRIBUTED
    return AttributionStatus.PARTIALLY_SUPPORTED


# ---------------------------------------------------------------------------
# Strategy contract
# ---------------------------------------------------------------------------


class AttributionStrategy(Protocol):
    """Strategy contract consumed by the Threat Attribution Engine.

    A strategy deterministically evaluates a validated
    :class:`ThreatAttributionInput` into a Step 14
    :class:`AttributionAssessment`.  It must:

    * be deterministic and stateless (same input + same ``timestamp`` +
      same ``uuid_factory`` ⇒ identical output);
    * never mutate its input and never read ``input.context`` (risk /
      investigation / RAG observations are policy-independent);
    * only produce hypotheses for targets declared by input claims;
    * raise :class:`AttributionStrategyError`-family exceptions for genuine
      policy failures.
    """

    name: str

    def assess(
        self,
        input_data: ThreatAttributionInput,
        *,
        timestamp: datetime,
        uuid_factory: Callable[[], uuid.UUID],
    ) -> AttributionAssessment:
        """Evaluate *input_data* as of *timestamp* into an assessment."""
        ...


# ---------------------------------------------------------------------------
# Baseline deterministic strategy
# ---------------------------------------------------------------------------


class DeterministicAttributionStrategy:
    """Baseline deterministic, evidence-grounded attribution strategy.

    Implements the policy described in the module docstring.  Calling the
    strategy directly (bypassing the engine) is supported for policy tests;
    the engine additionally performs input semantic validation, secret
    scanning, clock/UUID injection, and output re-validation.
    """

    name = POLICY_NAME

    def assess(
        self,
        input_data: ThreatAttributionInput,
        *,
        timestamp: datetime,
        uuid_factory: Callable[[], uuid.UUID],
    ) -> AttributionAssessment:
        if not isinstance(input_data, ThreatAttributionInput):
            raise TypeError(
                "attribution strategy requires a ThreatAttributionInput; "
                "received "
                f"{type(input_data).__module__}.{type(input_data).__qualname__}"
            )

        claims = input_data.claims

        # Single-pass grouping: iteration order is claim order; buckets are
        # keyed by (target_type.value, target_identifier).
        buckets: dict[tuple[str, str], dict[str, object]] = {}
        unsupported_unknown_count = 0
        for claim in claims:
            if claim.target_type is AttributionTargetType.UNKNOWN:
                unsupported_unknown_count += 1
                continue
            key = (claim.target_type.value, claim.target_identifier)
            bucket = buckets.get(key)
            if bucket is None:
                bucket = {
                    "supporting_count": 0,
                    "conflicting_count": 0,
                    "supporting_ids": [],
                    "conflicting_ids": [],
                }
                buckets[key] = bucket
            if claim.relationship is AttributionRelation.SUPPORTS:
                bucket["supporting_count"] += 1
                bucket["supporting_ids"].append(claim)
            else:
                bucket["conflicting_count"] += 1
                bucket["conflicting_ids"].append(claim)

        if unsupported_unknown_count:
            raise UnsupportedAttributionSignalError(
                "attribution input declares "
                f"{unsupported_unknown_count} claim(s) targeting 'unknown'; "
                "the deterministic policy only attributes to explicit, "
                "named candidates"
            )

        supported_keys = sorted(
            key
            for key, bucket in buckets.items()
            if int(bucket["supporting_count"]) >= MIN_SUPPORTING_SIGNALS
        )

        # Evidence records: one per claim, in claim order.
        evidence_map: dict[uuid.UUID, uuid.UUID] = {}
        evidence: list[AttributionEvidence] = []
        for claim in claims:
            if claim.target_type is AttributionTargetType.UNKNOWN:
                continue
            evidence_id = uuid_factory()
            evidence_map[claim.claim_id] = evidence_id
            merged_metadata = dict(claim.metadata)
            merged_metadata["claim_id"] = str(claim.claim_id)
            evidence.append(
                AttributionEvidence(
                    evidence_id=evidence_id,
                    evidence_type=claim.evidence_type,
                    provenance=claim.provenance,
                    event_id=claim.event_id,
                    detection_id=claim.detection_id,
                    correlation_id=claim.correlation_id,
                    risk_assessment_id=claim.risk_assessment_id,
                    investigation_id=claim.investigation_id,
                    metadata=merged_metadata,
                )
            )

        hypotheses: list[AttributionHypothesis] = []
        for key in supported_keys:
            bucket = buckets[key]
            supporting_ids = [
                evidence_map[claim.claim_id]
                for claim in bucket["supporting_ids"]
            ]
            conflicting_ids = [
                evidence_map[claim.claim_id]
                for claim in bucket["conflicting_ids"]
            ]
            hypotheses.append(
                AttributionHypothesis(
                    hypothesis_id=uuid_factory(),
                    target_type=AttributionTargetType(key[0]),
                    target_identifier=key[1],
                    confidence=attribution_confidence(
                        int(bucket["supporting_count"]),
                        int(bucket["conflicting_count"]),
                    ),
                    supporting_evidence_ids=supporting_ids,
                    conflicting_evidence_ids=conflicting_ids,
                    metadata={
                        "supporting_signal_count": int(bucket["supporting_count"]),
                        "conflicting_signal_count": int(bucket["conflicting_count"]),
                    },
                )
            )

        # Status is derived from the evidence state, never from confidence.
        supported_snapshot = tuple(
            (key, int(buckets[key]["supporting_count"]), int(buckets[key]["conflicting_count"]))
            for key in supported_keys
        )
        status = assess_status(
            claim_count=len(claims),
            supported_targets=supported_snapshot,
        )

        assessment = AttributionAssessment(
            attribution_assessment_id=uuid_factory(),
            correlation_id=input_data.correlation_id,
            status=status,
            hypotheses=hypotheses,
            evidence=evidence,
            metadata=_policy_metadata(
                claim_count=len(claims),
                supported_target_count=len(hypotheses),
                status=status,
            ),
            timestamp=timestamp,
        )

        _assert_output_resolvable(assessment)
        return assessment


def _policy_metadata(
    *,
    claim_count: int,
    supported_target_count: int,
    status: AttributionStatus,
) -> dict[str, object]:
    """Deterministic, JSON-compatible, secret-free policy metadata.

    Contains only counts, the policy label, and the decision path — never
    timestamps, identities, raw input, or content copied from claims.
    """
    decision: str
    if status is AttributionStatus.INSUFFICIENT_EVIDENCE:
        decision = DECISION_NO_CLAIMS
    elif status is AttributionStatus.UNATTRIBUTED:
        decision = DECISION_NO_SUPPORTED_TARGET
    elif status is AttributionStatus.CONFLICTING:
        if supported_target_count >= 2:
            decision = DECISION_MULTI_SUPPORTED_TARGETS
        else:
            decision = DECISION_SINGLE_SUPPORTED_CONFLICTED
    elif status is AttributionStatus.ATTRIBUTED:
        decision = DECISION_ATTRIBUTED
    else:
        decision = DECISION_PARTIALLY_SUPPORTED
    return {
        "policy": POLICY_NAME,
        "claim_count": claim_count,
        "supported_target_count": supported_target_count,
        "decision": decision,
        "min_supporting_signals": MIN_SUPPORTING_SIGNALS,
        "attributed_min_supporting_signals": ATTRIBUTED_MIN_SUPPORTING_SIGNALS,
        "confidence_saturation": CONFIDENCE_SATURATION,
    }


def _assert_output_resolvable(assessment: AttributionAssessment) -> None:
    """Reject evidence/resolution failures in a strategy-produced output.

    Every hypothesis must reference evidence present on the assessment and
    must carry at least one supporting reference; counts must respect the
    Step 14 hard bounds.  This is the strategy-side equivalent of the
    engine's output re-validation and makes fabricated citations
    structurally impossible before the Step 14 contract is consulted.
    """
    known = {item.evidence_id for item in assessment.evidence}
    for hypothesis in assessment.hypotheses:
        if not hypothesis.supporting_evidence_ids:
            raise AttributionEvidenceReferenceError(
                "strategy produced a hypothesis without supporting evidence "
                "references; rejection rather than fabrication"
            )
        unresolved = [
            reference
            for reference in [
                *hypothesis.supporting_evidence_ids,
                *hypothesis.conflicting_evidence_ids,
            ]
            if reference not in known
        ]
        if unresolved:
            raise AttributionEvidenceReferenceError(
                "strategy produced a hypothesis referencing evidence outside "
                "the assessment; rejection rather than fabrication"
            )
    if len(assessment.evidence) > MAX_ATTRIBUTION_EVIDENCE_ITEMS:
        raise AttributionEvidenceReferenceError(
            "strategy produced evidence beyond the Step 14 bound"
        )
    if len(assessment.hypotheses) > MAX_ATTRIBUTION_HYPOTHESES:
        raise AttributionEvidenceReferenceError(
            "strategy produced hypotheses beyond the Step 14 bound"
        )