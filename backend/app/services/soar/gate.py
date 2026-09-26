"""SOAR policy gate (V2.18).

The engine's **independent** gate: it does not trust the caller.  Before any
provider is invoked the gate re-verifies the authorizing policy decision and
the playbook/decision binding:

* provenance must be ``POLICY_DECIDED``;
* ``DENIED`` (or any unrecognised state) -> ``REJECTED`` and the provider is
  provably never called;
* ``REQUIRES_APPROVAL`` -> success only through the **existing V2.16
  human-in-the-loop approval workflow**: SOAR does not implement its own
  approval mechanism.  When the decision requires approval and no grant is
  verifiable, the run is ``rejected`` (or recorded ``pending`` when no
  ``approval_id`` was even presented) and no provider is ever called;
* ``ALLOWED`` -> integrity re-checks (playbook anchors the decision's
  action) then proceeds.

The gate is pure and side-effect-free.  A concrete grant verifier is
supplied from outside the SOAR package (the approval service's
:class:`~app.services.approval.ApprovalGrantVerifier`, which owns the
database).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.schemas.policy_decision import PolicyDecision, PolicyDecisionStatus
from app.schemas.security_event import Provenance
from app.schemas.soar import SoarExecutionStatus, SoarPlaybookDefinition
from app.services.response.approval_gate import (
    APPROVAL_NOT_GIVEN,
    ApprovalVerifier,
)

#: Stable rejection codes recorded verbatim on rejected/pending runs.
CODE_POLICY_DENIED = "POLICY_DENIED"
CODE_POLICY_INVALID = "POLICY_INVALID"
CODE_POLICY_REQUIRES_APPROVAL = "POLICY_REQUIRES_APPROVAL"
CODE_ACTION_MISMATCH = "ACTION_MISMATCH"
CODE_TARGET_INVALID = "TARGET_INVALID"


@dataclass(frozen=True)
class SoarGateResult:
    """Outcome of the gate.

    * ``allowed``  — True only when a provider may be invoked.
    * ``status``   — the execution status to record when not allowed
      (``rejected`` or ``pending``).
    * ``error_code`` — stable sanitized reason (None when allowed).
    """

    allowed: bool
    status: SoarExecutionStatus = SoarExecutionStatus.REJECTED
    error_code: str | None = None


class SoarPolicyGate:
    """Deterministic, side-effect-free policy gate for SOAR executions."""

    def __init__(
        self,
        *,
        approval_verifier: ApprovalVerifier | None = None,
    ) -> None:
        #: Optional V2.16 seam: lets REQUIRES_APPROVAL decisions pass only
        #: when a human grant verifies.  Absent (default) preserves the
        #: historic behaviour — REQUIRES_APPROVAL never reaches a provider.
        self._approval_verifier = approval_verifier

    def evaluate(
        self,
        *,
        decision: PolicyDecision,
        playbook: SoarPlaybookDefinition,
        approval_id: object,
        now: datetime,
    ) -> SoarGateResult:
        """Return the gate verdict for *decision* + *playbook*.

        Order: provenance, state, then integrity.  The target itself is
        validated by the engine via the Step 25 validator; here we only
        confirm the playbook anchors the decided action.
        """
        if decision.provenance is not Provenance.POLICY_DECIDED:
            return SoarGateResult(False, error_code=CODE_POLICY_INVALID)

        status = decision.decision
        if status is not PolicyDecisionStatus.ALLOWED:
            if status is PolicyDecisionStatus.DENIED:
                return SoarGateResult(False, error_code=CODE_POLICY_DENIED)
            if status is PolicyDecisionStatus.REQUIRES_APPROVAL:
                return self._approval_gate(decision, playbook, approval_id, now)
            return SoarGateResult(False, error_code=CODE_POLICY_INVALID)

        if playbook.primary_action is not decision.requested_action:
            return SoarGateResult(False, error_code=CODE_ACTION_MISMATCH)
        return SoarGateResult(True)

    def _approval_gate(
        self,
        decision: PolicyDecision,
        playbook: SoarPlaybookDefinition,
        approval_id: object,
        now: datetime,
    ) -> SoarGateResult:
        if playbook.primary_action is not decision.requested_action:
            return SoarGateResult(False, error_code=CODE_ACTION_MISMATCH)
        if approval_id is None:
            # No grant even presented: record the run as PENDING (nothing
            # executed).  A later granted re-submission (distinct by its
            # approval-bearing idempotency key) may execute.
            return SoarGateResult(
                False,
                status=SoarExecutionStatus.PENDING,
                error_code=APPROVAL_NOT_GIVEN,
            )
        if self._approval_verifier is None:
            # A grant was presented but no verifier is wired: fail closed.
            return SoarGateResult(
                False,
                error_code=CODE_POLICY_REQUIRES_APPROVAL,
            )
        grant = self._approval_verifier.verify_grant(
            approval_id=approval_id,
            policy_decision_id=decision.policy_decision_id,
            action_type=decision.requested_action,
            now=now,
        )
        if grant.ok:
            return SoarGateResult(True)
        return SoarGateResult(False, error_code=grant.error_code or APPROVAL_NOT_GIVEN)


__all__ = [
    "CODE_ACTION_MISMATCH",
    "CODE_POLICY_DENIED",
    "CODE_POLICY_INVALID",
    "CODE_POLICY_REQUIRES_APPROVAL",
    "CODE_TARGET_INVALID",
    "SoarGateResult",
    "SoarPolicyGate",
]