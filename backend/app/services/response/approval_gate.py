"""Approval gate contract for the Response executor (V2.16).

A small, pure, policy-free seam: the Step 25 Response layer must never
execute a ``REQUIRES_APPROVAL`` decision unless a human grant can be
verified.  It delegates that verification to an :class:`ApprovalVerifier`
injected from outside the Response package — the Response package stays
free of persistence, policy, LLM and I/O concerns, while the approval
service (which owns the database) supplies a verifier that consults the
persisted :class:`~app.schemas.approval.ApprovalRecord`.

Rules the executor enforces when a verifier is present (see
``ResponseExecutor._approval_gate``):

* identity/integrity of decision and request is checked *before* the
  grant is consulted;
* a non-OK grant means ``REJECTED`` and the provider is provably never
  invoked;
* the *absence* of a verifier preserves the historic behaviour
  (``REQUIRES_APPROVAL`` -> ``REJECTED``/``POLICY_REQUIRES_APPROVAL``).

This module is contract only: no database, no network, no filesystem, no
LLM, and no calls — a verifier implementation is supplied by the approval
package.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from app.schemas.policy_decision import ResponseActionType


# ---------------------------------------------------------------------------
# Gate result
# ---------------------------------------------------------------------------

#: Stable rejection codes for a non-OK grant (mapped verbatim onto the
#: ResponseResult.error_code of a REJECTED attempt).
APPROVAL_NOT_GIVEN = "APPROVAL_NOT_GIVEN"
APPROVAL_UNKNOWN = "APPROVAL_UNKNOWN"
APPROVAL_NOT_APPROVED = "APPROVAL_NOT_APPROVED"
APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
APPROVAL_REVOKED = "APPROVAL_REVOKED"
APPROVAL_MISMATCH = "APPROVAL_MISMATCH"


@dataclass(frozen=True)
class ApprovalGateResult:
    """Outcome of consulting a human-approval grant.

    ``ok`` is True only for a verifiable, unexpired, matching grant.  When
    False, ``error_code`` carries the stable reason (one of the
    ``APPROVAL_*`` constants above) that the executor records verbatim.
    """

    ok: bool
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not self.ok and not self.error_code:
            object.__setattr__(self, "error_code", APPROVAL_NOT_GIVEN)


#: A granted, valid approval (the executor has nothing to reject for).
GRANT_GRANTED = ApprovalGateResult(ok=True)

#: No usable grant (used by conservative verifier defaults).
GRANT_NOT_GIVEN = ApprovalGateResult(ok=False, error_code=APPROVAL_NOT_GIVEN)


# ---------------------------------------------------------------------------
# Verifier protocol
# ---------------------------------------------------------------------------


class ApprovalVerifier(Protocol):
    """Answers one question synchronously: *is this grant currently valid
    for this decision/action?*

    Implementations must be deterministic, free of side effects, and free
    of any LLM / policy / response logic — this is the enforcement seam,
    not a decision maker.
    """

    def verify_grant(
        self,
        *,
        approval_id: uuid.UUID | None,
        policy_decision_id: uuid.UUID,
        action_type: ResponseActionType,
        now: datetime,
    ) -> ApprovalGateResult:
        """Return GRANT_GRANTED when the grant is verifiable, else a
        non-OK :class:`ApprovalGateResult` with a stable error code."""
        ...


__all__ = [
    "APPROVAL_EXPIRED",
    "APPROVAL_MISMATCH",
    "APPROVAL_NOT_APPROVED",
    "APPROVAL_NOT_GIVEN",
    "APPROVAL_REVOKED",
    "APPROVAL_UNKNOWN",
    "ApprovalGateResult",
    "ApprovalVerifier",
    "GRANT_GRANTED",
    "GRANT_NOT_GIVEN",
]