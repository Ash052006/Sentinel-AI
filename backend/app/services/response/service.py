"""Response & Mitigation orchestration service (Step 25).

A thin, deterministic facade over :class:`ResponseExecutor`.  It
deliberately owns **no** policy-judging, no Gemini, no SQL, no commands,
and no OS manipulation — every decision happens inside the executor's
independent policy gate, and every action is realized by a registered
provider.

Typical call chain (integration)::

    RiskAssessment / Investigation / Attribution
      -> PolicyInput -> PolicyDecisionEngine -> PolicyDecision (ALLOWED)
        -> ResponseRequest -> ResponseMitigationService.execute
          -> ResponseExecutor -> ResponseProvider -> ResponseResult
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.schemas.policy_decision import ResponseActionType
from app.schemas.response import ResponseRequest, ResponseResult
from app.services.response import validator as _v  # noqa: A004
from app.services.response.approval_gate import ApprovalVerifier
from app.services.response.executor import ResponseExecutor
from app.services.response.registry import (
    DEFAULT_RESPONSE_REGISTRY,
    ResponseProviderRegistry,
)


class ResponseMitigationService:
    """Version 1 response & mitigation entry point.

    Attributes:
        executor: The gate-and-execute engine (injected for tests).
    """

    def __init__(
        self,
        *,
        executor: ResponseExecutor | None = None,
        registry: ResponseProviderRegistry | None = None,
        clock: Any = None,
        approval_verifier: ApprovalVerifier | None = None,
    ) -> None:
        self._executor = executor or ResponseExecutor(
            registry=registry or DEFAULT_RESPONSE_REGISTRY,
            clock=clock,
            approval_verifier=approval_verifier,
        )

    @property
    def executor(self) -> ResponseExecutor:
        return self._executor

    @property
    def registry(self) -> ResponseProviderRegistry:
        return self._executor.registry

    @property
    def processed_count(self) -> int:
        """Number of distinct idempotency keys processed so far."""
        return self._executor.processed_count

    @staticmethod
    def derive_response_id(
        *,
        policy_decision_id: uuid.UUID,
        action: ResponseActionType,
        target: str,
    ) -> uuid.UUID:
        """Determine the canonical ``response_id`` a valid request must
        carry (content-derived, never random)."""
        return _v.derive_response_id(
            policy_decision_id=policy_decision_id,
            action=action,
            target=target,
        )

    @staticmethod
    def derive_idempotency_key(
        *,
        policy_decision_id: uuid.UUID,
        action: ResponseActionType,
        target: str,
    ) -> str:
        """Content-derived SHA-256 idempotency key (same inputs -> same
        key; identical already-processed content is never re-executed)."""
        return _v.derive_idempotency_key(
            policy_decision_id=policy_decision_id,
            action=action,
            target=target,
        )

    def execute(
        self,
        request: ResponseRequest | dict[str, Any],
        policy_decision: Any,
        *,
        clock: Any = None,
    ) -> ResponseResult:
        """Execute *request* under the authorizing *policy_decision*.

        The executor independently enforces the policy gate: only an
        ``ALLOWED``, matching decision ever reaches a provider; anything
        else yields an auditable ``REJECTED`` result (never executed).

        Raises:
            ResponseValidationError: structurally invalid request.
            ResponseInternalError: idempotency-capacity / clock anomaly.
        """
        return self._executor.execute(request, policy_decision, clock=clock)


__all__ = ["ResponseMitigationService"]