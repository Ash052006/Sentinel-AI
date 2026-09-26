"""Response executor — the policy gate and safe orchestration (Step 25).

The executor is the *only* place the response lifecycle is driven, and it
**independently enforces the policy gate** — it does not trust the caller.
Sequence (each step audits a ``ResponseResult`` when it fails):

1. coerce + validate the request (malformed request is a caller error);
2. coerce + verify the policy decision (malformed/unverifiable decision
   fails closed as ``REJECTED/POLICY_INVALID``);
3. policy gate: only ``ALLOWED`` may proceed; ``DENIED`` /
   ``REQUIRES_APPROVAL`` / unknown state -> ``REJECTED`` and the provider
   is provably **never** called;
4. action/correlation/decision integrity: the request must match the
   decision exactly;
5. structural target validation for the exact action (no DNS, no
   filesystem, no network);
6. response identity must equal the deterministic content-derived
   ``response_id`` (no spoofed ids);
7. idempotency: the content-derived key suppresses duplicates — an
   identical, already-processed submission returns the stored result
   without re-invoking the provider;
8. provider resolution (no user-controlled names) and execution;
9. normalization to a provenance-pinned, sanitized ``ResponseResult``.

Failure semantics (§11 of the doctrine):

* ALLOWED + provider success -> ``EXECUTED``
* ALLOWED + provider failure  -> ``FAILED`` (never a silent success)
* DENIED                     -> ``REJECTED`` (provider not called)
* REQUIRES_APPROVAL (no verifier wired) -> ``REJECTED`` (provider not called)
* REQUIRES_APPROVAL (verifier wired)    -> consulted; an invalid/expired/
  unknown/missing grant is ``REJECTED`` and the provider is never called;
  only a verifiable human grant may fall through to execution (V2.16)
* malformed decision         -> ``REJECTED`` / fail closed
* invalid request/action/target -> validation failure (sanitized error)
* unsupported provider       -> ``REJECTED`` (provider not called)
* duplicate identical request -> stored deterministic result returned
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from app.schemas.policy_decision import PolicyDecision, PolicyDecisionStatus
from app.schemas.response import (
    RESPONSE_MAX_PROCESSED_KEYS,
    ResponseExecutionStatus,
    ResponseRequest,
    ResponseResult,
)
from app.schemas.security_event import Provenance
from app.services.response import validator as _v  # noqa: A004
from app.services.response.approval_gate import ApprovalVerifier
from app.services.response.errors import (
    ResponseInternalError,
    ResponseValidationError,
)
from app.services.response.providers import ResponseProvider
from app.services.response.registry import (
    DEFAULT_RESPONSE_REGISTRY,
    ResponseProviderRegistry,
)

#: Rejection message templates (static, sanitized — never echo raw
#: targets or payloads).
_MSG_POLICY_DENIED = (
    "Response not executed: the policy decision is DENIED; no provider "
    "was invoked."
)
_MSG_POLICY_APPROVAL = (
    "Response not executed: the policy decision requires human approval; "
    "no provider was invoked."
)
_MSG_APPROVAL_GRANT_DENIED = (
    "Response not executed: the human approval grant could not be "
    "verified; no provider was invoked."
)
_MSG_POLICY_INVALID = (
    "Response not executed: the policy decision could not be verified "
    "(invalid or unrecognised policy state); no provider was invoked."
)
_MSG_DECISION_MISMATCH = (
    "Response not executed: the request does not match the policy "
    "decision; no provider was invoked."
)
_MSG_TARGET_INVALID = (
    "Response not executed: the target failed structural validation for "
    "the requested action; no provider was invoked."
)
_MSG_IDENTITY_MISMATCH = (
    "Response not executed: the response identity is not the deterministic "
    "content-derived response_id; no provider was invoked."
)
_MSG_PROVIDER_UNSUPPORTED = (
    "Response not executed: no provider is registered for the requested "
    "action; no provider was invoked."
)
_MSG_PROVIDER_FAILED = (
    "Provider execution failed; no action was performed.  "
    "See error_code for the categorized reason."
)


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


class ResponseExecutor:
    """Deterministic executor with an independent policy gate."""

    def __init__(
        self,
        *,
        registry: ResponseProviderRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
        approval_verifier: ApprovalVerifier | None = None,
    ) -> None:
        self._registry: ResponseProviderRegistry = (
            registry if registry is not None else DEFAULT_RESPONSE_REGISTRY
        )
        self._clock: Callable[[], datetime] = clock or _default_now
        #: Optional V2.16 seam that lets REQUIRES_APPROVAL decisions pass
        #: only when a human-approval grant verifies.  Absent (the default)
        #: preserves historic behaviour: REQUIRES_APPROVAL is always
        #: REJECTED and the provider is never called.
        self._approval_verifier: ApprovalVerifier | None = approval_verifier
        #: Content-derived idempotency-key -> already-processed result.
        self._processed: dict[str, ResponseResult] = {}

    @property
    def registry(self) -> ResponseProviderRegistry:
        return self._registry

    @property
    def processed_count(self) -> int:
        return len(self._processed)

    # -- Public entry point ---------------------------------------------------

    def execute(
        self,
        request: ResponseRequest | dict[str, Any],
        policy_decision: PolicyDecision | dict[str, Any],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> ResponseResult:
        """Run the full response lifecycle for *request* under
        *policy_decision* and return the auditable :class:`ResponseResult`.

        Args:
            request: Validated request or plain mapping.  A structurally
                invalid request raises :class:`ResponseValidationError`
                (sanitized); a valid-request-but-denied decision returns
                an auditable ``REJECTED`` result.
            policy_decision: The Step 24 decision authorizing the action.
            clock: Optional per-call UTC clock override (fixed in tests).

        Raises:
            ResponseValidationError: malformed request.
            ResponseInternalError: processed-idempotency capacity
                exhausted, or the clock returned a naive timestamp.
        """
        req = self._coerce_request(request)
        now = (clock or self._clock)()
        self._enforce_clock(now)

        decision = _v.coerce_decision(policy_decision)
        if decision is None:
            return self._reject(req, _MSG_POLICY_INVALID, "POLICY_INVALID", now)
        provider_failure = self._policy_gate(req, decision, now)
        if provider_failure is not None:
            return provider_failure

        # Structural target validation for the EXACT action.
        try:
            target = _v.validate_target(req.action_type, req.target)
        except ResponseValidationError:
            return self._reject(req, _MSG_TARGET_INVALID, "TARGET_INVALID", now)

        # Response identity must be the deterministic content-derived id.
        if not _v.check_request_identity(
            req,
            policy_decision_id=decision.policy_decision_id,
            action=req.action_type,
            target=target,
        ):
            return self._reject(req, _MSG_IDENTITY_MISMATCH, "RESPONSE_ID_MISMATCH", now)

        # Idempotency: identical already-processed content never re-runs.
        key = _v.derive_idempotency_key(
            policy_decision_id=decision.policy_decision_id,
            action=req.action_type,
            target=target,
        )
        already = self._processed.get(key)
        if already is not None:
            # Duplicate suppression: the stored deterministic record is
            # returned by copy so caller mutation can never corrupt it.
            return already.model_copy(deep=True)
        if len(self._processed) >= RESPONSE_MAX_PROCESSED_KEYS:
            raise ResponseInternalError(
                "the response idempotency store is full; provisioning "
                "must be increased before further attempts"
            )

        # Resolve provider (no user-controlled names, no dynamic imports).
        try:
            provider = self._registry.provider_for(req.action_type)
        except ResponseValidationError:
            rejected = self._reject(
                req, _MSG_PROVIDER_UNSUPPORTED, "PROVIDER_UNSUPPORTED", now
            )
            self._processed[key] = rejected
            return rejected.model_copy(deep=True)

        final = self._run_provider(req, target, provider, key, now, clock or self._clock)
        return final.model_copy(deep=True)

    # -- Internal stages ------------------------------------------------------

    @staticmethod
    def _coerce_request(request: Any) -> ResponseRequest:
        if isinstance(request, ResponseRequest):
            return request
        if isinstance(request, dict):
            try:
                return ResponseRequest.model_validate(request)
            except Exception as exc:  # noqa: BLE001 - sanitized, never echoed
                raise ResponseValidationError(
                    "the response request failed validation"
                ) from exc
        raise ResponseValidationError(
            "the response request must be a ResponseRequest instance or a mapping"
        )

    @staticmethod
    def _enforce_clock(now: datetime) -> None:
        tz = now.tzinfo
        if tz is None or tz.utcoffset(now) is None:
            raise ResponseInternalError(
                "the response clock must return a timezone-aware timestamp"
            )

    def _policy_gate(
        self,
        req: ResponseRequest,
        decision: PolicyDecision,
        now: datetime,
    ) -> ResponseResult | None:
        """Return a REJECTED result when the decision does not authorize
        *req*, else None.  Order: provenance, state, then integrity."""
        if decision.provenance is not Provenance.POLICY_DECIDED:
            return self._reject(req, _MSG_POLICY_INVALID, "POLICY_INVALID", now)
        status = decision.decision
        if status is not PolicyDecisionStatus.ALLOWED:
            if status is PolicyDecisionStatus.DENIED:
                return self._reject(
                    req, _MSG_POLICY_DENIED, "POLICY_DENIED", now
                )
            if status is PolicyDecisionStatus.REQUIRES_APPROVAL:
                return self._approval_gate(req, decision, now)
            return self._reject(req, _MSG_POLICY_INVALID, "POLICY_INVALID", now)

        if req.policy_decision_id != decision.policy_decision_id:
            return self._reject(
                req, _MSG_DECISION_MISMATCH, "POLICY_DECISION_MISMATCH", now
            )
        if req.correlation_id != decision.correlation_id:
            return self._reject(req, _MSG_DECISION_MISMATCH, "CORRELATION_MISMATCH", now)
        if req.action_type != decision.requested_action:
            return self._reject(req, _MSG_DECISION_MISMATCH, "ACTION_MISMATCH", now)
        return None

    def _approval_gate(
        self,
        req: ResponseRequest,
        decision: PolicyDecision,
        now: datetime,
    ) -> ResponseResult | None:
        """Gate for a REQUIRES_APPROVAL decision (V2.16).

        With no verifier wired, historic behaviour is preserved:
        REQUIRES_APPROVAL always rejects and the provider is never called.
        With a verifier wired, integrity is checked *before* the grant is
        consulted (never evaluate a grant under a mismatched decision), and
        only a verifiable human grant falls through to execution.
        """
        if self._approval_verifier is None:
            return self._reject(
                req, _MSG_POLICY_APPROVAL, "POLICY_REQUIRES_APPROVAL", now
            )
        if req.policy_decision_id != decision.policy_decision_id:
            return self._reject(
                req, _MSG_DECISION_MISMATCH, "POLICY_DECISION_MISMATCH", now
            )
        if req.correlation_id != decision.correlation_id:
            return self._reject(req, _MSG_DECISION_MISMATCH, "CORRELATION_MISMATCH", now)
        if req.action_type != decision.requested_action:
            return self._reject(req, _MSG_DECISION_MISMATCH, "ACTION_MISMATCH", now)
        grant = self._approval_verifier.verify_grant(
            approval_id=req.approval_id,
            policy_decision_id=decision.policy_decision_id,
            action_type=req.action_type,
            now=now,
        )
        if grant.ok:
            return None
        return self._reject(
            req,
            _MSG_APPROVAL_GRANT_DENIED,
            grant.error_code or "APPROVAL_NOT_GIVEN",
            now,
        )

    def _run_provider(
        self,
        req: ResponseRequest,
        target: str,
        provider: ResponseProvider,
        key: str,
        now: datetime,
        clock: Callable[[], datetime],
    ) -> ResponseResult:
        started = clock()
        self._enforce_clock(started)
        try:
            result = provider.execute(req, clock=clock)
        except Exception as exc:  # noqa: BLE001 - normalized, sanitized
            from app.services.response.errors import ResponseProviderError

            if isinstance(exc, ResponseProviderError):
                error_code = "PROVIDER_ERROR"
            else:
                # Unexpected provider defect: still FAILED, never a
                # propagated leak; the attempt is recorded.
                error_code = "PROVIDER_FAILURE"
            failed = self._build_failed(
                req,
                provider=provider,
                started=started,
                completed=now,
                error_code=error_code,
            )
            self._processed[key] = failed
            return failed

        final = self._normalize(req, provider, target, result, now, key)
        self._processed[key] = final
        return final

    def _normalize(
        self,
        req: ResponseRequest,
        provider: ResponseProvider,
        target: str,
        result: ResponseResult,
        now: datetime,
        key: str,
    ) -> ResponseResult:
        """Enforce result invariants: identity is request-derived, target
        is the canonical form, provenance is RESPONSE_EXECUTED, and the
        record never aliases caller inputs."""
        return ResponseResult(
            response_id=req.response_id,
            policy_decision_id=req.policy_decision_id,
            correlation_id=req.correlation_id,
            action_type=req.action_type,
            execution_status=result.execution_status,
            target=target,
            provider=provider.name,
            started_at=result.started_at,
            completed_at=result.completed_at,
            message=result.message or "Provider completed execution.",
            error_code=result.error_code,
            metadata={
                **result.metadata,
                "simulated": bool(result.metadata.get("simulated", True)),
            },
            timestamp=now,
        )

    def _build_failed(
        self,
        req: ResponseRequest,
        *,
        provider: ResponseProvider,
        started: datetime,
        completed: datetime,
        error_code: str,
    ) -> ResponseResult:
        return ResponseResult(
            response_id=req.response_id,
            policy_decision_id=req.policy_decision_id,
            correlation_id=req.correlation_id,
            action_type=req.action_type,
            execution_status=ResponseExecutionStatus.FAILED,
            target=req.target,
            provider=provider.name,
            started_at=started,
            completed_at=completed,
            message=_MSG_PROVIDER_FAILED,
            error_code=error_code,
            metadata={"simulated": True, "failed": True},
            timestamp=completed,
        )

    def _reject(
        self,
        req: ResponseRequest,
        message: str,
        error_code: str,
        now: datetime,
    ) -> ResponseResult:
        return ResponseResult(
            response_id=req.response_id,
            policy_decision_id=req.policy_decision_id,
            correlation_id=req.correlation_id,
            action_type=req.action_type,
            execution_status=ResponseExecutionStatus.REJECTED,
            target=req.target,
            provider=None,
            started_at=None,
            completed_at=None,
            message=message,
            error_code=error_code,
            metadata={"rejected": True},
            timestamp=now,
        )


__all__ = ["ResponseExecutor"]