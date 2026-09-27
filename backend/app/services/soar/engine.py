"""SOAR execution engine (V2.18).

The engine is the *only* place a SOAR run is driven.  It is deliberately
pure with respect to persistence: it returns deterministic read records
(:class:`~app.schemas.soar.SoarExecutionRecord` / a dry-run projection);
durability is owned by the service layer.

Sequence (each refusal is auditable and provably never reaches a provider):

1. coerce + validate the execution request (malformed request is a caller
   error);
2. resolve the registered playbook (unknown playbook -> fail closed);
3. independent policy gate — ``DENIED`` / invalid / unverifiable-grant
   decisions are ``REJECTED`` and no provider is ever invoked; a
   ``REQUIRES_APPROVAL`` decision with no grant presented is recorded
   ``PENDING`` (still nothing executed);
4. canonical target extraction (Step 25 validator — the only target
   authority);
5. content-derived idempotency — an identical, already-processed
   submission returns the stored result without re-invoking providers;
6. per-step: resolve the provider, bind the effective target, execute the
   sandbox adapter with bounded retries (retryable categories only),
   bounded timeout, secret-free recording;
7. failure policy (stop/continue), execution-status derivation, and
   normalization to the read record.

Failure semantics (§ of ``docs/development/soar_v218.md``):

* ALLOWED + all steps completed  -> ``SUCCEEDED``
* any step failed, some succeeded -> ``PARTIAL`` (STOP_ON_FAILURE leaves the
  rest ``skipped``)
* no step succeeded, failure     -> ``FAILED``
* DENIED / unverifiable decision -> ``REJECTED`` (provider never called)
* REQUIRES_APPROVAL, no grant    -> ``PENDING`` (provider never called)
* duplicate identical request    -> stored deterministic result returned
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from app.schemas.policy_decision import PolicyDecision, ResponseActionType
from app.schemas.soar import (
    SOAR_MAX_PROCESSED_KEYS,
    SOAR_PLAYBOOK_INITIAL_VERSION,
    SOAR_RETRYABLE_CATEGORIES,
    SoarDryRunResult,
    SoarDryRunStepResult,
    SoarExecutionRecord,
    SoarExecutionRequest,
    SoarExecutionStatus,
    SoarFailureCategory,
    SoarFailurePolicy,
    SoarPlaybookDefinition,
    SoarStep,
    SoarStepExecutionRecord,
    SoarStepStatus,
)
from app.services.response.approval_gate import ApprovalVerifier
from app.services.soar import hashing as _hash  # noqa: A004
from app.services.soar import validator as _av  # noqa: A004
from app.services.soar.errors import (
    SoarInternalError,
    SoarServiceError,
    SoarValidationError,
)
from app.services.soar.gate import CODE_TARGET_INVALID, SoarPolicyGate
from app.services.soar.playbooks import (
    DEFAULT_SOAR_PLAYBOOK_REGISTRY,
    SoarPlaybookRegistry,
)
from app.services.soar.providers import SoarProvider, SoarProviderError
from app.services.soar.registry import (
    DEFAULT_SOAR_PROVIDER_REGISTRY,
    SoarProviderRegistry,
)


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


class SoarEngine:
    """Deterministic SOAR engine with an independent policy gate."""

    def __init__(
        self,
        *,
        provider_registry: SoarProviderRegistry | None = None,
        playbook_registry: SoarPlaybookRegistry | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
        persisted_lookup: Callable[[str], SoarExecutionRecord | None] | None = None,
    ) -> None:
        self._providers: SoarProviderRegistry = (
            provider_registry if provider_registry is not None else DEFAULT_SOAR_PROVIDER_REGISTRY
        )
        self._playbooks: SoarPlaybookRegistry = (
            playbook_registry if playbook_registry is not None else DEFAULT_SOAR_PLAYBOOK_REGISTRY
        )
        self._clock: Callable[[], datetime] = clock or _default_now
        self._gate = SoarPolicyGate(approval_verifier=approval_verifier)
        self._processed: dict[str, SoarExecutionRecord] = {}
        # Durable dedup.  ``_processed`` only spans one engine instance, so a
        # long-lived service (which builds an engine per call) needs the
        # already-persisted record for the content-derived key to avoid
        # re-running the playbook.  Consulted *before* any provider runs.
        self._persisted_lookup = persisted_lookup

    @property
    def processed_count(self) -> int:
        return len(self._processed)

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def execute(
        self,
        request: SoarExecutionRequest | dict[str, Any],
        *,
        actor_user_id: uuid.UUID,
        actor_role: str,
        clock: Callable[[], datetime] | None = None,
    ) -> SoarExecutionRecord:
        """Run the full SOAR lifecycle for *request* and return the
        auditable :class:`SoarExecutionRecord`.

        Args:
            request: Validated request or plain mapping.  A structurally
                invalid request raises :class:`SoarValidationError`
                (sanitized); a valid-request-but-denied decision returns an
                auditable ``REJECTED`` record.
            clock: Optional per-call UTC clock override (fixed in tests).

        Raises:
            SoarValidationError: malformed request or unknown playbook.
            SoarInternalError: idempotency capacity exhausted / naive clock.
        """
        req = self._coerce_request(request)
        now = (clock or self._clock)()
        self._enforce_clock(now)

        decision = _av.coerce_decision(req.decision)
        if decision is None:
            return self._rejected(req, "POLICY_INVALID", now, actor_user_id, actor_role)

        try:
            target = _av.canonical_target(
                action=decision.requested_action,
                target=req.target,
            )
        except SoarValidationError:
            return self._rejected(
                req, CODE_TARGET_INVALID, now, actor_user_id, actor_role
            )

        playbook = self._playbooks.require(req.playbook_id)

        gate = self._gate.evaluate(
            decision=decision,
            playbook=playbook,
            approval_id=req.approval_id,
            now=now,
        )
        if not gate.allowed:
            status = gate.status or SoarExecutionStatus.REJECTED
            return self._build(
                req,
                target=target,
                status=status,
                error_code=gate.error_code,
                now=now,
                actor_user_id=actor_user_id,
                actor_role=actor_role,
            )

        key = _hash.execution_idempotency_key(
            policy_decision_id=decision.policy_decision_id,
            approval_id=req.approval_id,
            response_id=req.response_id,
            playbook_id=playbook.playbook_id,
            playbook_version=SOAR_PLAYBOOK_INITIAL_VERSION,
            target=target,
            action=decision.requested_action.value,
        )
        already = self._processed.get(key)
        if already is not None:
            return already.model_copy(deep=True)
        if self._persisted_lookup is not None:
            persisted = self._persisted_lookup(key)
            if persisted is not None:
                self._processed[key] = persisted
                return persisted.model_copy(deep=True)
        if len(self._processed) >= SOAR_MAX_PROCESSED_KEYS:
            raise SoarInternalError(
                "the SOAR idempotency store is full; provisioning must be "
                "increased before further attempts"
            )

        record = self._run_steps(
            req,
            decision,
            playbook,
            target,
            key,
            now,
            clock or self._clock,
            actor_user_id,
            actor_role,
        )
        self._processed[key] = record
        return record.model_copy(deep=True)

    def dry_run(
        self,
        request: SoarExecutionRequest | dict[str, Any],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> SoarDryRunResult:
        """Validate and project a run without any side effect.

        The playbook must be registered, the decision gate must pass, every
        provider must resolve and support its operation, and every target
        must validate.  Each step is projected with ``status=succeeded`` and
        ``simulated=True``; the provider adapters are called with
        ``dry_run=True`` so their in-memory ledgers never mutate.  Nothing
        is persisted and no execution record is produced.
        """
        req = self._coerce_request(request)
        now = (clock or self._clock)()
        self._enforce_clock(now)

        decision = _av.coerce_decision(req.decision)
        if decision is None:
            return self._dry_run_rejected(req, "POLICY_INVALID", now)

        try:
            target = _av.canonical_target(
                action=decision.requested_action,
                target=req.target,
            )
        except SoarValidationError:
            return self._dry_run_rejected(req, CODE_TARGET_INVALID, now)

        playbook = self._playbooks.require(req.playbook_id)

        gate = self._gate.evaluate(
            decision=decision,
            playbook=playbook,
            approval_id=req.approval_id,
            now=now,
        )
        if not gate.allowed:
            return self._dry_run_rejected(
                req, gate.error_code or "POLICY_REJECTED", now
            )

        projected_steps: list[SoarDryRunStepResult] = []
        for step in playbook.steps:
            try:
                step_result = self._project_step(
                    step,
                    decision_action=decision.requested_action,
                    decision_target=target,
                    clock=clock or self._clock,
                )
            except SoarValidationError as exc:
                return self._dry_run_rejected(req, "PROVIDER_UNSUPPORTED", now, message=str(exc))
            except SoarProviderError as exc:
                code = _category_code(exc.category)
                return self._dry_run_rejected(req, code, now, message=str(exc))
            projected_steps.append(step_result)

        execution_id = _hash.execution_id(
            idempotency_key=_hash.execution_idempotency_key(
                policy_decision_id=decision.policy_decision_id,
                approval_id=req.approval_id,
                response_id=req.response_id,
                playbook_id=playbook.playbook_id,
                playbook_version=SOAR_PLAYBOOK_INITIAL_VERSION,
                target=target,
                action=decision.requested_action.value,
            )
        )
        return SoarDryRunResult(
            simulated=True,
            playbook_id=playbook.playbook_id,
            playbook_version=SOAR_PLAYBOOK_INITIAL_VERSION,
            policy_decision_id=decision.policy_decision_id,
            correlation_id=decision.correlation_id,
            response_id=req.response_id,
            approval_id=req.approval_id,
            target=target,
            status=SoarExecutionStatus.SUCCEEDED,
            steps=projected_steps,
            message=(
                f"Dry-run completed for playbook '{playbook.playbook_id}' "
                f"({len(projected_steps)} step(s) projected, no side effects)."
            ),
            created_at=now,
        )

    # ------------------------------------------------------------------
    # Internal stages
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_request(request: Any) -> SoarExecutionRequest:
        if isinstance(request, SoarExecutionRequest):
            return request
        if isinstance(request, dict):
            try:
                return SoarExecutionRequest.model_validate(request)
            except Exception as exc:  # noqa: BLE001 - sanitized, never echoed
                raise SoarValidationError(
                    "the SOAR execution request failed validation"
                ) from exc
        raise SoarValidationError(
            "the SOAR execution request must be a SoarExecutionRequest "
            "instance or a mapping"
        )

    @staticmethod
    def _enforce_clock(now: datetime) -> None:
        tz = now.tzinfo
        if tz is None or tz.utcoffset(now) is None:
            raise SoarInternalError(
                "the SOAR clock must return a timezone-aware timestamp"
            )

    def _run_steps(
        self,
        req: SoarExecutionRequest,
        decision: PolicyDecision,
        playbook: SoarPlaybookDefinition,
        target: str,
        key: str,
        now: datetime,
        clock: Callable[[], datetime],
        actor_user_id: uuid.UUID,
        actor_role: str,
    ) -> SoarExecutionRecord:
        step_records: list[SoarStepExecutionRecord] = []
        aborted = False
        for step in playbook.steps:
            if aborted:
                step_records.append(
                    _step_record(
                        step,
                        execution_id=_hash.execution_id(idempotency_key=key),
                        effective_target="",
                        status=SoarStepStatus.SKIPPED,
                        started=None,
                        completed=None,
                    )
                )
                continue
            effective_target = _av.step_effective_target(
                step=step,
                decision_action=decision.requested_action.value,
                decision_target=target,
            )
            outcome = self._run_step(
                step,
                effective_target,
                decision=decision,
                clock=clock,
                execution_id=_hash.execution_id(idempotency_key=key),
            )
            step_records.append(outcome)
            if outcome.status in (
                SoarStepStatus.FAILED,
                SoarStepStatus.TIMED_OUT,
            ) and playbook.failure_policy is SoarFailurePolicy.STOP_ON_FAILURE:
                aborted = True

        status = _derive_execution_status(step_records)
        return SoarExecutionRecord(
            id=uuid.UUID(int=0),
            execution_id=_hash.execution_id(idempotency_key=key),
            idempotency_key=key,
            policy_decision_id=decision.policy_decision_id,
            correlation_id=decision.correlation_id,
            approval_id=req.approval_id,
            response_id=req.response_id,
            playbook_id=playbook.playbook_id,
            playbook_version=SOAR_PLAYBOOK_INITIAL_VERSION,
            primary_action=decision.requested_action,
            target=target,
            status=status,
            failure_policy=playbook.failure_policy,
            simulated=False,
            error_code=_execution_error_code(step_records),
            started_at=now,
            completed_at=clock(),
            created_by=actor_user_id,
            created_by_role=actor_role,
            metadata=req.metadata,
            steps=step_records,
            created_at=now,
            updated_at=now,
        )

    def _run_step(
        self,
        step: SoarStep,
        effective_target: str,
        *,
        decision: PolicyDecision,
        clock: Callable[[], datetime],
        execution_id: uuid.UUID,
    ) -> SoarStepExecutionRecord:
        del decision
        attempts = 1 + step.retries
        retries_attempted = 0
        started = clock()
        last_category: SoarFailureCategory = SoarFailureCategory.PROVIDER_ERROR
        last_message: str | None = None

        for attempt in range(attempts):
            if attempt > 0:
                retries_attempted += 1
            attempt_started = clock()
            try:
                provider = self._providers.provider_for(step.provider_id)
                if step.operation not in provider.supported_operations:
                    raise SoarProviderError(
                        f"provider '{step.provider_id}' does not support "
                        f"operation '{step.operation.value}'",
                        category=SoarFailureCategory.INVALID_INPUT,
                    )
                result = provider.execute(
                    operation=step.operation,
                    target=effective_target,
                    params=step.params,
                    step_label=step.label,
                    clock=clock,
                    dry_run=False,
                )
            except SoarProviderError as exc:
                last_category = exc.category
                last_message = str(exc)
                result = None
            except SoarValidationError as exc:
                # A registered playbook referencing an unregistered provider
                # is a seed/config defect — fail closed as internal, never a
                # dynamic resolution.
                last_category = SoarFailureCategory.INTERNAL
                last_message = str(exc)
                result = None
            except Exception:  # noqa: BLE001 - normalized, sanitized fail-closed
                last_category = SoarFailureCategory.INTERNAL
                last_message = "provider execution failed"
                result = None

            if result is not None:
                elapsed = (clock() - attempt_started).total_seconds()
                if elapsed > step.timeout_seconds:
                    last_category = SoarFailureCategory.TIMEOUT
                    last_message = f"step timed out after {step.timeout_seconds}s"
                elif result.ok:
                    return _step_record(
                        step,
                        execution_id=execution_id,
                        effective_target=effective_target,
                        status=SoarStepStatus.SUCCEEDED,
                        started=started,
                        completed=clock(),
                        retries_attempted=retries_attempted,
                        metadata=result.metadata,
                    )
                else:
                    # A provider reported a non-OK result: honor its stable
                    # category/error instead of the default.
                    last_category = (
                        result.failure_category
                        if result.failure_category is not None
                        else SoarFailureCategory.PROVIDER_ERROR
                    )
                    last_message = (
                        result.message
                        or result.error_code
                        or "provider reported a failure"
                    )
                    result = None

            if (
                last_category in SOAR_RETRYABLE_CATEGORIES
                and attempt + 1 < attempts
            ):
                continue
            # Final failure (no more attempts, or non-retryable).
            status, code = (
                (SoarStepStatus.TIMED_OUT, "STEP_TIMEOUT")
                if last_category is SoarFailureCategory.TIMEOUT
                else (SoarStepStatus.FAILED, _category_code(last_category))
            )
            return _step_record(
                step,
                execution_id=execution_id,
                effective_target=effective_target,
                status=status,
                started=started,
                completed=clock(),
                retries_attempted=retries_attempted,
                error_code=code,
                message=last_message,
                metadata={"failed": True, "category": last_category.value},
            )

        # Unreachable (the loop always returns), kept for type narrowing.
        return _step_record(
            step,
            execution_id=execution_id,
            effective_target=effective_target,
            status=SoarStepStatus.FAILED,
            started=started,
            completed=clock(),
        )

    def _project_step(
        self,
        step: SoarStep,
        *,
        decision_action: ResponseActionType,
        decision_target: str,
        clock: Callable[[], datetime],
    ) -> SoarDryRunStepResult:
        effective_target = _av.step_effective_target(
            step=step,
            decision_action=decision_action.value,
            decision_target=decision_target,
        )
        provider = self._providers.provider_for(step.provider_id)
        if step.operation not in provider.supported_operations:
            raise SoarProviderError(
                f"provider '{step.provider_id}' does not support operation "
                f"'{step.operation.value}'",
                category=SoarFailureCategory.INVALID_INPUT,
            )
        result = provider.execute(
            operation=step.operation,
            target=effective_target,
            params=step.params,
            step_label=step.label,
            clock=clock,
            dry_run=True,
        )
        return SoarDryRunStepResult(
            step_execution_id=_hash.step_execution_id(
                execution_id=_hash.execution_id(
                    idempotency_key="dry-run"
                ),
                step_number=step.step_number,
            ),
            step_number=step.step_number,
            label=step.label,
            provider_id=step.provider_id,
            operation=step.operation,
            target=effective_target,
            status=SoarStepStatus.SUCCEEDED,
            simulated=True,
            message=result.message or "simulated step (no side effects)",
            metadata={**result.metadata, "dry_run": True},
        )

    def _rejected(
        self,
        req: SoarExecutionRequest,
        error_code: str,
        now: datetime,
        actor_user_id: uuid.UUID,
        actor_role: str,
    ) -> SoarExecutionRecord:
        decision = _av.coerce_decision(req.decision)
        policy_decision_id = (
            decision.policy_decision_id if decision else uuid.UUID(int=0)
        )
        correlation_id = decision.correlation_id if decision else uuid.UUID(int=0)
        key = _hash.execution_idempotency_key(
            policy_decision_id=policy_decision_id,
            approval_id=req.approval_id,
            response_id=req.response_id,
            playbook_id=req.playbook_id,
            playbook_version=SOAR_PLAYBOOK_INITIAL_VERSION,
            target="",
            action=decision.requested_action.value if decision else "",
        )
        return SoarExecutionRecord(
            id=uuid.UUID(int=0),
            execution_id=_hash.execution_id(idempotency_key=key),
            idempotency_key=key,
            policy_decision_id=policy_decision_id,
            correlation_id=correlation_id,
            approval_id=req.approval_id,
            response_id=req.response_id,
            playbook_id=req.playbook_id,
            playbook_version=SOAR_PLAYBOOK_INITIAL_VERSION,
            primary_action=(
                decision.requested_action
                if decision
                else ResponseActionType.BLOCK_IP
            ),
            target="",
            status=SoarExecutionStatus.REJECTED,
            failure_policy=SoarFailurePolicy.STOP_ON_FAILURE,
            simulated=False,
            error_code=error_code,
            started_at=None,
            completed_at=None,
            created_by=actor_user_id,
            created_by_role=actor_role,
            metadata=req.metadata,
            steps=[],
            created_at=now,
            updated_at=now,
        )

    def _build(
        self,
        req: SoarExecutionRequest,
        *,
        target: str,
        status: SoarExecutionStatus,
        error_code: str | None,
        now: datetime,
        actor_user_id: uuid.UUID,
        actor_role: str,
    ) -> SoarExecutionRecord:
        decision = _av.coerce_decision(req.decision)
        policy_decision_id = decision.policy_decision_id
        correlation_id = decision.correlation_id
        key = _hash.execution_idempotency_key(
            policy_decision_id=policy_decision_id,
            approval_id=req.approval_id,
            response_id=req.response_id,
            playbook_id=req.playbook_id,
            playbook_version=SOAR_PLAYBOOK_INITIAL_VERSION,
            target=target,
            action=decision.requested_action.value,
        )
        return SoarExecutionRecord(
            id=uuid.UUID(int=0),
            execution_id=_hash.execution_id(idempotency_key=key),
            idempotency_key=key,
            policy_decision_id=policy_decision_id,
            correlation_id=correlation_id,
            approval_id=req.approval_id,
            response_id=req.response_id,
            playbook_id=req.playbook_id,
            playbook_version=SOAR_PLAYBOOK_INITIAL_VERSION,
            primary_action=decision.requested_action,
            target=target,
            status=status,
            failure_policy=SoarFailurePolicy.STOP_ON_FAILURE,
            simulated=False,
            error_code=error_code,
            started_at=None,
            completed_at=None,
            created_by=actor_user_id,
            created_by_role=actor_role,
            metadata=req.metadata,
            steps=[],
            created_at=now,
            updated_at=now,
        )

    def _dry_run_rejected(
        self,
        req: SoarExecutionRequest,
        error_code: str,
        now: datetime,
        *,
        message: str | None = None,
    ) -> SoarDryRunResult:
        decision = _av.coerce_decision(req.decision)
        return SoarDryRunResult(
            simulated=True,
            playbook_id=req.playbook_id,
            playbook_version=SOAR_PLAYBOOK_INITIAL_VERSION,
            policy_decision_id=decision.policy_decision_id if decision else uuid.UUID(int=0),
            correlation_id=decision.correlation_id if decision else uuid.UUID(int=0),
            response_id=req.response_id,
            approval_id=req.approval_id,
            target="",
            status=SoarExecutionStatus.REJECTED,
            error_code=error_code,
            steps=[],
            message=message or "the dry-run was rejected before any projection",
            created_at=now,
        )


def _category_code(category: SoarFailureCategory) -> str:
    mapping = {
        SoarFailureCategory.TIMEOUT: "STEP_TIMEOUT",
        SoarFailureCategory.TRANSIENT: "STEP_TRANSIENT_FAILURE",
        SoarFailureCategory.PROVIDER_ERROR: "PROVIDER_ERROR",
        SoarFailureCategory.INVALID_INPUT: "INVALID_INPUT",
        SoarFailureCategory.POLICY: "POLICY_FAILURE",
        SoarFailureCategory.AUTHORIZATION: "AUTHORIZATION_FAILURE",
        SoarFailureCategory.INTERNAL: "PROVIDER_FAILURE",
    }
    return mapping.get(category, "PROVIDER_FAILURE")


def _step_record(
    step: SoarStep,
    *,
    execution_id: uuid.UUID,
    effective_target: str,
    status: SoarStepStatus,
    started: datetime | None,
    completed: datetime | None,
    retries_attempted: int = 0,
    error_code: str | None = None,
    message: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SoarStepExecutionRecord:
    return SoarStepExecutionRecord(
        step_execution_id=_hash.step_execution_id(
            execution_id=execution_id,
            step_number=step.step_number,
        ),
        execution_id=execution_id,
        step_number=step.step_number,
        label=step.label,
        provider_id=step.provider_id,
        operation=step.operation,
        target=effective_target,
        status=status,
        retries_attempted=retries_attempted,
        error_code=error_code,
        message=message,
        started_at=started,
        completed_at=completed,
        metadata=metadata or {},
    )


def _derive_execution_status(
    step_records: list[SoarStepExecutionRecord],
) -> SoarExecutionStatus:
    terminal = {r.status for r in step_records}
    failed = terminal & {SoarStepStatus.FAILED, SoarStepStatus.TIMED_OUT}
    succeeded = SoarStepStatus.SUCCEEDED in terminal
    if failed:
        return SoarExecutionStatus.PARTIAL if succeeded else SoarExecutionStatus.FAILED
    return SoarExecutionStatus.SUCCEEDED


def _execution_error_code(
    step_records: list[SoarStepExecutionRecord],
) -> str | None:
    for record in step_records:
        if record.status in (SoarStepStatus.FAILED, SoarStepStatus.TIMED_OUT):
            return record.error_code or "STEP_FAILED"
    return None


__all__ = ["SoarEngine"]