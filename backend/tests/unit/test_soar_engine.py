"""SOAR engine tests (V2.18).

The engine is the only place a run is driven and it is deterministic.
These tests pin the full lifecycle without any persistence: allowed runs,
the audit trail of refusals (DENIED / invalid target / invalid decision /
pending approval), an approved run through the verifier seam, bounded
retries, and dry-run purity (identical projection, zero side effects).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)
from app.schemas.security_event import Provenance
from app.schemas.soar import (
    SOAR_PLAYBOOK_INITIAL_VERSION,
    SoarExecutionRequest,
    SoarExecutionStatus,
    SoarFailureCategory,
    SoarStepStatus,
)
from app.services.response.approval_gate import APPROVAL_EXPIRED
from app.services.soar import (
    DEFAULT_SOAR_PLAYBOOK_REGISTRY,
    SoarEngine,
    SoarProvider,
    SoarProviderError,
    SoarProviderResult,
    SoarValidationError,
)
from app.services.soar.gate import (
    APPROVAL_NOT_GIVEN,
    CODE_POLICY_DENIED,
    CODE_POLICY_INVALID,
    CODE_TARGET_INVALID,
)
from app.services.soar.playbooks import SoarPlaybookRegistry
from app.services.soar.providers import MockFirewallProvider, SoarProviderType
from tests.unit.soar_test_helpers import (
    StubApprovalVerifier,
    a_decision,
    a_request,
)

TZ = timezone.utc
FIXED = datetime(2026, 9, 24, 8, 30, 0, tzinfo=TZ)

ACTOR_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
ACTOR_ROLE = "admin"


def _engine(*, verifier=None) -> SoarEngine:
    return SoarEngine(approval_verifier=verifier, clock=lambda: FIXED)


class TestExecuteAllowed:
    def test_allowed_single_step_succeeds(self) -> None:
        engine = _engine()
        record = engine.execute(
            a_request(),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        assert record.status is SoarExecutionStatus.SUCCEEDED
        assert record.error_code is None
        assert record.playbook_id == "block_ip"
        assert record.playbook_version == SOAR_PLAYBOOK_INITIAL_VERSION
        assert record.primary_action is ResponseActionType.BLOCK_IP
        assert record.target == "203.0.113.7"
        assert len(record.steps) == 1
        assert record.steps[0].status is SoarStepStatus.SUCCEEDED
        assert record.steps[0].operation is ResponseActionType.BLOCK_IP
        assert record.steps[0].target == "203.0.113.7"

    def test_duplicate_submission_is_idempotent(self) -> None:
        engine = _engine()
        body = a_request()
        first = engine.execute(body, actor_user_id=ACTOR_ID, actor_role=ACTOR_ROLE)
        second = engine.execute(body, actor_user_id=ACTOR_ID, actor_role=ACTOR_ROLE)
        assert first.execution_id == second.execution_id
        assert first == second
        assert engine.processed_count == 1

    def test_identical_submission_different_approval_differs(self) -> None:
        # An approval-bearing grant changes the idempotency identity, so a
        # granted re-submission is a *new* run that may execute.
        engine = _engine(verifier=StubApprovalVerifier(ok=True))
        base = a_request(status=PolicyDecisionStatus.REQUIRES_APPROVAL)
        with_grant = a_request(
            status=PolicyDecisionStatus.REQUIRES_APPROVAL,
            approval_id=uuid.uuid4(),
        )
        first = engine.execute(base, actor_user_id=ACTOR_ID, actor_role=ACTOR_ROLE)
        assert first.status is SoarExecutionStatus.PENDING
        assert (
            engine.execute(base, actor_user_id=ACTOR_ID, actor_role=ACTOR_ROLE)
            == first
        )
        approved = engine.execute(
            with_grant, actor_user_id=ACTOR_ID, actor_role=ACTOR_ROLE
        )
        assert approved.status is SoarExecutionStatus.SUCCEEDED
        assert approved.execution_id != first.execution_id
        # Only executed runs are idempotency-deduped; the PENDING record and
        # its repeat are no-op projections, so just the granted run is stored.
        assert engine.processed_count == 1


class TestExecuteRejections:
    def test_denied_decision_rejected_and_unrun(self) -> None:
        engine = _engine()
        record = engine.execute(
            a_request(status=PolicyDecisionStatus.DENIED),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
        )
        assert record.status is SoarExecutionStatus.REJECTED
        assert record.error_code == CODE_POLICY_DENIED
        assert record.steps == []

    def test_requires_approval_without_grant_records_pending(self) -> None:
        engine = _engine()
        record = engine.execute(
            a_request(status=PolicyDecisionStatus.REQUIRES_APPROVAL),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
        )
        assert record.status is SoarExecutionStatus.PENDING
        assert record.error_code == APPROVAL_NOT_GIVEN
        assert record.steps == []

    def test_requires_approval_with_failed_grant_rejected(self) -> None:
        engine = _engine(
            verifier=StubApprovalVerifier(ok=False, error_code=APPROVAL_EXPIRED)
        )
        record = engine.execute(
            a_request(
                status=PolicyDecisionStatus.REQUIRES_APPROVAL,
                approval_id=uuid.uuid4(),
            ),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
        )
        assert record.status is SoarExecutionStatus.REJECTED
        assert record.error_code == APPROVAL_EXPIRED

    def test_requires_approval_with_valid_grant_executes(self) -> None:
        engine = _engine(verifier=StubApprovalVerifier(ok=True))
        record = engine.execute(
            a_request(
                status=PolicyDecisionStatus.REQUIRES_APPROVAL,
                approval_id=uuid.uuid4(),
            ),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
        )
        assert record.status is SoarExecutionStatus.SUCCEEDED
        assert len(record.steps) == 1

    def test_invalid_target_rejected_as_target_invalid(self) -> None:
        engine = _engine()
        record = engine.execute(
            a_request(target="not-an-ip-address"),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
        )
        assert record.status is SoarExecutionStatus.REJECTED
        assert record.error_code == CODE_TARGET_INVALID
        assert record.steps == []

    def test_malformed_decision_rejected_as_invalid(self) -> None:
        # A decision that is *not* the result of the upstream policy service
        # (non-POLICY_DECIDED provenance is the forged/malformed case) is
        # refused by the independent gate and never reaches a provider.
        # model_construct bypasses the schemas' provenance pin so the gate's
        # fail-closed guard is exercised (the pin makes the forged case
        # unpresentable through a validated request).
        engine = _engine()
        forged = PolicyDecision.model_construct(
            **a_decision().model_dump(exclude={"provenance"}),
            provenance=Provenance.DETECTED,
        )
        req = SoarExecutionRequest.model_construct(
            decision=forged,
            target="203.0.113.7",
            approval_id=None,
            response_id=uuid.uuid4(),
            playbook_id="block_ip",
            metadata={},
        )
        record = engine.execute(
            req, actor_user_id=ACTOR_ID, actor_role=ACTOR_ROLE
        )
        assert record.status is SoarExecutionStatus.REJECTED
        assert record.error_code == CODE_POLICY_INVALID
        assert record.steps == []

    def test_unknown_playbook_raises_validation_error(self) -> None:
        engine = _engine()
        with pytest.raises(SoarValidationError, match="no registered playbook"):
            engine.execute(
                a_request(playbook_id="does_not_exist"),
                actor_user_id=ACTOR_ID,
                actor_role=ACTOR_ROLE,
            )


class TestCompositeExecution:
    def test_composite_playbook_runs_all_steps(self) -> None:
        engine = _engine()
        record = engine.execute(
            a_request(
                playbook_id="endpoint_containment",
                target="host-7f3a",
                action=ResponseActionType.ISOLATE_ENDPOINT,
            ),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
        )
        assert record.status is SoarExecutionStatus.SUCCEEDED
        assert len(record.steps) == 3
        # secondary steps apply their registered-bound targets
        assert record.steps[1].target == "198.51.100.7"
        assert record.steps[2].target == "actor-198.51.100.7@example.com"


class FlakyProvider(SoarProvider):
    """Provider that fails once (transient) then succeeds — proves retry."""

    provider_id = "flaky"
    provider_type = SoarProviderType.FIREWALL
    supported_operations = frozenset({ResponseActionType.BLOCK_IP})

    def __init__(self) -> None:
        self.attempts = 0

    def execute(
        self,
        *,
        operation: ResponseActionType,
        target: str,
        params: dict,
        step_label: str,
        clock,
        dry_run: bool = False,
    ) -> SoarProviderResult:
        del params, step_label, clock, operation, target, dry_run
        self.attempts += 1
        if self.attempts == 1:
            raise SoarProviderError(
                "transient blip",
                category=SoarFailureCategory.TRANSIENT,
            )
        return SoarProviderResult(message="ok after retry")


class TestRetry:
    def test_retryable_failure_is_retried(self) -> None:
        definition = DEFAULT_SOAR_PLAYBOOK_REGISTRY.require("block_ip")
        retrying = definition.steps[0].model_copy(
            update={
                "retries": 1,
                "provider_id": FlakyProvider.provider_id,
                "operation": ResponseActionType.BLOCK_IP,
            }
        )
        registry = SoarPlaybookRegistry(
            [definition.model_copy(update={"steps": [retrying]})]
        )
        provider = FlakyProvider()
        engine = SoarEngine(
            provider_registry=_registry_with(provider),
            playbook_registry=registry,
            clock=lambda: FIXED,
        )
        record = engine.execute(
            a_request(),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
        )
        assert provider.attempts == 2
        assert record.status is SoarExecutionStatus.SUCCEEDED
        assert record.steps[0].retries_attempted == 1
        assert record.steps[0].status is SoarStepStatus.SUCCEEDED


def _registry_with(provider: SoarProvider):
    from app.services.soar.registry import SoarProviderRegistry

    return SoarProviderRegistry([provider])


class TestDryRun:
    def test_dry_run_projects_with_no_side_effects(self) -> None:
        firewall = MockFirewallProvider()
        engine = SoarEngine(
            provider_registry=_registry_with(firewall),
            clock=lambda: FIXED,
        )
        result = engine.dry_run(a_request())
        assert result.simulated is True
        assert result.playbook_id == "block_ip"
        assert result.status is SoarExecutionStatus.SUCCEEDED
        assert len(result.steps) == 1
        assert result.steps[0].simulated is True
        assert result.steps[0].status is SoarStepStatus.SUCCEEDED
        # prove nothing executed in the fresh provider ledger
        assert firewall.blocked_ips == set()
        assert firewall.attempt_count == 0

    def test_dry_run_rejected_projections(self) -> None:
        engine = SoarEngine(clock=lambda: FIXED)
        denied = engine.dry_run(a_request(status=PolicyDecisionStatus.DENIED))
        assert denied.simulated is True
        assert denied.status is SoarExecutionStatus.REJECTED
        assert denied.steps == []

    def test_dry_run_unknown_playbook_raises(self) -> None:
        engine = SoarEngine(clock=lambda: FIXED)
        with pytest.raises(SoarValidationError):
            engine.dry_run(a_request(playbook_id="ghost"))