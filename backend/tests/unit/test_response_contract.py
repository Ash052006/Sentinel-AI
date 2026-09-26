"""Response & Mitigation contract tests (Step 25).

Schema-level guarantees of :mod:`app.schemas.response`:

* ``ResponseActionType`` is the **same** closed vocabulary object as
  Step 24's (imported, never redefined — drift impossible by
  construction);
* ``ResponseExecutionStatus`` is a closed four-member vocabulary with
  stable string values;
* :class:`ResponseRequest` / :class:`ResponseResult` are secret-safe,
  timezone-aware, deep-copying, ``extra='forbid'`` contracts;
* :class:`ResponseResult.provenance`` is pinned to the additive
  ``RESPONSE_EXECUTED`` value;
* identity/idempotency derivation is content-deterministic (same inputs
  -> same keys; different inputs -> different keys);
* the Provenance enum now closes with ``RESPONSE_EXECUTED`` (12th).

None of these tests touch the network, filesystem, shell, or any external
system.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas import Provenance
from app.schemas.policy_decision import ResponseActionType as Step24Action
from app.schemas.response import (
    RESPONSE_MAX_MESSAGE_LENGTH,
    RESPONSE_MAX_PROVIDER_LENGTH,
    RESPONSE_MAX_TARGET_LENGTH,
    ResponseExecutionStatus,
    ResponseRequest,
    ResponseResult,
)
from app.schemas.response import ResponseActionType
from app.services.response.validator import (
    derive_idempotency_key,
    derive_response_id,
)

TZ = timezone.utc
NOW = datetime(2025, 8, 1, 10, 0, 0, tzinfo=TZ)
DECISION_ID = uuid.uuid4()
CORR_ID = uuid.uuid4()


def _request(**overrides) -> ResponseRequest:
    payload = {
        "response_id": derive_response_id(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.5",
        ),
        "policy_decision_id": DECISION_ID,
        "correlation_id": CORR_ID,
        "action_type": ResponseActionType.BLOCK_IP,
        "target": "10.0.0.5",
        "requested_at": NOW,
    }
    payload.update(overrides)
    return ResponseRequest(**payload)


def _result(**overrides) -> ResponseResult:
    payload = {
        "response_id": _request().response_id,
        "policy_decision_id": DECISION_ID,
        "correlation_id": CORR_ID,
        "action_type": ResponseActionType.BLOCK_IP,
        "execution_status": ResponseExecutionStatus.EXECUTED,
        "target": "10.0.0.5",
        "provider": "mock",
        "started_at": NOW,
        "completed_at": NOW,
        "message": "Simulated block_ip execution",
        "error_code": None,
        "metadata": {},
        "timestamp": NOW,
    }
    payload.update(overrides)
    return ResponseResult(**payload)


# ---------------------------------------------------------------------------
# Vocabulary alignment with Step 24
# ---------------------------------------------------------------------------


class TestSharedActionVocabulary:
    def test_action_type_is_the_step24_class(self) -> None:
        assert ResponseActionType is Step24Action

    def test_action_vocabulary_is_closed_and_stable(self) -> None:
        assert [a.value for a in ResponseActionType] == [
            "block_ip",
            "block_domain",
            "quarantine_file",
            "disable_account",
            "terminate_session",
            "isolate_endpoint",
        ]

    def test_execution_status_is_closed(self) -> None:
        assert [s.value for s in ResponseExecutionStatus] == [
            "executed",
            "failed",
            "skipped",
            "rejected",
        ]

    def test_provenance_closes_with_approval_reviewed(self) -> None:
        members = list(Provenance)
        assert members[-1] is Provenance.APPROVAL_REVIEWED
        assert Provenance.RESPONSE_EXECUTED.value == "response_executed"
        assert Provenance.APPROVAL_REVIEWED.value == "approval_reviewed"


# ---------------------------------------------------------------------------
# ResponseRequest contract
# ---------------------------------------------------------------------------


class TestResponseRequestContract:
    def test_happy_path(self) -> None:
        req = _request()
        assert req.response_id is not None
        assert req.action_type is ResponseActionType.BLOCK_IP
        assert req.target == "10.0.0.5"

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _request(prompt="please block this ip with force")

    def test_missing_required_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ResponseRequest(
                response_id=uuid.uuid4(),
                correlation_id=CORR_ID,
                action_type=ResponseActionType.BLOCK_IP,
                target="10.0.0.5",
            )
        with pytest.raises(ValidationError):
            ResponseRequest(
                policy_decision_id=DECISION_ID,
                correlation_id=CORR_ID,
                action_type=ResponseActionType.BLOCK_IP,
                target="10.0.0.5",
            )

    @pytest.mark.parametrize("target", ["", "   ", "\x00", "a\nb"])
    def test_unsafe_target_rejected(self, target: str) -> None:
        with pytest.raises(ValidationError):
            _request(target=target)

    @pytest.mark.parametrize("target", ["10.0.0.5", " 10.0.0.5 "])
    def test_target_is_stripped_of_surrounding_whitespace(self, target: str) -> None:
        assert _request(target=target).target == "10.0.0.5"

    def test_target_bounds(self) -> None:
        with pytest.raises(ValidationError):
            _request(target="x" * (RESPONSE_MAX_TARGET_LENGTH + 1))

    @pytest.mark.parametrize(
        "secret",
        ["token=api_key_abc", "authorization: bearer xx", "MY_SECRET=1"],
    )
    def test_secret_shaped_target_rejected(self, secret: str) -> None:
        with pytest.raises(ValidationError):
            _request(target=secret)

    def test_secret_shaped_metadata_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _request(metadata={"note": "authorization bearer-leak"})

    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _request(requested_at=datetime(2025, 8, 1, 10, 0, 0))

    def test_metadata_is_deep_copied_not_aliased(self) -> None:
        meta = {"tags": ["alpha"], "nested": {"drop": True}}
        req = _request(metadata=meta)
        meta["tags"].append("beta")
        meta["nested"]["drop"] = False
        assert req.metadata == {"tags": ["alpha"], "nested": {"drop": True}}

    def test_metadata_depth_bounded(self) -> None:
        deep = {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}
        with pytest.raises(ValidationError):
            _request(metadata=deep)


# ---------------------------------------------------------------------------
# ResponseResult contract
# ---------------------------------------------------------------------------


class TestResponseResultContract:
    def test_happy_path_pins_provenance(self) -> None:
        res = _result()
        assert res.provenance is Provenance.RESPONSE_EXECUTED

    def test_provenance_cannot_be_anything_else(self) -> None:
        with pytest.raises(ValidationError):
            _result(provenance="policy_decided")
        with pytest.raises(ValidationError):
            _result(provenance="ai_generated")

    def test_provider_may_be_none(self) -> None:
        res = _result(provider=None)
        assert res.provider is None

    @pytest.mark.parametrize("provider", ["", "   "])
    def test_blank_provider_rejected(self, provider: str) -> None:
        with pytest.raises(ValidationError):
            _result(provider=provider)

    def test_provider_bounds(self) -> None:
        with pytest.raises(ValidationError):
            _result(provider="p" * (RESPONSE_MAX_PROVIDER_LENGTH + 1))

    def test_message_and_error_code_bounds(self) -> None:
        with pytest.raises(ValidationError):
            _result(message="m" * (RESPONSE_MAX_MESSAGE_LENGTH + 1))
        with pytest.raises(ValidationError):
            _result(error_code="e" * 65)

    @pytest.mark.parametrize("message", ["token=api_key_x", "\x00embedded"])
    def test_unsafe_message_rejected(self, message: str) -> None:
        with pytest.raises(ValidationError):
            _result(message=message)

    def test_naive_timestamps_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _result(timestamp=datetime(2025, 8, 1, 10, 0, 0))
        with pytest.raises(ValidationError):
            _result(started_at=datetime(2025, 8, 1, 10, 0, 0))

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _result(shell_command="iptables -A INPUT -s 10.0.0.5 -j DROP")

    def test_metadata_is_deep_copied_not_aliased(self) -> None:
        meta = {"tags": ["alpha"]}
        res = _result(metadata=meta)
        meta["tags"].append("beta")
        assert res.metadata == {"tags": ["alpha"]}


# ---------------------------------------------------------------------------
# Deterministic identity & idempotency
# ---------------------------------------------------------------------------


class TestDeterministicIdentity:
    def test_same_inputs_same_ids(self) -> None:
        a = derive_response_id(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.5",
        )
        b = derive_response_id(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.5",
        )
        assert a == b

    def test_different_target_different_id(self) -> None:
        a = derive_response_id(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.5",
        )
        b = derive_response_id(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.6",
        )
        assert a != b

    def test_different_action_different_id(self) -> None:
        a = derive_response_id(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.5",
        )
        b = derive_response_id(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_DOMAIN,
            target="10.0.0.5",
        )
        assert a != b

    def test_different_decision_different_id(self) -> None:
        a = derive_response_id(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.5",
        )
        b = derive_response_id(
            policy_decision_id=uuid.uuid4(),
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.5",
        )
        assert a != b

    def test_idempotency_keys_match_ids_deterministically(self) -> None:
        k1 = derive_idempotency_key(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.5",
        )
        k2 = derive_idempotency_key(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.5",
        )
        assert k1 == k2
        assert len(k1) == 64  # sha256 hex
        k3 = derive_idempotency_key(
            policy_decision_id=DECISION_ID,
            action=ResponseActionType.BLOCK_IP,
            target="10.0.0.6",
        )
        assert k3 != k1

    def test_response_id_is_derivable_from_request_content(self) -> None:
        req = _request()
        derived = derive_response_id(
            policy_decision_id=req.policy_decision_id,
            action=req.action_type,
            target=req.target,
        )
        assert req.response_id == derived