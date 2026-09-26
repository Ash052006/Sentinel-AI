"""SOAR playbook registry tests (V2.18).

The playbook set is **code-registered**: no client can author, upload,
import or mutate a playbook.  These tests pin the fixed seed set, its
closed structural invariants, and the fail-closed registry behaviour.
"""

from __future__ import annotations

import pytest

from app.schemas.policy_decision import ResponseActionType
from app.schemas.soar import (
    SOAR_CURRENT_SCHEMA_VERSION,
    SOAR_MAX_STEPS,
    SOAR_PLAYBOOK_INITIAL_VERSION,
    SoarFailurePolicy,
    SoarPlaybookDefinition,
    SoarStep,
)
from app.services.soar import (
    DEFAULT_SOAR_PLAYBOOK_REGISTRY,
    DEFAULT_SOAR_PROVIDER_REGISTRY,
    SoarPlaybookRegistry,
    SoarValidationError,
)
from app.services.soar.playbooks import _seed_definitions


class TestSeedSetIsClosed:
    def test_registry_is_closed_and_deterministic(self) -> None:
        registry = SoarPlaybookRegistry()
        assert registry.ids() == DEFAULT_SOAR_PLAYBOOK_REGISTRY.ids()
        assert registry.ids() == tuple(sorted(registry.ids()))

    def test_seed_set_has_the_documented_playbooks(self) -> None:
        ids = set(DEFAULT_SOAR_PLAYBOOK_REGISTRY.ids())
        assert ids == {
            "block_ip",
            "block_domain",
            "quarantine_file",
            "disable_account",
            "terminate_session",
            "isolate_endpoint",
            "endpoint_containment",
        }

    def test_every_seed_playbook_is_well_formed(self) -> None:
        for definition in DEFAULT_SOAR_PLAYBOOK_REGISTRY.all():
            assert definition.playbook_id == definition.playbook_id.lower()
            assert definition.schema_version == SOAR_CURRENT_SCHEMA_VERSION
            assert 1 <= len(definition.steps) <= SOAR_MAX_STEPS
            for index, step in enumerate(definition.steps, start=1):
                assert step.step_number == index
                assert step.provider_id in DEFAULT_SOAR_PROVIDER_REGISTRY
                assert DEFAULT_SOAR_PROVIDER_REGISTRY.provider_for(
                    step.provider_id
                ).supported_operations.__contains__(step.operation)
            assert definition.steps[0].operation is definition.primary_action

    def test_every_seed_playbook_starts_at_initial_version(self) -> None:
        for definition in DEFAULT_SOAR_PLAYBOOK_REGISTRY.all():
            # Service-level seeding persists this exact version label.
            assert SOAR_PLAYBOOK_INITIAL_VERSION == "1.0.0"
            assert definition.schema_version == "1.0.0"


class TestCompositePlaybook:
    def test_endpoint_containment_binds_secondary_targets(self) -> None:
        definition = DEFAULT_SOAR_PLAYBOOK_REGISTRY.require(
            "endpoint_containment"
        )
        assert len(definition.steps) == 3
        assert definition.failure_policy is SoarFailurePolicy.STOP_ON_FAILURE
        assert definition.primary_action is ResponseActionType.ISOLATE_ENDPOINT
        # The primary step inherits the decision target; secondary steps
        # are bound at registration and structurally validated.
        assert definition.steps[0].target is None
        assert definition.steps[1].target is not None
        assert definition.steps[2].target is not None


class TestRegistryFailClosed:
    def test_duplicate_registration_rejected(self) -> None:
        definition = DEFAULT_SOAR_PLAYBOOK_REGISTRY.require("block_ip")
        with pytest.raises(SoarValidationError, match="duplicate"):
            SoarPlaybookRegistry([definition, definition])

    def test_stepless_playbook_rejected(self) -> None:
        # model_construct bypasses the schema validators so the registry's
        # own fail-closed guard (which the schema would otherwise mask) is
        # exercised directly.
        definition = SoarPlaybookDefinition.model_construct(
            playbook_id="empty_pb",
            name="Empty",
            description="No steps.",
            schema_version=SOAR_CURRENT_SCHEMA_VERSION,
            primary_action=ResponseActionType.BLOCK_IP,
            failure_policy=SoarFailurePolicy.STOP_ON_FAILURE,
            steps=[],
        )
        with pytest.raises(SoarValidationError, match="at least one step"):
            SoarPlaybookRegistry([definition])

    def test_unanchored_playbook_rejected(self) -> None:
        # Same construction bypass: schema rejects it on its own, but the
        # registry guard is the actual boundary being pinned here.
        definition = SoarPlaybookDefinition.model_construct(
            playbook_id="misanchored",
            name="Mis-anchored",
            description="Primary action is not performed by step 1.",
            schema_version=SOAR_CURRENT_SCHEMA_VERSION,
            primary_action=ResponseActionType.BLOCK_IP,
            failure_policy=SoarFailurePolicy.STOP_ON_FAILURE,
            steps=[
                SoarStep(
                    step_number=1,
                    label="Block a domain",
                    provider_id="firewall",
                    operation=ResponseActionType.BLOCK_DOMAIN,
                    target="evil.example.com",
                    retries=0,
                    timeout_seconds=30,
                )
            ],
        )
        with pytest.raises(SoarValidationError, match="first step"):
            SoarPlaybookRegistry([definition])

    def test_unknown_playbook_fails_closed(self) -> None:
        with pytest.raises(SoarValidationError, match="no registered playbook"):
            DEFAULT_SOAR_PLAYBOOK_REGISTRY.require("does_not_exist")

    def test_seed_definitions_are_all_registrable(self) -> None:
        # Every descriptor in the seed factory must register without error
        # and produce the canonical registry.
        registry = SoarPlaybookRegistry(_seed_definitions())
        assert registry.ids() == DEFAULT_SOAR_PLAYBOOK_REGISTRY.ids()


class TestBoundary:
    def test_no_api_surface_mutates_playbooks(self) -> None:
        from app.main import app

        spec = app.openapi()
        for path in spec["paths"]:
            if path.startswith("/api/soar/playbooks"):
                methods = set(spec["paths"][path])
                assert methods <= {"get"}, path