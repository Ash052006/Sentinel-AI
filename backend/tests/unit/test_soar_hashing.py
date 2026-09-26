"""SOAR identity hashing tests (V2.18).

Identities are content-derived and deterministic.  The critical V2.18
guarantee pinned here is that ``playbook_version`` participates in the
execution idempotency key: a new playbook revision must derive a *distinct*
execution lineage even when every other field is identical.
"""

from __future__ import annotations

import uuid

from app.services.soar import hashing


class TestExecutionIdempotencyKey:
    def test_deterministic_for_identical_inputs(self) -> None:
        kwargs = dict(
            policy_decision_id=uuid.uuid4(),
            approval_id=None,
            response_id=uuid.uuid4(),
            playbook_id="block_ip",
            playbook_version="1.0.0",
            target="203.0.113.7",
            action="block_ip",
        )
        assert hashing.execution_idempotency_key(**kwargs) == (
            hashing.execution_idempotency_key(**kwargs)
        )

    def test_playbook_version_participates(self) -> None:
        kwargs = dict(
            policy_decision_id=uuid.uuid4(),
            approval_id=None,
            response_id=uuid.uuid4(),
            playbook_id="block_ip",
            playbook_version="1.0.0",
            target="203.0.113.7",
            action="block_ip",
        )
        upgraded = dict(kwargs, playbook_version="1.1.0")
        assert hashing.execution_idempotency_key(**kwargs) != (
            hashing.execution_idempotency_key(**upgraded)
        )

    def test_disambiguating_fields_participate(self) -> None:
        base = dict(
            policy_decision_id=uuid.uuid4(),
            approval_id=None,
            response_id=uuid.uuid4(),
            playbook_id="block_ip",
            playbook_version="1.0.0",
            target="203.0.113.7",
            action="block_ip",
        )
        variants = [
            dict(base, target="203.0.113.8"),
            dict(base, action="block_domain"),
            dict(base, approval_id=uuid.uuid4()),
            dict(base, playbook_id="block_domain"),
            dict(base, policy_decision_id=uuid.uuid4()),
            dict(base, response_id=uuid.uuid4()),
        ]
        keys = {
            hashing.execution_idempotency_key(**base),
            *(hashing.execution_idempotency_key(**v) for v in variants),
        }
        assert len(keys) == 1 + len(variants)


class TestDerivedIdentities:
    def test_execution_id_is_deterministic_uuid5(self) -> None:
        key = hashing.execution_idempotency_key(
            policy_decision_id=uuid.uuid4(),
            approval_id=None,
            response_id=uuid.uuid4(),
            playbook_id="block_ip",
            playbook_version="1.0.0",
            target="203.0.113.7",
            action="block_ip",
        )
        first = hashing.execution_id(idempotency_key=key)
        assert hashing.execution_id(idempotency_key=key) == first
        assert isinstance(first, uuid.UUID)

        other = hashing.execution_idempotency_key(
            policy_decision_id=uuid.uuid4(),
            approval_id=None,
            response_id=uuid.uuid4(),
            playbook_id="block_ip",
            playbook_version="1.0.0",
            target="203.0.113.8",
            action="block_ip",
        )
        assert hashing.execution_id(idempotency_key=other) != first

    def test_step_execution_id_is_deterministic_per_step(self) -> None:
        execution_id = uuid.uuid4()
        assert hashing.step_execution_id(
            execution_id=execution_id, step_number=1
        ) == hashing.step_execution_id(execution_id=execution_id, step_number=1)
        assert hashing.step_execution_id(
            execution_id=execution_id, step_number=1
        ) != hashing.step_execution_id(execution_id=execution_id, step_number=2)

    def test_playbook_identities_are_content_derived(self) -> None:
        definition = {"playbook_id": "block_ip", "version": "1.0.0", "steps": []}
        source_hash = hashing.playbook_source_hash(definition)
        assert source_hash == hashing.playbook_source_hash(definition)
        altered = dict(definition, name="Block source IP v2")
        assert hashing.playbook_source_hash(altered) != source_hash

        version_id = hashing.playbook_version_id(
            playbook_id="block_ip",
            version="1.0.0",
            source_hash=source_hash,
        )
        assert version_id == hashing.playbook_version_id(
            playbook_id="block_ip",
            version="1.0.0",
            source_hash=source_hash,
        )