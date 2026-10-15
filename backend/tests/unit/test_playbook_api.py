"""Playbook API route tests — V3.25.

The API is the only place a client can touch the generator, so it is where the
proposal surface's guarantees have to hold against a *hostile* caller rather
than a cooperative one.  These tests route real HTTP requests through the real
assembler, engine, persistence and audit trail against PostgreSQL, because the
guarantees under test are exactly the ones a mocked stack would not exercise: the
authorization dependency, the status-code mapping, audit ordering around a real
commit, and what a client can and cannot influence.

The properties:

* **the client cannot define a playbook** — the POST body is ignored, so no
  action, target, priority, confidence or approval state can be injected;
* **generating is not approving and proposing is not executing** — no route can
  return or persist an executed or approved playbook;
* **a failure never becomes a playbook** — governed failures surface as their
  mapped status with a ``PlaybookFailureResponse`` body;
* **replay is not re-reasoning** — an identical re-POST writes no second row and
  logs no second ``playbook.created``;
* **audit reflects the database** — ``playbook.created`` is only written after
  persistence actually succeeded.
"""

from __future__ import annotations

import json
import logging
import uuid

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from app.main import app as fastapi_app

from app.database.postgres.session import SessionLocal
from app.models.audit_log import AuditLog
from app.models.knowledge_graph import KnowledgeGraphEdge, KnowledgeGraphNode
from app.models.playbook import PlaybookSessionRecord
from app.services.knowledge_graph.vocabulary import (
    NodeType,
    Provenance,
    RelationshipType,
    deterministic_edge_id,
    deterministic_node_id,
)

CORRELATION_ID = uuid.UUID("66666666-6666-4666-8666-666666666666")
UNKNOWN_CORRELATION_ID = uuid.UUID("77777777-7777-4777-8777-777777777777")
UNKNOWN_PLAYBOOK_ID = uuid.UUID("88888888-8888-4888-8888-888888888888")
VIEWER_EMAIL = "playbook-viewer@sentinel.test"

PLAYBOOKS = "/api/playbooks"


# ---------------------------------------------------------------------------
# Graph fixture
# ---------------------------------------------------------------------------


#: The only lifecycles the generator can emit, per the frozen V3.25 contract.
GENERATED_LIFECYCLE_VALUES = {"proposed", "approval_required"}

#: Field names that would imply an execution record.  Absent by contract.
_EXECUTION_CLAIM_FIELDS = {
    "status",
    "outcome",
    "result",
    "executed_at",
    "execution_time",
    "executed",
    "executed_by",
    "execution_result",
}


def _actions(body: dict) -> list[dict]:
    """Every action in a response, in step order.

    ``Playbook.actions`` is a Python property, not a serialized field, so the
    wire format nests actions under ``playbook.steps[*].actions``.
    """
    return [a for step in body["playbook"]["steps"] for a in step["actions"]]


def _executed_claims(node) -> list[str]:
    """Every path in ``node`` whose value asserts a completed execution.

    Structural rather than textual: only a *lifecycle/status/outcome* carrying an
    executed-like value counts.  Prose that merely discusses execution -- the
    ``execution_note`` disclaimer above all -- is not a claim.
    """
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _EXECUTION_CLAIM_FIELDS and isinstance(value, str):
                if "execut" in value or value == "executed":
                    found.append(f"{key}={value}")
            found.extend(_executed_claims(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_executed_claims(item))
    return found


def _client() -> TestClient:
    """A client bound to the real app.

    The suite's shared ``client`` fixture is session-scoped and mutates its
    headers, so this builds a fresh one per call to keep the authorization
    matrix independent.
    """
    return TestClient(fastapi_app)


def _seed_graph() -> None:
    """Persist a minimal correlation graph the assembler can reason over.

    One correlation node plus one connected threat-intelligence indicator.  The
    indicator carries an IP so a *destructive* action is genuinely proposable,
    which is what makes the "cannot inject actions" and "never executed"
    assertions meaningful rather than vacuous.
    """
    session = SessionLocal()
    try:
        correlation_node_id = deterministic_node_id(
            NodeType.CORRELATION, str(CORRELATION_ID)
        )
        indicator_node_id = deterministic_node_id(
            NodeType.THREAT_INDICATOR, f"ind-{CORRELATION_ID}"
        )
        session.add(
            KnowledgeGraphNode(
                id=correlation_node_id,
                node_type=NodeType.CORRELATION.value,
                source_id=str(CORRELATION_ID),
                source_reference=f"correlation:{CORRELATION_ID}",
                provenance=Provenance.PERSISTED_CORRELATION_RESULT.value,
                label=f"correlation {CORRELATION_ID}",
                node_metadata={},
            )
        )
        session.add(
            KnowledgeGraphNode(
                id=indicator_node_id,
                node_type=NodeType.THREAT_INDICATOR.value,
                source_id=f"ind-{CORRELATION_ID}",
                source_reference=f"threat_intelligence:ind-{CORRELATION_ID}",
                provenance=Provenance.PERSISTED_THREAT_INTEL_INDICATOR.value,
                label="ip:203.0.113.10",
                node_metadata={"indicator_type": "ip", "value": "203.0.113.10"},
            )
        )
        session.add(
            KnowledgeGraphEdge(
                id=deterministic_edge_id(
                    RelationshipType.ASSOCIATED_WITH_INDICATOR,
                    correlation_node_id,
                    indicator_node_id,
                ),
                source_node_id=correlation_node_id,
                target_node_id=indicator_node_id,
                relationship_type=RelationshipType.ASSOCIATED_WITH_INDICATOR.value,
                source_reference=f"threat_intelligence:ind-{CORRELATION_ID}",
                evidence_references=[f"threat_intelligence:ind-{CORRELATION_ID}"],
            )
        )
        session.commit()
    finally:
        session.close()


@pytest.fixture(scope="module", autouse=True)
def _graph_in_the_database():
    """Seed the graph once for this module, then remove it and every proposal.

    Module-scoped because the nodes are deterministic and immutable, and the
    generator's output is derived from them; per-test reseeding would be
    redundant work for identical state.  Teardown deletes the proposals this
    module created so nothing leaks into other suites.
    """
    _seed_graph()
    yield
    session = SessionLocal()
    try:
        _purge_playbooks(session)
        for node_id in (
            deterministic_node_id(NodeType.CORRELATION, str(CORRELATION_ID)),
            deterministic_node_id(NodeType.THREAT_INDICATOR, f"ind-{CORRELATION_ID}"),
        ):
            row = session.get(KnowledgeGraphNode, node_id)
            if row is not None:
                session.delete(row)
        session.commit()
    finally:
        session.close()


def _purge_playbooks(session) -> None:
    ids = list(
        session.execute(
            sa.select(PlaybookSessionRecord.id).where(
                PlaybookSessionRecord.correlation_id == CORRELATION_ID
            )
        ).scalars()
    )
    if ids:
        session.execute(
            sa.delete(PlaybookSessionRecord).where(
                PlaybookSessionRecord.id.in_(ids)
            )
        )
        session.commit()


def _reset() -> None:
    """Clear proposals and this module's audit rows before each test.

    Both audit resources this module writes have to go, or the RBAC tests would
    pass on rows a previous test left behind.
    """
    session = SessionLocal()
    try:
        _purge_playbooks(session)
        session.execute(
            sa.delete(AuditLog).where(
                sa.or_(
                    AuditLog.resource.like(f"%{CORRELATION_ID}%"),
                    AuditLog.resource == "playbooks",
                )
            )
        )
        session.commit()
    finally:
        session.close()


def _audit_actions(correlation_id: uuid.UUID = CORRELATION_ID) -> list[str]:
    """Audit rows for the playbook runs of one correlation."""
    session = SessionLocal()
    try:
        return list(
            session.execute(
                sa.select(AuditLog.action).where(
                    AuditLog.resource.like(f"%{correlation_id}%")
                )
            ).scalars()
        )
    finally:
        session.close()


def _unauthorized_attempts() -> list[str]:
    session = SessionLocal()
    try:
        return list(
            session.execute(
                sa.select(AuditLog.action).where(
                    AuditLog.action == "playbook.unauthorized_attempt",
                    AuditLog.resource == "playbooks",
                )
            ).scalars()
        )
    finally:
        session.close()


def _stored_playbooks() -> int:
    session = SessionLocal()
    try:
        return int(
            session.execute(
                sa.select(sa.func.count())
                .select_from(PlaybookSessionRecord)
                .where(PlaybookSessionRecord.correlation_id == CORRELATION_ID)
            ).scalar()
            or 0
        )
    finally:
        session.close()


@pytest.fixture()
def api(admin_token):
    """An authenticated client, with per-test cleanup around the test body."""
    _reset()
    client = _client()
    client.headers.update({"Authorization": f"Bearer {admin_token}"})
    yield client
    _reset()


# ---------------------------------------------------------------------------
# Authentication and RBAC
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_post_without_credentials_is_401(self) -> None:
        response = _client().post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        assert response.status_code == 401

    def test_get_without_credentials_is_401(self) -> None:
        assert _client().get(f"{PLAYBOOKS}/{UNKNOWN_PLAYBOOK_ID}").status_code == 401

    def test_list_without_credentials_is_401(self) -> None:
        response = _client().get(f"{PLAYBOOKS}/correlation/{CORRELATION_ID}")
        assert response.status_code == 401

    @pytest.mark.parametrize(
        "header",
        [
            {"Authorization": "Bearer not-a-real-token"},
            {"Authorization": "Bearer "},
            {"Authorization": "Basic YWRtaW46YWRtaW4="},
            {"Authorization": "gsk_test_canary"},
        ],
    )
    def test_an_unusable_credential_is_401(self, header) -> None:
        client = _client()
        client.headers.update(header)
        assert client.post(f"{PLAYBOOKS}/{CORRELATION_ID}").status_code == 401

    def test_a_denied_attempt_is_audited(self, admin_token) -> None:
        """Rejected access must leave a trace, or RBAC is unauditable.

        Denied attempts are recorded against the ``playbooks`` resource rather
        than a specific correlation, because an unauthenticated caller cannot be
        trusted to supply one.
        """
        _reset()
        _client().get(f"{PLAYBOOKS}/{UNKNOWN_PLAYBOOK_ID}")
        assert _unauthorized_attempts()


class TestRoleBasedAccess:
    @pytest.mark.parametrize("fixture_name", ["analyst_token", "ciso_token"])
    def test_permitted_roles_may_generate(self, request, fixture_name) -> None:
        token = request.getfixturevalue(fixture_name)
        _reset()
        client = _client()
        client.headers.update({"Authorization": f"Bearer {token}"})
        response = client.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        assert response.status_code == 200
        _reset()

    def test_a_viewer_is_forbidden(self, db_session) -> None:
        """Authorization must not be weakened.

        The reader roles are admin/analyst/ciso only.  A viewer is authenticated
        but unpermitted, which must be 403 and must be audited.
        """
        from app.core.security import create_access_token
        from app.models.role import Role
        from app.models.user import User

        session = SessionLocal()
        try:
            # A previous interrupted run may have left the row behind; the audit
            # rows referencing it are cleared first to satisfy the FK.
            session.execute(
                sa.delete(AuditLog).where(
                    AuditLog.resource == "playbooks"
                )
            )
            session.execute(
                sa.delete(User).where(User.email == VIEWER_EMAIL)
            )
            session.commit()
            role = session.execute(
                sa.select(Role).where(Role.name == "viewer")
            ).scalar_one()
            user = User(
                email=VIEWER_EMAIL,
                password_hash="x" * 60,
                role_id=role.id,
                is_active=True,
            )
            session.add(user)
            session.commit()
            token = create_access_token(str(user.id))
        finally:
            session.close()

        _reset()
        try:
            client = _client()
            client.headers.update({"Authorization": f"Bearer {token}"})
            response = client.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
            assert response.status_code == 403
            assert response.json()["detail"] == "Insufficient permissions"
            assert _unauthorized_attempts()
        finally:
            _reset()
            cleanup = SessionLocal()
            try:
                cleanup.execute(
                    sa.delete(AuditLog).where(AuditLog.resource == "playbooks")
                )
                cleanup.execute(
                    sa.delete(User).where(User.email == VIEWER_EMAIL)
                )
                cleanup.commit()
            finally:
                cleanup.close()


# ---------------------------------------------------------------------------
# POST: generation, determinism, replay
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_a_grounded_correlation_yields_a_proposal(self, api) -> None:
        response = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        assert response.status_code == 200
        body = response.json()
        assert body["lifecycle"] in {"proposed", "approval_required"}
        assert body["status"] in {"proposed", "insufficient_evidence", "contested"}
        assert _actions(body), "the seeded graph must be actionable"

    def test_the_response_never_claims_execution(self, api) -> None:
        """The surface must not be able to report that anything happened.

        Asserted structurally rather than by scanning for the word "executed":
        ``execution_note`` is a disclaimer that legitimately contains it, so a
        substring search would either be vacuous or force a brittle whitelist.
        """
        body = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        assert body["lifecycle"] in GENERATED_LIFECYCLE_VALUES
        assert body["status"] != "executed"
        assert body["provenance"] == "ai_generated"
        assert body["execution_note"]
        # No action carries an outcome or timestamp of execution: the contract
        # has no such field, and none may appear as an extra.
        for action in _actions(body):
            assert not [k for k in action if k in {"status", "outcome", "result",
                                                    "executed_at", "execution_time"}]
            assert action["capability"] in {"available", "degraded", "unavailable"}
        # Nothing anywhere in the payload asserts a completed execution.
        assert _executed_claims(body) == []

    def test_generation_is_deterministic_across_calls(self, api) -> None:
        first = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        second = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        assert first == second
        assert first["playbook_id"] == second["playbook_id"]

    def test_identical_replay_reuses_the_stored_proposal(self, api) -> None:
        first = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        second = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        assert first.json()["playbook_id"] == second.json()["playbook_id"]
        assert _stored_playbooks() == 1

    def test_a_malformed_correlation_id_is_422(self, api) -> None:
        response = api.post(f"{PLAYBOOKS}/not-a-uuid")
        assert response.status_code == 422

    def test_an_unknown_correlation_is_404_not_500(self, api) -> None:
        """The documented 404 must actually happen.

        ``get_correlation_graph`` raises ``GraphNodeNotFound`` — a ``LookupError``,
        not a ``PlaybookError`` — so it escapes the route's ``except PlaybookError``
        handlers and reaches the catch-all 500.  The failure is still *governed* in
        intent, but the status and body are wrong.
        """
        response = api.post(f"{PLAYBOOKS}/{UNKNOWN_CORRELATION_ID}")
        assert response.status_code == 404
        assert response.json()["detail"]["failure_code"] == "playbook_context_error"


class TestClientCannotDefineThePlaybook:
    """The client supplies a correlation id and nothing else."""

    @pytest.mark.parametrize(
        "payload",
        [
            {"playbook": {"actions": [{"action": "block_ip", "target": "8.8.8.8"}]}},
            {"actions": [{"action": "disable_account", "target": "root"}]},
            {"lifecycle": "executed"},
            {"lifecycle": "approved"},
            {"status": "executed"},
            {"playbook_id": str(UNKNOWN_PLAYBOOK_ID)},
            {"metadata": {"provenance": "observed"}},
            {"uncertainty": {"confidence": 1.0}},
            {"actions": [{"action": "block_ip", "approval": {"requirement": "not_required"}}]},
            {"graph_snapshot_digest": "f" * 64},
        ],
    )
    def test_an_injected_body_cannot_change_the_result(self, api, payload) -> None:
        """A smuggled field must be ignored, not honoured.

        The POST contract takes no body.  Whatever a client sends, the proposal
        must equal the one the server derives from persisted evidence.
        """
        honest = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        smuggled = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}", json=payload).json()
        assert smuggled == honest

    def test_a_client_cannot_obtain_an_executed_playbook(self, api) -> None:
        """Not even by asking for one explicitly."""
        body = api.post(
            f"{PLAYBOOKS}/{CORRELATION_ID}",
            json={"lifecycle": "executed", "status": "executed"},
        ).json()
        assert body["lifecycle"] in {"proposed", "approval_required"}
        assert body["status"] != "executed"

    def test_a_client_cannot_bypass_approval(self, api) -> None:
        """A destructive action keeps its approval requirement whatever is sent."""
        body = api.post(
            f"{PLAYBOOKS}/{CORRELATION_ID}",
            json={"approval": {"requirement": "not_required"}},
        ).json()
        for action in _actions(body):
            assert action["approval"]["requirement"] in {
                "approval_required",
                "not_required",
                "not_executable",
            }
            if action["action"] in {
                "block_ip",
                "block_domain",
                "quarantine_file",
                "disable_account",
                "terminate_session",
                "isolate_endpoint",
            }:
                assert action["approval"]["requirement"] != "not_required"

    def test_a_client_cannot_inject_a_confidence(self, api) -> None:
        body = api.post(
            f"{PLAYBOOKS}/{CORRELATION_ID}", json={"uncertainty": {"confidence": 1.0}}
        ).json()
        assert body["uncertainty"]["confidence"] < 1.0


# ---------------------------------------------------------------------------
# GET /api/playbooks/{playbook_id}
# ---------------------------------------------------------------------------


class TestGetPlaybook:
    def test_a_stored_proposal_is_returned(self, api) -> None:
        created = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        response = api.get(f"{PLAYBOOKS}/{created['playbook_id']}")
        assert response.status_code == 200
        assert response.json() == created

    def test_the_returned_result_matches_the_persisted_one(self, api) -> None:
        created = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        fetched = api.get(f"{PLAYBOOKS}/{created['playbook_id']}").json()
        assert fetched == created

    def test_an_unknown_playbook_is_404(self, api) -> None:
        response = api.get(f"{PLAYBOOKS}/{UNKNOWN_PLAYBOOK_ID}")
        assert response.status_code == 404
        body = response.json()["detail"]
        assert body["failure_code"] == "playbook_not_found"
        assert body["status"] == "failed"

    def test_a_malformed_playbook_id_is_422(self, api) -> None:
        assert api.get(f"{PLAYBOOKS}/not-a-uuid").status_code == 422

    def test_the_response_carries_its_qualifications(self, api) -> None:
        """A proposal is never returned without its uncertainty."""
        body = api.get(
            f"{PLAYBOOKS}/{api.post(f'{PLAYBOOKS}/{CORRELATION_ID}').json()['playbook_id']}"
        ).json()
        assert "uncertainty" in body
        assert "limitations" in body
        assert body["metadata"]["provenance"] == "ai_generated"
        for action in _actions(body):
            assert action["evidence"], "every action must cite evidence"
            assert action["rollback"] is not None or action["rollback_supported"] is False


# ---------------------------------------------------------------------------
# GET /api/playbooks/correlation/{correlation_id}
# ---------------------------------------------------------------------------


class TestListForCorrelation:
    def test_a_generated_proposal_appears_in_the_list(self, api) -> None:
        created = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        response = api.get(f"{PLAYBOOKS}/correlation/{CORRELATION_ID}")
        assert response.status_code == 200
        listed = response.json()["playbooks"]
        assert [p["playbook_id"] for p in listed] == [created["playbook_id"]]
        assert listed[0]["action_count"] == len(_actions(created))

    def test_an_unknown_correlation_is_an_empty_list_not_404(self, api) -> None:
        """Not-yet-generated is a legitimate state, not a missing resource."""
        response = api.get(f"{PLAYBOOKS}/correlation/{UNKNOWN_CORRELATION_ID}")
        assert response.status_code == 200
        assert response.json()["playbooks"] == []

    def test_a_malformed_correlation_id_is_422(self, api) -> None:
        assert api.get(f"{PLAYBOOKS}/correlation/not-a-uuid").status_code == 422


# ---------------------------------------------------------------------------
# Evidence and references survive the boundary
# ---------------------------------------------------------------------------


class TestReferencesSurviveTheBoundary:
    def test_evidence_references_are_preserved_verbatim(self, api) -> None:
        body = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        for action in _actions(body):
            for item in action["evidence"]:
                assert item["source"]
                assert item["reference"]
                assert ":" in item["reference"], item["reference"]

    def test_the_graph_snapshot_digest_is_preserved(self, api) -> None:
        body = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        assert len(body["metadata"]["graph_snapshot_digest"]) == 64
        assert body["correlation_id"] == str(CORRELATION_ID)

    def test_prediction_and_debate_references_are_carried_or_declared_absent(
        self, api
    ) -> None:
        """A reference must survive, not be silently dropped.

        With no V3.23/V3.24 records persisted for this correlation the assembler
        declares them unavailable, which is the truthful outcome.
        """
        body = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        assert body["metadata"]["prediction_session_id"] is None
        assert "prediction" in body["metadata"]["unavailable_inputs"]
        assert "debate" in body["metadata"]["unavailable_inputs"]


# ---------------------------------------------------------------------------
# Audit ordering — the trail must match the database
# ---------------------------------------------------------------------------


class TestAuditOrdering:
    def test_a_successful_creation_is_audited(self, api) -> None:
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        actions = _audit_actions()
        assert "playbook.created" in actions
        assert "playbook.completed" in actions

    def test_creation_is_audited_only_after_the_row_exists(self, api) -> None:
        """``playbook.created`` must not precede persistence.

        If the audit were written first, a failed write would leave a permanent
        record of a proposal that was never stored.  Asserted by checking that
        whenever the audit exists, the row exists too.
        """
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        if "playbook.created" in _audit_actions():
            assert _stored_playbooks() == 1

    def test_an_idempotent_replay_logs_no_second_creation(self, api) -> None:
        """Audit should reflect how much reasoning happened, not retries."""
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        actions = _audit_actions()
        assert actions.count("playbook.created") == 1
        assert actions.count("playbook.completed") == 1

    def test_a_failed_generation_logs_a_failure_not_a_creation(self, api) -> None:
        """A failure must be recorded as a failure, never as a creation."""
        api.post(f"{PLAYBOOKS}/{UNKNOWN_CORRELATION_ID}")
        actions = _audit_actions(UNKNOWN_CORRELATION_ID)
        assert "playbook.created" not in actions
        assert "playbook.failed" in actions

    def test_no_execution_event_exists_on_this_surface(self, api) -> None:
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        actions = _audit_actions()
        assert not [a for a in actions if "execut" in a.lower()]

    def test_the_completion_record_states_nothing_executed(self, api) -> None:
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        session = SessionLocal()
        try:
            details = list(
                session.execute(
                    sa.select(AuditLog.details).where(
                        AuditLog.action == "playbook.completed",
                        AuditLog.resource.like(f"%{CORRELATION_ID}%"),
                    )
                ).scalars()
            )
        finally:
            session.close()
        assert details
        assert "executed=none" in details[0]


# ---------------------------------------------------------------------------
# Governed failures
# ---------------------------------------------------------------------------


class TestGovernedFailures:
    def test_a_failure_body_is_validated_and_carries_a_code(self, api) -> None:
        response = api.post(f"{PLAYBOOKS}/{UNKNOWN_CORRELATION_ID}")
        body = response.json()["detail"]
        assert body["status"] == "failed"
        assert body["failure_code"]
        assert body["detail"]
        assert "playbook" not in body, "a failure must not carry a playbook"

    def test_a_bounds_violation_is_422(self, api, monkeypatch) -> None:
        """An exceeded bound is refused, never silently truncated."""
        from app.services.playbook.exceptions import PlaybookBoundsError
        from app.services.playbook.vocabulary import PlaybookBounds

        def refuse(self, correlation_id):
            raise PlaybookBoundsError(
                f"correlation graph has 99 nodes, exceeding max_graph_nodes="
                f"{PlaybookBounds().max_graph_nodes}"
            )

        monkeypatch.setattr(
            "app.services.playbook.context.PlaybookContextAssembler.assemble", refuse
        )
        response = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        assert response.status_code == 422
        assert response.json()["detail"]["failure_code"] == "playbook_bounds_error"

    def test_a_persistence_failure_is_503(self, api, monkeypatch) -> None:
        from app.services.playbook.exceptions import PlaybookPersistenceError

        def fail(self, result):
            raise PlaybookPersistenceError("the database write did not complete")

        monkeypatch.setattr(
            "app.services.playbook.persistence.PlaybookService.persist_result", fail
        )
        response = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        assert response.status_code == 503
        assert (
            response.json()["detail"]["failure_code"] == "playbook_persistence_error"
        )

    def test_a_persistence_failure_logs_no_creation(self, api, monkeypatch) -> None:
        """The ordering rule, exercised on the failure branch."""
        from app.services.playbook.exceptions import PlaybookPersistenceError

        def fail(self, result):
            raise PlaybookPersistenceError("the database write did not complete")

        monkeypatch.setattr(
            "app.services.playbook.persistence.PlaybookService.persist_result", fail
        )
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        assert "playbook.created" not in _audit_actions()

    def test_a_provider_failure_is_503(self, api, monkeypatch) -> None:
        from app.services.playbook.exceptions import PlaybookProviderError

        def fail(self, inputs):
            raise PlaybookProviderError("the generation provider is unavailable")

        monkeypatch.setattr(
            "app.agents.playbook.engine.PlaybookEngine.generate", fail
        )
        response = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        assert response.status_code == 503
        assert (
            response.json()["detail"]["failure_code"]
            == "playbook_generation_provider_error"
        )

    def test_a_timeout_is_reported_as_a_provider_failure(self, api, monkeypatch) -> None:
        """A provider timeout is governed, not a hang and not a 500."""
        from app.services.playbook.exceptions import PlaybookProviderError

        def timeout(self, inputs):
            raise PlaybookProviderError("the generation provider did not respond")

        monkeypatch.setattr(
            "app.agents.playbook.engine.PlaybookEngine.generate", timeout
        )
        response = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        assert response.status_code == 503


# ---------------------------------------------------------------------------
# Provider failures must not echo provider text to the client
# ---------------------------------------------------------------------------

#: Strings shaped like credentials.  They are fabricated, but deliberately
#: grep-able so a leak into a response, a log or the database is unambiguous.
PROVIDER_SECRETS = (
    "gsk_live_canary_0123456789abcdef",
    "sk-proj-canary-9876543210",
    "Bearer eyJhbGciOiJIUzI1NiJ9.canary",
    "AKIAIOSFODNN7CANARY",
    "-----BEGIN PRIVATE KEY-----canary",
    "postgres://sentinel:hunter2canary@db:5432/sentinel",
)


def _provider_failure_with(secrets: tuple[str, ...]):
    """A synthetic provider failure whose message embeds ``secrets``."""

    def explode(self, inputs):
        from app.services.playbook.exceptions import PlaybookProviderError

        raise PlaybookProviderError(
            "the model-candidate provider rejected the request: "
            + " ".join(secrets)
        )

    return explode


class TestProviderSecretsAreRedacted:
    """A provider outage is governed; its payload is not a client deliverable.

    The route echoes ``str(exc)`` for most failures because those messages are
    authored inside this package and describe persisted data.  A provider failure
    is different in kind: its text originates outside the process, in a client's
    own error reporting, where credentials, headers and connection strings
    routinely appear.  The governed status and failure code are what the client
    needs; the upstream message is not.
    """

    @pytest.mark.parametrize("secret", PROVIDER_SECRETS)
    def test_a_secret_never_reaches_the_response(self, api, monkeypatch, secret) -> None:
        monkeypatch.setattr(
            "app.agents.playbook.engine.PlaybookEngine.generate",
            _provider_failure_with((secret,)),
        )
        response = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        assert response.status_code == 503
        assert secret not in response.text

    def test_no_secret_reaches_the_response_body(self, api, monkeypatch) -> None:
        monkeypatch.setattr(
            "app.agents.playbook.engine.PlaybookEngine.generate",
            _provider_failure_with(PROVIDER_SECRETS),
        )
        response = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        for secret in PROVIDER_SECRETS:
            assert secret not in response.text

    def test_the_client_still_learns_which_failure_it_was(self, api, monkeypatch) -> None:
        """Redaction must not degrade the governed signal."""
        monkeypatch.setattr(
            "app.agents.playbook.engine.PlaybookEngine.generate",
            _provider_failure_with(PROVIDER_SECRETS),
        )
        body = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()["detail"]
        assert body["failure_code"] == "playbook_generation_provider_error"
        assert body["status"] == "failed"
        assert body["detail"], "a safe explanation is still owed to the client"

    def test_no_secret_reaches_the_audit_trail(self, api, monkeypatch) -> None:
        """The audit trail is read by auditors, so it is a disclosure surface too."""
        monkeypatch.setattr(
            "app.agents.playbook.engine.PlaybookEngine.generate",
            _provider_failure_with(PROVIDER_SECRETS),
        )
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        session = SessionLocal()
        try:
            details = list(
                session.execute(
                    sa.select(AuditLog.details).where(
                        AuditLog.action == "playbook.failed",
                        AuditLog.resource.like(f"%{CORRELATION_ID}%"),
                    )
                ).scalars()
            )
        finally:
            session.close()
        assert details
        for secret in PROVIDER_SECRETS:
            assert all(secret not in (d or "") for d in details)

    def test_no_secret_is_persisted(self, api, monkeypatch) -> None:
        """A failed run must leave nothing durable behind.

        Asserted over every column of the playbook tables rather than one field,
        so a secret cached in a new column would still be caught.
        """
        monkeypatch.setattr(
            "app.agents.playbook.engine.PlaybookEngine.generate",
            _provider_failure_with(PROVIDER_SECRETS),
        )
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        session = SessionLocal()
        try:
            dumped = " ".join(
                str(value)
                for row in session.execute(
                    sa.select(PlaybookSessionRecord)
                    .where(PlaybookSessionRecord.correlation_id == CORRELATION_ID)
                ).scalars()
                for value in row.__dict__.values()
                if value is not None
            )
        finally:
            session.close()
        assert _stored_playbooks() == 0
        for secret in PROVIDER_SECRETS:
            assert secret not in dumped

    def test_no_secret_is_logged(self, api, monkeypatch, caplog) -> None:
        """``_raise_playbook_failure`` logs ``str(exc)``; for a provider failure
        that must be the sanitized form, not the upstream text."""
        monkeypatch.setattr(
            "app.agents.playbook.engine.PlaybookEngine.generate",
            _provider_failure_with(PROVIDER_SECRETS),
        )
        with caplog.at_level(logging.DEBUG):
            api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        logged = "\n".join(
            record.getMessage() for record in caplog.records
        ) + "\n".join(str(record.exc_info) for record in caplog.records)
        for secret in PROVIDER_SECRETS:
            assert secret not in logged

    def test_a_non_provider_failure_still_explains_itself(self, api, monkeypatch) -> None:
        """Redaction is scoped to provider failures.

        A bounds or context failure is authored here, describes persisted data,
        and is the most useful thing the client can be told.  Blanket-replacing
        every ``detail`` would throw away that diagnostic for no security gain.
        """
        from app.services.playbook.exceptions import PlaybookContextError

        def refuse(self, correlation_id):
            raise PlaybookContextError(
                "no knowledge-graph entities are persisted for this correlation"
            )

        monkeypatch.setattr(
            "app.services.playbook.context.PlaybookContextAssembler.assemble", refuse
        )
        body = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()["detail"]
        assert body["failure_code"] == "playbook_context_error"
        assert "knowledge-graph" in body["detail"]


# ---------------------------------------------------------------------------
# Retrieval and listing edge cases — compact additional coverage
# ---------------------------------------------------------------------------


class TestGetPlaybookExtra:
    def test_get_after_replay_returns_identical_stored_result(self, api) -> None:
        created = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        # replay to ensure stored row is canonical
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        fetched = api.get(f"{PLAYBOOKS}/{created['playbook_id']}").json()
        assert fetched == created

    def test_unknown_playbook_returns_governed_not_found(self, api) -> None:
        resp = api.get(f"{PLAYBOOKS}/{UNKNOWN_PLAYBOOK_ID}")
        assert resp.status_code == 404
        body = resp.json()["detail"]
        assert body["failure_code"] == "playbook_not_found"
        assert body["status"] == "failed"

    def test_playbook_lifecycle_preserved_on_read(self, api) -> None:
        created = api.post(f"{PLAYBOOKS}/{CORRELATION_ID}").json()
        fetched = api.get(f"{PLAYBOOKS}/{created['playbook_id']}").json()
        assert fetched["lifecycle"] in GENERATED_LIFECYCLE_VALUES
        assert fetched["lifecycle"] == created["lifecycle"]
        assert "execution_note" in fetched


class TestListPlaybooksExtra:
    def test_correlation_list_empty_for_unknown_correlation(self, api) -> None:
        resp = api.get(f"{PLAYBOOKS}/correlation/{UNKNOWN_CORRELATION_ID}")
        assert resp.status_code == 200
        assert resp.json()["playbooks"] == []

    def test_list_does_not_leak_unrelated_correlation(self, api, admin_token) -> None:
        # generate for main correlation
        api.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
        # try unknown
        resp = api.get(f"{PLAYBOOKS}/correlation/{UNKNOWN_CORRELATION_ID}")
        assert resp.status_code == 200
        assert len(resp.json()["playbooks"]) == 0

    def test_malformed_correlation_in_list_is_422(self, api) -> None:
        assert api.get(f"{PLAYBOOKS}/correlation/not-a-uuid").status_code == 422


class TestAuthExtra:
    def test_viewer_role_cannot_generate(self, db_session) -> None:
        from app.core.security import create_access_token
        from app.models.role import Role
        from app.models.user import User

        session = SessionLocal()
        try:
            session.execute(sa.delete(AuditLog).where(AuditLog.resource == "playbooks"))
            session.execute(sa.delete(User).where(User.email == VIEWER_EMAIL))
            session.commit()
            role = session.execute(sa.select(Role).where(Role.name == "viewer")).scalar_one()
            user = User(
                email=VIEWER_EMAIL,
                password_hash="x" * 60,
                role_id=role.id,
                is_active=True,
            )
            session.add(user)
            session.commit()
            token = create_access_token(str(user.id))
        finally:
            session.close()
        _reset()
        try:
            c = _client()
            c.headers.update({"Authorization": f"Bearer {token}"})
            resp = c.post(f"{PLAYBOOKS}/{CORRELATION_ID}")
            assert resp.status_code == 403
            assert _unauthorized_attempts()
        finally:
            cleanup = SessionLocal()
            try:
                cleanup.execute(sa.delete(AuditLog).where(AuditLog.resource == "playbooks"))
                cleanup.execute(sa.delete(User).where(User.email == VIEWER_EMAIL))
                cleanup.commit()
            finally:
                cleanup.close()
            _reset()


class TestErrorBoundariesExtra:
    def test_generation_failure_not_logged_as_creation(self, api) -> None:
        api.post(f"{PLAYBOOKS}/{UNKNOWN_CORRELATION_ID}")
        assert "playbook.created" not in _audit_actions(UNKNOWN_CORRELATION_ID)
        assert "playbook.failed" in _audit_actions(UNKNOWN_CORRELATION_ID)

    def test_repeated_unknown_correlation_does_not_create_playbook(self, api) -> None:
        api.post(f"{PLAYBOOKS}/{UNKNOWN_CORRELATION_ID}")
        api.post(f"{PLAYBOOKS}/{UNKNOWN_CORRELATION_ID}")
        assert _stored_playbooks() == 0


class TestValidateEndpointExtra:
    def test_validate_endpoint_requires_auth(self) -> None:
        assert _client().post(f"{PLAYBOOKS}/{UNKNOWN_PLAYBOOK_ID}/validate").status_code == 401

    def test_validate_endpoint_malformed_id_is_422(self, api) -> None:
        resp = api.post(f"{PLAYBOOKS}/bad-uuid/validate")
        assert resp.status_code == 422

    def test_validate_endpoint_unknown_id_is_404(self, api) -> None:
        resp = api.post(f"{PLAYBOOKS}/{UNKNOWN_PLAYBOOK_ID}/validate")
        assert resp.status_code == 404
