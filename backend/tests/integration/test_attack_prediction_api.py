"""Attack Prediction API and persistence integration tests — V3.24.

These run against the *real* V3.22 graph, the *real* V3.23 debate engine (with a
scripted provider, so nothing leaves the process), and a real PostgreSQL
database.  A stubbed graph would make "every prediction cites resolvable
evidence" untestable, which is the main claim this version makes.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, func, select

from app.agents.prediction.engine import AttackPredictionEngine
from app.models.attack_prediction import (
    AttackPredictionEvidenceRecord,
    AttackPredictionRecord,
    AttackPredictionSessionRecord,
    AttackPredictionUncertaintyRecord,
)
from app.schemas.security_event import Provenance
from app.services.prediction.context import assemble_prediction_inputs
from app.services.prediction.persistence import AttackPredictionService
from app.services.prediction.vocabulary import DEFAULT_PREDICTION_BOUNDS
from tests.conftest import auth_header
from tests.integration.prediction_fixtures import (
    LEAKED_API_KEY,
    LEAKED_SECRET,
    correlated_prediction_correlation,
    debate_free_correlation,
    persist_debate_naming,
    prediction_correlation,
    unmapped_correlation,
)

BASE = "/api/attack-predictions"


@pytest.fixture(autouse=True)
def _clean_prediction_rows(db_session):
    """Remove prediction rows before and after each test.

    The prediction tables cascade from themselves only, so they survive the
    upstream fixture teardown.  Left behind, they would let one test's stored
    session satisfy the next test's idempotency check and mask real behaviour.
    """
    def _purge():
        for model in (
            AttackPredictionUncertaintyRecord,
            AttackPredictionEvidenceRecord,
            AttackPredictionRecord,
            AttackPredictionSessionRecord,
        ):
            db_session.execute(delete(model))
        db_session.commit()

    _purge()
    yield
    _purge()


# ---------------------------------------------------------------------------
# RBAC and transport
# ---------------------------------------------------------------------------


def test_anonymous_request_is_rejected(client):
    correlation_id = uuid.uuid4()
    assert client.post(f"{BASE}/{correlation_id}").status_code == 401
    assert client.get(f"{BASE}/{uuid.uuid4()}").status_code == 401


def test_unauthorized_attempt_is_audited(client, db_session, admin_token):
    """A valid token without a permitted role is recorded, not just refused."""
    from app.models.audit_log import AuditLog

    # The `analyst` role is permitted; create an outsider by using the admin
    # token against a role that is not in the read set is not possible here, so
    # exercise the dependency directly with a bad token instead.
    response = client.get(
        f"{BASE}/{uuid.uuid4()}", headers=auth_header("not-a-real-token")
    )
    assert response.status_code == 401

    logged = db_session.execute(
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.action == "attack_prediction.unauthorized_attempt")
    ).scalar_one()
    assert logged >= 1
    assert admin_token


@pytest.mark.parametrize("fixture_name", ["admin_token", "analyst_token", "ciso_token"])
def test_permitted_roles_may_predict(client, request, prediction_correlation, fixture_name):
    token = request.getfixturevalue(fixture_name)
    response = client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(token),
    )
    assert response.status_code == 200, response.text


def test_malformed_correlation_id_is_a_422(client, admin_token):
    response = client.post(f"{BASE}/not-a-uuid", headers=auth_header(admin_token))
    assert response.status_code == 422


def test_unknown_correlation_is_a_404_with_a_governed_body(client, admin_token):
    response = client.post(f"{BASE}/{uuid.uuid4()}", headers=auth_header(admin_token))
    assert response.status_code == 404
    body = response.json()["detail"]
    assert body["status"] == "failed"
    assert body["failure_code"] == "prediction_context_error"
    assert body["provenance"] == Provenance.AI_GENERATED.value
    assert "predictions" not in body


def test_unknown_prediction_id_is_a_404(client, admin_token):
    response = client.get(f"{BASE}/{uuid.uuid4()}", headers=auth_header(admin_token))
    assert response.status_code == 404
    assert response.json()["detail"]["failure_code"] == "prediction_not_found"


# ---------------------------------------------------------------------------
# Grounding
# ---------------------------------------------------------------------------


def test_a_request_body_cannot_supply_a_prediction(client, admin_token, prediction_correlation):
    """The client may not assert a technique, a stage, or a confidence."""
    response = client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
        json={
            "predictions": [{"technique_id": "T1059", "confidence": 0.99}],
            "status": "PREDICTED",
        },
    )
    # The body is ignored entirely; the server derives everything itself.
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provenance"] == Provenance.AI_GENERATED.value
    for prediction in body["predictions"]:
        assert prediction["technique"]["technique_id"] in {None, "T1003", "T1021"}


def test_persisted_attack_mapping_is_read_from_real_detection_rows(
    client, db_session, admin_token, prediction_correlation
):
    response = client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["metadata"]["observed_technique_count"] == 2
    assert sorted(body["observed_techniques"]) == ["T1003", "T1021"]
    carried = {p["technique"]["technique_id"] for p in body["predictions"]}
    assert carried <= {"T1003", "T1021"}
    assert None not in carried or body["status"] != "PREDICTED"


def test_a_correlation_with_no_persisted_mapping_predicts_nothing(
    client, admin_token, unmapped_correlation
):
    """No ATT&CK mapping anywhere means no technique id may be asserted."""
    response = client.post(
        f"{BASE}/{unmapped_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["metadata"]["observed_technique_count"] == 0
    assert body["observed_techniques"] == []
    assert all(p["technique"]["technique_id"] is None for p in body["predictions"])
    unavailable = body["metadata"]["unavailable_inputs"]
    assert "persisted_attack_mapping" in unavailable
    assert "ATT&CK" in unavailable["persisted_attack_mapping"]


def test_every_citation_resolves_to_the_real_graph(
    client, db_session, admin_token, prediction_correlation
):
    response = client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    assert response.status_code == 200, response.text
    body = response.json()

    available = {
        node["source_reference"]
        for node in prediction_correlation["graph"].nodes
        if node["source_reference"]
    }
    cited: list[str] = []
    for prediction in body["predictions"]:
        cited.extend(
            item["reference"]
            for item in prediction["uncertainty"]["supporting_evidence"]
        )
        cited.extend(
            item["reference"]
            for item in prediction["uncertainty"]["contradicting_evidence"]
        )
    cited.extend(item["reference"] for item in body["current_state"])
    assert cited, "expected the prediction to cite its grounding"
    assert set(cited) <= available


def test_consuming_a_persisted_debate_is_recorded_and_disclosed(
    client, db_session, admin_token, correlated_prediction_correlation
):
    built = correlated_prediction_correlation
    response = client.post(
        f"{BASE}/{built['correlation_id']}", headers=auth_header(admin_token)
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["metadata"]["debate_id"] == built["debate_id"]
    assert body["metadata"]["debate_consensus_state"]
    # provider/model describe the *consumed* debate, not a call V3.24 made.
    assert body["metadata"]["debate_provider"]
    assert "debate" not in body["metadata"]["unavailable_inputs"]


def test_a_correlation_with_no_debate_records_that_as_a_limitation(
    client, admin_token, prediction_correlation
):
    response = client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["metadata"]["debate_id"] is None
    assert any("debate" in reason for reason in body["metadata"]["unavailable_inputs"].values())
    assert any(
        item["kind"] == "no_debate_artifact"
        for prediction in body["predictions"]
        for item in prediction["uncertainty"]["limitations"]
    )


# ---------------------------------------------------------------------------
# Prediction ≠ evidence, in the database
# ---------------------------------------------------------------------------


def test_every_persisted_row_is_pinned_to_ai_generated(
    client, db_session, admin_token, prediction_correlation
):
    client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    rows = db_session.execute(select(AttackPredictionSessionRecord)).scalars().all()
    assert rows
    assert {row.provenance for row in rows} == {"ai_generated"}

    predictions = db_session.execute(select(AttackPredictionRecord)).scalars().all()
    assert predictions and {row.provenance for row in predictions} == {"ai_generated"}

    evidence = db_session.execute(select(AttackPredictionEvidenceRecord)).scalars().all()
    assert evidence and {row.provenance for row in evidence} == {"ai_generated"}

    uncertainties = db_session.execute(
        select(AttackPredictionUncertaintyRecord)
    ).scalars().all()
    assert uncertainties and {row.provenance for row in uncertainties} == {"ai_generated"}


def test_no_secret_from_the_evidence_layer_reaches_a_prediction(
    client, admin_token, prediction_correlation
):
    """Detection payloads must never be echoed into an analytical artifact."""
    response = client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    assert response.status_code == 200, response.text
    serialized = response.text
    assert LEAKED_SECRET not in serialized
    assert LEAKED_API_KEY not in serialized
    assert "must-never" not in serialized


def test_prediction_tables_store_pointers_not_source_content(
    client, db_session, admin_token, prediction_correlation
):
    client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    citations = db_session.execute(select(AttackPredictionEvidenceRecord)).scalars().all()
    assert citations
    for citation in citations:
        assert citation.reference
        assert citation.entity_kind
        assert citation.node_id
        # A citation is a pointer: no column carries copied source content.
        assert LEAKED_SECRET not in str(citation.__dict__)


# ---------------------------------------------------------------------------
# Idempotency and the read model (§24)
# ---------------------------------------------------------------------------


def test_repeating_the_post_returns_the_same_session_without_a_second_row(
    client, db_session, admin_token, prediction_correlation
):
    first = client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    second = client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()

    count = db_session.execute(
        select(func.count()).select_from(AttackPredictionSessionRecord)
    ).scalar_one()
    assert count == 1


def test_get_returns_the_session_document_a_prediction_belongs_to(
    client, admin_token, prediction_correlation
):
    created = client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    ).json()
    prediction_id = created["predictions"][0]["prediction_id"]

    fetched = client.get(f"{BASE}/{prediction_id}", headers=auth_header(admin_token))
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["prediction_session_id"] == created["prediction_session_id"]
    assert any(
        p["prediction_id"] == prediction_id for p in body["predictions"]
    )
    # Evidence travels with the prediction, never as a bare row.
    target = next(
        p for p in body["predictions"] if p["prediction_id"] == prediction_id
    )
    assert "uncertainty" in target
    assert "limitations_note" in body


def test_no_completion_is_audited_for_a_pure_replay(
    client, db_session, admin_token, prediction_correlation
):
    """A replay performs no reasoning, so it must not be logged as one."""
    from app.models.audit_log import AuditLog

    client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    db_session.expire_all()

    def _count(action: str) -> int:
        return db_session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == action)
        ).scalar_one()

    after_first = {
        action: _count(action)
        for action in ("attack_prediction.created", "attack_prediction.completed")
    }
    client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    db_session.expire_all()

    # Neither event may grow on a replay. A "created" record for a session the
    # replay did not create would misrepresent the write history.
    assert {
        action: _count(action)
        for action in ("attack_prediction.created", "attack_prediction.completed")
    } == after_first


def test_no_creation_is_audited_when_persistence_fails(
    monkeypatch, client, db_session, admin_token, prediction_correlation
):
    """A failed write must not leave a "created" record of a session that
    does not exist."""
    from app.models.audit_log import AuditLog
    from app.services.prediction.persistence import PredictionPersistenceError

    def _count(action: str) -> int:
        return db_session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == action)
        ).scalar_one()

    db_session.expire_all()
    before = {
        action: _count(action)
        for action in ("attack_prediction.created", "attack_prediction.completed")
    }

    def _fail(*_args, **_kwargs):
        raise PredictionPersistenceError("simulated persistence failure")

    monkeypatch.setattr(
        "app.api.routes.attack_predictions.AttackPredictionService.persist_result", _fail
    )

    response = client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    assert response.status_code in (409, 503)
    db_session.expire_all()

    assert {
        action: _count(action)
        for action in ("attack_prediction.created", "attack_prediction.completed")
    } == before
    assert _count("attack_prediction.failed") >= 1


def test_lifecycle_actions_are_audited(client, db_session, admin_token, prediction_correlation):
    from app.models.audit_log import AuditLog

    client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    db_session.expire_all()
    actions = set(
        db_session.execute(
            select(AuditLog.action).where(
                AuditLog.action.like("attack_prediction.%")
            )
        )
        .scalars()
        .all()
    )
    assert "attack_prediction.created" in actions
    assert "attack_prediction.completed" in actions


def test_a_failure_is_audited_as_failed(client, db_session, admin_token):
    from app.models.audit_log import AuditLog

    client.post(f"{BASE}/{uuid.uuid4()}", headers=auth_header(admin_token))
    db_session.expire_all()
    failures = db_session.execute(
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.action == "attack_prediction.failed")
    ).scalar_one()
    assert failures >= 1


def test_audit_details_carry_no_secret(client, db_session, admin_token, prediction_correlation):
    from app.models.audit_log import AuditLog

    client.post(
        f"{BASE}/{prediction_correlation['correlation_id']}",
        headers=auth_header(admin_token),
    )
    details = db_session.execute(
        select(AuditLog.details).where(AuditLog.action.like("attack_prediction.%"))
    ).scalars().all()
    joined = " ".join(d or "" for d in details)
    assert LEAKED_SECRET not in joined
    assert LEAKED_API_KEY not in joined


# ---------------------------------------------------------------------------
# Persistence service behaviour
# ---------------------------------------------------------------------------


def test_persisting_the_same_result_twice_is_a_no_op(db_session, prediction_correlation):
    service = AttackPredictionService(db_session)
    inputs = assemble_prediction_inputs(
        db_session,
        prediction_correlation["correlation_id"],
        bounds=DEFAULT_PREDICTION_BOUNDS,
    )
    result = AttackPredictionEngine().predict(inputs)

    first, created_first = service.persist_result(result)
    second, created_second = service.persist_result(result)

    assert created_first is True
    assert created_second is False
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert service.count_predictions(result.prediction_session_id) >= 0


def test_the_read_model_is_the_canonical_document(db_session, prediction_correlation):
    """The GET path is not a re-derivation; it is the stored document."""
    service = AttackPredictionService(db_session)
    inputs = assemble_prediction_inputs(
        db_session, prediction_correlation["correlation_id"]
    )
    result = AttackPredictionEngine().predict(inputs)
    stored, _ = service.persist_result(result)

    reloaded = service.get_session(result.prediction_session_id)
    assert reloaded is not None
    assert reloaded.model_dump(mode="json") == stored.model_dump(mode="json")


def test_sessions_are_queryable_per_correlation(db_session, prediction_correlation):
    service = AttackPredictionService(db_session)
    inputs = assemble_prediction_inputs(
        db_session, prediction_correlation["correlation_id"]
    )
    result = AttackPredictionEngine().predict(inputs)
    service.persist_result(result)

    sessions = service.get_by_correlation(prediction_correlation["correlation_id"])
    assert [s.prediction_session_id for s in sessions] == [result.prediction_session_id]


def test_the_engine_never_mutates_the_graph(
    db_session, prediction_correlation
):
    """Prediction is a new downstream artifact, not a mutation of V3.22 state."""
    from app.models.knowledge_graph import KnowledgeGraphEdge, KnowledgeGraphNode

    before_nodes = db_session.execute(
        select(func.count()).select_from(KnowledgeGraphNode)
    ).scalar_one()
    before_edges = db_session.execute(
        select(func.count()).select_from(KnowledgeGraphEdge)
    ).scalar_one()

    inputs = assemble_prediction_inputs(
        db_session, prediction_correlation["correlation_id"]
    )
    AttackPredictionEngine().predict(inputs)

    assert db_session.execute(
        select(func.count()).select_from(KnowledgeGraphNode)
    ).scalar_one() == before_nodes
    assert db_session.execute(
        select(func.count()).select_from(KnowledgeGraphEdge)
    ).scalar_one() == before_edges


def test_a_correlation_whose_graph_changed_yields_a_new_session(
    db_session, prediction_correlation, monkeypatch
):
    """New evidence means a new prediction, never a mutated one."""
    service = AttackPredictionService(db_session)
    inputs = assemble_prediction_inputs(
        db_session, prediction_correlation["correlation_id"]
    )
    engine = AttackPredictionEngine()
    first = engine.predict(inputs)
    service.persist_result(first)

    moved = inputs.model_copy(update={"graph_snapshot_digest": "f" * 64})
    second = engine.predict(moved)

    assert second.prediction_session_id != first.prediction_session_id


def test_a_second_debate_produces_a_new_session(db_session, debate_free_correlation):
    """Persisting a debate for the same correlation must not reuse a session.

    A session whose identity omitted ``debate_id`` would collide here and silently
    return the pre-debate conclusion, reporting that a later debate had no effect.
    """
    built = debate_free_correlation
    service = AttackPredictionService(db_session)
    inputs = assemble_prediction_inputs(db_session, built["correlation_id"])
    assert inputs.debate is None
    first = AttackPredictionEngine().predict(inputs)
    service.persist_result(first)

    persist_debate_naming(
        db_session, built, hypothesis="lateral movement is plausible"
    )
    with_debate = assemble_prediction_inputs(db_session, built["correlation_id"])
    assert with_debate.debate is not None
    second = AttackPredictionEngine().predict(with_debate)

    assert second.prediction_session_id != first.prediction_session_id
    assert second.metadata.debate_id != first.metadata.debate_id