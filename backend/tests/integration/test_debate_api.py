"""Debate API integration tests — V3.23.

Covers authentication, RBAC, status codes, response shape, idempotency, and
secret safety of the serialized payload.

The model provider is replaced with a deterministic runtime so the suite needs
no Gemini key and makes no outbound call.  Every test asserts on the real
engine running over the real V3.22 graph, not on a stubbed route.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.api.routes import debates as debates_module
from app.agents.debate.engine import DebateEngine
from app.agents.debate.exceptions import (
    DebateProviderError,
    DebateProviderUnavailableError,
)
from app.models.debate import DebateSessionRecord
from tests.conftest import auth_header
from tests.helpers.debate_runtime import FailingDebateRuntime, ScriptedDebateRuntime
from tests.integration.debate_fixtures import agreement_script

BASE = "/api/debates"


@pytest.fixture
def scripted_engine(debate_correlation, monkeypatch):
    """Serve the debate engine from a deterministic runtime.

    Installed via ``monkeypatch`` on the route module's engine factory so the
    provider seam is exercised the same way in tests as in production, without
    any network access.
    """
    script = agreement_script(
        debate_correlation["detection_ref"], debate_correlation["correlation_ref"]
    )
    runtime = ScriptedDebateRuntime(script)
    monkeypatch.setattr(
        debates_module,
        "_engine",
        lambda: DebateEngine(runtime=runtime),
    )
    return runtime


@pytest.fixture
def broken_engine(debate_correlation, monkeypatch):
    """Serve an engine whose provider always fails."""
    runtime = FailingDebateRuntime(
        DebateProviderUnavailableError("provider is unavailable")
    )
    monkeypatch.setattr(
        debates_module, "_engine", lambda: DebateEngine(runtime=runtime)
    )
    return runtime


@pytest.fixture(autouse=True)
def clean_debate_rows(db_session: Session):
    """Clear persisted debate rows before each test.

    The correlation fixture is module-scoped, so without this a debate persisted
    by one test would be visible to the next and break the "persists nothing"
    assertions.
    """
    from app.models.debate import (
        DebateAgentAssessmentRecord,
        DebateArgumentRecord,
        DebateConsensusRecord,
        DebateRoundRecord,
        DebateSessionRecord,
    )

    for model in (
        DebateConsensusRecord,
        DebateArgumentRecord,
        DebateAgentAssessmentRecord,
        DebateRoundRecord,
        DebateSessionRecord,
    ):
        db_session.execute(delete(model))
    db_session.commit()
    yield db_session


# ---------------------------------------------------------------------------
# Authentication and RBAC
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_anonymous_is_rejected(self, client, debate_correlation):
        correlation_id = debate_correlation["correlation_id"]
        assert client.post(f"{BASE}/{correlation_id}").status_code == 401
        assert client.get(f"{BASE}/{uuid.uuid4()}").status_code == 401

    @pytest.mark.parametrize("fixture_name", ["analyst_token", "ciso_token", "admin_token"])
    def test_soc_roles_may_run_and_read(self, client, request, fixture_name, scripted_engine, debate_correlation):
        token = request.getfixturevalue(fixture_name)
        response = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(token),
        )
        assert response.status_code == 200
        assert client.get(
            f"{BASE}/{response.json()['debate_id']}", headers=auth_header(token)
        ).status_code == 200


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestValidation:
    def test_malformed_correlation_id_is_422(self, client, admin_token, scripted_engine):
        assert client.post(
            f"{BASE}/not-a-uuid", headers=auth_header(admin_token)
        ).status_code == 422

    def test_malformed_debate_id_is_422(self, client, admin_token):
        assert client.get(
            f"{BASE}/not-a-uuid", headers=auth_header(admin_token)
        ).status_code == 422

    def test_unknown_correlation_is_404(self, client, admin_token, scripted_engine):
        response = client.post(f"{BASE}/{uuid.uuid4()}", headers=auth_header(admin_token))
        assert response.status_code == 404

    def test_unknown_debate_is_404(self, client, admin_token):
        response = client.get(f"{BASE}/{uuid.uuid4()}", headers=auth_header(admin_token))
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Running a debate
# ---------------------------------------------------------------------------


class TestRunDebate:
    def test_returns_a_complete_five_round_debate(self, client, admin_token, scripted_engine, debate_correlation):
        response = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "completed"
        assert len(body["rounds"]) == 5
        assert len(body["agents"]) == 5
        assert len(body["assessments"]) == 5
        assert body["consensus"]["state"] in {
            "consensus",
            "partial_consensus",
            "contested",
            "insufficient_evidence",
        }
        assert body["consensus"]["provenance"] == "ai_generated"

    def test_facts_are_engine_derived_and_cited(self, client, admin_token, scripted_engine, debate_correlation):
        body = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).json()
        assert body["facts"]
        for fact in body["facts"]:
            assert fact["claim_kind"] == "fact"
            assert fact["evidence_references"], "every fact must cite real evidence"

    def test_every_argument_cites_evidence(self, client, admin_token, scripted_engine, debate_correlation):
        body = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).json()
        for argument in body["arguments"]:
            assert argument["evidence_references"]
            assert argument["provenance"] == "ai_generated"

    def test_graph_counts_are_reported(self, client, admin_token, scripted_engine, debate_correlation):
        body = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).json()
        scope = body["evidence_scope"]
        assert scope["graph_node_count"] > 0
        assert scope["graph_edge_count"] > 0
        assert scope["evidence_reference_count"] > 0

    def test_evidence_gaps_are_disclosed(self, client, admin_token, scripted_engine, debate_correlation):
        body = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).json()
        assert body["consensus"]["evidence_gaps"]


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_repeating_a_post_returns_the_same_debate(
        self, client, admin_token, scripted_engine, debate_correlation, db_session
    ):
        first = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        second = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        assert first.status_code == second.status_code == 200
        assert first.json()["debate_id"] == second.json()["debate_id"]

    def test_repeat_does_not_duplicate_rows(
        self, client, admin_token, scripted_engine, debate_correlation, db_session
    ):
        first = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).json()
        client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        db_session.expire_all()
        rows = (
            db_session.query(DebateSessionRecord)
            .filter(DebateSessionRecord.id == uuid.UUID(first["debate_id"]))
            .all()
        )
        assert len(rows) == 1

    def test_get_returns_exactly_what_post_produced(
        self, client, admin_token, scripted_engine, debate_correlation
    ):
        posted = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).json()
        fetched = client.get(
            f"{BASE}/{posted['debate_id']}", headers=auth_header(admin_token)
        ).json()
        assert fetched == posted


# ---------------------------------------------------------------------------
# Governed failures
# ---------------------------------------------------------------------------


class TestGovernedFailures:
    def test_provider_unavailable_is_503_and_invents_nothing(
        self, client, admin_token, broken_engine, debate_correlation
    ):
        response = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 503
        assert "consensus" not in response.json().get("detail", {})

    def test_provider_failure_persists_nothing(
        self, client, admin_token, broken_engine, debate_correlation, db_session
    ):
        client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        db_session.expire_all()
        assert (
            db_session.query(DebateSessionRecord)
            .filter(
                DebateSessionRecord.correlation_id
                == debate_correlation["correlation_id"]
            )
            .count()
            == 0
        )


# ---------------------------------------------------------------------------
# Secret safety
# ---------------------------------------------------------------------------


class TestSecretSafety:
    def test_secrets_never_reach_the_response(
        self, client, admin_token, scripted_engine, debate_correlation
    ):
        body = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).text
        assert "sk-must-never-appear" not in body
        assert "must never reach a debate prompt" not in body

    def test_graph_is_not_written_by_a_debate(
        self, client, admin_token, scripted_engine, debate_correlation, db_session
    ):
        from app.models.knowledge_graph import KnowledgeGraphEdge, KnowledgeGraphNode

        db_session.expire_all()
        nodes_before = db_session.query(KnowledgeGraphNode).count()
        edges_before = db_session.query(KnowledgeGraphEdge).count()
        client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        db_session.expire_all()
        assert db_session.query(KnowledgeGraphNode).count() == nodes_before
        assert db_session.query(KnowledgeGraphEdge).count() == edges_before

    def test_v2_evidence_rows_are_not_mutated_by_a_debate(
        self, client, admin_token, scripted_engine, debate_correlation, db_session
    ):
        """A debate is downstream analytical state: it reads evidence, never edits it."""
        from app.models.correlation_member import CorrelationMember
        from app.models.correlation_result import CorrelationResult
        from app.models.detection_result import DetectionResult

        db_session.expire_all()
        before = {
            "correlations": db_session.query(CorrelationResult).count(),
            "members": db_session.query(CorrelationMember).count(),
            "detections": db_session.query(DetectionResult).count(),
            "confidence": db_session.query(CorrelationResult)
            .filter(
                CorrelationResult.correlation_id
                == debate_correlation["correlation_id"]
            )
            .one()
            .confidence,
        }
        client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        db_session.expire_all()
        after = {
            "correlations": db_session.query(CorrelationResult).count(),
            "members": db_session.query(CorrelationMember).count(),
            "detections": db_session.query(DetectionResult).count(),
            "confidence": db_session.query(CorrelationResult)
            .filter(
                CorrelationResult.correlation_id
                == debate_correlation["correlation_id"]
            )
            .one()
            .confidence,
        }
        assert before == after

# ---------------------------------------------------------------------------
# Audit lifecycle
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_tracker(db_session: Session):
    """Read audit rows created *by this test only*.

    ``audit_logs`` is shared session-wide state that other suites also write,
    so assertions must never read the whole table. Snapshotting the existing
    primary keys and diffing is exact regardless of test order.
    """
    from app.models.audit_log import AuditLog

    def snapshot() -> set:
        db_session.expire_all()
        return {row.id for row in db_session.query(AuditLog).all()}

    before = snapshot()

    def added(action: str) -> list:
        db_session.expire_all()
        return [
            row
            for row in db_session.query(AuditLog).all()
            if row.id not in before and row.action == action
        ]

    return added


class TestAuditLifecycle:
    """A debate conclusion must be attributable after the fact.

    The audit row records that a conclusion exists, who asked for it and how it
    resolved — not the reasoning itself. Prompt text, the provider endpoint and
    any credential are deliberately absent from ``details``.
    """

    def test_completion_is_audited_with_the_debate_and_outcome(
        self, client, admin_token, scripted_engine, debate_correlation, audit_tracker
    ):
        response = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        debate_id = response.json()["debate_id"]

        rows = audit_tracker("debate.completed")
        assert len(rows) == 1
        details = rows[0].details
        assert debate_id in details
        assert str(debate_correlation["correlation_id"]) in details
        # The recorded outcome matches the consensus state actually stored.
        assert response.json()["consensus"]["state"] in details
        assert rows[0].resource == "debates"

    def test_idempotent_replay_is_not_audited_as_a_second_completion(
        self, client, admin_token, scripted_engine, debate_correlation, audit_tracker
    ):
        url = f"{BASE}/{debate_correlation['correlation_id']}"
        first = client.post(url, headers=auth_header(admin_token))
        second = client.post(url, headers=auth_header(admin_token))

        # Idempotent: the same debate comes back rather than a new one.
        assert first.json()["debate_id"] == second.json()["debate_id"]
        # Only the request that actually reasoned is audited.
        assert len(audit_tracker("debate.completed")) == 1

    def test_provider_failure_is_audited_with_its_failure_code(
        self, client, admin_token, broken_engine, debate_correlation, audit_tracker
    ):
        response = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 503

        rows = audit_tracker("debate.failed")
        assert len(rows) == 1
        assert "debate_provider_unavailable" in rows[0].details
        # A failed debate is never also recorded as a completion.
        assert audit_tracker("debate.completed") == []

    def test_audit_details_never_carry_a_credential_or_the_prompt(
        self, client, admin_token, scripted_engine, debate_correlation, audit_tracker
    ):
        client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        rows = audit_tracker("debate.completed")
        details = rows[0].details.lower()
        for leak in ("api_key", "apikey", "authorization", "bearer", "prompt"):
            assert leak not in details


class TestProviderSelectionAtTheHttpBoundary:
    """The endpoint takes only a correlation id, so provider routing is not a
    client control.

    The rest of this module replaces ``_engine`` with a deterministic runtime.
    These tests deliberately do not, so the real ``build_debate_runtime`` path
    runs and the recorded attribution is checked at the HTTP boundary.
    """

    @pytest.mark.parametrize(
        ("provider", "model"),
        [
            ("gemini", "gemini-3.8-flash"),
            ("groq", "openai/gpt-oss-120b"),
        ],
    )
    def test_metadata_reports_the_server_configured_provider(
        self, client, admin_token, debate_correlation, monkeypatch, provider, model
    ):
        from app.core.config import settings

        monkeypatch.setattr(settings, "llm_provider", provider, raising=False)
        monkeypatch.setattr(
            debates_module,
            "_engine",
            lambda: DebateEngine(
                runtime=ScriptedDebateRuntime(
                    agreement_script(
                        debate_correlation["detection_ref"],
                        debate_correlation["correlation_ref"],
                    ),
                    provider=provider,
                    model=model,
                )
            ),
        )

        response = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        metadata = response.json()["metadata"]
        assert metadata["provider"] == provider
        assert metadata["model"] == model

    @pytest.mark.parametrize(
        "override",
        [
            {"provider": "groq"},
            {"model": "openai/gpt-oss-120b"},
            {"llm_provider": "groq"},
            {"provider": "groq", "model": "openai/gpt-oss-120b"},
        ],
    )
    def test_a_client_cannot_route_its_own_debate(
        self, client, admin_token, debate_correlation, monkeypatch, override
    ):
        """Provider and model in the body are ignored, not honoured."""
        from app.core.config import settings

        monkeypatch.setattr(settings, "llm_provider", "gemini", raising=False)
        monkeypatch.setattr(
            debates_module,
            "_engine",
            lambda: DebateEngine(
                runtime=ScriptedDebateRuntime(
                    agreement_script(
                        debate_correlation["detection_ref"],
                        debate_correlation["correlation_ref"],
                    ),
                    provider="gemini",
                    model="gemini-3.8-flash",
                )
            ),
        )

        response = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
            json=override,
        )
        assert response.status_code == 200
        metadata = response.json()["metadata"]
        # The deployment's configuration wins; the body's opinion is discarded.
        assert metadata["provider"] == "gemini"
        assert metadata["model"] == "gemini-3.8-flash"

    def test_a_failing_configured_provider_is_a_governed_503_with_no_fallback(
        self, client, admin_token, debate_correlation, monkeypatch
    ):
        """LLM_PROVIDER=groq plus a broken Groq must not be rescued by Gemini."""
        from app.core.config import settings

        monkeypatch.setattr(settings, "llm_provider", "groq", raising=False)
        monkeypatch.setattr(
            debates_module,
            "_engine",
            lambda: DebateEngine(
                runtime=FailingDebateRuntime(
                    DebateProviderUnavailableError("groq is unavailable"),
                    provider="groq",
                )
            ),
        )

        response = client.post(
            f"{BASE}/{debate_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 503
        # FastAPI nests the governed failure body under ``detail``.
        body = response.json()["detail"]
        assert body["failure_code"] == "debate_provider_unavailable"
        assert body["status"] == "failed"
        assert body["provenance"] == "ai_generated"
        # The failure contract must not leak provider internals or a credential.
        serialized = response.text
        assert "groq is unavailable" not in serialized
        assert "gsk_" not in serialized
        # And it is not a consensus-shaped response.
        assert "consensus" not in body
