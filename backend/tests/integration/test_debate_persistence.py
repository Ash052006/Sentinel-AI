"""Debate persistence tests — V3.23.

Covers the properties that make stored debates trustworthy: lossless round-trip,
database-enforced idempotency, provenance pinning, and the fact that persisting
a debate never touches the knowledge graph or any V2 record.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.agents.debate.engine import DebateEngine
from app.models.debate import (
    DebateAgentAssessmentRecord,
    DebateArgumentRecord,
    DebateConsensusRecord,
    DebateRoundRecord,
    DebateSessionRecord,
)
from app.services.debate.persistence import DebateService
from tests.helpers.debate_runtime import ScriptedDebateRuntime
from tests.integration.debate_fixtures import agreement_script, argument_script


@pytest.fixture(autouse=True)
def clean_rows(db_session: Session):
    for model in (
        DebateConsensusRecord,
        DebateArgumentRecord,
        DebateAgentAssessmentRecord,
        DebateRoundRecord,
        DebateSessionRecord,
    ):
        db_session.execute(text(f"DELETE FROM {model.__tablename__}"))
    db_session.commit()
    yield db_session


@pytest.fixture
def completed_debate(debate_correlation):
    script = agreement_script(
        debate_correlation["detection_ref"], debate_correlation["correlation_ref"]
    )
    engine = DebateEngine(runtime=ScriptedDebateRuntime(script))
    return engine.run(
        debate_correlation["graph"],
        correlation_id=debate_correlation["correlation_id"],
        unavailable_entity_types=debate_correlation["queries"].unavailable_entity_types(),
    )


@pytest.fixture
def debated_with_arguments(debate_correlation):
    """A debate that raises real arguments and counterarguments."""
    engine = DebateEngine(
        runtime=ScriptedDebateRuntime(
            argument_script(
                debate_correlation["detection_ref"],
                debate_correlation["correlation_ref"],
            )
        )
    )
    return engine.run(
        debate_correlation["graph"],
        correlation_id=debate_correlation["correlation_id"],
        unavailable_entity_types=debate_correlation["queries"].unavailable_entity_types(),
    )


def _counts(db: Session, debate_id: uuid.UUID) -> tuple[int, ...]:
    return tuple(
        db.execute(
            text(
                f"SELECT (SELECT count(*) FROM debate_sessions WHERE id = :i), "
                f"(SELECT count(*) FROM debate_rounds WHERE debate_id = :i), "
                f"(SELECT count(*) FROM debate_agent_assessments WHERE debate_id = :i), "
                f"(SELECT count(*) FROM debate_arguments WHERE debate_id = :i), "
                f"(SELECT count(*) FROM debate_consensus WHERE debate_id = :i)"
            ),
            {"i": debate_id},
        ).one()
    )


class TestPersistSession:
    def test_writes_all_five_tables(self, db_session, debated_with_arguments):
        DebateService(db_session).persist_session(debated_with_arguments)
        sessions, rounds, assessments, arguments, consensus = _counts(
            db_session, debated_with_arguments.debate_id
        )
        assert (sessions, rounds, assessments, consensus) == (1, 5, 5, 1)
        assert arguments == len(debated_with_arguments.arguments) + len(
            debated_with_arguments.counterarguments
        )
        assert arguments > 0

    def test_round_trip_is_lossless(self, db_session, completed_debate):
        stored, _ = DebateService(db_session).persist_session(completed_debate)
        loaded = DebateService(db_session).get_session(completed_debate.debate_id)
        assert loaded is not None
        assert loaded.model_dump_json() == stored.model_dump_json()

    def test_get_returns_none_for_unknown_id(self, db_session):
        assert DebateService(db_session).get_session(uuid.uuid4()) is None

    def test_list_for_correlation(self, db_session, completed_debate):
        service = DebateService(db_session)
        service.persist_session(completed_debate)
        found = service.list_for_correlation(completed_debate.correlation_id)
        assert [s.debate_id for s in found] == [completed_debate.debate_id]


class TestIdempotency:
    def test_repeated_persist_creates_one_row(self, db_session, completed_debate):
        service = DebateService(db_session)
        _, first = service.persist_session(completed_debate)
        _, second = service.persist_session(completed_debate)
        assert first is True
        assert second is False
        assert _counts(db_session, completed_debate.debate_id)[0] == 1

    def test_repeated_persist_does_not_mutate_the_stored_conclusion(
        self, db_session, completed_debate
    ):
        service = DebateService(db_session)
        service.persist_session(completed_debate)
        original = service.get_session(completed_debate.debate_id)

        altered = completed_debate.model_copy(
            update={
                "consensus": completed_debate.consensus.model_copy(
                    update={"leading_hypothesis": "A different conclusion."}
                )
            }
        )
        service.persist_session(altered)
        unchanged = service.get_session(completed_debate.debate_id)
        assert unchanged.consensus.leading_hypothesis == (
            original.consensus.leading_hypothesis
        )

    def test_same_graph_and_config_yields_the_same_id(self, debate_correlation):
        script = agreement_script(
            debate_correlation["detection_ref"], debate_correlation["correlation_ref"]
        )
        first = DebateEngine(runtime=ScriptedDebateRuntime(script)).run(
            debate_correlation["graph"],
            correlation_id=debate_correlation["correlation_id"],
            unavailable_entity_types=debate_correlation["queries"].unavailable_entity_types(),
        )
        second = DebateEngine(runtime=ScriptedDebateRuntime(script)).run(
            debate_correlation["graph"],
            correlation_id=debate_correlation["correlation_id"],
            unavailable_entity_types=debate_correlation["queries"].unavailable_entity_types(),
        )
        assert first.debate_id == second.debate_id


class TestProvenanceIsPinned:
    @pytest.mark.parametrize(
        "table",
        [
            "debate_sessions",
            "debate_rounds",
            "debate_agent_assessments",
            "debate_arguments",
            "debate_consensus",
        ],
    )
    def test_every_debate_table_is_ai_generated(self, db_session, debated_with_arguments, table):
        DebateService(db_session).persist_session(debated_with_arguments)
        values = db_session.execute(
            text(f"SELECT DISTINCT provenance FROM {table}")
        ).scalars().all()
        assert values, f"{table} should hold rows"
        assert values == ["ai_generated"]

    @pytest.mark.parametrize(
        "table",
        [
            "debate_sessions",
            "debate_rounds",
            "debate_agent_assessments",
            "debate_arguments",
            "debate_consensus",
        ],
    )
    def test_provenance_is_check_constrained(self, db_session, table):
        """The pinning is a database constraint, not just a convention."""
        names = db_session.execute(
            text(
                "SELECT conname FROM pg_constraint "
                "WHERE conrelid = to_regclass(:t)"
            ),
            {"t": table},
        ).scalars().all()
        assert f"ck_{table}_provenance_ai_generated" in names

    def test_database_rejects_evidence_provenance_on_a_debate(
        self, db_session, debated_with_arguments
    ):
        DebateService(db_session).persist_session(debated_with_arguments)
        with pytest.raises(Exception):
            db_session.execute(
                text(
                    "UPDATE debate_consensus SET provenance = 'observed' "
                    "WHERE debate_id = :i"
                ),
                {"i": debated_with_arguments.debate_id},
            )
        db_session.rollback()

    def test_argument_without_evidence_is_rejected(self, db_session, debated_with_arguments):
        DebateService(db_session).persist_session(debated_with_arguments)
        db_session.add(
            DebateArgumentRecord(
                id=uuid.uuid4(),
                debate_id=debated_with_arguments.debate_id,
                argument_id="no-evidence",
                kind="argument",
                author_agent_id="agent:skeptic",
                author_role="skeptic",
                statement="An argument citing nothing.",
                evidence_references=[],
                provenance="ai_generated",
            )
        )
        with pytest.raises(Exception):
            db_session.commit()
        db_session.rollback()


class TestNoEvidenceDuplication:
    def test_persisting_a_debate_writes_no_graph_rows(
        self, db_session, completed_debate
    ):
        before = tuple(
            db_session.execute(
                text(
                    "SELECT (SELECT count(*) FROM knowledge_graph_nodes), "
                    "(SELECT count(*) FROM knowledge_graph_edges), "
                    "(SELECT count(*) FROM correlation_results), "
                    "(SELECT count(*) FROM detection_results)"
                )
            ).one()
        )
        DebateService(db_session).persist_session(completed_debate)
        db_session.expire_all()
        after = tuple(
            db_session.execute(
                text(
                    "SELECT (SELECT count(*) FROM knowledge_graph_nodes), "
                    "(SELECT count(*) FROM knowledge_graph_edges), "
                    "(SELECT count(*) FROM correlation_results), "
                    "(SELECT count(*) FROM detection_results)"
                )
            ).one()
        )
        assert before == after

    def test_stored_evidence_references_are_pointers_not_records(
        self, db_session, completed_debate
    ):
        DebateService(db_session).persist_session(completed_debate)
        db_session.expire_all()
        stored = (
            db_session.query(DebateAgentAssessmentRecord)
            .filter(
                DebateAgentAssessmentRecord.debate_id == completed_debate.debate_id
            )
            .first()
        )
        assert stored is not None
        for reference in stored.evidence_references:
            assert set(reference) == {"reference", "entity_kind", "node_id"}
            # A pointer, not a copied V2 payload.
            assert set(reference) & {
                "evidence",
                "result_metadata",
                "api_key",
                "secret",
            } == set()

class TestProviderAttribution:
    """A stored debate must name the backend that actually produced it.

    Provider and model are part of the analytical artifact's identity, so they
    have to survive the round trip through the database rather than being lost
    or defaulted on read-back. This is also why no schema migration was needed:
    the columns already existed.
    """

    @pytest.mark.parametrize(
        ("provider", "model"),
        [
            ("gemini", "gemini-3.8-flash"),
            ("groq", "openai/gpt-oss-120b"),
        ],
    )
    def test_provider_and_model_round_trip(
        self, db_session, debate_correlation, provider, model
    ):
        script = agreement_script(
            debate_correlation["detection_ref"], debate_correlation["correlation_ref"]
        )
        session = DebateEngine(
            runtime=ScriptedDebateRuntime(script, provider=provider, model=model)
        ).run(
            debate_correlation["graph"],
            correlation_id=debate_correlation["correlation_id"],
            unavailable_entity_types=debate_correlation[
                "queries"
            ].unavailable_entity_types(),
        )

        DebateService(db_session).persist_session(session)
        db_session.expire_all()

        stored = (
            db_session.query(DebateSessionRecord)
            .filter(DebateSessionRecord.id == session.debate_id)
            .one()
        )
        assert stored.provider == provider
        assert stored.model == model
        # The persisted digests must match what the engine computed, or the
        # stored artifact would not be reproducible from its own inputs.
        assert stored.configuration_digest == session.metadata.configuration_digest
        assert stored.graph_snapshot_digest == session.metadata.graph_snapshot_digest

    def test_two_providers_over_identical_evidence_persist_as_two_artifacts(
        self, db_session, debate_correlation
    ):
        """Distinct backends must not collide into one stored row."""

        def run(provider: str, model: str):
            script = agreement_script(
                debate_correlation["detection_ref"],
                debate_correlation["correlation_ref"],
            )
            return DebateEngine(
                runtime=ScriptedDebateRuntime(script, provider=provider, model=model)
            ).run(
                debate_correlation["graph"],
                correlation_id=debate_correlation["correlation_id"],
                unavailable_entity_types=debate_correlation[
                    "queries"
                ].unavailable_entity_types(),
            )

        service = DebateService(db_session)
        gemini = run("gemini", "gemini-3.8-flash")
        groq = run("groq", "openai/gpt-oss-120b")

        assert gemini.debate_id != groq.debate_id
        service.persist_session(gemini)
        service.persist_session(groq)
        db_session.expire_all()

        rows = (
            db_session.query(DebateSessionRecord)
            .filter(
                DebateSessionRecord.id.in_([gemini.debate_id, groq.debate_id])
            )
            .all()
        )
        assert len(rows) == 2
        assert {row.provider for row in rows} == {"gemini", "groq"}
        assert {row.configuration_digest for row in rows} == {
            gemini.metadata.configuration_digest,
            groq.metadata.configuration_digest,
        }

    def test_persisting_a_debate_does_not_rewrite_v2_records(
        self, db_session, completed_debate, debate_correlation
    ):
        """Attribution bookkeeping must not mutate evidence."""
        correlation_id = debate_correlation["correlation_id"]
        before = db_session.execute(
            text("SELECT confidence FROM correlation_results WHERE correlation_id = :cid"),
            {"cid": str(correlation_id)},
        ).scalar()

        DebateService(db_session).persist_session(completed_debate)
        db_session.expire_all()

        after = db_session.execute(
            text("SELECT confidence FROM correlation_results WHERE correlation_id = :cid"),
            {"cid": str(correlation_id)},
        ).scalar()
        assert before == after
