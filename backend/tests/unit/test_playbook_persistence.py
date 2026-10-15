"""Playbook persistence tests — V3.25.

Idempotency is the property this file exists to defend, and it is a safety
property rather than an optimisation.  Playbook identity is derived from content,
so two runs over the same correlation, graph snapshot, debate, prediction and
configuration resolve to the *same* ``playbook_id``.  If a replay were allowed to
insert, every regeneration would fork a second proposal for the same incident —
an analyst reviewing one would approve a different document than the one that
executed, and the audit trail would show two plans where there was only ever one
decision.

So a replay must be a genuine no-op: no second session row, no duplicated child
rows, and a stored document returned untouched rather than rewritten.

These tests run against real PostgreSQL rather than SQLite.  The models use
``postgresql.UUID`` and the schema carries the CHECK constraints that the
identity argument depends on; an in-memory SQLite database cannot render the
project's JSONB columns at all, so a SQLite fixture would quietly test a schema
that does not exist.
"""

from __future__ import annotations

import json
import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy import delete, func, select

from app.agents.playbook.engine import PlaybookEngine
from app.database.postgres.session import SessionLocal
from app.models.playbook import (
    PlaybookActionEvidenceRecord,
    PlaybookActionRecord,
    PlaybookSessionRecord,
    PlaybookStepRecord,
)
from app.schemas.playbook import (
    ActionEvidence,
    ActionType,
    EvidenceSource,
    PlaybookInputs,
    PlaybookLifecycle,
    ResolvableTarget,
    TargetType,
)
from app.services.playbook.persistence import PlaybookService

#: Distinct from the engine suite's correlation so this file's rows cannot be
#: mistaken for, or cleaned up alongside, another test's data.
CORRELATION_ID = uuid.UUID("44444444-4444-5444-9444-444444444444")


def _evidence(reference: str = "threat_intelligence:ind-9") -> ActionEvidence:
    return ActionEvidence(
        source=EvidenceSource.THREAT_INTELLIGENCE,
        reference=reference,
        detail="a persisted row inside this correlation",
        stance="supporting",
    )


def _inputs() -> PlaybookInputs:
    """A proposal with several actions, so child-table counts are meaningful."""
    return PlaybookInputs(
        correlation_id=CORRELATION_ID,
        graph_snapshot_digest="b" * 64,
        graph_node_count=4,
        graph_edge_count=3,
        established_evidence={"threat_intelligence:ind-9": _evidence()},
        targets={
            "threat_intelligence:ind-9": ResolvableTarget(
                target_type=TargetType.IP,
                value="10.9.8.7",
                reference="threat_intelligence:ind-9",
                from_indicator=True,
            ),
        },
    )


def _proposal():
    return PlaybookEngine().generate(_inputs())


def _canonical(result) -> str:
    """Serialize the whole document so an unordered set cannot hide a change."""
    return json.dumps(result.model_dump(mode="json"), sort_keys=True)


@pytest.fixture()
def db():
    """A session cleaned up around this file's own rows.

    The suite's ``db_session`` fixture is session-scoped and shared, and the
    playbook tables cascade from the session row, so deleting this module's
    correlation is enough to leave no residue for other tests.
    """
    session = SessionLocal()
    try:
        _purge(session)
        yield session
    finally:
        _purge(session)
        session.close()


def _purge(session) -> None:
    ids = list(
        session.execute(
            select(PlaybookSessionRecord.id).where(
                PlaybookSessionRecord.correlation_id == CORRELATION_ID
            )
        ).scalars()
    )
    if not ids:
        return
    action_ids = list(
        session.execute(
            select(PlaybookActionRecord.id).where(
                PlaybookActionRecord.session_id.in_(ids)
            )
        ).scalars()
    )
    session.execute(
        delete(PlaybookActionEvidenceRecord).where(
            PlaybookActionEvidenceRecord.action_id.in_(action_ids)
        )
    )
    session.execute(
        delete(PlaybookActionRecord).where(PlaybookActionRecord.session_id.in_(ids))
    )
    session.execute(
        delete(PlaybookStepRecord).where(PlaybookStepRecord.session_id.in_(ids))
    )
    session.execute(delete(PlaybookSessionRecord).where(PlaybookSessionRecord.id.in_(ids)))
    session.commit()


def _session_rows(session) -> int:
    return int(
        session.execute(
            select(func.count())
            .select_from(PlaybookSessionRecord)
            .where(PlaybookSessionRecord.correlation_id == CORRELATION_ID)
        ).scalar()
        or 0
    )


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_the_stored_document_is_the_generated_document(self, db) -> None:
        """The child tables are for querying; the payload is the read model.

        A GET must return exactly what the POST produced.  Reconstructing from
        child rows instead would risk a lossy round trip that silently differs
        from the plan an analyst approved.
        """
        result = _proposal()
        PlaybookService(db).persist_result(result)
        loaded = PlaybookService(db).get_session(result.playbook_id)
        assert loaded is not None
        assert _canonical(loaded) == _canonical(result)

    def test_a_stored_proposal_reads_back_before_any_write(self, db) -> None:
        assert PlaybookService(db).get_session(uuid.uuid4()) is None


# ---------------------------------------------------------------------------
# Idempotency — the property under test
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_a_replay_creates_no_second_session(self, db) -> None:
        """Repeated generation must not fork a second proposal."""
        result = _proposal()
        service = PlaybookService(db)

        _, created_first = service.persist_result(result)
        _, created_second = service.persist_result(result)
        _, created_third = service.persist_result(result)

        assert created_first is True
        assert created_second is False
        assert created_third is False
        assert _session_rows(db) == 1

    def test_a_replay_does_not_duplicate_child_rows(self, db) -> None:
        """Steps, actions and citations are all keyed by the same identity."""
        result = _proposal()
        service = PlaybookService(db)
        service.persist_result(result)

        def counts() -> tuple[int, int, int]:
            session_ids = [result.playbook_id]
            action_ids = list(
                db.execute(
                    select(PlaybookActionRecord.id).where(
                        PlaybookActionRecord.session_id.in_(session_ids)
                    )
                ).scalars()
            )
            return (
                int(
                    db.execute(
                        select(func.count())
                        .select_from(PlaybookStepRecord)
                        .where(PlaybookStepRecord.session_id.in_(session_ids))
                    ).scalar()
                    or 0
                ),
                len(action_ids),
                int(
                    db.execute(
                        select(func.count())
                        .select_from(PlaybookActionEvidenceRecord)
                        .where(PlaybookActionEvidenceRecord.action_id.in_(action_ids))
                    ).scalar()
                    or 0
                ),
            )

        before = counts()
        assert before[0] > 0 and before[1] > 0 and before[2] > 0
        service.persist_result(result)
        assert counts() == before

    def test_a_replay_returns_the_stored_proposal_untouched(self, db) -> None:
        """An analyst may already be reviewing this document.

        A replay that rewrote the row — even with identical content — would race
        the review.  The stored bytes are compared before and after.
        """
        result = _proposal()
        service = PlaybookService(db)
        service.persist_result(result)
        row_before = db.get(PlaybookSessionRecord, result.playbook_id)
        assert row_before is not None
        payload_before = json.dumps(row_before.playbook_payload, sort_keys=True)
        created_at_before = row_before.created_at

        stored, created = service.persist_result(result)
        db.expire_all()

        assert created is False
        assert _canonical(stored) == _canonical(result)
        row_after = db.get(PlaybookSessionRecord, result.playbook_id)
        assert row_after is not None
        assert json.dumps(row_after.playbook_payload, sort_keys=True) == payload_before
        assert row_after.created_at == created_at_before

    def test_two_independent_sessions_converge_on_one_row(self, db) -> None:
        """Concurrent writers computed the same content-derived identity.

        Modelled with a second session that has not yet observed the first
        writer's commit, which is the window the unique constraint exists for.
        """
        result = _proposal()
        PlaybookService(db).persist_result(result)

        other = SessionLocal()
        try:
            stored, created = PlaybookService(other).persist_result(result)
        finally:
            other.close()

        assert created is False
        assert _canonical(stored) == _canonical(result)
        assert _session_rows(db) == 1

    def test_identity_is_content_derived_not_incidental(self) -> None:
        """Two independent runs agree on the id, which is why replay is safe."""
        first, second = _proposal(), _proposal()
        assert first.playbook_id == second.playbook_id
        assert _canonical(first) == _canonical(second)


# ---------------------------------------------------------------------------
# A hash indicator cannot reach a destructive file action
# ---------------------------------------------------------------------------


class TestHashIndicatorIsNotAddressable:
    """End-to-end proof that a digest cannot reach ``quarantine_file``.

    ``INDICATOR_TYPE_TO_TARGET_TYPE`` used to map ``hash -> TargetType.FILE``.
    ``FILE`` validates a *logical path*, and a hex digest satisfies that shape,
    so a sha256 indicator resolved into a FILE target and the engine proposed
    ``quarantine_file(<digest>)`` — a claim about a path that does not exist.

    The fix keeps a hash usable as evidence while making it non-addressable.  The
    frozen vocabulary has no ``HASH`` target, so "no target" is the existing
    vocabulary's way of saying a hash cannot be acted on.
    """

    DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def _assembled_from_hash_indicator(self):
        from app.services.knowledge_graph.queries import BoundedGraph
        from app.services.knowledge_graph.vocabulary import NodeType
        from app.services.playbook.context import PlaybookContextAssembler
        from tests.unit.test_playbook_context import (
            StubDebates,
            StubGraphQueries,
            StubPredictions,
        )

        graph = BoundedGraph(
            nodes=[
                {
                    "id": "node-ind-1",
                    "node_type": NodeType.THREAT_INDICATOR.value,
                    "source_id": "ind-1",
                    "label": f"hash:{self.DIGEST}",
                    "metadata": {"indicator_type": "hash", "value": self.DIGEST},
                }
            ]
        )
        return PlaybookContextAssembler(
            None,
            graph_queries=StubGraphQueries(graph),
            debate_service=StubDebates(),
            prediction_service=StubPredictions(),
        ).assemble(CORRELATION_ID)

    def test_a_hash_indicator_yields_no_target(self) -> None:
        assert self._assembled_from_hash_indicator().targets == {}

    def test_a_hash_indicator_remains_usable_evidence(self) -> None:
        """Non-addressable must not mean discarded.

        A detection grounded on the indicator that reported it can still cite it;
        removing the *target* must not remove the *evidence*.
        """
        inputs = self._assembled_from_hash_indicator()
        assert "threat_intelligence:ind-1" in inputs.established_evidence

    def test_the_engine_cannot_propose_quarantine_file_for_a_hash(self) -> None:
        result = PlaybookEngine().generate(self._assembled_from_hash_indicator())
        proposed = {a.action for a in result.playbook.actions}
        assert ActionType.QUARANTINE_FILE not in proposed
        assert ActionType.SCAN_FILE not in proposed

    def test_an_explicitly_constructed_digest_target_is_refused(self) -> None:
        """Defense in depth: the mapping is not the only guard.

        Removing ``hash -> FILE`` closes the indicator path, where threat
        intelligence actually enters.  A caller that *explicitly* builds a FILE
        target from a digest is a second route to the same mistake, and
        ``QUARANTINE_FILE`` is destructive, so FILE validation refuses the digest
        shape directly.  This tightens an existing rule; it adds no target type,
        action or vocabulary member.
        """
        with pytest.raises(ValidationError, match="not a logical file path"):
            ResolvableTarget(
                target_type=TargetType.FILE,
                value=self.DIGEST,
                reference="threat_intelligence:ind-9",
                from_indicator=True,
            )

    def test_a_digest_target_is_refused_however_it_is_supplied(self) -> None:
        """Both construction routes agree, so the guard cannot be side-stepped.

        Checked as the pydantic ``ValidationError`` it actually raises, because
        that wrapper is what a caller would have to catch -- asserting on the
        inner ``TargetValidationError`` would describe an API the contract does
        not expose.
        """
        with pytest.raises(ValidationError, match="not a logical file path"):
            ResolvableTarget.model_validate(
                {
                    "target_type": TargetType.FILE.value,
                    "value": self.DIGEST,
                    "reference": "threat_intelligence:ind-9",
                    "from_indicator": True,
                }
            )

    def test_a_legitimate_file_path_is_still_accepted(self) -> None:
        """The guard must not cost a real file its addressable target."""
        for path in (
            "etc/passwd",
            "var/log/auth.log",
            "Users/analyst/Downloads/report.pdf",
            "srv/app/config.yaml",
            "tmp/a.b.c",
        ):
            target = ResolvableTarget(
                target_type=TargetType.FILE,
                value=path,
                reference="threat_intelligence:ind-9",
                from_indicator=True,
            )
            assert target.value == path


# ---------------------------------------------------------------------------
# Governance columns — what a reader must be able to trust
# ---------------------------------------------------------------------------


class TestStoredGovernance:
    def test_a_proposal_is_never_stored_as_executed(self, db) -> None:
        """Generation is the whole of V3.25.

        Persisting a proposal must not create a record that reads as though
        something happened, so neither lifecycle nor status may claim execution.
        """
        result = _proposal()
        PlaybookService(db).persist_result(result)
        row = db.get(PlaybookSessionRecord, result.playbook_id)
        assert row is not None
        assert row.lifecycle == PlaybookLifecycle.APPROVAL_REQUIRED.value.lower()
        assert row.lifecycle in {"proposed", "approval_required", "contested"}
        assert "executed" not in {row.lifecycle, row.status}

    def test_counts_agree_with_the_document(self, db) -> None:
        """Denormalised counts are a convenience and must not drift from truth."""
        result = _proposal()
        service = PlaybookService(db)
        service.persist_result(result)
        row = db.get(PlaybookSessionRecord, result.playbook_id)
        assert row is not None
        assert row.action_count == len(result.playbook.actions)
        assert row.step_count == len(result.playbook.steps)
        assert service.count_actions(result.playbook_id) == len(result.playbook.actions)
        assert service.count_evidence(result.playbook_id) > 0

    def test_every_row_is_pinned_to_ai_generated_provenance(self, db) -> None:
        """Provenance is what keeps a proposal from being read as governance.

        An approval carries ``approval_reviewed`` provenance; a proposal must
        never be able to borrow it.
        """
        result = _proposal()
        PlaybookService(db).persist_result(result)
        session_ids = [result.playbook_id]
        action_ids = list(
            db.execute(
                select(PlaybookActionRecord.id).where(
                    PlaybookActionRecord.session_id.in_(session_ids)
                )
            ).scalars()
        )
        provenances = {
            row[0]
            for row in db.execute(
                select(PlaybookSessionRecord.provenance).where(
                    PlaybookSessionRecord.id.in_(session_ids)
                )
            ).all()
        }
        provenances |= {
            row[0]
            for row in db.execute(
                select(PlaybookStepRecord.provenance).where(
                    PlaybookStepRecord.session_id.in_(session_ids)
                )
            ).all()
        }
        provenances |= {
            row[0]
            for row in db.execute(
                select(PlaybookActionRecord.provenance).where(
                    PlaybookActionRecord.id.in_(action_ids)
                )
            ).all()
        }
        provenances |= {
            row[0]
            for row in db.execute(
                select(PlaybookActionEvidenceRecord.provenance).where(
                    PlaybookActionEvidenceRecord.action_id.in_(action_ids)
                )
            ).all()
        }
        assert provenances == {"ai_generated"}
        assert "approval_reviewed" not in provenances


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


class TestLookup:
    def test_a_correlation_finds_its_proposal(self, db) -> None:
        from app.schemas.playbook import PlaybookListResult

        result = _proposal()
        PlaybookService(db).persist_result(result)
        listed = PlaybookService(db).get_by_correlation(CORRELATION_ID)
        assert isinstance(listed, PlaybookListResult)
        assert [p.playbook_id for p in listed.playbooks] == [result.playbook_id]
        summary = listed.playbooks[0]
        assert summary.action_count == len(result.playbook.actions)
        assert summary.lifecycle is PlaybookLifecycle.APPROVAL_REQUIRED

    def test_an_unrelated_correlation_finds_nothing(self, db) -> None:
        listed = PlaybookService(db).get_by_correlation(uuid.uuid4())
        assert listed.playbooks == []