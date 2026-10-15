"""Relational persistence for debates — V3.23.

Two responsibilities:

1. :meth:`DebateService.persist_session` writes a completed debate into the five
   debate tables.
2. :meth:`DebateService.get_session` rebuilds the domain object from storage so
   a GET returns exactly what the POST produced.

**Idempotency is enforced by the database, not by application convention.**  A
session's primary key is a deterministic ``uuid5`` over
``(correlation_id, graph_snapshot_digest, configuration_digest)``.  Re-running a
debate over the same immutable graph snapshot therefore collides on the primary
key and is treated as an idempotent re-persist rather than an insert.  If the
graph snapshot changed, the digest — and therefore the id — changes, so new
evidence yields a new debate instead of overwriting the old conclusion.  That is
the correct behavior: an analytical conclusion is a record of what was known at
the time, not a mutable view.

A re-persist is a genuine no-op rather than an update.  The existing session row
is returned untouched, so the stored conclusion of a past debate can never be
rewritten by a later run.  This is also what makes concurrent POSTs for the same
correlation safe: the loser of the race reads the winner's row.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.postgres.session import get_db
from app.models.debate import (
    DebateAgentAssessmentRecord,
    DebateArgumentRecord,
    DebateConsensusRecord,
    DebateRoundRecord,
    DebateSessionRecord,
)
from app.schemas.debate import DebateSession

#: Provenance written to every debate row.  A debate conclusion is AI-generated
#: reasoning; the database CHECK pins this so reasoning can never be serialized
#: as evidence provenance.
_AI_GENERATED = "ai_generated"


class DebateService:
    """Persistence for debate sessions."""

    def __init__(self, db: Session) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------
    def persist_session(self, session: DebateSession) -> tuple[DebateSession, bool]:
        """Persist a completed debate.

        Returns ``(debate, created)`` where ``created`` is ``False`` when an
        identical debate already existed.  Re-persisting never mutates the
        stored conclusion.
        """
        existing = self._db.get(DebateSessionRecord, session.debate_id)
        if existing is not None:
            return self._rebuild(existing), False

        metadata = session.metadata
        record = DebateSessionRecord(
            id=session.debate_id,
            correlation_id=session.correlation_id,
            graph_snapshot_digest=metadata.graph_snapshot_digest,
            configuration_digest=metadata.configuration_digest,
            status=session.status.value,
            provider=metadata.provider,
            model=metadata.model,
            engine_version=metadata.engine_version,
            provenance=_AI_GENERATED,
            graph_node_count=metadata.graph_node_count,
            graph_edge_count=metadata.graph_edge_count,
            evidence_reference_count=session.evidence_scope.evidence_reference_count,
            agent_count=metadata.agent_count,
            failure_code=None,
            session_payload=session.model_dump(mode="json"),
            completed_at=metadata.created_at,
            created_at=metadata.created_at,
            updated_at=metadata.created_at,
        )
        for rnd in session.rounds:
            record.rounds.append(
                DebateRoundRecord(
                    id=_child_id(session.debate_id, "round", rnd.round_number),
                    debate_id=session.debate_id,
                    round_number=rnd.round_number,
                    round_kind=rnd.round_kind.value,
                    summary=rnd.summary,
                    agent_ids=list(rnd.agent_ids),
                    argument_ids=list(rnd.argument_ids),
                    counterargument_ids=list(rnd.counterargument_ids),
                    provenance=_AI_GENERATED,
                    created_at=metadata.created_at,
                    updated_at=metadata.created_at,
                )
            )
        for assessment in session.assessments:
            record.assessments.append(
                DebateAgentAssessmentRecord(
                    id=_child_id(session.debate_id, "assessment", assessment.agent_id),
                    debate_id=session.debate_id,
                    agent_id=assessment.agent_id,
                    role=assessment.role.value,
                    objective=assessment.objective,
                    confidence=assessment.confidence,
                    observations=[c.model_dump(mode="json") for c in assessment.observations],
                    hypotheses=[c.model_dump(mode="json") for c in assessment.hypotheses],
                    evidence_references=_refs(assessment.evidence_references),
                    limitations=list(assessment.limitations),
                    provenance=_AI_GENERATED,
                    created_at=metadata.created_at,
                    updated_at=metadata.created_at,
                )
            )
        for argument in session.arguments:
            record.arguments.append(
                DebateArgumentRecord(
                    id=_child_id(session.debate_id, "argument", argument.argument_id),
                    debate_id=session.debate_id,
                    argument_id=argument.argument_id,
                    kind="argument",
                    author_agent_id=argument.author_agent_id,
                    author_role=argument.author_role.value,
                    target_agent_id=argument.target_agent_id,
                    target_role=argument.target_role.value if argument.target_role else None,
                    target_hypothesis_id=argument.target_hypothesis_id,
                    target_argument_id=None,
                    stance=argument.stance.value if argument.stance else None,
                    weakness=None,
                    statement=argument.statement,
                    evidence_references=_refs(argument.evidence_references),
                    provenance=_AI_GENERATED,
                    created_at=metadata.created_at,
                    updated_at=metadata.created_at,
                )
            )
        for counter in session.counterarguments:
            record.arguments.append(
                DebateArgumentRecord(
                    id=_child_id(session.debate_id, "argument", counter.counterargument_id),
                    debate_id=session.debate_id,
                    argument_id=counter.counterargument_id,
                    kind="counterargument",
                    author_agent_id=counter.author_agent_id,
                    author_role=counter.author_role.value,
                    target_agent_id=None,
                    target_role=None,
                    target_hypothesis_id=None,
                    target_argument_id=counter.target_argument_id,
                    stance=None,
                    weakness=counter.weakness.value,
                    statement=counter.statement,
                    evidence_references=_refs(counter.evidence_references),
                    provenance=_AI_GENERATED,
                    created_at=metadata.created_at,
                    updated_at=metadata.created_at,
                )
            )

        consensus = session.consensus
        record.consensus = DebateConsensusRecord(
            id=_child_id(session.debate_id, "consensus", "consensus"),
            debate_id=session.debate_id,
            state=consensus.state.value,
            leading_hypothesis=consensus.leading_hypothesis,
            leading_hypothesis_id=consensus.leading_hypothesis_id,
            consensus_strength=consensus.consensus_strength,
            confidence=consensus.confidence,
            supporting_argument_ids=[a.argument_id for a in consensus.supporting_arguments],
            opposing_argument_ids=[a.argument_id for a in consensus.opposing_arguments],
            dissent=[d.model_dump(mode="json") for d in consensus.dissent],
            unresolved_questions=list(consensus.unresolved_questions),
            evidence_gaps=list(consensus.evidence_gaps),
            evidence_references=_refs(consensus.evidence_references),
            provenance=_AI_GENERATED,
            created_at=metadata.created_at,
            updated_at=metadata.created_at,
        )

        self._db.add(record)
        try:
            self._db.commit()
        except IntegrityError:
            # Lost a concurrent race for the same deterministic identity. The
            # winner's row is authoritative; ours is discarded, not merged.
            self._db.rollback()
            winner = self._db.get(DebateSessionRecord, session.debate_id)
            if winner is None:  # pragma: no cover - defensive
                raise
            return self._rebuild(winner), False
        return session, True

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------
    def get_session(self, debate_id: uuid.UUID) -> DebateSession | None:
        record = self._db.get(DebateSessionRecord, debate_id)
        if record is None:
            return None
        return self._rebuild(record)

    def list_for_correlation(self, correlation_id: uuid.UUID) -> list[DebateSession]:
        """All debates recorded for a correlation, newest first."""
        stmt = (
            select(DebateSessionRecord)
            .where(DebateSessionRecord.correlation_id == correlation_id)
            .order_by(DebateSessionRecord.created_at.desc())
        )
        records = self._db.execute(stmt).scalars().all()
        return [self._rebuild(r) for r in records]

    # ------------------------------------------------------------------
    # Rebuild
    # ------------------------------------------------------------------
    def _rebuild(self, record: DebateSessionRecord) -> DebateSession:
        """Return the stored debate exactly as it was written.

        The canonical ``session_payload`` is the lossless read model.  The
        normalized child tables are the queryable and auditable projection of
        the same write; they are never mixed into a read, so the two can never
        disagree.  Engine-derived facts and evidence scope are included in the
        payload precisely so a GET does not have to re-derive them from a graph
        that may since have changed.
        """
        return DebateSession.model_validate(record.session_payload)


def _refs(refs) -> list[dict]:
    """Serialize evidence references for storage.

    An ``EvidenceReference`` is a *pointer* (reference, entity_kind, node_id)
    into persisted V2 evidence, not a copy of the V2 record, so persisting it
    verbatim keeps the audit trail intact without duplicating evidence.
    """
    return [r.model_dump(mode="json") for r in refs]


def _child_id(parent: uuid.UUID, kind: str, key: str) -> uuid.UUID:
    """Deterministic child-row id so re-persisting cannot mint new rows."""
    return uuid.uuid5(uuid.NAMESPACE_OID, f"{parent}:{kind}:{key}")


def get_debate_service(db: Session | None = None) -> DebateService:
    """FastAPI dependency providing a :class:`DebateService`."""
    if db is not None:
        return DebateService(db)
    return DebateService(next(get_db()))


__all__ = ["DebateService", "get_debate_service"]