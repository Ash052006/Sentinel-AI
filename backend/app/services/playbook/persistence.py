"""Idempotent persistence for proposed playbooks — V3.25.

A playbook is a pure function of its inputs, so persistence is keyed the same
way: ``playbook_sessions.id`` is a deterministic ``uuid5`` over
``(correlation_id, graph_snapshot_digest, debate_id, prediction_session_id,
playbook_configuration_digest)``.  Generating twice over unchanged inputs
therefore collides on the primary key and returns the stored proposal rather than
writing a second one.  Nothing here compares timestamps to decide whether work is
"still fresh" — freshness is expressed in the identity.

That matters for more than tidiness.  A stored proposal is a record that a
specific analyst-facing plan was derived from a specific snapshot of specific
evidence.  If re-running could append a near-duplicate each time, the table would
become a log of repeated attempts rather than a set of distinct proposals, and
"which plan did we agree to?" would stop having an answer.
"""

from __future__ import annotations

import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.playbook import (
    PlaybookActionEvidenceRecord,
    PlaybookActionRecord,
    PlaybookSessionRecord,
    PlaybookStepRecord,
    playbook_row_payloads,
)
from app.schemas.playbook import (
    PlaybookListResult,
    PlaybookResult,
    PlaybookSummary,
)
from app.services.playbook.exceptions import (
    PlaybookPersistenceError,
)
from app.services.playbook.vocabulary import (
    PLAYBOOK_ROW_NAMESPACE,
    ApprovalRequirement,
    deterministic_row_id,
)


def _row_id(parent: uuid.UUID, kind: str, key: str) -> uuid.UUID:
    """Derive a child-row identity from its owning session."""
    return uuid.uuid5(
        PLAYBOOK_ROW_NAMESPACE, f"{parent}|{kind}|{key}"
    )


def _summary(result: PlaybookResult) -> PlaybookSummary:
    """Project a result onto the listing shape."""
    actions = result.playbook.actions
    return PlaybookSummary(
        playbook_id=result.playbook_id,
        correlation_id=result.correlation_id,
        status=result.status,
        lifecycle=result.lifecycle,
        action_count=len(actions),
        step_count=len(result.playbook.steps),
        approval_required_count=sum(
            1
            for action in actions
            if action.approval.requirement is ApprovalRequirement.APPROVAL_REQUIRED
        ),
        not_executable_count=sum(
            1
            for action in actions
            if action.approval.requirement is ApprovalRequirement.NOT_EXECUTABLE
        ),
        confidence=result.uncertainty.confidence,
        prediction_session_id=result.metadata.prediction_session_id,
    )


class PlaybookService:
    """Read/write access to persisted playbook proposals."""

    def __init__(self, db: Session) -> None:
        self._db = db

    # -- write ---------------------------------------------------------------

    def persist_result(self, result: PlaybookResult) -> tuple[PlaybookResult, bool]:
        """Persist ``result``, or return the identical stored proposal.

        Returns ``(stored_result, created)``.  ``created`` is ``False`` for a
        genuine no-op replay: the stored proposal is returned untouched rather
        than rewritten, so repeated generation cannot manufacture a second record
        or mutate the plan an analyst may already be reviewing.
        """
        existing = self.get_session(result.playbook_id)
        if existing is not None:
            return existing, False

        rows = playbook_row_payloads(result)
        actions = result.playbook.actions
        session_row = PlaybookSessionRecord(
            id=result.playbook_id,
            correlation_id=result.correlation_id,
            graph_snapshot_digest=result.metadata.graph_snapshot_digest,
            playbook_configuration_digest=(
                result.metadata.playbook_configuration_digest
            ),
            debate_id=(
                uuid.UUID(result.metadata.debate_id)
                if result.metadata.debate_id
                else None
            ),
            prediction_session_id=(
                uuid.UUID(result.metadata.prediction_session_id)
                if result.metadata.prediction_session_id
                else None
            ),
            status=result.status.value.lower(),
            lifecycle=result.lifecycle.value.lower(),
            engine_version=result.metadata.engine_version,
            action_count=len(actions),
            step_count=len(result.playbook.steps),
            approval_required_count=sum(
                1
                for action in actions
                if action.approval.requirement
                is ApprovalRequirement.APPROVAL_REQUIRED
            ),
            not_executable_count=sum(
                1
                for action in actions
                if action.approval.requirement
                is ApprovalRequirement.NOT_EXECUTABLE
            ),
            confidence=result.uncertainty.confidence,
            graph_node_count=result.metadata.graph_node_count,
            graph_edge_count=result.metadata.graph_edge_count,
            target_count=result.metadata.target_count,
            provenance="ai_generated",
            playbook_payload=result.model_dump(mode="json"),
        )
        try:
            self._db.add(session_row)
            self._db.flush()
        except IntegrityError:
            # A concurrent writer won the deterministic key.  Roll back and
            # return the winner's row: the identity is content-derived, so both
            # writers computed the same answer.
            self._db.rollback()
            stored = self.get_session(result.playbook_id)
            if stored is None:  # pragma: no cover - only if the row vanished
                raise PlaybookPersistenceError(
                    "playbook session conflicted and could not be read back"
                )
            return stored, False

        step_ids: dict[int, uuid.UUID] = {}
        for row in rows["steps"]:
            step_id = _row_id(result.playbook_id, "step", str(row["step_number"]))
            step_ids[row["step_number"]] = step_id
            session_row.steps.append(
                PlaybookStepRecord(
                    id=step_id,
                    session_id=result.playbook_id,
                    step_number=row["step_number"],
                    name=row["name"],
                    purpose=row["purpose"],
                    depends_on_steps=row["depends_on_steps"],
                    provenance="ai_generated",
                )
            )
        self._db.flush()

        known_actions: set[uuid.UUID] = set()
        for row in rows["actions"]:
            known_actions.add(row["action_id"])
            self._db.add(
                PlaybookActionRecord(
                    id=_row_id(
                        result.playbook_id, "action", str(row["action_id"])
                    ),
                    session_id=result.playbook_id,
                    step_id=step_ids[row["step_number"]],
                    action_id=row["action_id"],
                    position=row["position"],
                    action=row["action"],
                    category=row["category"],
                    target_type=row["target_type"],
                    target_reference=row["target_reference"],
                    target_basis=row["target_basis"],
                    capability=row["capability"],
                    execution_backend=row["execution_backend"],
                    approval_requirement=row["approval_requirement"],
                    response_action=row["response_action"],
                    rollback_supported=row["rollback_supported"],
                    rollback_action=row["rollback_action"],
                    risk_level=row["risk_level"],
                    priority=row["priority"],
                    expected_outcome=row["expected_outcome"],
                    verification_required=row["verification_required"],
                    confidence=row["confidence"],
                    confidence_band=row["confidence_band"],
                    confidence_basis=row["confidence_basis"],
                    grounding_basis=row["grounding_basis"],
                    provenance="ai_generated",
                    action_payload=row["action_payload"],
                )
            )
        self._db.flush()

        for row in rows["evidence"]:
            if row["action_id"] not in known_actions:
                continue
            self._db.add(
                PlaybookActionEvidenceRecord(
                    id=_row_id(
                        result.playbook_id,
                        "evidence",
                        f"{row['action_id']}|{row['reference']}|{row['stance']}",
                    ),
                    action_id=_row_id(
                        result.playbook_id, "action", str(row["action_id"])
                    ),
                    source=row["source"],
                    reference=row["reference"],
                    stance=row["stance"],
                    detail=row["detail"],
                    provenance="ai_generated",
                )
            )

        try:
            self._db.commit()
        except IntegrityError as exc:
            self._db.rollback()
            stored = self.get_session(result.playbook_id)
            if stored is not None:
                return stored, False
            raise PlaybookPersistenceError(
                "playbook session could not be persisted"
            ) from exc
        except Exception as exc:  # pragma: no cover - defensive
            self._db.rollback()
            raise PlaybookPersistenceError(
                "playbook session could not be persisted"
            ) from exc

        stored = self.get_session(result.playbook_id)
        if stored is None:  # pragma: no cover - defensive
            raise PlaybookPersistenceError("playbook session vanished after commit")
        return stored, True

    # -- read ----------------------------------------------------------------

    def get_session(self, playbook_id: uuid.UUID) -> PlaybookResult | None:
        """Load one proposal by its deterministic id, or ``None``."""
        row = self._db.get(PlaybookSessionRecord, playbook_id)
        if row is None:
            return None
        return self._rebuild(row)

    def get_by_correlation(
        self, correlation_id: uuid.UUID, *, limit: int = 20
    ) -> PlaybookListResult:
        """Proposals recorded for a correlation, newest first."""
        from sqlalchemy import select

        rows = (
            self._db.execute(
                select(PlaybookSessionRecord)
                .where(PlaybookSessionRecord.correlation_id == correlation_id)
                .order_by(
                    PlaybookSessionRecord.created_at.desc(),
                    PlaybookSessionRecord.id.desc(),
                )
                .limit(limit)
            )
            .scalars()
            .all()
        )
        return PlaybookListResult(
            correlation_id=correlation_id,
            playbooks=[_summary(self._rebuild(row)) for row in rows],
        )

    def count_actions(self, playbook_id: uuid.UUID) -> int:
        from sqlalchemy import func, select

        return int(
            self._db.execute(
                select(func.count())
                .select_from(PlaybookActionRecord)
                .where(PlaybookActionRecord.session_id == playbook_id)
            ).scalar()
            or 0
        )

    def count_evidence(self, playbook_id: uuid.UUID) -> int:
        """Citations across one proposal.

        Counted through the owning session rather than by joining on the action's
        deterministic ``action_id``, because the evidence table's foreign key
        points at the row identity.
        """
        from sqlalchemy import func, select

        action_rows = self._db.execute(
            select(PlaybookActionRecord.id).where(
                PlaybookActionRecord.session_id == playbook_id
            )
        ).scalars()
        return int(
            self._db.execute(
                select(func.count())
                .select_from(PlaybookActionEvidenceRecord)
                .where(
                    PlaybookActionEvidenceRecord.action_id.in_(list(action_rows))
                )
            ).scalar()
            or 0
        )

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _rebuild(row: PlaybookSessionRecord) -> PlaybookResult:
        """Rehydrate the canonical document.

        The child tables exist for querying and auditing; the stored payload is
        the lossless read model, so a GET returns exactly the structure the POST
        produced rather than a reconstruction that could silently differ.
        """
        return PlaybookResult.model_validate(row.playbook_payload)


def get_playbook_service(db: Session | None = None) -> PlaybookService:
    """FastAPI dependency factory."""
    if db is None:  # pragma: no cover - convenience only
        from app.api.dependencies import get_db

        generator = get_db()
        db = next(generator)
    return PlaybookService(db)


__all__ = [
    "PlaybookService",
    "PlaybookSummary",
    "deterministic_row_id",
    "get_playbook_service",
]