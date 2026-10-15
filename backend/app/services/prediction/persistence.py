"""Persistence for attack prediction sessions — V3.24.

Idempotency is a database guarantee here, not an application convention.  The
session primary key is a deterministic ``uuid5`` over
``(correlation_id, graph_snapshot_digest, debate_id,
prediction_configuration_digest)``, so re-running the same prediction over the
same immutable inputs collides on the key and returns the stored row instead of
inserting a duplicate.  No current time participates in any identity, which is
what makes that true rather than merely likely.

Every read reconstructs the canonical :class:`PredictionResult` from the
``session_payload`` JSON column rather than from the normalized child tables, so
a GET returns byte-for-byte what the POST produced.  The child tables are the
queryable, auditable projection of the same write — never a second source of
truth.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.attack_prediction import (
    AttackPredictionEvidenceRecord,
    AttackPredictionRecord,
    AttackPredictionSessionRecord,
    AttackPredictionUncertaintyRecord,
    prediction_row_payloads,
)
from app.schemas.attack_prediction import PredictionResult
from app.services.prediction.exceptions import PredictionPersistenceError
from app.services.prediction.vocabulary import deterministic_row_id

_AI_GENERATED = "ai_generated"


class AttackPredictionService:
    """Read/write access to persisted prediction sessions."""

    def __init__(self, db: Session) -> None:
        self._db = db

    # -- write ---------------------------------------------------------------

    def persist_result(self, result: PredictionResult) -> tuple[PredictionResult, bool]:
        """Persist ``result``, or return the identical stored session.

        Returns ``(stored_result, created)``.  ``created`` is ``False`` for a
        genuine no-op replay: the stored conclusion is returned untouched rather
        than rewritten, so repeated execution cannot manufacture a second record.
        """
        existing = self.get_session(result.prediction_session_id)
        if existing is not None:
            return existing, False

        rows = prediction_row_payloads(result)
        session_row = AttackPredictionSessionRecord(
            id=result.prediction_session_id,
            correlation_id=result.correlation_id,
            graph_snapshot_digest=result.metadata.graph_snapshot_digest,
            prediction_configuration_digest=result.metadata.prediction_configuration_digest,
            debate_id=uuid.UUID(result.metadata.debate_id) if result.metadata.debate_id else None,
            status=result.status.value.lower(),
            engine_version=result.metadata.engine_version,
            graph_node_count=result.metadata.graph_node_count,
            graph_edge_count=result.metadata.graph_edge_count,
            observed_technique_count=result.metadata.observed_technique_count,
            max_depth=result.metadata.max_depth,
            provenance=_AI_GENERATED,
            session_payload=result.model_dump(mode="json"),
        )
        try:
            self._db.add(session_row)
            self._db.flush()
        except IntegrityError:
            # A concurrent writer won the deterministic key. Roll back and return
            # the winner's row: the identity is content-derived, so both writers
            # computed the same answer.
            self._db.rollback()
            stored = self.get_session(result.prediction_session_id)
            if stored is None:  # pragma: no cover - only if the row vanished
                raise PredictionPersistenceError(
                    "prediction session conflicted and could not be read back"
                )
            return stored, False

        for row in rows["predictions"]:
            session_row.predictions.append(
                AttackPredictionRecord(
                    id=row["prediction_id"],
                    session_id=result.prediction_session_id,
                    prediction_kind=row["prediction_kind"],
                    depth=row["depth"],
                    prediction_status=row["prediction_status"],
                    target=row["target"],
                    target_basis=row["target_basis"],
                    basis=row["basis"],
                    technique_id=row["technique_id"],
                    technique_name=row["technique_name"],
                    tactic=row["tactic"],
                    technique_id_reason=row["technique_id_reason"],
                    confidence=row["confidence"],
                    confidence_band=row["confidence_band"],
                    evidence_support=row["evidence_support"],
                    rationale_summary=row["rationale_summary"],
                    basis_detail=row["basis_detail"],
                    provenance=_AI_GENERATED,
                    prediction_payload=row["prediction_payload"],
                )
            )
        self._db.flush()

        known_predictions = {row["prediction_id"] for row in rows["predictions"]}
        for row in rows["evidence"]:
            self._db.add(
                AttackPredictionEvidenceRecord(
                    id=deterministic_row_id(
                        result.prediction_session_id, "evidence", f"{row['prediction_id']}|{row['reference']}|{row['stance']}"
                    ),
                    prediction_id=row["prediction_id"],
                    reference=row["reference"],
                    entity_kind=row["entity_kind"],
                    node_id=row["node_id"],
                    stance=row["stance"],
                    detail=row["detail"],
                    provenance=_AI_GENERATED,
                )
            )
        for row in rows["uncertainties"]:
            if row["prediction_id"] not in known_predictions:
                continue
            self._db.add(
                AttackPredictionUncertaintyRecord(
                    id=deterministic_row_id(
                        result.prediction_session_id, "uncertainty", str(row["prediction_id"])
                    ),
                    prediction_id=row["prediction_id"],
                    confidence=row["confidence"],
                    confidence_band=row["confidence_band"],
                    confidence_basis=row["confidence_basis"],
                    supporting_count=row["supporting_count"],
                    contradicting_count=row["contradicting_count"],
                    evidence_gaps=row["evidence_gaps"],
                    unresolved_questions=row["unresolved_questions"],
                    limitations=row["limitations"],
                    provenance=_AI_GENERATED,
                )
            )

        try:
            self._db.commit()
        except IntegrityError as exc:
            self._db.rollback()
            stored = self.get_session(result.prediction_session_id)
            if stored is not None:
                return stored, False
            raise PredictionPersistenceError(
                "prediction session could not be persisted"
            ) from exc
        except Exception as exc:  # pragma: no cover - defensive
            self._db.rollback()
            raise PredictionPersistenceError(
                "prediction session could not be persisted"
            ) from exc

        stored = self.get_session(result.prediction_session_id)
        if stored is None:  # pragma: no cover - defensive
            raise PredictionPersistenceError("prediction session vanished after commit")
        return stored, True

    # -- read ----------------------------------------------------------------

    def get_session(self, prediction_session_id: uuid.UUID) -> PredictionResult | None:
        """Load one session by its deterministic id, or ``None``."""
        row = self._db.get(AttackPredictionSessionRecord, prediction_session_id)
        if row is None:
            return None
        return self._rebuild(row)

    def get_by_correlation(
        self, correlation_id: uuid.UUID, *, limit: int = 20
    ) -> list[PredictionResult]:
        """Sessions for a correlation, newest first, deterministically ordered."""
        rows = (
            self._db.execute(
                select(AttackPredictionSessionRecord)
                .where(AttackPredictionSessionRecord.correlation_id == correlation_id)
                .order_by(
                    AttackPredictionSessionRecord.created_at.desc(),
                    AttackPredictionSessionRecord.id.desc(),
                )
                .limit(limit)
            )
            .scalars()
            .all()
        )
        return [self._rebuild(row) for row in rows]

    def get_prediction(self, prediction_id: uuid.UUID) -> PredictionResult | None:
        """Load the session owning ``prediction_id``, or ``None``.

        The API exposes a single prediction by id, so it returns the owning
        session document: a prediction is never meaningful in isolation, because
        its evidence, gaps and limitations are session-scoped context.
        """
        row = self._db.get(AttackPredictionRecord, prediction_id)
        if row is None:
            return None
        session_row = self._db.get(AttackPredictionSessionRecord, row.session_id)
        if session_row is None:  # pragma: no cover - FK guarantees presence
            return None
        return self._rebuild(session_row)

    def count_predictions(self, prediction_session_id: uuid.UUID) -> int:
        return int(
            self._db.execute(
                select(AttackPredictionRecord.id).where(
                    AttackPredictionRecord.session_id == prediction_session_id
                )
            )
            .scalars()
            .all()
            .__len__()
        )

    def count_evidence(self, prediction_session_id: uuid.UUID) -> int:
        prediction_ids = select(AttackPredictionRecord.id).where(
            AttackPredictionRecord.session_id == prediction_session_id
        )
        return int(
            self._db.execute(
                select(AttackPredictionEvidenceRecord.id).where(
                    AttackPredictionEvidenceRecord.prediction_id.in_(prediction_ids)
                )
            )
            .scalars()
            .all()
            .__len__()
        )

    # -- internals -----------------------------------------------------------

    def _rebuild(self, row: AttackPredictionSessionRecord) -> PredictionResult:
        return PredictionResult.model_validate(row.session_payload)


def get_attack_prediction_service(db: Session | None = None) -> AttackPredictionService:
    """FastAPI dependency factory."""
    if db is None:  # pragma: no cover - convenience only
        from app.api.dependencies import get_db

        generator = get_db()
        db = next(generator)
    return AttackPredictionService(db)


__all__ = ["AttackPredictionService", "get_attack_prediction_service"]