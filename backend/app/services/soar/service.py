"""SOAR orchestration service (V2.18).

Facade between the API layer and the pure :class:`SoarEngine`.  Owns
persistence and the durable idempotency guarantee, the code-owned playbook
seed sync into ``soar_playbooks``/``soar_playbook_versions``, cancellation,
and the audit trail.

Boundaries honoured here (see ``docs/development/soar_v218.md``):

* **Playbooks are code-registered**, never client-created.  The service
  only syncs the fixed seed set; the API can never author, mutate, import
  or delete a playbook.
* **Every run goes through the engine's independent policy gate.**  A
  DENIED / unverifiable decision can never reach a provider; a
  REQUIRES_APPROVAL decision with no presented grant is recorded
  ``PENDING`` (E2E Case B) and nothing executes.
* **The approval seam is the existing V2.16 grant** — the engine is wired
  with the approval service's :class:`ApprovalGrantVerifier`, never a
  homegrown decision maker.
* **Dry-runs never persist and never mutate**: they return a
  ``simulated=True`` projection only.
* **Durability = unique ``idempotency_key``**: an identical governed
  submission returns the stored record; it is never re-executed and never
  double-persisted.

The service owns transactions and commits each unit (seed sync, one
execution + steps, one cancel) atomically, then audits after commit so the
audit trail cannot be rolled back by a later failure.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.soar_execution import SoarExecutionRow
from app.models.soar_playbook import SoarPlaybookRow
from app.models.soar_playbook_version import SoarPlaybookVersionRow
from app.models.soar_step_execution import SoarStepExecutionRow
from app.repositories.soar import SoarRepository
from app.schemas.soar import (
    SOAR_PLAYBOOK_INITIAL_VERSION,
    ResponseActionType,
    SoarDryRunResult,
    SoarExecutionPage,
    SoarExecutionRecord,
    SoarExecutionRequest,
    SoarExecutionStatus,
    SoarFailurePolicy,
    SoarPlaybookPage,
    SoarPlaybookRecord,
    SoarStep,
    SoarStepExecutionRecord,
)
from app.services.approval.service import ApprovalGrantVerifier
from app.services.audit_service import log_action
from app.services.soar import hashing as _hash  # noqa: A004
from app.services.soar.engine import SoarEngine
from app.services.soar.errors import (
    SoarConflictError,
    SoarNotFoundError,
    SoarServiceError,
    SoarValidationError,
)
from app.services.soar.playbooks import DEFAULT_SOAR_PLAYBOOK_REGISTRY

logger = logging.getLogger(__name__)

#: Default page size for paginated reads (bounded offset pagination).
DEFAULT_PAGE_SIZE = 50

#: Hard cap on a single page.
MAX_PAGE_SIZE = 200

#: Roles authorized to read SOAR state.
SOAR_READ_ROLES = ("admin", "analyst", "ciso")

#: Roles authorized to drive SOAR lifecycle (execute / cancel / dry-run).
SOAR_MUTATION_ROLES = ("admin",)


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalize a possibly-naive database instant to tz-aware UTC.

    SQLite stores ``DateTime(timezone=True)`` as naive UTC; PostgreSQL
    returns tz-aware values.  Normalizing at the read boundary gives both
    backends identical records.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _playbook_record(row: SoarPlaybookRow) -> SoarPlaybookRecord:
    return SoarPlaybookRecord(
        id=row.id,
        playbook_id=row.playbook_id,
        name=row.name,
        description=row.description,
        schema_version=row.schema_version,
        version=row.version,
        version_id=row.version_id,
        primary_action=ResponseActionType(row.primary_action),
        failure_policy=SoarFailurePolicy(row.failure_policy),
        enabled=row.enabled,
        step_count=len(row.steps or []),
        steps=[SoarStep.model_validate(step) for step in (row.steps or [])],
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )


def _step_record(row: SoarStepExecutionRow, *, parent_execution_id: uuid.UUID) -> SoarStepExecutionRecord:
    return SoarStepExecutionRecord(
        step_execution_id=row.step_execution_id,
        execution_id=parent_execution_id,
        step_number=row.step_number,
        label=row.label,
        provider_id=row.provider_id,
        operation=ResponseActionType(row.operation),
        target=row.target,
        status=row.status,
        retries_attempted=row.retries_attempted,
        error_code=row.error_code,
        message=row.message,
        started_at=_as_utc(row.started_at),
        completed_at=_as_utc(row.completed_at),
        metadata=dict(row.step_metadata or {}),
    )


def _execution_record(
    row: SoarExecutionRow,
    *,
    steps: list[SoarStepExecutionRow],
) -> SoarExecutionRecord:
    return SoarExecutionRecord(
        id=row.id,
        execution_id=row.execution_id,
        idempotency_key=row.idempotency_key,
        policy_decision_id=row.policy_decision_id,
        correlation_id=row.correlation_id,
        approval_id=row.approval_id,
        response_id=row.response_id,
        playbook_id=row.playbook_id,
        playbook_version=row.playbook_version,
        primary_action=ResponseActionType(row.primary_action),
        target=row.target,
        status=row.status,
        failure_policy=SoarFailurePolicy(row.failure_policy),
        simulated=bool(row.simulated),
        error_code=row.error_code,
        started_at=_as_utc(row.started_at),
        completed_at=_as_utc(row.completed_at),
        created_by=row.created_by,
        created_by_role=row.created_by_role,
        metadata=dict(row.execution_metadata or {}),
        steps=[
            _step_record(step, parent_execution_id=row.execution_id)
            for step in steps
        ],
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )


class SoarService:
    """Orchestrates SOAR executions, seed sync, cancellation and reads."""

    def __init__(
        self,
        repository_factory: Callable[[Session], SoarRepository] = SoarRepository,
    ) -> None:
        self._repository_factory = repository_factory

    def _repo(self, db: Session) -> SoarRepository:
        return self._repository_factory(db)

    def _engine(
        self,
        db: Session,
        *,
        clock: Callable[[], datetime],
    ) -> SoarEngine:
        """One engine per call, wired with the V2.16 grant verifier.

        The engine's in-memory dedup ledger is scoped to a single engine, so
        the durable idempotency store is wired in as ``persisted_lookup``:
        the engine resolves an already-persisted execution for the
        content-derived key *before* running any playbook step, so a
        duplicate submission never re-invokes a provider.
        """

        def _persisted(idempotency_key: str) -> SoarExecutionRecord | None:
            try:
                row = self._repo(db).get_execution_by_idempotency_key(idempotency_key)
            except SQLAlchemyError as exc:
                raise self._db_error(exc, context="execute idempotency") from exc
            if row is None:
                return None
            return _execution_record(
                row, steps=self._steps_for(db, row.id, origin="execute dup")
            )

        return SoarEngine(
            approval_verifier=ApprovalGrantVerifier(db, clock=clock),
            clock=clock,
            persisted_lookup=_persisted,
        )

    @staticmethod
    def _validate_page(page: object, page_size: object) -> tuple[int, int]:
        try:
            page_int = int(page)
            page_size_int = int(page_size)
        except (TypeError, ValueError) as exc:
            raise SoarValidationError("page and page_size must be integers") from exc
        if page_int < 1:
            raise SoarValidationError("page must be >= 1")
        if page_size_int < 1:
            raise SoarValidationError("page_size must be >= 1")
        if page_size_int > MAX_PAGE_SIZE:
            raise SoarValidationError(f"page_size must not exceed {MAX_PAGE_SIZE}")
        return page_int, page_size_int

    @staticmethod
    def _coerce_uuid(value: object, *, field: str) -> uuid.UUID:
        try:
            if isinstance(value, uuid.UUID):
                return value
            return uuid.UUID(str(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise SoarValidationError(f"{field} must be a valid UUID") from exc

    @staticmethod
    def _db_error(exc: Exception, *, context: str = "") -> SoarServiceError:
        logger.warning("SOAR service failed (%s): %s", context or "?", exc)
        return SoarServiceError("SOAR data is unavailable")

    # ------------------------------------------------------------------
    # Seed sync — the code-owned playbook set, idempotent
    # ------------------------------------------------------------------

    def sync_seed_playbooks(
        self,
        db: Session,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> int:
        """Persist the fixed seed playbook set (playbooks + versions).

        Idempotent: an unchanged, already-registered seed is a no-op.  A
        changed definition derives a new ``version_id``, supersedes the old
        active version and updates the playbook row.  Returns how many
        playbook rows were inserted.  Commits its own unit.
        """
        clock = clock or _default_now
        repo = self._repo(db)
        inserted = 0
        try:
            for definition in DEFAULT_SOAR_PLAYBOOK_REGISTRY.all():
                source_hash = _hash.playbook_source_hash(
                    definition.model_dump(mode="json")
                )
                version_id = _hash.playbook_version_id(
                    playbook_id=definition.playbook_id,
                    version=SOAR_PLAYBOOK_INITIAL_VERSION,
                    source_hash=source_hash,
                )
                row = repo.get_playbook_by_id(definition.playbook_id)
                if row is None:
                    row = SoarPlaybookRow(
                        playbook_id=definition.playbook_id,
                        name=definition.name,
                        description=definition.description,
                        schema_version=definition.schema_version,
                        version=SOAR_PLAYBOOK_INITIAL_VERSION,
                        version_id=version_id,
                        source_hash=source_hash,
                        primary_action=definition.primary_action.value,
                        failure_policy=definition.failure_policy.value,
                        steps=[step.model_dump(mode="json") for step in definition.steps],
                        enabled=True,
                    )
                    repo.add(row)
                    db.flush()
                    repo.add(
                        SoarPlaybookVersionRow(
                            playbook_row_id=row.id,
                            version_id=version_id,
                            playbook_id=definition.playbook_id,
                            version=SOAR_PLAYBOOK_INITIAL_VERSION,
                            source_hash=source_hash,
                            definition=definition.model_dump(mode="json"),
                            status="active",
                        )
                    )
                    inserted += 1
                    continue
                if row.source_hash == source_hash and row.version_id == version_id:
                    continue
                # A changed seed definition: supersede the old active
                # version and promote the new one.
                row.version = SOAR_PLAYBOOK_INITIAL_VERSION
                row.version_id = version_id
                row.source_hash = source_hash
                row.name = definition.name
                row.description = definition.description
                row.schema_version = definition.schema_version
                row.primary_action = definition.primary_action.value
                row.failure_policy = definition.failure_policy.value
                row.steps = [step.model_dump(mode="json") for step in definition.steps]
                row.updated_at = clock()
                db.flush()
                db.execute(
                    update(SoarPlaybookVersionRow)
                    .where(
                        SoarPlaybookVersionRow.playbook_id == definition.playbook_id
                    )
                    .values(status="superseded", updated_at=clock())
                )
                repo.add(
                    SoarPlaybookVersionRow(
                        playbook_row_id=row.id,
                        version_id=version_id,
                        playbook_id=definition.playbook_id,
                        version=SOAR_PLAYBOOK_INITIAL_VERSION,
                        source_hash=source_hash,
                        definition=definition.model_dump(mode="json"),
                        status="active",
                    )
                )
            db.commit()
        except SQLAlchemyError as exc:
            db.rollback()
            raise self._db_error(exc, context="seed") from exc
        if inserted:
            log_action(
                db,
                "soar.playbooks_seeded",
                user_id=None,
                resource="soar:playbooks",
                details=f"registered {inserted} seed playbook(s)",
            )
        return inserted

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def list_playbooks(
        self,
        db: Session,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        clock: Callable[[], datetime] | None = None,
    ) -> SoarPlaybookPage:
        page, page_size = self._validate_page(page, page_size)
        self.sync_seed_playbooks(db, clock=clock)
        repo = self._repo(db)
        try:
            total = repo.count_playbooks()
            rows = repo.list_playbooks(limit=page_size, offset=(page - 1) * page_size)
        except SQLAlchemyError as exc:
            raise self._db_error(exc, context="list playbooks") from exc
        return SoarPlaybookPage(
            items=[_playbook_record(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

    def get_playbook(
        self,
        db: Session,
        playbook_id: str,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> SoarPlaybookRecord:
        self.sync_seed_playbooks(db, clock=clock)
        try:
            row = self._repo(db).get_playbook_by_id(playbook_id)
        except SQLAlchemyError as exc:
            raise self._db_error(exc, context="get playbook") from exc
        if row is None:
            raise SoarNotFoundError(playbook_id)
        return _playbook_record(row)

    def list_executions(
        self,
        db: Session,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        status: SoarExecutionStatus | None = None,
    ) -> SoarExecutionPage:
        page, page_size = self._validate_page(page, page_size)
        repo = self._repo(db)
        try:
            total = repo.count_executions(
                status=None if status is None else status.value
            )
            rows = repo.list_executions(
                limit=page_size,
                offset=(page - 1) * page_size,
                status=None if status is None else status.value,
            )
        except SQLAlchemyError as exc:
            raise self._db_error(exc, context="list executions") from exc
        by_id = {}
        for row in rows:
            steps = self._steps_for(db, row.id, origin="list executions")
            by_id[row.id] = steps
        return SoarExecutionPage(
            items=[
                _execution_record(row, steps=by_id[row.id])
                for row in rows
                if row.id in by_id
            ],
            total=total,
            page=page,
            page_size=page_size,
        )

    def get_execution(
        self,
        db: Session,
        execution_id: uuid.UUID | str,
    ) -> SoarExecutionRecord:
        execution_id = self._coerce_uuid(execution_id, field="execution_id")
        repo = self._repo(db)
        try:
            row = repo.get_execution_by_execution_id(execution_id)
        except SQLAlchemyError as exc:
            raise self._db_error(exc, context="get execution") from exc
        if row is None:
            raise SoarNotFoundError(execution_id)
        steps = self._steps_for(db, row.id, origin="get execution")
        return _execution_record(row, steps=steps)

    def _steps_for(
        self,
        db: Session,
        row_id: uuid.UUID,
        *,
        origin: str,
    ) -> list[SoarStepExecutionRow]:
        try:
            return self._repo(db).get_execution_steps(row_id)
        except SQLAlchemyError as exc:
            raise self._db_error(exc, context=origin) from exc

    # ------------------------------------------------------------------
    # Lifecycle — execute / dry-run / cancel
    # ------------------------------------------------------------------

    def execute(
        self,
        db: Session,
        request: SoarExecutionRequest | dict[str, Any],
        *,
        actor_user_id: uuid.UUID,
        actor_role: str,
        ip_address: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> SoarExecutionRecord:
        clock = clock or _default_now
        self.sync_seed_playbooks(db, clock=clock)
        try:
            record = self._engine(db, clock=clock).execute(
                request,
                actor_user_id=actor_user_id,
                actor_role=actor_role,
                clock=clock,
            )
        except (SoarValidationError, SoarServiceError):
            raise
        except Exception as exc:  # noqa: BLE001 - sanitized
            raise self._db_error(exc, context="execute") from exc

        repo = self._repo(db)
        existing = None
        try:
            existing = repo.get_execution_by_idempotency_key(record.idempotency_key)
        except SQLAlchemyError as exc:
            raise self._db_error(exc, context="execute idempotency") from exc
        if existing is not None:
            steps = self._steps_for(db, existing.id, origin="execute dup")
            return _execution_record(existing, steps=steps)

        row = SoarExecutionRow(
            execution_id=record.execution_id,
            idempotency_key=record.idempotency_key,
            policy_decision_id=record.policy_decision_id,
            correlation_id=record.correlation_id,
            approval_id=record.approval_id,
            response_id=record.response_id,
            playbook_id=record.playbook_id,
            playbook_version=record.playbook_version,
            primary_action=record.primary_action.value,
            target=record.target,
            status=record.status.value,
            failure_policy=record.failure_policy.value,
            simulated=bool(record.simulated),
            error_code=record.error_code,
            started_at=_as_utc(record.started_at),
            completed_at=_as_utc(record.completed_at),
            created_by=record.created_by,
            created_by_role=record.created_by_role,
            execution_metadata=dict(record.metadata),
        )
        try:
            repo.add(row)
            db.flush()
            for step in record.steps:
                repo.add(
                    SoarStepExecutionRow(
                        step_execution_id=step.step_execution_id,
                        execution_id=row.id,
                        step_number=step.step_number,
                        label=step.label,
                        provider_id=step.provider_id,
                        operation=step.operation.value,
                        target=step.target,
                        status=step.status.value,
                        retries_attempted=step.retries_attempted,
                        error_code=step.error_code,
                        message=step.message,
                        started_at=_as_utc(step.started_at),
                        completed_at=_as_utc(step.completed_at),
                        step_metadata=dict(step.metadata),
                    )
                )
            db.commit()
        except SQLAlchemyError as exc:
            db.rollback()
            raise self._db_error(exc, context="persist execution") from exc

        log_action(
            db,
            f"soar.execution.{record.status.value}",
            user_id=actor_user_id,
            resource=f"soar:execution:{record.execution_id}",
            details=(
                f"playbook {record.playbook_id} target {record.target} "
                f"{record.status.value}"
            ),
            ip_address=ip_address,
        )
        steps = self._steps_for(db, row.id, origin="execute persist")
        return _execution_record(row, steps=steps)

    def dry_run(
        self,
        db: Session,
        request: SoarExecutionRequest | dict[str, Any],
        *,
        actor_user_id: uuid.UUID,
        actor_role: str,
        ip_address: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> SoarDryRunResult:
        del actor_role
        clock = clock or _default_now
        self.sync_seed_playbooks(db, clock=clock)
        try:
            result = self._engine(db, clock=clock).dry_run(
                request,
                clock=clock,
            )
        except (SoarValidationError, SoarServiceError):
            raise
        except Exception as exc:  # noqa: BLE001 - sanitized
            raise self._db_error(exc, context="dry-run") from exc

        log_action(
            db,
            "soar.dry_run",
            user_id=actor_user_id,
            resource=f"soar:dry-run:{result.playbook_id}",
            details=(
                f"projected {result.status.value} for {result.playbook_id} "
                "(no side effects, nothing executed)"
            ),
            ip_address=ip_address,
        )
        return result

    def cancel(
        self,
        db: Session,
        execution_id: uuid.UUID | str,
        *,
        actor_user_id: uuid.UUID,
        actor_role: str,
        ip_address: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> SoarExecutionRecord:
        del actor_role
        clock = clock or _default_now
        now = clock()
        execution_id = self._coerce_uuid(execution_id, field="execution_id")
        repo = self._repo(db)
        try:
            row = repo.get_execution_by_execution_id(execution_id)
        except SQLAlchemyError as exc:
            raise self._db_error(exc, context="cancel lookup") from exc
        if row is None:
            raise SoarNotFoundError(execution_id)

        if row.status == SoarExecutionStatus.CANCELLED.value:
            steps = self._steps_for(db, row.id, origin="cancel dup")
            return _execution_record(row, steps=steps)

        if row.status not in (
            SoarExecutionStatus.PENDING.value,
            SoarExecutionStatus.RUNNING.value,
        ):
            raise SoarConflictError(
                f"execution {execution_id} is {row.status} and cannot be cancelled"
            )

        try:
            row.status = SoarExecutionStatus.CANCELLED.value
            row.completed_at = now
            row.updated_at = now
            db.flush()
            for step in self._steps_for(db, row.id, origin="cancel steps"):
                if step.status in (
                    "pending",
                    "running",
                ):
                    step.status = "cancelled"
                    step.updated_at = now
            db.commit()
        except SQLAlchemyError as exc:
            db.rollback()
            raise self._db_error(exc, context="cancel transition") from exc

        log_action(
            db,
            "soar.execution.cancelled",
            user_id=actor_user_id,
            resource=f"soar:execution:{execution_id}",
            details=f"cancelled execution for playbook {row.playbook_id}",
            ip_address=ip_address,
        )
        steps = self._steps_for(db, row.id, origin="cancel read")
        return _execution_record(row, steps=steps)


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "SOAR_MUTATION_ROLES",
    "SOAR_READ_ROLES",
    "SoarService",
]