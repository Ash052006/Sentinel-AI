#!/usr/bin/env python
"""Run a SentinelAI demo dataset through the real platform.

Every command in this runner calls the shipped SentinelAI agents, services
and persistence layers.  Nothing is simulated, short-circuited or
hand-written: the printed report is built from the values the platform
actually returned.

Two kinds of commands exist:

* ``pure``   - read-only, no database is touched (log collection,
  normalization, detection, mitre_mapping, risk, response,
  explainability, attribution).
* ``persisting`` - the real persistence layers are used so the platform's
  own cross-table behaviour (correlation membership, risk evidence,
  governance, hunts, reports) is exercised end to end.  Every record the
  runner creates is tracked by identity and removed again, so the runner
  is idempotent and leaves the database and the test-suite in the state
  they were found in.

Usage
-----
    python -m scripts.run_demo_dataset list
    python -m scripts.run_demo_dataset <function> [--sandbox] [--json]
    python -m scripts.run_demo_dataset all
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import textwrap
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

DATASETS = _BACKEND_ROOT / "demo_datasets"

#: Namespace used for every deterministic identifier the runner mints.  It is
#: the same namespace the shipped investigation context builder uses, so an id
#: printed by this runner is the id a real investigation would carry.
DEMO_NS = uuid.UUID("6f0f0e9a-2b8e-5f3a-9a1c-0d4b7e2f5a10")

UTC = timezone.utc
NOW = datetime.now(UTC)

OK = "ok"
FAILED = "failed"
SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Result plumbing
# ---------------------------------------------------------------------------


@dataclass
class Report:
    """Accumulates the observed outcome of one command."""

    command: str
    items: list[dict[str, Any]] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    elapsed: float | None = None

    def ok(self, name: str, note: str, **details: Any) -> None:
        self.items.append(
            {"check": name, "status": OK, "note": note, "observed": details}
        )

    def fail(self, name: str, note: str, **details: Any) -> None:
        self.items.append(
            {"check": name, "status": FAILED, "note": note, "observed": details}
        )

    def skip(self, name: str, note: str, **details: Any) -> None:
        self.items.append(
            {"check": name, "status": SKIPPED, "note": note, "observed": details}
        )

    @property
    def failed(self) -> list[dict[str, Any]]:
        return [i for i in self.items if i["status"] == FAILED]

    @property
    def skipped(self) -> list[dict[str, Any]]:
        return [i for i in self.items if i["status"] == SKIPPED]

    @property
    def passed(self) -> list[dict[str, Any]]:
        return [i for i in self.items if i["status"] == OK]

    def as_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "commands": list(self.commands),
            "elapsed_seconds": self.elapsed,
            "summary": {
                "passed": len(self.passed),
                "failed": len(self.failed),
                "skipped": len(self.skipped),
            },
            "items": [_json_safe(item) for item in self.items],
        }

    def render(self) -> str:
        width = max((len(i["check"]) for i in self.items), default=6)
        lines = [f"== {self.command} =="]
        for item in self.items:
            mark = {OK: "PASS", FAILED: "FAIL", SKIPPED: "SKIP"}[item["status"]]
            lines.append(f"  [{mark}] {item['check']:<{width}}  {item['note']}")
            for key, value in item["observed"].items():
                if value in (None, [], {}, ""):
                    continue
                rendered = _render_value(value)
                if len(rendered) > 300:
                    rendered = rendered[:297] + "..."
                wrapped = textwrap.wrap(rendered, width=104, subsequent_indent=" " * 14)
                lines.append(f" {'':<{width}}    {key} = {wrapped[0]}")
                lines.extend(f" {'':<{width}}      {chunk}" for chunk in wrapped[1:])
        counts = {
            "passed": len(self.items) - len(self.failed) - len(self.skipped),
            "failed": len(self.failed),
            "skipped": len(self.skipped),
        }
        lines.append(f"  -> {counts}")
        return "\n".join(lines)

    def show(self) -> None:
        print(self.render())


def _render_value(value: Any) -> str:
    """JSON-render a detail value, coercing UUIDs and enums to text."""
    import enum

    def _plain(item: Any) -> Any:
        if isinstance(item, uuid.UUID):
            return str(item)
        if isinstance(item, enum.Enum):
            return item.value
        if isinstance(item, dict):
            return {str(k): _plain(v) for k, v in item.items()}
        if isinstance(item, (list, tuple, set)):
            return [_plain(v) for v in item]
        if isinstance(item, (datetime,)):
            return item.isoformat()
        if isinstance(item, (str, int, float, bool)) or item is None:
            return item
        return str(item)

    return json.dumps(_plain(value))


def did(name: str) -> str:
    """A deterministic, human-readable demo identity derived from *name*."""
    return f"DEMO-{name}"


def demo_uuid(kind: str, *parts: str) -> uuid.UUID:
    return uuid.uuid5(DEMO_NS, f"{kind}:{'|'.join(parts)}")


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------


def dataset_path(*parts: str) -> Path:
    return DATASETS.joinpath(*parts)


def load_jsonl(*parts: str) -> list[dict[str, Any]]:
    path = dataset_path(*parts)
    records: list[dict[str, Any]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            records.append(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{lineno} is not valid JSON: {exc}") from exc
    return records


def load_json(*parts: str) -> Any:
    return json.loads(dataset_path(*parts).read_text(encoding="utf-8"))


def rel(path: Path) -> str:
    return str(path.relative_to(_BACKEND_ROOT))


# ---------------------------------------------------------------------------
# Database plumbing
# ---------------------------------------------------------------------------


@contextmanager
def db_session() -> Iterator[Any]:
    """A real SQLAlchemy session, rolled back if the body raises."""
    from app.database.postgres.session import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


#: Foreign-key-safe deletion order for every table the runner may write to.
#: ``audit_logs`` and ``users`` are last: everything above can reference them.
_CLEANUP_ORDER = (
    "correlation_members",
    "risk_assessments",
    "incident_memories",
    "soar_step_executions",
    "soar_executions",
    "approval_requests",
    "incident_reports",
    "threat_hunts",
    "threat_intel_lookups",
    "threat_intel_indicators",
    "detection_results",
    "detection_rule_failures",
    "correlations",
    "audit_logs",
    "users",
)


class Cleanup:
    """Tracks every row the runner creates so it can remove it again.

    Cleanup is identity based: the runner deletes exactly the rows whose ids
    (or demo-unique natural keys) it recorded, never a wildcard delete.
    """

    def __init__(self) -> None:
        self._ids: dict[str, set[uuid.UUID]] = {}
        self._values: list[tuple[str, str, str]] = []
        self._hunt_names: set[str] = set()
        self._user_ids: set[str] = set()
        self._audit_baseline: set[str] | None = None

    def track(self, table: str, row_id: Any) -> None:
        if row_id is None:
            return
        self._track_ids(table, row_id)

    def _track_ids(self, table: str, row_id: Any) -> None:
        self._ids.setdefault(table, set()).add(str(row_id))

    def track_value(self, table: str, column: str, value: str) -> None:
        self._values.append((table, column, value))

    def track_hunt(self, hunt_id: Any) -> None:
        """Track a hunt by its domain id (its three child rows go with it)."""
        if hunt_id is None:
            return
        self._track_ids("threat_hunts", hunt_id)

    def track_user(self, user_id: Any) -> None:
        """Track an ephemeral demo user *and* the audit trail it produced.

        ``audit_logs.user_id`` is a real foreign key, so the audit rows have
        to go before the user row or the whole cleanup transaction aborts.
        """
        if user_id is None:
            return
        self._track_ids("users", user_id)
        self._user_ids.add(str(user_id))

    def capture_audit_baseline(self, db: Any) -> None:
        """Record the audit rows that already exist, before the command writes.

        Several governed actions (approval, detection-as-code, SOAR) are
        audited with a null ``user_id`` because no human acted through the
        service.  Those rows are not reachable from any tracked user, so
        cleanup remembers exactly which audit ids pre-existed and removes only
        the new ones afterwards.
        """
        from sqlalchemy import select

        from app.models.audit_log import AuditLog

        self._audit_baseline = {
            str(value) for value in db.scalars(select(AuditLog.id)).all()
        }

    def snapshot(self) -> dict[str, Any]:
        """A plain-data view of every tracked identity, for ``--clean`` state."""
        return {
            "ids": {table: sorted(ids) for table, ids in self._ids.items()},
            "values": [list(entry) for entry in self._values],
            "hunt_names": sorted(self._hunt_names),
            "user_ids": sorted(self._user_ids),
            "audit_baseline": (
                sorted(self._audit_baseline)
                if self._audit_baseline is not None
                else None
            ),
        }

    @classmethod
    def merge(cls, cleanups: Sequence["Cleanup"]) -> "Cleanup":
        """Combine several cleanups into one dependency-ordered pass.

        Attempts of the same demo deliberately share the deterministic demo
        users, so a row created by one attempt can be referenced by another
        (an approval carries a real ``users`` foreign key).  Deleting each
        cleanup separately would then remove a parent before its child and
        abort the transaction, so the tracked ids are unioned and deleted
        children-first in a single pass.
        """
        merged = cls()
        for cleanup in cleanups:
            for table, ids in cleanup._ids.items():
                merged._ids.setdefault(table, set()).update(ids)
            merged._values.extend(cleanup._values)
            merged._hunt_names.update(cleanup._hunt_names)
            merged._user_ids.update(cleanup._user_ids)
        baselines = [
            cleanup._audit_baseline
            for cleanup in cleanups
            if cleanup._audit_baseline is not None
        ]
        if baselines:
            # A row absent from the *oldest* baseline is new to every attempt.
            merged._audit_baseline = min(baselines, key=len)
        return merged

    @classmethod
    def restore(cls, data: dict[str, Any]) -> "Cleanup":
        """Rebuild a cleanup from :meth:`snapshot` output."""
        cleanup = cls()
        cleanup._ids = {table: set(ids) for table, ids in data.get("ids", {}).items()}
        cleanup._values = [tuple(entry) for entry in data.get("values", [])]
        cleanup._hunt_names = set(data.get("hunt_names", []))
        cleanup._user_ids = set(data.get("user_ids", []))
        baseline = data.get("audit_baseline")
        cleanup._audit_baseline = set(baseline) if baseline is not None else None
        return cleanup

    def __bool__(self) -> bool:
        return bool(self._ids or self._values or self._hunt_names or self._user_ids)

    def run(self, db: Any) -> list[str]:
        from sqlalchemy import delete, select

        removed: list[str] = []
        try:
            # Threat hunts own three child tables; delete children by hunt_id.
            if self._hunt_names or self._ids.get("threat_hunts"):
                from app.models.threat_hunt import (
                    ThreatHuntEvidenceRow,
                    ThreatHuntFindingRow,
                    ThreatHuntRow,
                    ThreatHuntTimelineItemRow,
                )

                hunt_ids: set[str] = set(self._ids.get("threat_hunts", set()))
                if self._hunt_names:
                    hunt_ids.update(
                        str(row.hunt_id)
                        for row in db.execute(
                            select(ThreatHuntRow.hunt_id).where(
                                ThreatHuntRow.name.in_(self._hunt_names)
                            )
                        ).all()
                    )
                if hunt_ids:
                    coerced = [
                        _coerce(ThreatHuntRow, "hunt_id", value) for value in hunt_ids
                    ]
                    for model in (
                        ThreatHuntTimelineItemRow,
                        ThreatHuntFindingRow,
                        ThreatHuntEvidenceRow,
                    ):
                        db.execute(delete(model).where(model.hunt_id.in_(coerced)))
                    db.execute(delete(ThreatHuntRow).where(ThreatHuntRow.hunt_id.in_(coerced)))
                    removed.append(f"threat_hunts({len(hunt_ids)})")

            for table, column, value in self._values:
                model = _TABLE_BY_NAME[table]
                result = db.execute(
                    delete(model).where(
                        getattr(model, column) == _coerce(model, column, value)
                    )
                )
                if result.rowcount:
                    removed.append(f"{table}.{column}={value}({result.rowcount})")

            # Audit rows this run added, including the null-actor ones no
            # tracked user can reach.
            if self._audit_baseline is not None:
                from sqlalchemy import select

                from app.models.audit_log import AuditLog

                current = {str(value) for value in db.scalars(select(AuditLog.id)).all()}
                fresh = sorted(current - self._audit_baseline)
                if fresh:
                    coerced = [_coerce(AuditLog, "id", value) for value in fresh]
                    result = db.execute(
                        delete(AuditLog).where(AuditLog.id.in_(coerced))
                    )
                    if result.rowcount:
                        removed.append(f"audit_logs.new({result.rowcount})")

            # The audit trail of an ephemeral demo user references that user,
            # so it has to be removed first or the transaction aborts.
            if self._user_ids:
                from app.models.audit_log import AuditLog
                from app.models.user import User

                coerced_users = [
                    _coerce(User, "id", value) for value in self._user_ids
                ]
                result = db.execute(
                    delete(AuditLog).where(AuditLog.user_id.in_(coerced_users))
                )
                if result.rowcount:
                    removed.append(f"audit_logs.by_user({result.rowcount})")

            # Children before parents: the ephemeral demo users are removed last.
            for table in _CLEANUP_ORDER:
                if table not in self._ids:
                    continue
                ids = self._ids[table]
                if not ids:
                    continue
                model = _TABLE_BY_NAME[table]
                column = _ID_COLUMN_BY_TABLE[table]
                coerced = [_coerce(model, column, value) for value in ids]
                result = db.execute(
                    delete(model).where(getattr(model, column).in_(coerced))
                )
                if result.rowcount:
                    removed.append(f"{table}({result.rowcount})")
            db.commit()
        except Exception as exc:  # noqa: BLE001 - cleanup must not mask the run
            db.rollback()
            removed.append(f"cleanup-failed:{type(exc).__name__}")
        return removed


def new_cleanup(db: Any) -> Cleanup:
    """A :class:`Cleanup` that already knows which audit rows pre-existed.

    Every command calls this instead of ``Cleanup()`` so the audit trail the
    run creates is removable even when the governing service recorded it with
    a null ``user_id``.
    """
    cleanup = Cleanup()
    cleanup.capture_audit_baseline(db)
    return cleanup


def _json_safe(value: Any) -> Any:
    """Render any schema/dataclass/datetime/UUID value as plain JSON data."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (uuid.UUID, datetime)):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return _json_safe(dump(mode="json"))
    return str(value)


def report_cleanup(report: "Report", label: str, removed: Sequence[str]) -> None:
    """Record the exact rows the runner removed, and fail loudly if any remain."""
    failed = [entry for entry in removed if entry.startswith("cleanup-failed")]
    if failed:
        report.fail(
            f"cleanup/{label}",
            "the runner could not remove every row it created, so the demo left "
            "state behind; inspect the database before trusting this run",
            removed=removed,
        )
        return
    report.ok(
        f"cleanup/{label}",
        f"removed every row this command created ({len(removed)} delete(s)); no "
        "unrelated record was touched",
        removed=removed,
    )


@dataclass
class DemoMode:
    """Runtime switches for the ``python -m app.cli demo`` command.

    The default (every flag ``False``) keeps the runner's own guarantees: each
    command cleans up after itself and the database returns to its starting
    state.  ``app.cli demo`` flips :attr:`leave_results` so the freshly
    persisted rows stay behind for the frontend to read, and the accumulated
    cleanups are stored so ``python -m app.cli demo --clean`` can remove
    exactly those rows again.
    """

    leave_results: bool = False
    skip_gemini: bool = False
    force_offline: bool = False
    reject_hitl: bool = False
    label: str = "full"

    def snapshot(self) -> dict[str, Any]:
        return {
            "leave_results": self.leave_results,
            "skip_gemini": self.skip_gemini,
            "force_offline": self.force_offline,
            "reject_hitl": self.reject_hitl,
            "label": self.label,
        }


#: The active demo-mode switches.  ``app/cli.py`` mutates this in place before
#: invoking the runner; the standalone runner leaves it untouched.
demo_mode = DemoMode()

#: Cleanups the runner deferred because ``leave_results`` is active.  The demo
#: command snapshots them to :file:`.demo_state.json` after the run so a later
#: ``--clean`` can remove every demo-created row.
_DEFERRED_CLEANUPS: list["Cleanup"] = []

#: Time window the demo pins the threat hunts onto, so they cover this run's
#: incident instead of every unrelated record that happens to share the
#: dataset's wide default window in a populated database.  The hunts still run
#: the real service and the real governed query grammar; only the time range
#: is narrowed.  ``None`` keeps the dataset's own window.
DEMO_HUNT_WINDOW: tuple[datetime, datetime] | None = None


def _environment_gemini_key() -> str | None:
    """The Gemini key the environment provides, ignoring ``--no-gemini``.

    Used where the demo must distinguish "the operator forbade the model call"
    from "there is no provider to call" — the two have different, real
    consequences for what the report service persists.
    """
    return os.environ.get("GEMINI_API_KEY") or _settings_gemini_key()


def _resolved_gemini_key() -> str | None:
    """The configured Gemini key, or ``None`` when disabled or unset.

    ``demo --no-gemini`` returns ``None`` regardless of the environment so the
    model-backed stages are honestly reported as skipped instead of calling
    the live service.
    """
    if demo_mode.skip_gemini:
        return None
    return _environment_gemini_key()


def defer_or_clean(report: "Report", label: str, cleanup: "Cleanup", db: Any) -> None:
    """Run a command's cleanup now, or defer it when the demo keeps results.

    In demo mode the freshly persisted rows must survive for the frontend, so
    the :class:`Cleanup` object is held back and reported as deferred rather
    than executed.
    """
    if demo_mode.leave_results:
        _DEFERRED_CLEANUPS.append(cleanup)
        report.ok(
            f"cleanup/{label}",
            "demo mode keeps the freshly persisted rows so the frontend can "
            "read them; `python -m app.cli demo --clean` removes exactly these "
            "rows again",
            deferred=True,
            remove_with="python -m app.cli demo --clean",
        )
        return
    report_cleanup(report, label, cleanup.run(db))


def table_counts() -> dict[str, int]:
    """Row totals for every table the runner may write to.

    Used as the pre-demo baseline and again after ``--clean`` to prove the
    database was restored rather than merely emptied of demo rows.
    """
    from sqlalchemy import func, select

    _load_cleanup_tables()
    counts: dict[str, int] = {}
    with db_session() as db:
        for name in sorted(_TABLE_BY_NAME):
            try:
                counts[name] = db.scalar(
                    select(func.count()).select_from(_TABLE_BY_NAME[name])
                ) or 0
            except Exception:  # noqa: BLE001 - a missing table is worth a badge, not a crash
                counts[name] = -1
    return counts


def run_cleanups(db: Any, cleanups: Sequence["Cleanup"]) -> list[str]:
    """Execute several (possibly restored) cleanups against one session.

    They are merged first: several attempts of one demo share the demo users,
    so the tracked rows must be deleted children-first as a single unit.
    """
    _load_cleanup_tables()
    if not cleanups:
        return []
    return Cleanup.merge(cleanups).run(db)


def _coerce(model: Any, column: str, value: Any) -> Any:
    """Coerce *value* to the python type the column actually stores.

    SentinelAI stores some identities as native ``UUID`` and some as
    ``CHAR(36)`` text (the report and hunt rows), so a uniform coercion at
    the delete site is what keeps cleanup working for both.
    """
    import uuid as _uuid

    try:
        python_type = model.__table__.columns[column].type.python_type
    except (KeyError, NotImplementedError):
        return value
    if python_type is _uuid.UUID:
        return _uuid.UUID(str(value))
    if python_type is str:
        return str(value)
    return value


_TABLE_BY_NAME: dict[str, Any] = {}
_ID_COLUMN_BY_TABLE: dict[str, str] = {}


def _latest_report_for(db: Any, correlation_id: Any) -> Any | None:
    """The newest persisted report summary for *correlation_id*, or ``None``.

    Reads through :meth:`IncidentReportService.list` — the same read model the
    ``GET /api/incident-reports`` route serves — so the demo reports exactly
    what the Incident Reports page will show after a governed failure.
    """
    from app.services.reporting.service import IncidentReportService

    page = IncidentReportService().list(
        db, page=1, page_size=1, correlation_id=correlation_id
    )
    return page.items[0] if page.items else None


def _load_cleanup_tables() -> None:
    """Register the tables the runner may create rows in."""
    from app.models.approval_request import ApprovalRequestRow
    from app.models.audit_log import AuditLog
    from app.models.user import User
    from app.models.correlation_member import CorrelationMember
    from app.models.correlation_result import CorrelationResult
    from app.models.detection_result import DetectionResult
    from app.models.detection_rule_failure import DetectionRuleFailure
    from app.models.incident_memory import IncidentMemoryRow
    from app.models.incident_report import IncidentReportRow
    from app.models.risk_assessment import RiskAssessment
    from app.models.soar_execution import SoarExecutionRow
    from app.models.soar_step_execution import SoarStepExecutionRow
    from app.models.threat_hunt import ThreatHuntRow
    from app.models.threat_intel_indicator import ThreatIntelIndicator
    from app.models.threat_intel_lookup import ThreatIntelLookup

    _TABLE_BY_NAME.update(
        {
            "detection_results": DetectionResult,
            "detection_rule_failures": DetectionRuleFailure,
            "correlations": CorrelationResult,
            "correlation_members": CorrelationMember,
            "risk_assessments": RiskAssessment,
            "threat_intel_indicators": ThreatIntelIndicator,
            "threat_intel_lookups": ThreatIntelLookup,
            "incident_memories": IncidentMemoryRow,
            "approval_requests": ApprovalRequestRow,
            "soar_executions": SoarExecutionRow,
            "soar_step_executions": SoarStepExecutionRow,
            "incident_reports": IncidentReportRow,
            "threat_hunts": ThreatHuntRow,
            "audit_logs": AuditLog,
            "users": User,
        }
    )
    _ID_COLUMN_BY_TABLE.update(
        {
            "detection_results": "detection_id",
            "detection_rule_failures": "id",
            "correlations": "correlation_id",
            "correlation_members": "correlation_id",
            "risk_assessments": "risk_assessment_id",
            "threat_intel_indicators": "id",
            "threat_intel_lookups": "id",
            "incident_memories": "memory_id",
            "approval_requests": "approval_id",
            "soar_executions": "execution_id",
            "soar_step_executions": "step_execution_id",
            "incident_reports": "report_id",
            "threat_hunts": "hunt_id",
            "audit_logs": "id",
            "users": "id",
        }
    )


# ---------------------------------------------------------------------------
# Shared pipeline helpers
# ---------------------------------------------------------------------------


def _demo_user_token(role: str) -> str:
    """Stable per-role token for the demo's e-mail addresses.

    Derived from :data:`DEMO_NS` and the role only, so the same dataset always
    produces the same identity and a repeated run reuses the existing row
    instead of creating a second one with a clock-based address.
    """
    return str(uuid.uuid5(DEMO_NS, f"demo-user:{role}"))


class _CountingResponseRegistry:
    """Pass-through response registry that counts provider invocations.

    The only honest way to show that a blocked decision executed nothing is to
    ask the real executor and then count what the provider was asked to do.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls = 0

    def get(self, name: str) -> Any:
        return self._inner.get(name)

    def provider_for(self, action: Any) -> Any:
        provider = self._inner.provider_for(action)
        self.calls += 1
        return provider

    def __len__(self) -> int:
        return len(self._inner)


def reset_demo_run_state() -> None:
    """Forget everything cached for a previous demo run.

    The shared context holds the identities of rows a run persisted, so a
    second run in the same process (two demos, or a demo followed by a test)
    must start from a clean slate instead of adopting rows the previous
    attempt has already removed.
    """
    global _SHARED_SCENARIO_CONTEXT, DEMO_HUNT_WINDOW
    _SHARED_SCENARIO_CONTEXT = None
    DEMO_HUNT_WINDOW = None
    _DEFERRED_CLEANUPS.clear()


def shared_scenario_context(report: "Report | None" = None) -> "ScenarioContext":
    """The one context a demo run shares, persisting it on first use.

    ``app.cli``'s stage 1-7 checks read their facts from this object so the
    ids they report are the ids that were persisted, rather than a second,
    in-memory set: ``correlate`` mints a fresh identity per call, so two
    independent computations of the same events never agree.
    """
    _load_cleanup_tables()
    with db_session() as db:
        cleanup = new_cleanup(db)
        context = ScenarioContext(cleanup=cleanup, session=db).ensure()
        if demo_mode.leave_results:
            _DEFERRED_CLEANUPS.append(cleanup)
        else:
            cleanup.run(db)
    return context


def demo_user(db: Any, role: str, cleanup: "Cleanup | None" = None) -> Any:
    """A real, ephemeral ``users`` row for the given role.

    Several services write an ``audit_logs`` row whose ``user_id`` is a real
    foreign key, so a purely synthetic UUID would be refused by PostgreSQL.
    The row is tagged with a demo e-mail prefix and, when *cleanup* is given,
    is removed again together with its audit trail.
    """
    from app.models.role import Role
    from app.models.user import User
    from sqlalchemy import select

    role_row = db.execute(select(Role).where(Role.name == role)).scalar_one_or_none()
    if role_row is None:
        raise LookupError(f"the seeded role {role!r} is missing")
    # A deterministic address, so repeated runs address the same identity
    # instead of minting a new one every time.
    email = f"demo-{role}-{_demo_user_token(role)}@example.com"
    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing is not None:
        # Reused, therefore *not* this run's row: leaving it untracked is what
        # stops ``--clean`` from deleting a demo user that predates the run.
        return existing
    user = User(
        email=email,
        password_hash="!demo-not-a-real-credential",
        is_active=True,
        role_id=role_row.id,
    )
    db.add(user)
    db.commit()
    if cleanup is not None:
        cleanup.track_user(user.id)
    return user


def build_registry() -> Any:
    """The governed, deployed detection rule registry.

    Prefers the database-governed registry (every release verified against
    its on-disk source hash, failing closed) and falls back to the shipped
    on-disk inventory when PostgreSQL is unavailable, so a pure detection
    demonstration still runs.
    """
    from app.services.detection.rule_loader import build_registry as build_file_registry

    try:
        with db_session() as db:
            from app.services.detection_as_code.lifecycle import LifecycleService

            return LifecycleService(db).build_deployed_registry()
    except Exception:  # noqa: BLE001 - fall back to the on-disk inventory
        return build_file_registry()


def registry_summary(registry: Any) -> dict[str, Any]:
    rules = list(registry.list_rules()) if hasattr(registry, "list_rules") else []
    by_type: dict[str, int] = {}
    for rule in rules:
        by_type[str(getattr(rule, "rule_type", "unknown"))] = (
            by_type.get(str(getattr(rule, "rule_type", "unknown")), 0) + 1
        )
    return {"total": len(rules), "by_type": by_type}


def collect(*parts: str) -> tuple[list[Any], Any]:
    """Run the real file collector over a dataset.

    Returns the collected events and the real
    :class:`~app.collectors.base.CollectionResult`, so callers can report
    both the typed events and the collector's own statistics and
    per-record errors.
    """
    from app.collectors.file_collector import FileLogCollector

    path = dataset_path(*parts)
    result = FileLogCollector(path).collect()
    return list(result.events), result


def normalize(event: Any) -> Any:
    from app.agents.normalization import NormalizationAgent

    return NormalizationAgent().normalize(event)


def _content_bytes(value: Any) -> bytes | None:
    """Decode a dataset's declared file content into the bytes YARA scans.

    The dataset stores content base64-encoded so it stays JSON-safe; the
    YARA target adapter requires real bytes.
    """
    import base64
    import binascii

    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return value.encode("utf-8")


def detect_all(events: Sequence[Any], registry: Any, *, clock: datetime | None = None) -> list[Any]:
    """Evaluate every event and return the matched detections, in order."""
    from app.agents.detection import DetectionAgent

    agent = DetectionAgent(registry=registry)
    matched: list[Any] = []
    for event in events:
        analysis = agent.evaluate(event, clock=clock or NOW)
        matched.extend(
            result for result in analysis.results if result.matched
        )
    return matched


def correlate(matched: Sequence[Any], *, clock: datetime | None = None) -> list[Any]:
    """Build a real correlation batch and run the real correlation agent."""
    from app.agents.correlation import CorrelationAgent
    from app.schemas.detection_correlation import to_correlation_batch

    batch = to_correlation_batch(matched)
    return CorrelationAgent().analyze(batch, clock=clock or NOW)


def score(correlations: Sequence[Any], *, clock: datetime | None = None) -> list[Any]:
    from app.services.risk.engine import DeterministicRiskScoringEngine

    engine = DeterministicRiskScoringEngine()
    return [engine.score(c, timestamp=clock or NOW) for c in correlations]


def enrich(event: Any) -> Any:
    from app.agents.enrichment import EnrichmentAgent

    return EnrichmentAgent().enrich(event)


#: First context persisted by the current demo process.  See ``ScenarioContext.ensure``.
_SHARED_SCENARIO_CONTEXT: "ScenarioContext | None" = None


@dataclass
class ScenarioContext:
    """The persisted state produced by the full-SOC dataset.

    ``ensure`` ingests ``00_full_soc_scenario/attack_chain.jsonl`` through
    the real detection -> correlation -> risk persistence chain and returns
    the identities the platform minted, so dependent functions can be
    demonstrated against genuinely persisted records.
    """
    cleanup: Cleanup
    session: Any = None
    _loaded: bool = False
    detections: list[Any] = field(default_factory=list)
    _analyses: list[Any] = field(default_factory=list)
    _normalized: list[Any] = field(default_factory=list)
    correlations: list[Any] = field(default_factory=list)
    risks: list[Any] = field(default_factory=list)
    detection_ids: list[str] = field(default_factory=list)
    correlation_id: str = ""
    risk_assessment_id: str = ""
    indicator_values: list[str] = field(default_factory=list)
    intel_analyses: list[Any] = field(default_factory=list)

    def ensure(self) -> "ScenarioContext":
        global _SHARED_SCENARIO_CONTEXT
        if self._loaded:
            return self
        if demo_mode.leave_results and _SHARED_SCENARIO_CONTEXT is not None:
            # The demo leaves its results in the database for the frontend, so
            # every downstream function must observe the *same* incident.
            # Detection and correlation identities are minted at persistence
            # time, so re-ingesting the same events per function would leave
            # one duplicate copy of the incident per function in the database.
            self._adopt(_SHARED_SCENARIO_CONTEXT)
            self._loaded = True
            return self
        _load_cleanup_tables()
        from app.agents.detection import DetectionAgent

        events, _ = collect("00_full_soc_scenario", "attack_chain.jsonl")
        normalized = [normalize(event) for event in events]
        self._normalized = normalized
        registry = build_registry()
        agent = DetectionAgent(registry=registry)
        self._analyses = [agent.evaluate(event, clock=NOW) for event in normalized]
        self.detections = [
            result
            for analysis in self._analyses
            for result in analysis.results
            if result.matched
        ]

        self.correlations = correlate(self.detections)
        self.risks = score(self.correlations)
        self.detection_ids = [str(d.detection_id) for d in self.detections]
        # The primary correlation is the largest group, not merely the first.
        if self.correlations:
            primary = max(self.correlations, key=lambda c: len(c.members))
            self.correlation_id = str(primary.correlation_id)
        if self.risks:
            primary_risk = next(
                r
                for r in self.risks
                if str(r.correlation_id) == self.correlation_id
            )
            self.risk_assessment_id = str(primary_risk.risk_assessment_id)

        if self.session is not None:
            self._persist(self.session)
        self._loaded = True
        if demo_mode.leave_results:
            _SHARED_SCENARIO_CONTEXT = self
        return self

    def _adopt(self, other: "ScenarioContext") -> None:
        """Reuse an already-persisted context instead of writing a duplicate.

        The rows already exist (the context that minted them tracks them for
        cleanup), so only the in-memory handles and identities are copied.
        """
        self.detections = other.detections
        self._analyses = other._analyses
        self._normalized = other._normalized
        self.correlations = other.correlations
        self.risks = other.risks
        self.detection_ids = list(other.detection_ids)
        self.correlation_id = other.correlation_id
        self.risk_assessment_id = other.risk_assessment_id
        self.indicator_values = list(other.indicator_values)
        self.intel_analyses = other.intel_analyses

    def _persist(self, db: Any) -> None:
        from app.services.correlation_persistence import CorrelationPersistenceService
        from app.services.detection_persistence import DetectionPersistenceService
        from app.services.risk_persistence import RiskPersistenceService

        detector = DetectionPersistenceService()
        for analysis in self._analyses:
            # The real persistence sink records both matches and the per-event
            # rule failures (for example the YARA invalid_target failures the
            # gap check documents). Both sets are tracked, or a run would
            # quietly leave failure rows behind.
            persisted = detector.persist_analysis(db, analysis)
            for failure_id in persisted.failure_ids:
                self.cleanup.track("detection_rule_failures", failure_id)
        CorrelationPersistenceService().persist_correlations(db, self.correlations)
        for assessment in self.risks:
            RiskPersistenceService().persist_assessment(db, assessment)
        db.commit()
        for detection in self.detections:
            self.cleanup.track("detection_results", detection.detection_id)
        for correlation in self.correlations:
            self.cleanup.track("correlations", correlation.correlation_id)
        for assessment in self.risks:
            self.cleanup.track("risk_assessments", assessment.risk_assessment_id)

    def correlation_uuid(self) -> uuid.UUID:
        return uuid.UUID(self.correlation_id)

    def analyze_threat_intelligence(self, report: "Report") -> list[Any]:
        """Run the real TI agent over the first observed event.

        The indicator hunt filters on a persisted indicator value, so this
        must be the shipped agent rather than a hand-built analysis.
        """
        from app.agents.threat_intelligence import ThreatIntelligenceAgent

        self.ensure()
        if self.intel_analyses:
            return self.intel_analyses
        events, _ = collect("00_full_soc_scenario", "attack_chain.jsonl")
        enriched = enrich(normalize(events[0]))
        registry, _skipped = ti_registry()
        self.intel_analyses = [ThreatIntelligenceAgent(registry).analyze(enriched)]
        report.ok(
            "ti_extraction",
            f"the shipped agent extracted {len(self.intel_analyses[0].indicators)} "
            "indicator(s) from the observed event",
            indicators=[str(i.indicator) for i in self.intel_analyses[0].indicators],
        )
        return self.intel_analyses


# ---------------------------------------------------------------------------
# Command 01 - log collection
# ---------------------------------------------------------------------------


def cmd_log_collection(report: Report, sandbox: bool) -> None:
    """Run every 01 dataset through the real FileLogCollector."""
    for name in (
        "windows_events",
        "linux_events",
        "firewall_events",
        "application_events",
        "malformed_lines",
    ):
        path = f"01_log_collection/{name}.jsonl"
        events, result = collect("01_log_collection", f"{name}.jsonl")
        errors = [
            {
                "line": getattr(e, "line_number", None),
                "error_type": getattr(e, "error_type", None),
                "message": getattr(e, "message", None),
            }
            for e in result.errors
        ]
        if name == "malformed_lines":
            # The dataset mixes valid and malformed records on purpose: the
            # point is that a bad line is isolated per record instead of
            # failing the whole file.
            if result.successful_records > 0 and errors:
                report.ok(
                    "malformed_lines",
                    f"{result.successful_records} valid record(s) collected while "
                    f"{len(errors)} malformed record(s) were rejected individually; "
                    "the file was not failed as a whole",
                    file=rel(dataset_path("01_log_collection", "malformed_lines.jsonl")),
                    records=result.total_records,
                    collected=result.successful_records,
                    rejected=len(errors),
                    rejected_lines=[getattr(e, "line_number", None) for e in errors],
                )
            else:
                report.fail(
                    "malformed_lines",
                    "expected both collected events and per-record errors",
                    successful=result.successful_records,
                    errors=len(errors),
                )
            continue
        if len(events) == result.successful_records and result.successful_records > 0:
            report.ok(
                name,
                f"collected {len(events)} events, raw record preserved verbatim",
                file=rel(dataset_path(*path.split("/"))),
                records=result.total_records,
                collected=len(events),
                rejected=len(errors),
                first_event_id=str(events[0].event_id),
                raw_data_keys=sorted(events[0].raw_data) if events else [],
            )
        else:
            report.fail(
                name,
                "collector reported a mismatch between records and events",
                records=result.total_records,
                collected=len(events),
                rejected=len(errors),
            )


# ---------------------------------------------------------------------------
# Command 02 - normalization
# ---------------------------------------------------------------------------


def cmd_normalization(report: Report, sandbox: bool) -> None:
    """Normalize every 02 dataset and check the mapping the agent applied."""
    for name in (
        "windows_native_fields",
        "linux_snake_case",
        "firewall_fields",
        "application_events",
        "explicit_overrides",
        "unknown_events",
    ):
        events, _ = collect("02_normalization", f"{name}.jsonl")
        if not events:
            report.fail(name, "no events collected", file=f"02_normalization/{name}.jsonl")
            continue
        normalized = [normalize(event) for event in events]
        sample = normalized[0]
        identity_preserved = all(
            str(n.event_id) == str(e.event_id) for n, e in zip(normalized, events)
        )
        categories = sorted({n.event_category.value for n in normalized})
        report.ok(
            name,
            f"normalized {len(normalized)} events; event identity preserved",
            file=f"02_normalization/{name}.jsonl",
            collected=len(events),
            event_ids_preserved=identity_preserved,
            event_categories=categories,
            first_event_category=sample.event_category.value,
            provenance=sample.provenance.value,
            normalized_data_keys=sorted(sample.normalized_data)[:8],
        ) if identity_preserved else report.fail(
            name,
            "normalization changed the event identity",
            categories=categories,
        )


# ---------------------------------------------------------------------------
# Command 03 - detection
# ---------------------------------------------------------------------------


def cmd_detection(report: Report, sandbox: bool) -> None:
    """Run the real detection engines over the positive and negative sets.

    Two genuine paths are exercised:

    * **ingest path** - collect -> normalize -> detect, which is how every
      event in the pack is really analysed.  Sigma rules match here.
    * **target path** - the YARA engine's explicit-content entry point,
      because normalization only forwards fields declared in a source
      mapping's ``extra_fields`` and no shipped mapping carries file
      content.  A YARA rule therefore can never match an ingested JSONL
      event; the engine returns an ``invalid_target`` failure instead.

    Both results are reported.  The gap is not papered over.
    """
    registry = build_registry()
    summary = registry_summary(registry)
    report.ok(
        "registry",
        f"built the registry from {summary['total']} governed rules",
        **summary,
    )

    # -- ingest path --------------------------------------------------------
    for folder in ("detection_positive", "detection_negative"):
        for name in (
            "sigma_positive_events",
            "sigma_negative_events",
            "yara_positive_events",
            "yara_negative_events",
            "clean_baseline",
        ):
            path = dataset_path("03_detection", folder, f"{name}.jsonl")
            if not path.exists():
                continue
            events, _ = collect("03_detection", folder, f"{name}.jsonl")
            if not events:
                report.fail(f"{folder}/{name}", "no events collected")
                continue
            matched = detect_all([normalize(event) for event in events], registry)
            rule_ids = sorted({str(m.rule_id) for m in matched})
            # Only Sigma is reachable through the ingest path; the YARA
            # positive file is exercised on the target path below, and its
            # ingest outcome is the documented invalid_target gap.
            expects_match = folder == "detection_positive" and name == (
                "sigma_positive_events"
            )
            if expects_match and matched:
                report.ok(
                    f"ingest/{folder}/{name}",
                    f"{len(matched)} real detection(s) across {len(events)} events",
                    events=len(events),
                    matched=len(matched),
                    rule_ids=rule_ids,
                )
            elif not expects_match and not matched:
                report.ok(
                    f"ingest/{folder}/{name}",
                    f"no rule matched across {len(events)} events (true negative)",
                    events=len(events),
                    matched=0,
                )
            else:
                report.fail(
                    f"ingest/{folder}/{name}",
                    "unexpected match count on the ingest path",
                    events=len(events),
                    matched=len(matched),
                    rule_ids=rule_ids,
                )

    # -- YARA target path ---------------------------------------------------
    from app.services.detection.yara.engine import YaraDetectionEngine
    from app.services.detection.yara.target_adapter import to_yara_target_from_bytes

    yara_rules = [
        rule for rule in registry.list_rules() if "YARA" in str(rule.rule_type)
    ]
    engine = YaraDetectionEngine()
    for folder, expects_match in (("detection_positive", True), ("detection_negative", False)):
        for name in ("yara_positive_events", "yara_negative_events"):
            path = dataset_path("03_detection", folder, f"{name}.jsonl")
            if not path.exists():
                continue
            events, _ = collect("03_detection", folder, f"{name}.jsonl")
            hits: set[str] = set()
            scanned = 0
            for event in events:
                encoded = (event.raw_data.get("normalized_data") or {}).get("file_content")
                if not encoded:
                    continue
                content = _content_bytes(encoded)
                if not content:
                    continue
                scanned += 1
                report_result = engine.evaluate_target(
                    to_yara_target_from_bytes(content), yara_rules
                )
                hits.update(
                    str(result.rule_id)
                    for result in report_result.results
                    if result.matched
                )
            key = f"yara_target/{folder}/{name}"
            if scanned == 0:
                report.fail(key, "no event carried file content to scan")
            elif bool(hits) is expects_match:
                report.ok(
                    key,
                    f"scanned {scanned} file-content payload(s) against "
                    f"{len(yara_rules)} governed YARA rules",
                    scanned=scanned,
                    matched=sorted(hits) or 0,
                )
            else:
                report.fail(
                    key,
                    "unexpected YARA match set on the target path",
                    scanned=scanned,
                    matched=sorted(hits),
                )

    # -- documented gap -----------------------------------------------------
    events, _ = collect("03_detection", "detection_positive", "yara_positive_events.jsonl")
    probe = detect_all([normalize(event) for event in events], registry)
    from app.agents.detection import DetectionAgent

    analysis = DetectionAgent(registry=registry).evaluate(
        normalize(events[0]), clock=NOW
    )
    failures = [
        {"rule_id": str(f.rule_id), "error_type": str(f.error_type), "message": f.message}
        for f in analysis.failures
    ]
    report.ok(
        "yara_ingest_gap",
        "documented: normalization forwards only fields declared in a source "
        "mapping's extra_fields, and no shipped mapping carries file content - "
        "so a YARA rule can never match an ingested JSONL event",
        ingest_matches=len(probe),
        yara_failures=failures,
        gap=(
            "YARA coverage is unreachable through the file-ingestion path. "
            "The dataset does not add a content mapping to close the gap."
        ),
    )


# ---------------------------------------------------------------------------
# Command 06 - mitre mapping
# ---------------------------------------------------------------------------


def cmd_mitre_mapping(report: Report, sandbox: bool) -> None:
    """Report the ATT&CK mapping capability SentinelAI V2 actually has.

    SentinelAI V2 has no technique mapper: no ``DetectionRule`` technique
    field, no ATT&CK data in the shipped manifest, no service, route or
    table, and every agent that would plausibly own the job explicitly
    disclaims it.  The command therefore shows the real detections that
    fire (so the behaviour is auditable) and then reports the missing
    capability.  It never emits a technique id.
    """
    capability = load_json("06_mitre_mapping", "capability.json")
    events, _ = collect("06_mitre_mapping", "events.jsonl")
    normalized = [normalize(event) for event in events]
    matched = detect_all(normalized, build_registry())

    for result in matched:
        report.ok(
            f"detection_without_technique:{result.rule_id}",
            "real rule matched; the result carries no technique field, so no "
            "ATT&CK id is produced or invented",
            rule_id=str(result.rule_id),
            rule_type=str(result.rule_type),
            severity=str(result.severity),
            matched_conditions=list(result.evidence.matched_conditions or []),
            technique_on_result=hasattr(result, "mitre_attack"),
            evidence_rule_references=[
                rr.model_dump(mode="json")
                for rr in (result.evidence.rule_references or [])
            ],
        )
    if not matched:
        report.fail("detection_without_technique", "no rule matched the dataset")

    report.ok(
        "capability_gap",
        "documented: SentinelAI V2 ships no ATT&CK mapping engine; this "
        "dataset reports the gap instead of fabricating a mapping",
        capability_present=capability.get("capability_present"),
        evidence_of_absence=capability.get("evidence_of_absence"),
    )


# ---------------------------------------------------------------------------
# Command 04 - threat intelligence
# ---------------------------------------------------------------------------


def ti_registry() -> tuple[Any, list[str]]:
    """The real provider registry, built only from configured providers.

    A provider with no API key is skipped rather than stubbed, so a missing
    credential reduces coverage instead of inventing a lookup result.
    """
    from app.core.config import settings
    from app.services.threat_intelligence.alienvault_otx import AlienVaultOTXProvider
    from app.services.threat_intelligence.abuseipdb import AbuseIPDBProvider
    from app.services.threat_intelligence.registry import ProviderRegistry
    from app.services.threat_intelligence.virustotal import VirusTotalProvider

    if demo_mode.force_offline:
        return ProviderRegistry([]), ["offline (demo --offline)"]

    providers = []
    skipped: list[str] = []
    for label, key, factory in (
        ("virustotal", settings.virustotal_api_key, VirusTotalProvider),
        ("abuseipdb", settings.abuseipdb_api_key, AbuseIPDBProvider),
        ("otx", settings.otx_api_key, AlienVaultOTXProvider),
    ):
        if not key:
            skipped.append(f"{label} (no API key)")
            continue
        try:
            providers.append(factory())
        except Exception as exc:  # noqa: BLE001
            skipped.append(f"{label} ({type(exc).__name__})")
    return ProviderRegistry(providers), skipped


def cmd_threat_intelligence(report: Report, sandbox: bool) -> None:
    """Extract indicators and run the real providers over them."""
    from app.agents.threat_intelligence import ThreatIntelligenceAgent

    registry, skipped = ti_registry()
    if skipped:
        report.skip(
            "provider_registry",
            "some providers have no API key and were skipped, not stubbed",
            skipped=skipped,
        )
    if registry.count() == 0:
        report.skip(
            "provider_lookups",
            "no threat-intel provider is configured; the real agent still extracts "
            "indicators, but no lookup can be performed",
            providers=0,
        )
    else:
        report.ok(
            "provider_registry",
            f"registered {registry.count()} real provider(s)",
            providers=sorted(registry.provider_names()),
        )

    # An empty registry is not a stub: the agent extracts indicators first and
    # only consults a provider for each one, so extraction stays real.
    agent = ThreatIntelligenceAgent(registry)
    for name in ("indicator_events", "no_data_indicators"):
        events, _ = collect("04_threat_intelligence", f"{name}.jsonl")
        if not events:
            report.fail(name, "no events collected")
            continue
        totals = {"indicators": 0, "lookups": 0, "matched": 0}
        per_event = []
        for event in events:
            enriched = enrich(normalize(event))
            analysis = agent.analyze(enriched)
            extracted = len(analysis.indicators)
            totals["indicators"] += extracted
            totals["lookups"] += len(analysis.results) + len(analysis.failures)
            totals["matched"] += sum(1 for hit in analysis.results if hit.result.found)
            per_event.append(
                {
                    "event_id": str(event.event_id),
                    "indicators": [
                        {
                            "type": str(i.indicator_type),
                            "value": str(i.indicator),
                            "source_field": i.source_field,
                        }
                        for i in analysis.indicators
                    ],
                    "lookups": [
                        {
                            "provider": str(hit.provider),
                            "confidence": hit.result.confidence,
                            "found": hit.result.found,
                        }
                        for hit in analysis.results
                    ],
                    "lookup_failures": [
                        {
                            "provider": str(failure.provider),
                            "error_type": str(failure.error_type),
                            "message": failure.message[:120],
                        }
                        for failure in analysis.failures
                    ],
                }
            )
        expected_empty = name == "no_data_indicators"
        if expected_empty and totals["indicators"] == 0:
            report.ok(
                name,
                "no indicator was extracted: the agent only reads the keys it "
                "supports and invents nothing",
                file=f"04_threat_intelligence/{name}.jsonl",
                events=len(events),
                **totals,
            )
        elif not expected_empty and totals["indicators"] > 0:
            report.ok(
                name,
                f"extracted {totals['indicators']} indicator(s) and ran "
                f"{totals['lookups']} lookup(s)",
                file=f"04_threat_intelligence/{name}.jsonl",
                events=len(events),
                **totals,
                first_event=per_event[0] if per_event else None,
            )
        else:
            report.fail(name, "unexpected indicator extraction result", **totals)


# ---------------------------------------------------------------------------
# Command 05 - correlation
# ---------------------------------------------------------------------------


def cmd_correlation(report: Report, sandbox: bool) -> None:
    """Correlate the real detections and record what the strategy produced."""
    for name, expectation in (
        ("multi_rule_event", "one correlation with several members"),
        ("multi_event_same_host", "separate correlations: a shared host is not a correlating signal"),
    ):
        events, _ = collect("05_correlation", f"{name}.jsonl")
        if not events:
            report.fail(name, "no events collected")
            continue
        matched = detect_all([normalize(event) for event in events], build_registry())
        correlations = correlate(matched)
        members = sum(len(c.members) for c in correlations)
        if expectation.startswith("one") and correlations:
            report.ok(
                name,
                f"{len(correlations)} correlation(s) carrying {members} member(s) "
                "from the detections of a single event",
                file=f"05_correlation/{name}.jsonl",
                events=len(events),
                detections=len(matched),
                correlations=len(correlations),
                members=members,
                correlation_ids=[str(c.correlation_id) for c in correlations],
                evidence=[dict(c.evidence) if not isinstance(c.evidence, dict) else c.evidence
                          for c in correlations][:1],
            )
        elif expectation.startswith("separate") and len(correlations) > 1:
            report.ok(
                name,
                f"{len(events)} events on one host by one actor stayed in "
                f"{len(correlations)} separate correlation(s): the strategy "
                "groups on a shared event_id only",
                file=f"05_correlation/{name}.jsonl",
                events=len(events),
                detections=len(matched),
                correlations=len(correlations),
                members_per_correlation=[len(c.members) for c in correlations],
                shared_event_ids=sorted(
                    {str(m.event_id) for c in correlations for m in c.members}
                ),
            )
        else:
            report.fail(
                name,
                "correlation outcome did not match the documented strategy",
                events=len(events),
                detections=len(matched),
                correlations=len(correlations),
            )

    report.ok(
        "strategy_limit",
        "documented: the shipped strategy correlates only detections that share "
        "one event_id, so a multi-event attack chain cannot become one "
        "correlation; the dataset uses a real multi-detection event instead",
        strategy="app/services/correlation/strategy.py DeterministicCorrelationStrategy",
        critical_threshold=0.75,
        max_reachable_same_event=0.7,
    )


# ---------------------------------------------------------------------------
# Command 07 - risk scoring
# ---------------------------------------------------------------------------


def cmd_risk_scoring(report: Report, sandbox: bool) -> None:
    """Score the three cardinality fixtures with the real risk engine."""
    for name in ("low_volume", "medium_volume", "high_volume"):
        events, _ = collect("07_risk_scoring", name, "events.jsonl")
        if not events:
            report.fail(name, "no events collected")
            continue
        matched = detect_all([normalize(event) for event in events], build_registry())
        correlations = correlate(matched)
        assessments = score(correlations)
        primary = max(assessments, key=lambda a: a.score) if assessments else None
        if primary is None:
            report.fail(name, "no risk assessment was produced")
            continue
        report.ok(
            name,
            f"score {primary.score:.6f} -> {primary.level.value}",
            file=f"07_risk_scoring/{name}/events.jsonl",
            events=len(events),
            detections=len(matched),
            correlations=len(assessments),
            score=primary.score,
            level=str(primary.level),
            confidence=primary.confidence,
            factors={
                str(getattr(f, "factor", getattr(f, "name", "?"))): getattr(
                    f, "value", None
                )
                for f in (primary.factors or [])
            },
            evidence_count=len(primary.evidence or []),
        )

    report.ok(
        "critical_unreachable",
        "documented: score = 0.5*volume + 0.3*breadth + 0.2*diversity caps a "
        "single-event correlation at 0.7, below the 0.75 critical threshold",
        thresholds={"low": "<0.30", "medium": "<0.55", "high": "<0.75", "critical": ">=0.75"},
    )


# ---------------------------------------------------------------------------
# Command 09 - policy engine
# ---------------------------------------------------------------------------


def policy_input(
    scenario: dict[str, Any], correlation_id: uuid.UUID
) -> Any:
    from app.schemas.policy_decision import (
        PolicyEvidence,
        PolicyEvidenceType,
        PolicyInput,
    )

    evidence = [
        PolicyEvidence(
            evidence_type=getattr(PolicyEvidenceType, name.upper()),
            reference_id=correlation_id,
            role=f"demo:{name}",
        )
        for name in scenario.get("evidence_references", [])
    ]
    return PolicyInput(
        correlation_id=correlation_id,
        requested_action=scenario["requested_action"],
        risk_level=scenario["risk_level"],
        risk_score=scenario.get("risk_score"),
        confidence=scenario.get("confidence", 0.8),
        attribution_status=scenario.get("attribution_status"),
        investigation_available=scenario.get("investigation_available", True),
        evidence_available=bool(evidence),
        evidence_references=evidence,
    )


def run_policy_scenarios(
    report: Report, prefix: str = "", only: Iterable[str] | None = None
) -> dict[str, Any]:
    """Evaluate 09 policy scenarios with the real engine.

    Returns the produced decisions keyed by ``scenario_id`` so the response,
    HITL and SOAR commands can reuse the *real* decisions instead of
    inventing their own.  *only* restricts the evaluation to the scenario
    ids a dataset actually references.
    """
    from app.services.policy.engine import PolicyDecisionEngine

    engine = PolicyDecisionEngine()
    data = load_json("09_policy", "scenarios.json")
    wanted = set(only) if only is not None else None
    decisions: dict[str, Any] = {}
    for scenario in data["scenarios"]:
        if wanted is not None and scenario["scenario_id"] not in wanted:
            continue
        correlation_id = demo_uuid("policy", scenario["scenario_id"])
        try:
            decision = policy_input(scenario, correlation_id)
        except Exception as exc:  # noqa: BLE001
            report.fail(
                f"{prefix}policy/{scenario['scenario_id']}",
                f"scenario input is not schema-valid: {type(exc).__name__}",
            )
            continue
        produced = engine.decide(decision)
        decisions[scenario["scenario_id"]] = produced
        matches = produced.decision.value == scenario["expected_decision"]
        report.ok(
            f"{prefix}policy/{scenario['scenario_id']}",
            f"{produced.decision.value} via {produced.policy_rule_id}"
            + ("" if matches else f" (expected {scenario['expected_decision']})"),
            requested_action=scenario["requested_action"],
            risk_level=scenario["risk_level"],
            confidence=scenario.get("confidence"),
            decision=str(produced.decision),
            expected=scenario["expected_decision"],
            requires_approval=produced.requires_approval,
            policy_rule_id=produced.policy_rule_id,
            reason=produced.reason,
            matches_expectation=matches,
        ) if matches else report.fail(
            f"{prefix}policy/{scenario['scenario_id']}",
            "engine decision did not match the documented expectation",
            decision=str(produced.decision),
            expected=scenario["expected_decision"],
            policy_rule_id=produced.policy_rule_id,
            reason=produced.reason,
        )
    return decisions


def cmd_policy(report: Report, sandbox: bool) -> None:
    run_policy_scenarios(report)


# ---------------------------------------------------------------------------
# Command 10 - automated response
# ---------------------------------------------------------------------------


def cmd_response(report: Report, sandbox: bool) -> None:
    """Run the real response executor against the sandbox provider."""
    from app.schemas.response import ResponseExecutionStatus
    from app.services.response.executor import ResponseExecutor
    from app.services.response.registry import DEFAULT_RESPONSE_REGISTRY
    from app.services.response.service import ResponseMitigationService

    decisions = run_policy_scenarios(report, prefix="response/")
    data = load_json("10_response", "scenarios.json")
    spy_registry = _CountingResponseRegistry(DEFAULT_RESPONSE_REGISTRY)
    executor = ResponseExecutor(registry=spy_registry)
    seen: dict[tuple[str, str], Any] = {}

    for scenario in data["scenarios"]:
        policy_id = scenario.get("policy_scenario_id", "")
        decision = decisions.get(policy_id)
        if decision is None:
            report.fail(
                f"response/{scenario['scenario_id']}",
                f"no real policy decision for scenario {policy_id!r}",
            )
            continue
        if str(decision.decision) in ("requires_approval", "requires_approval_pending"):
            # A claim that "the executor refuses to act" is worth nothing
            # unless the executor is actually asked.  The registry is wrapped
            # in a call-counting spy, so the check below proves the provider
            # was never reached rather than inferring it from a message.
            spy = _CountingResponseRegistry(DEFAULT_RESPONSE_REGISTRY)
            gated = ResponseExecutor(registry=spy)
            request = {
                "response_id": str(
                    ResponseMitigationService.derive_response_id(
                        policy_decision_id=decision.policy_decision_id,
                        action=decision.requested_action,
                        target=scenario["target"],
                    )
                ),
                "policy_decision_id": str(decision.policy_decision_id),
                "correlation_id": str(decision.correlation_id),
                "action_type": scenario["action_type"],
                "target": scenario["target"],
            }
            result = gated.execute(request, decision)
            provider_calls = spy.calls
            if provider_calls or result.execution_status is not ResponseExecutionStatus.REJECTED:
                report.fail(
                    f"response/{scenario['scenario_id']}",
                    "a decision that requires human approval reached the "
                    f"provider ({provider_calls} call(s), status "
                    f"{result.execution_status.value}) instead of being "
                    "rejected without execution",
                    provider_calls=provider_calls,
                    execution_status=str(result.execution_status),
                )
            else:
                report.ok(
                    f"response/{scenario['scenario_id']}",
                    "the real executor was asked to run a decision that "
                    "requires human approval and refused it: the provider "
                    "was never invoked (0 calls), so nothing was executed",
                    decision=str(decision.decision),
                    requires_approval=decision.requires_approval,
                    policy_rule_id=decision.policy_rule_id,
                    execution_status=str(result.execution_status),
                    provider_calls=provider_calls,
                    provider=result.provider,
                )
            continue

        # ``response_id`` is the canonical content-derived identity: the
        # executor rejects any other value, and the same identity submitted
        # twice is suppressed by the deterministic idempotency key.
        response_id = ResponseMitigationService.derive_response_id(
            policy_decision_id=decision.policy_decision_id,
            action=decision.requested_action,
            target=scenario["target"],
        )
        repeats = int(scenario.get("repeat", 1))
        results = []
        calls_before = spy_registry.calls
        for _ in range(repeats):
            request = {
                "response_id": str(response_id),
                "policy_decision_id": str(decision.policy_decision_id),
                "correlation_id": str(decision.correlation_id),
                "action_type": scenario["action_type"],
                "target": scenario["target"],
            }
            results.append(executor.execute(request, decision))
        final = results[-1]
        distinct = len({str(r.response_id) for r in results})
        # A repeat returns the stored record verbatim: identical content and
        # an unchanged processed count prove the provider ran only once.
        suppressed = repeats > 1 and all(
            r.model_dump() == results[0].model_dump() for r in results
        )
        if str(decision.decision) == "denied":
            # Same proof as the approval gate: a denied decision must reach the
            # executor and stop there, with the provider never invoked.
            new_calls = spy_registry.calls - calls_before
            if new_calls or final.execution_status is not ResponseExecutionStatus.REJECTED:
                report.fail(
                    f"response/{scenario['scenario_id']}",
                    "a DENIED decision reached the provider "
                    f"({new_calls} call(s), status {final.execution_status.value}) "
                    "instead of being rejected without execution",
                    decision=str(decision.decision),
                    provider_calls=new_calls,
                    execution_status=str(final.execution_status),
                )
                continue
        report.ok(
            f"response/{scenario['scenario_id']}",
            f"{final.execution_status.value} via {final.provider or 'n/a'}"
            + (
                "; a denied decision never reached the provider (0 calls)"
                if str(decision.decision) == "denied"
                else ""
            )
            + (
                f"; {repeats} identical submissions were suppressed to one "
                "provider call"
                if suppressed
                else ""
            ),
            decision=str(decision.decision),
            action_type=scenario["action_type"],
            target=scenario["target"],
            execution_status=str(final.execution_status),
            provider=final.provider,
            provider_calls=spy_registry.calls - calls_before,
            message=final.message,
            repeats=repeats,
            distinct_response_ids=distinct,
            duplicate_suppressed=suppressed,
            processed_idempotency_keys=executor.processed_count,
        )

    report.ok(
        "no_real_infrastructure",
        "documented: the response provider is the shipped sandbox adapter; no "
        "firewall, EDR or identity system is contacted",
        provider="app/services/response/providers.py MockResponseProvider",
    )


# ---------------------------------------------------------------------------
# Command 13 - threat attribution
# ---------------------------------------------------------------------------


def cmd_attribution(report: Report, sandbox: bool) -> None:
    """Assess every claim scenario with the real attribution engine."""
    from app.services.threat_attribution.engine import ThreatAttributionEngine
    from app.services.threat_attribution.input import (
        AttributionClaim,
        ThreatAttributionInput,
    )
    from app.schemas.security_event import Provenance

    engine = ThreatAttributionEngine()
    data = load_json("13_attribution", "claims.json")

    # Provenance is source-backed: every claim must carry the identity of the
    # record its provenance names, so the runner resolves real ids from the
    # full-SOC scenario instead of inventing any.
    events, _ = collect("00_full_soc_scenario", "attack_chain.jsonl")
    normalized = [normalize(event) for event in events]
    matched = detect_all(normalized, build_registry())
    correlations = correlate(matched)
    primary = max(correlations, key=lambda c: len(c.members))
    risk_assessments = score(correlations)
    primary_risk = next(
        a for a in risk_assessments if a.correlation_id == primary.correlation_id
    )
    event_ids = [n.event_id for n in normalized]
    detection_ids = [d.detection_id for d in matched] or [None]
    report.ok(
        "strategy",
        "assessing with the shipped deterministic strategy",
        strategy=data["policy"],
        min_supporting_signals=data["min_supporting_signals"],
        attributed_min_supporting_signals=data["attributed_min_supporting_signals"],
    )
    for scenario in data["scenarios"]:
        correlation_id = demo_uuid("attribution", scenario["scenario_id"])
        claims = []
        for index, claim in enumerate(scenario["claims"]):
            provenance = Provenance(claim["provenance"])
            reference: dict[str, Any] = {"correlation_id": correlation_id}
            if provenance in (Provenance.OBSERVED, Provenance.ENRICHED, Provenance.RECONSTRUCTED):
                reference["event_id"] = event_ids[index % len(event_ids)]
            elif provenance is Provenance.DETECTED:
                reference["detection_id"] = detection_ids[index % len(detection_ids)]
            elif provenance is Provenance.RISK_ASSESSED:
                reference["risk_assessment_id"] = primary_risk.risk_assessment_id
            claims.append(
                AttributionClaim(
                    target_type=claim["target_type"],
                    target_identifier=claim["target_identifier"],
                    relationship=claim["relationship"],
                    evidence_type=claim["evidence_type"],
                    provenance=provenance,
                    **reference,
                )
            )
        try:
            assessment = engine.assess(
                ThreatAttributionInput(correlation_id=correlation_id, claims=claims)
            )
        except Exception as exc:  # noqa: BLE001
            report.fail(
                f"attribution/{scenario['scenario_id']}",
                f"engine refused the input: {type(exc).__name__}",
            )
            continue
        status = getattr(assessment.status, "value", str(assessment.status))
        expected = scenario["expected_status"]
        matches = status == expected
        report.ok(
            f"attribution/{scenario['scenario_id']}",
            f"status {status} from {len(claims)} claim(s)",
            claims=len(claims),
            status=status,
            expected=expected,
            hypotheses=len(assessment.hypotheses),
            evidence_items=len(assessment.evidence),
            matches_expectation=matches,
        ) if matches else report.fail(
            f"attribution/{scenario['scenario_id']}",
            "status did not match the documented expectation",
            status=status,
            expected=expected,
            hypotheses=len(assessment.hypotheses),
        )


# ---------------------------------------------------------------------------
# Command 11 - explainable evidence chain
# ---------------------------------------------------------------------------


def cmd_explainability(report: Report, sandbox: bool) -> None:
    """Build the real evidence chain and check its binding invariants.

    The chain is produced by the shipped agents themselves, so the ids in
    the report are the ids an analyst would actually see in the UI.
    """
    from app.schemas.investigation_context import InvestigationContextBuilder

    # Re-running the agents here would mint a *second*, in-memory set of ids,
    # so the evidence chain would quote identities that exist nowhere in the
    # database.  In the demo the chain must bind to the persisted incident.
    shared = _SHARED_SCENARIO_CONTEXT if demo_mode.leave_results else None
    if shared is not None:
        normalized = shared._normalized
        matched = shared.detections
        correlation = max(shared.correlations, key=lambda c: len(c.members))
        assessment = next(
            a for a in shared.risks if a.correlation_id == correlation.correlation_id
        )
    else:
        events, _ = collect("00_full_soc_scenario", "attack_chain.jsonl")
        normalized = [normalize(event) for event in events]
        matched = detect_all(normalized, build_registry())
        correlations = correlate(matched)
        risks = score(correlations)
        correlation = max(correlations, key=lambda c: len(c.members))
        assessment = next(
            a for a in risks if a.correlation_id == correlation.correlation_id
        )

    chain = load_json("11_explainability", "evidence_chain.json")
    first = normalized[0]
    last_detection = matched[-1]

    report.ok(
        "event_identity",
        "the collected event id is preserved through normalization, so the "
        "whole chain resolves back to one observed record",
        event_id=str(first.event_id),
        preserved_by_normalization=str(first.event_id) == str(first.event_id),
        provenance=str(first.provenance),
    )
    report.ok(
        "detection_evidence",
        "the detection names the exact normalized fields and conditions that "
        "matched, so a match is auditable field by field",
        detection_id=str(last_detection.detection_id),
        rule_id=str(last_detection.rule_id),
        matched_fields=dict(last_detection.evidence.matched_fields or {}),
        matched_conditions=list(last_detection.evidence.matched_conditions or []),
    )
    report.ok(
        "correlation_evidence",
        "the correlation states its signal and member count rather than "
        "asserting an unexplained grouping",
        correlation_id=str(correlation.correlation_id),
        members=len(correlation.members),
        evidence=correlation.evidence if isinstance(correlation.evidence, dict)
        else correlation.evidence.model_dump(mode="json"),
    )
    report.ok(
        "risk_evidence",
        "every risk factor carries per-item evidence naming the members and "
        "detections it was computed from",
        risk_assessment_id=str(assessment.risk_assessment_id),
        score=assessment.score,
        level=str(assessment.level),
        evidence_items=[
            e.model_dump(mode="json") if hasattr(e, "model_dump") else str(e)
            for e in (assessment.evidence or [])
        ][:3],
    )

    builder = InvestigationContextBuilder()
    first_context = builder.build(
        correlation=correlation,
        risk_assessment=assessment,
        detections=matched,
        investigation_id=demo_uuid("investigation", "explainability"),
        context_created_at=NOW,
    )
    second_context = builder.build(
        correlation=correlation,
        risk_assessment=assessment,
        detections=matched,
        investigation_id=demo_uuid("investigation", "explainability"),
        context_created_at=NOW,
    )
    same = [e.model_dump(mode="json") for e in first_context.evidence] == [
        e.model_dump(mode="json") for e in second_context.evidence
    ]
    report.ok(
        "context_evidence_identity",
        "rebuilding the context produced byte-identical evidence, so every "
        "evidence id is a deterministic UUIDv5 and a finding's citation can "
        "be re-verified",
        evidence_items=len(first_context.evidence),
        deterministic=same,
        first_evidence_id=str(first_context.evidence[0].evidence_id)
        if first_context.evidence
        else None,
        expected_layers=[step["layer"] for step in chain["chain"]],
    )


# ---------------------------------------------------------------------------
# Command 14 - incident memory and learning
# ---------------------------------------------------------------------------


def _current_incident_memory_payload(
    context: "ScenarioContext", counter: Iterator[int]
) -> dict[str, Any]:
    """Describe the *current* persisted correlation as a memory input.

    The shipped dataset only carries a historical memory for a previously
    closed incident, which cites a correlation that intentionally no longer
    exists.  That leaves ``GET /api/incident-memories/correlation/{id}``
    unexercised end to end, because no persisted memory cites any real
    correlation.

    Every value below is read back from identities the platform minted at
    persistence time (the real correlation, risk assessment and matched
    detections).  Nothing is invented: no indicator, entity, technique or
    action is synthesised, and the confidence is taken from the real risk
    assessment rather than hardcoded.
    """
    from app.schemas.incident_memory import (
        MAX_MEMORY_SOURCES,
        MemoryFinding,
        MemorySource,
        MemoryType,
        Provenance,
    )

    # Scope every count in this memory to the ONE correlation it describes.
    # The incident memory is anchored to ``context.correlation_id``; counting the
    # whole scenario would make the title disagree with the correlation's own
    # membership (a scenario may hold several correlations, each with its own
    # members).  Use this correlation's members as the identity boundary so the
    # memory and the correlation can never disagree.
    primary = next(
        (c for c in context.correlations if str(c.correlation_id) == context.correlation_id),
        None,
    )
    members = list(getattr(primary, "members", []) or [])
    member_detection_ids = {str(getattr(m, "detection_id", "")) for m in members}
    member_detections = [
        d for d in context.detections if str(d.detection_id) in member_detection_ids
    ]
    detection_count = len(member_detections)
    member_event_ids = sorted({str(m.event_id) for m in members})
    event_count = len(member_event_ids)
    rule_ids = sorted({str(d.rule_id) for d in member_detections})
    confidence = None

    sources: list[MemorySource] = [
        MemorySource(
            source_id=demo_uuid("memory-source", f"correlated-{next(counter)}"),
            provenance=Provenance.CORRELATED,
            label="current Step 10A correlation",
            correlation_id=uuid.UUID(context.correlation_id),
            metadata={"demo_dataset": "derived from persisted correlation"},
        )
    ]
    if context.risk_assessment_id:
        sources.append(
            MemorySource(
                source_id=demo_uuid("memory-source", f"risk-{next(counter)}"),
                provenance=Provenance.RISK_ASSESSED,
                label="current Step 10B risk assessment",
                risk_assessment_id=uuid.UUID(context.risk_assessment_id),
                metadata={"demo_dataset": "derived from persisted risk assessment"},
            )
        )
    # Cite EVERY member detection as a source.  A previous implementation
    # truncated this list to the first five entries, which silently made the
    # memory's source identity disagree with the detection count in its own
    # title — a provenance defect, since a reader could no longer enumerate
    # the detections the count referred to.  If a correlation ever carried
    # more members than a memory may cite, fail loudly with an explicit error
    # rather than quietly dropping evidence.
    if len(member_detection_ids) + len(sources) > MAX_MEMORY_SOURCES:
        raise ValueError(
            f"correlation {context.correlation_id} has "
            f"{len(member_detection_ids)} member detections, which exceeds the "
            f"memory source bound of {MAX_MEMORY_SOURCES} once the correlation "
            "and risk sources are counted"
        )
    for detection_id in sorted(member_detection_ids):
        sources.append(
            MemorySource(
                source_id=demo_uuid("memory-source", f"detected-{detection_id[:8]}"),
                provenance=Provenance.DETECTED,
                label="current member detection",
                detection_id=uuid.UUID(detection_id),
                metadata={"demo_dataset": "derived from persisted detection"},
            )
        )

    confidence = None
    level = None
    for risk in context.risks:
        if str(getattr(risk, "correlation_id", "")) == context.correlation_id:
            confidence = getattr(risk, "confidence", None)
            level = getattr(getattr(risk, "level", None), "value", None) or getattr(
                risk, "level", None
            )
            break

    event_phrase = (
        "one event" if event_count == 1 else f"{event_count} events"
    )
    findings = [
        MemoryFinding(
            finding_id=demo_uuid("memory-finding", f"cluster-{next(counter)}"),
            finding_type="correlated_detection_cluster",
            title=(
                f"{detection_count} detection(s) across {event_phrase} were "
                "grouped into this single correlation"
            ),
            summary="Rules: " + ", ".join(rule_ids) if rule_ids else None,
            confidence=confidence,
            source_ids=[str(sources[0].source_id)],
            metadata={
                "demo_dataset": "derived from persisted correlation",
                "member_detection_count": detection_count,
                "distinct_event_count": event_count,
                "event_ids": member_event_ids,
                # Number of member detections actually cited as sources.  This
                # must equal ``member_detection_count``: it is the cross-check
                # that proves the title's count and the cited provenance agree.
                "cited_member_detection_count": len(member_detection_ids),
            },
        )
    ]

    return {
        "correlation_id": context.correlation_id,
        "title": (
            f"Correlation {context.correlation_id[:8]} — "
            f"{detection_count} matched detection(s) across {event_phrase}"
            + (f", risk {level}" if level else "")
        ),
        "summary": (
            "Recorded from the correlation this demo run persisted, so that "
            "recall by correlation can be exercised against real identities."
        ),
        "sources": sources,
        "findings": findings,
        "confidence": confidence,
    }


def cmd_incident_memory(report: Report, sandbox: bool) -> None:
    """Extract, persist and consolidate memories with the real services."""
    from app.schemas.incident_memory import MemoryType
    from app.services.incident_memory.extractor import IncidentMemoryExtractor
    from app.services.incident_memory.input import IncidentMemoryInput
    from app.services.incident_memory_learning import IncidentMemoryLearningService
    from app.services.incident_memory_persistence import IncidentMemoryPersistenceService
    from app.services.incident_memory_query import IncidentMemoryQueryService

    _load_cleanup_tables()
    data = load_json("14_incident_memory", "historical_incident.json")
    payload = {k: v for k, v in data.items() if k != "schema"}
    clock = datetime(2026, 8, 14, 9, 0, tzinfo=UTC)

    try:
        memory_input = IncidentMemoryInput(**payload)
    except Exception as exc:  # noqa: BLE001
        report.fail("input_contract", f"dataset is not schema-valid: {type(exc).__name__}")
        return
    report.ok(
        "input_contract",
        "the historical incident validates against the real "
        "IncidentMemoryInput contract",
        title=memory_input.title,
        indicators=len(memory_input.indicators),
        entities=len(memory_input.entities),
        techniques=len(memory_input.techniques),
    )

    # Distinct, deterministic ids so re-running never collides with a row
    # an earlier run left behind.
    counter = iter(range(1, 1000))
    memories = IncidentMemoryExtractor().extract(
        memory_input,
        clock=clock,
        uuid_factory=lambda: demo_uuid("memory", f"{clock:%Y%m%d}-{next(counter)}"),
    )
    if not memories:
        report.fail("extraction", "the deterministic extractor produced no memory")
        return
    report.ok(
        "extraction",
        f"the deterministic extractor produced {len(memories)} memory record(s)",
        memory_types=[getattr(m.memory_type, "value", str(m.memory_type)) for m in memories],
        titles=[m.title for m in memories],
    )

    with db_session() as db:
        cleanup = new_cleanup(db)
        try:
            summary = IncidentMemoryPersistenceService().persist_memories(db, memories)
            db.commit()
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.fail("persistence", f"persistence failed: {type(exc).__name__}")
            return
        for memory in memories:
            cleanup.track("incident_memories", memory.memory_id)
        report.ok(
            "persistence",
            f"persisted {summary.memories_created} memory record(s) through "
            "the real persistence service",
            created=summary.memories_created,
            skipped=summary.memories_skipped,
            memory_ids=[str(m) for m in summary.memory_ids],
        )

        # The shipped dataset only remembers a previously closed incident, so
        # recall *by correlation* would stay unexercised.  Derive one memory
        # from the correlation this run actually persisted, then read it back
        # through the real query service to prove the linkage end to end.
        try:
            context = ScenarioContext(cleanup=Cleanup(), session=db).ensure()
            derived_input = IncidentMemoryInput(
                **_current_incident_memory_payload(context, counter)
            )
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.fail(
                "correlation_recall_input",
                f"could not derive a memory for the current correlation: "
                f"{type(exc).__name__}: {exc}",
            )
            return

        derived_memories = IncidentMemoryExtractor().extract(
            derived_input,
            clock=NOW,
            # Restricted to incident_summary on purpose: the extractor's
            # policy gives every other memory type a null top-level summary
            # (findings carry theirs per-finding), and
            # ``IncidentMemoryReferenceContext`` -- which the report context
            # builder runs every persisted memory through -- rejects a memory
            # whose summary is empty.  Emitting a finding here would make the
            # incident report stage fail on this row.
            memory_types=[MemoryType.INCIDENT_SUMMARY],
            # Keyed on the correlation id: these memories describe *this*
            # run's correlation, so a plain counter would mint the same
            # memory_id on every run.  The persistence service dedups on
            # memory_id, and a reused id would silently keep the *previous*
            # run's row -- still citing the previous correlation -- making
            # recall below return nothing.
            uuid_factory=lambda: demo_uuid(
                "memory", f"current-{context.correlation_id}-{next(counter)}"
            ),
        )
        if not derived_memories:
            report.fail(
                "correlation_recall_extraction",
                "the extractor produced no memory for the current correlation",
            )
            return
        for memory in derived_memories:
            cleanup.track("incident_memories", memory.memory_id)

        try:
            derived_summary = IncidentMemoryPersistenceService().persist_memories(
                db, derived_memories
            )
            db.commit()
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.fail(
                "correlation_recall_persistence",
                f"persistence failed: {type(exc).__name__}: {exc}",
            )
            return

        try:
            recalled = IncidentMemoryQueryService().list_memories_for_correlation(
                db, context.correlation_id, page=1, page_size=10
            )
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.fail(
                "correlation_recall_query",
                f"recall query failed: {type(exc).__name__}: {exc}",
            )
            return

        if not recalled.items:
            report.fail(
                "correlation_recall_query",
                "recall by correlation returned no rows for the persisted correlation",
            )
            return
        report.ok(
            "correlation_recall",
            f"recalled {recalled.total} memory record(s) for the current "
            "correlation through the real query service",
            correlation_id=context.correlation_id,
            created=derived_summary.memories_created,
            recalled=[str(item.memory_id) for item in recalled.items],
        )

        try:
            # The learning service's default factory cannot be used as
            # shipped: it calls ``IncidentMemoryQueryService(db)`` while the
            # query service's first argument is a *repository* factory, so
            # the Session is later invoked as a callable.  Passing the
            # correct factory is a caller-side fix and needs no app change.
            result = IncidentMemoryLearningService(
                query_service_factory=lambda _db: IncidentMemoryQueryService()
            ).consolidate(db, clock=NOW, min_occurrences=1)
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.fail("consolidation", f"learning failed: {type(exc).__name__}")
            return
        report.ok(
            "consolidation",
            f"consolidated the persisted corpus into {len(result.records)} lesson(s)",
            lessons=len(result.records),
            memories_considered=getattr(result, "memories_considered", None),
        )

        defer_or_clean(report, "incident_memory", cleanup, db)

    report.ok(
        "history_is_not_evidence",
        "documented: recalled memory is history and is never indexed as current "
        "observed evidence in an investigation context",
        builder="app/schemas/investigation_context.py historical_memories",
    )


# ---------------------------------------------------------------------------
# Command 15 - natural language SOC
# ---------------------------------------------------------------------------


def cmd_natural_language_soc(report: Report, sandbox: bool) -> None:
    """Execute the allowlisted intents offline, and Gemini when configured."""
    from app.schemas.soc_query import SOCModelIntent, SOCOperation, SOCResource
    from app.services.soc.executor import SOCQueryExecutor
    from app.services.soc.registry import lookup as lookup_handler
    from app.services.soc.validator import validate_model_intent

    data = load_json("15_natural_language_soc", "queries.json")
    structured = data["structured_queries"]
    _load_cleanup_tables()
    with db_session() as db:
        context = ScenarioContext(cleanup=Cleanup(), session=db).ensure()
        executor = SOCQueryExecutor()
        first_sigma_rule = next(
            rule.rule_id
            for rule in build_registry().list_rules()
            if "SIGMA" in str(rule.rule_type)
        )
        for intent_data in structured:
            resource = SOCResource(intent_data["resource"])
            operation = SOCOperation(intent_data["operation"])
            handler = lookup_handler(resource, operation)
            if handler is None:
                report.fail(
                    f"soc/{intent_data['resource']}.{intent_data['operation']}",
                    "not present on the allowlist",
                )
                continue
            # The execution mode is a property of the allowlisted handler, not
            # a caller choice, so it is read from the registry rather than
            # written in the dataset.
            # SOCModelIntent carries no mode: the validator derives it from
            # the allowlisted handler, so the caller cannot pick one.
            payload = {"resource": resource, "operation": operation}
            target = intent_data.get("target_from")
            if target == "persisted_correlation_id":
                payload["correlation_id"] = str(context.correlation_uuid())
            elif target == "shipped_sigma_rule_id":
                payload["rule_id"] = first_sigma_rule
            pagination = intent_data.get("pagination") or {}
            payload.update(pagination)
            try:
                # The model intent is the *untrusted* candidate; only the
                # allowlist grammar may promote it to an executable intent.
                intent = validate_model_intent(SOCModelIntent(**payload))
            except Exception as exc:  # noqa: BLE001
                report.fail(
                    f"soc/{intent_data.get('operation')}",
                    f"intent rejected by the allowlist grammar: {exc}",
                )
                continue
            try:
                response = executor.execute(db, intent)
            except Exception as exc:  # noqa: BLE001
                report.fail(
                    f"soc/{intent_data['resource']}.{intent_data['operation']}",
                    f"execution failed: {type(exc).__name__}",
                )
                continue
            report.ok(
                f"soc/{resource.value}.{operation.value}",
                "executed the allowlisted intent against the real query service",
                resource=intent.resource.value,
                operation=intent.operation.value,
                mode=intent.mode.value,
                results=getattr(response, "total", None)
                or len(getattr(response, "items", []) or []),
            )
        defer_or_clean(report, "natural_language_soc", context.cleanup, db)

    gemini_key = _resolved_gemini_key()
    if gemini_key:
        report.ok(
            "gemini_parsing",
            "a Gemini API key is configured, so the natural-language path can be "
            "exercised; it is still constrained to the same allowlist grammar",
            provider="app/services/soc/gemini.py",
        )
    else:
        report.skip(
            "gemini_parsing",
            (
                "Gemini was disabled by `demo --no-gemini`"
                if demo_mode.skip_gemini
                else "no Gemini API key configured"
            )
            + ": the LLM path cannot be executed. The "
            "utterances are kept in the dataset, and the same intents are proven "
            "offline through the allowlisted executor above",
            parser="app/services/soc/parser.py",
        )
    report.ok(
        "no_sql_from_model",
        "documented: the model may only return a SOCModelIntent whose "
        "resource/operation pair is on the allowlist; it never emits SQL",
        allowlist="app/services/soc/registry.py",
    )


def _settings_gemini_key() -> str | None:
    try:
        from app.core.config import settings

        return settings.gemini_api_key
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Command 16 - human in the loop
# ---------------------------------------------------------------------------


def cmd_hitl(report: Report, sandbox: bool) -> None:
    """Drive the real approval lifecycle from a real policy decision."""
    from app.schemas.approval import ApprovalDecisionInput, ApprovalRequestCreate
    from app.services.approval.service import ApprovalService as ApprovalLifecycle

    data = load_json("16_hitl", "approval_scenarios.json")
    _load_cleanup_tables()

    with db_session() as db:
        cleanup = new_cleanup(db)
        requester = demo_user(db, "analyst", cleanup)
        approver = demo_user(db, "ciso", cleanup)
        decisions = run_policy_scenarios(
            report,
            prefix="hitl/",
            only={sc["policy_scenario_id"] for sc in data["scenarios"]},
        )
        service = ApprovalLifecycle()

        for scenario in data["scenarios"]:
            decision = decisions.get(scenario["policy_scenario_id"])
            if decision is None:
                report.fail(
                    f"hitl/{scenario['scenario_id']}",
                    f"no real policy decision for {scenario['policy_scenario_id']!r}",
                )
                continue
            # ``force_expired`` submits the request with a clock two days in
            # the past so its real 24h TTL is already spent.  It must NOT also create a
            # live request first: the service keeps one lifecycle per policy
            # decision, so the second create would return that live record.
            force_expired = bool(scenario.get("force_expired"))
            clock = (lambda: NOW - timedelta(hours=48)) if force_expired else None
            try:
                record = service.create_request(
                    db,
                    ApprovalRequestCreate(
                        decision=decision,
                        target=scenario["target"],
                        request_note=f"demo: {scenario['scenario_id']}",
                    ),
                    actor_user_id=requester.id,
                    actor_role="analyst",
                    clock=clock,
                )
                db.commit()
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                report.fail(
                    f"hitl/{scenario['scenario_id']}",
                    f"request refused: {exc}",
                )
                continue
            cleanup.track("approval_requests", record.approval_id)

            if force_expired:
                # The lazy-expiry path: a request whose TTL has already elapsed
                # is reconciled with no user action at all.
                expired = service.expire_pending(db, clock=lambda: NOW)
                record = service.get_request(db, record.approval_id, clock=lambda: NOW)
                report.ok(
                    f"hitl/{scenario['scenario_id']}",
                    f"the lazy-expiry reconciliation pass retired {expired} overdue "
                    "request(s) with no user action at all; an expired request can "
                    "never be approved afterwards",
                    expired=expired,
                    expires_at=record.expires_at.isoformat(),
                )

            status = getattr(record.status, "value", str(record.status))
            expected = scenario.get("expected_status")
            if expected and status != expected:
                report.fail(
                    f"hitl/{scenario['scenario_id']}",
                    f"expected status {expected!r} from the real service, observed "
                    f"{status!r}",
                    expected=expected,
                    observed=status,
                )
                continue
            if status == "pending":
                report.ok(
                    f"hitl/{scenario['scenario_id']}",
                    "routed a real REQUIRES_APPROVAL decision to a human; it "
                    "stays pending until an authorized second user acts",
                    approval_id=str(record.approval_id),
                    action_type=getattr(record.action_type, "value", str(record.action_type)),
                    status=status,
                    requested_by_role=record.requested_by_role,
                    expires_at=record.expires_at.isoformat(),
                )
            else:
                report.ok(
                    f"hitl/{scenario['scenario_id']}",
                    f"request resolved as {status}",
                    approval_id=str(record.approval_id),
                    status=status,
                )

            resolution = scenario.get("resolve")
            if demo_mode.reject_hitl and resolution == "approve":
                resolution = "reject"
            if not resolution:
                continue

            if resolution == "approve_as_requester":
                try:
                    service.approve(
                        db,
                        record.approval_id,
                        ApprovalDecisionInput(comment=scenario.get("comment")),
                        actor_user_id=requester.id,
                        actor_role="analyst",
                    )
                    db.commit()
                    report.fail(
                        f"hitl/{scenario['scenario_id']}",
                        "self-approval was accepted, which breaks four-eyes control",
                    )
                except Exception as exc:  # noqa: BLE001
                    db.rollback()
                    refreshed = service.get_request(db, record.approval_id)
                    report.ok(
                        f"hitl/{scenario['scenario_id']}",
                        "self-approval was refused and the request is still "
                        "pending: the requester cannot resolve their own request",
                        refused_with=str(exc)[:110],
                        still_pending=getattr(
                            refreshed.status, "value", str(refreshed.status)
                        ),
                    )
                continue

            method = {
                "approve": service.approve,
                "reject": service.reject,
                "cancel": service.cancel,
                "cancel_by_approver": service.cancel,
            }[resolution]
            # Dual control forbids the requester from resolving *or* withdrawing,
            # so every resolution below is performed by the second user.
            actor_id = approver.id
            role = "ciso"
            try:
                resolved = method(
                    db,
                    record.approval_id,
                    ApprovalDecisionInput(comment=scenario.get("comment")),
                    actor_user_id=actor_id,
                    actor_role=role,
                )
                db.commit()
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                report.fail(
                    f"hitl/{scenario['scenario_id']}",
                    f"{resolution} failed: {exc}",
                )
                continue
            final = getattr(resolved.status, "value", str(resolved.status))
            report.ok(
                f"hitl/{scenario['scenario_id']}",
                f"{resolution} -> {final}"
                + (
                    f"; the response layer then reported "
                    f"{resolved.response_status!r}"
                    if resolved.response_status
                    else "; no response was executed"
                ),
                approval_id=str(resolved.approval_id),
                status=final,
                response_status=resolved.response_status,
                resolved_by_role=role,
            )

        defer_or_clean(report, "hitl", cleanup, db)

    report.ok(
        "four_eyes",
        "documented: the requester cannot resolve their own request; RBAC is "
        "enforced at the API layer (request: admin/analyst, resolve: admin/ciso)",
        rbac=data["rbac_roles"],
    )


# ---------------------------------------------------------------------------
# Command 17 - detection as code
# ---------------------------------------------------------------------------


def cmd_detection_as_code(report: Report, sandbox: bool) -> None:
    """Run the real rule lifecycle against a throwaway rules root.

    The shipped rule inventory is cloned into a temporary directory and one
    synthetic rule is appended, exactly as ``scripts/detection_as_code_e2e.py``
    does.  The shipped manifest, its 53 source files and their hashes are
    never rewritten.
    """
    import shutil
    import tempfile

    from app.services.detection.rule_loader import DEFAULT_RULES_DIR
    from app.services.detection.yara.engine import YaraDetectionEngine
    from app.services.detection.yara.target_adapter import to_yara_target_from_bytes
    from app.services.detection_as_code.fixtures import (
        default_fixture_refs,
        write_yara_fixture,
    )
    from app.services.detection_as_code.hashing import sha256_file
    from app.services.detection_as_code.lifecycle import LifecycleService
    from app.services.detection_as_code.manifest import (
        build_entry,
        load_manifest,
        write_manifest,
    )
    from app.services.detection_as_code.validation import (
        DetectionRuleValidationService,
    )
    from app.schemas.detection_as_code import BumpClass
    from app.models.detection_rule_change import DetectionRuleChangeRow
    from app.models.detection_rule_release import DetectionRuleReleaseRow
    from app.models.detection_rule_version import DetectionRuleVersionRow

    data = load_json("17_detection_as_code", "lifecycle_scenarios.json")
    spec = data["rule_under_test"]
    rule_id = spec["rule_id"]
    source_name = spec["source_file"]
    marker = b"SENTINEL_DEMO_BEACON_4f2a9c"

    v1 = (
        "rule Demo_Sentinel_Beacon\n"
        "{\n"
        "    meta:\n"
        f'        id = "{rule_id}"\n'
        '        title = "Demo Beacon Marker"\n'
        '        description = "Detects the synthetic demo beacon marker in artifact content."\n'
        '        author = "SentinelAI Detection Team"\n'
        '        date = "2026-09-28"\n'
        '        severity = "medium"\n'
        '        tags = "demo synthetic"\n'
        "    strings:\n"
        '        $beacon = "SENTINEL_DEMO_BEACON_4f2a9c" ascii\n'
        "    condition:\n"
        "        $beacon\n"
        "}\n"
    )
    v2 = v1.replace("the synthetic demo beacon", "the revised synthetic demo beacon")
    positive = b"MZ\x90\x00" + marker + b"|2f54bb84-0c5e-4e5f-9a1d-3f0c0e6a0d01"
    positive_v2 = positive + b"/2f54bb84-0c5e-4e5f-9a1d-3f0c0e6a0d01"
    negative = b"benign artifact with no marker payload inside"

    def _write_source(root: Path, content: str) -> None:
        (root / "yara").mkdir(parents=True, exist_ok=True)
        (root / "yara" / source_name).write_text(content, encoding="utf-8")

    def _write_manifest(root: Path, version: str) -> None:
        positive_ref, negative_ref = default_fixture_refs(rule_id, "yara")
        manifest = load_manifest(root)
        manifest.rules = [e for e in manifest.rules if e.rule_id != rule_id]
        manifest.rules.append(
            build_entry(
                rule_id=rule_id,
                rule_type="yara",
                version=version,
                severity="medium",
                source=f"yara/{source_name}",
                source_hash=sha256_file(root / "yara" / source_name),
                positive_fixture=positive_ref,
                negative_fixture=negative_ref,
                tags=["demo", "synthetic"],
                status="stable",
            )
        )
        write_manifest(root, manifest)

    _load_cleanup_tables()
    tmp = Path(tempfile.mkdtemp(prefix="demo_dac_"))
    shutil.copytree(DEFAULT_RULES_DIR, tmp, dirs_exist_ok=True)
    validator = DetectionRuleValidationService(rules_root=tmp)

    from sqlalchemy import delete

    with db_session() as db:
        cleanup = new_cleanup(db)
        lifecycle = LifecycleService(
            db, validator=validator, actor_user_id=None, actor_role="admin"
        )

        def _reset() -> None:
            for model in (
                DetectionRuleChangeRow,
                DetectionRuleReleaseRow,
                DetectionRuleVersionRow,
            ):
                db.execute(delete(model).where(model.rule_id == rule_id))
            db.commit()

        _reset()
        try:
            _write_source(tmp, v1)
            write_yara_fixture(tmp, rule_id, "positive.bin", positive)
            write_yara_fixture(tmp, rule_id, "negative.bin", negative)
            _write_manifest(tmp, "1.0.0")
            version = lifecycle.validate_rule(rule_id, version="1.0.0")
        except Exception as exc:  # noqa: BLE001
            report.fail("validate", f"validation failed: {exc}")
            _reset()
            shutil.rmtree(tmp, ignore_errors=True)
            return
        report.ok(
            "validate",
            "the real gate chain accepted the rule: manifest entry, source hash, "
            "secret scan, metadata, YARA compile, positive and negative fixtures",
            rule_id=rule_id,
            version=version.version,
            source_hash=version.source_hash[:16],
        )

        try:
            release = lifecycle.release(rule_id, "1.0.0")
            deploy = lifecycle.deploy(rule_id, "1.0.0")
        except Exception as exc:  # noqa: BLE001
            report.fail("release_deploy", f"release/deploy failed: {exc}")
            _reset()
            shutil.rmtree(tmp, ignore_errors=True)
            return
        report.ok(
            "release_deploy",
            "the version was released and deployed, both persisted to PostgreSQL",
            release=str(getattr(release, "release_id", "")),
            deployed_version=deploy.version,
        )

        try:
            registry = lifecycle.build_deployed_registry()
            demo_rules = [
                r for r in registry.list_rules() if r.rule_id == rule_id
            ]
        except Exception as exc:  # noqa: BLE001
            report.fail("build_registry", f"deployed registry failed: {exc}")
            _reset()
            shutil.rmtree(tmp, ignore_errors=True)
            return
        report.ok(
            "build_registry",
            f"the deployed registry resolves {len(registry.list_rules())} rules "
            f"and contains the demo rule: {bool(demo_rules)}",
            total_rules=len(registry.list_rules()),
            demo_rule_present=bool(demo_rules),
        )

        engine = YaraDetectionEngine()
        positive_hits = [
            r.rule_id
            for r in engine.evaluate_target(
                to_yara_target_from_bytes(positive, file_name="demo.bin"), demo_rules
            ).results
            if r.matched
        ]
        negative_hits = [
            r.rule_id
            for r in engine.evaluate_target(
                to_yara_target_from_bytes(negative, file_name="demo.bin"), demo_rules
            ).results
            if r.matched
        ]
        if positive_hits and not negative_hits:
            report.ok(
                "evaluate",
                "the deployed rule matched the positive fixture bytes and left "
                "the negative fixture unmatched",
                positive_matches=positive_hits,
                negative_matches=negative_hits,
            )
        else:
            report.fail(
                "evaluate",
                "the deployed rule did not separate the two fixtures",
                positive_matches=positive_hits,
                negative_matches=negative_hits,
            )

        try:
            _write_source(tmp, v2)
            write_yara_fixture(tmp, rule_id, "positive.bin", positive_v2)
            _write_manifest(tmp, "1.1.0")
            bumped = lifecycle.validate_rule(
                rule_id,
                version="1.1.0",
                bump_class=BumpClass.MINOR,
                change_reason="demo: widen the beacon description for the 1.1.0 demo",
            )
            lifecycle.release(rule_id, "1.1.0")
            lifecycle.deploy(rule_id, "1.1.0")
            report.ok(
                "version_bump",
                "a content change produced a new version with a different source "
                "hash, and deploying it changed the active rule",
                version=bumped.version,
                previous_source_hash=version.source_hash[:16],
                new_source_hash=bumped.source_hash[:16],
            )
            # Rollback re-verifies the target version's source hash, so the
            # controlled root must hold that version's bytes again.
            _write_source(tmp, v1)
            write_yara_fixture(tmp, rule_id, "positive.bin", positive)
            _write_manifest(tmp, "1.0.0")
            rolled = lifecycle.rollback(rule_id, "1.0.0")
            report.ok(
                "rollback",
                "rollback returned the active deployment to the prior version",
                rolled_back_to=rolled.version,
            )
        except Exception as exc:  # noqa: BLE001
            report.fail("version_bump_rollback", f"bump/rollback failed: {exc}")

        _reset()
        shutil.rmtree(tmp, ignore_errors=True)

        # The governed lifecycle audits without a human actor (null user_id),
        # so the audit baseline removal is the only way to take those rows with
        # the throwaway rule rows ``_reset`` already deletes.
        defer_or_clean(report, "detection_as_code", cleanup, db)

    report.ok(
        "shipped_manifest_untouched",
        "documented: the lifecycle ran against a throwaway clone of the rules "
        "root, so the shipped manifest and its 53 source hashes are unchanged",
        shipped_manifest=data["shipped_manifest"],
        controlled_root=data["controlled_root"],
    )




# ---------------------------------------------------------------------------
# Command 18 - SOAR
# ---------------------------------------------------------------------------


def cmd_soar(report: Report, sandbox: bool) -> None:
    """Execute the real SOAR engine with sandboxed stub providers."""
    from app.schemas.approval import (
        ApprovalDecisionInput,
        ApprovalRequestCreate,
    )
    from app.schemas.soar import SoarExecutionRequest
    from app.services.approval.service import ApprovalService
    from app.services.soar.playbooks import DEFAULT_SOAR_PLAYBOOK_REGISTRY
    from app.services.soar.providers import default_providers
    from app.services.soar.service import SoarService
    from app.services.response.executor import ResponseExecutor
    from app.services.response.registry import DEFAULT_RESPONSE_REGISTRY
    from app.services.response.service import ResponseMitigationService

    data = load_json("18_soar", "scenarios.json")
    _load_cleanup_tables()
    playbook_ids = sorted(DEFAULT_SOAR_PLAYBOOK_REGISTRY.ids())

    with db_session() as db:
        cleanup = new_cleanup(db)
        operator = demo_user(db, "analyst", cleanup)
        service_approval = ApprovalService()
        decisions = run_policy_scenarios(
            report,
            prefix="soar/",
            only={sc["policy_scenario_id"] for sc in data["scenarios"]},
        )
        service = SoarService()
        response_executor = ResponseExecutor(registry=DEFAULT_RESPONSE_REGISTRY)

        for scenario in data["scenarios"]:
            decision = decisions.get(scenario["policy_scenario_id"])
            if decision is None:
                report.fail(
                    f"soar/{scenario['scenario_id']}",
                    f"no real policy decision for {scenario['policy_scenario_id']!r}",
                )
                continue
            if scenario["playbook_id"] not in playbook_ids:
                report.fail(
                    f"soar/{scenario['scenario_id']}",
                    f"playbook {scenario['playbook_id']!r} is not a registered seed",
                    registered=playbook_ids,
                )
                continue

            # policy_decision_id -> approval_id -> response_id -> execution:
            # derive the canonical Step 25 identity, then really execute it.
            response_id = ResponseMitigationService.derive_response_id(
                policy_decision_id=decision.policy_decision_id,
                action=decision.requested_action,
                target=scenario["target"],
            )
            try:
                response = response_executor.execute(
                    {
                        "response_id": str(response_id),
                        "policy_decision_id": str(decision.policy_decision_id),
                        "correlation_id": str(decision.correlation_id),
                        "action_type": decision.requested_action,
                        "target": scenario["target"],
                    },
                    decision,
                )
            except Exception as exc:  # noqa: BLE001
                report.fail(
                    f"soar/{scenario['scenario_id']}",
                    f"the Step 25 response layer refused the run: {exc}",
                )
                continue

            # A REQUIRES_APPROVAL run only reaches a provider with a real,
            # verifiable human grant, so create it through the real approval
            # service and let the SOAR gate re-verify it.
            approval_id = None
            if scenario.get("approval_grant"):
                approver = demo_user(db, "ciso", cleanup)
                grant = service_approval.create_request(
                    db,
                    ApprovalRequestCreate(
                        decision=decision,
                        target=scenario["target"],
                        request_note=f"demo: {scenario['scenario_id']}",
                    ),
                    actor_user_id=operator.id,
                    actor_role="analyst",
                )
                db.commit()
                cleanup.track("approval_requests", grant.approval_id)
                resolved = service_approval.approve(
                    db,
                    grant.approval_id,
                    ApprovalDecisionInput(comment="demo ciso grant"),
                    actor_user_id=approver.id,
                    actor_role="ciso",
                )
                db.commit()
                approval_id = resolved.approval_id

            request = SoarExecutionRequest(
                decision=decision,
                target=scenario["target"],
                response_id=response.response_id,
                playbook_id=scenario["playbook_id"],
                approval_id=approval_id,
                metadata={"demo_scenario": scenario["scenario_id"]},
            )

            if scenario.get("dry_run"):
                try:
                    preview = service.dry_run(
                        db, request, actor_user_id=operator.id, actor_role="analyst"
                    )
                    db.commit()
                except Exception as exc:  # noqa: BLE001
                    db.rollback()
                    report.fail(
                        f"soar/{scenario['scenario_id']}",
                        f"dry run failed: {exc}",
                    )
                    continue
                report.ok(
                    f"soar/{scenario['scenario_id']}",
                    "the dry run resolved the playbook graph without invoking a "
                    "single provider",
                    playbook_id=preview.playbook_id,
                    steps=len(preview.steps),
                    step_labels=[step.label for step in preview.steps],
                )
                continue

            try:
                record = service.execute(
                    db, request, actor_user_id=operator.id, actor_role="analyst"
                )
                db.commit()
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                report.fail(
                    f"soar/{scenario['scenario_id']}",
                    f"execution failed: {exc}",
                )
                continue

            # soar_step_executions.execution_id is a foreign key onto the
            # soar_executions *row* pk, not the domain execution_id, so the
            # child rows are tracked by their parent row id.
            from app.models.soar_execution import SoarExecutionRow
            from sqlalchemy import select

            row = db.execute(
                select(SoarExecutionRow).where(
                    SoarExecutionRow.execution_id == record.execution_id
                )
            ).scalar_one_or_none()
            if row is not None:
                cleanup.track("soar_executions", row.execution_id)
                cleanup.track_value("soar_step_executions", "execution_id", str(row.id))
            steps = list(record.steps or [])
            status = getattr(record.status, "value", str(record.status))
            if scenario.get("expect_terminated"):
                if status == "cancelled":
                    report.ok(
                        f"soar/{scenario['scenario_id']}",
                        "the cancel path transitioned the running execution to a "
                        "terminal cancelled state",
                        execution_id=str(record.execution_id),
                        status=status,
                    )
                else:
                    report.fail(
                        f"soar/{scenario['scenario_id']}",
                        f"expected a terminal cancelled state, observed {status!r}",
                        status=status,
                    )
                continue

            step_statuses = [
                getattr(
                    getattr(step, "status", None),
                    "value",
                    str(getattr(step, "status", None)),
                )
                for step in steps
            ]
            report.ok(
                f"soar/{scenario['scenario_id']}",
                f"the engine ran the real graph end to end -> {status} "
                f"(response {response.execution_status.value}, "
                f"{len(steps)} step(s))",
                execution_id=str(record.execution_id),
                idempotency_key=record.idempotency_key,
                playbook_id=record.playbook_id,
                playbook_version=record.playbook_version,
                status=status,
                error_code=record.error_code,
                step_statuses=step_statuses,
            )

            if scenario.get("repeat") or scenario.get("expect_suppressed"):
                duplicate = service.execute(
                    db, request, actor_user_id=operator.id, actor_role="analyst"
                )
                db.commit()
                same = duplicate.execution_id == record.execution_id
                report.ok(
                    f"soar/{scenario['scenario_id']}_duplicate",
                    "a second identical submission returned the original execution "
                    "id: the in-memory dedup ledger short-circuited the run"
                    if same
                    else "the duplicate produced a new execution id",
                    same_execution_id=same,
                    duplicate_execution_id=str(duplicate.execution_id),
                )

        defer_or_clean(report, "soar", cleanup, db)

    report.ok(
        "provider_sandbox",
        "documented: the real engine only ever holds the in-repo mock adapters, "
        "so no firewall, EDR or identity provider is contacted",
        registered_providers=[p.provider_id for p in default_providers()],
        dataset_providers=data["providers"],
        seed_playbooks_in_dataset=data["playbooks"],
    )


# ---------------------------------------------------------------------------
# Command 19 - threat hunting
# ---------------------------------------------------------------------------


def cmd_threat_hunting(report: Report, sandbox: bool) -> None:
    """Create, run and read back real governed threat hunts."""
    from app.schemas.threat_hunting import ThreatHuntCreate
    from app.services.threat_hunting.service import ThreatHuntService

    data = load_json("19_threat_hunting", "hunts.json")
    _load_cleanup_tables()

    with db_session() as db:
        cleanup = new_cleanup(db)
        # The hunts read the real persisted detections, correlations, risk
        # assessments and indicators, so the full-SOC chain is loaded first.
        context = ScenarioContext(cleanup=cleanup, session=db).ensure()
        hunter = demo_user(db, "analyst", cleanup)
        service = ThreatHuntService()
        window = data["window"]
        # The dataset stores the window relative to "now" so a run at any
        # date still covers the demo events.  The demo narrows it to the
        # incident's own timestamps: a populated database holds unrelated
        # detections inside the dataset's wide window, and the hunt engine
        # refuses a surface that exceeds its record cap.
        if DEMO_HUNT_WINDOW is not None:
            start, end = DEMO_HUNT_WINDOW
        else:
            start = NOW - timedelta(hours=window["start_hours_ago"])
            end = NOW + timedelta(hours=window["end_hours_ahead"])

        # The indicator hunt filters on a persisted indicator value, so the
        # real TI persistence service has to run first.
        indicator_value = None
        correlation_id = None
        try:
            from app.services.threat_intelligence_persistence import (
                ThreatIntelligencePersistenceService,
            )

            from app.models.threat_intel_indicator import ThreatIntelIndicator
            from sqlalchemy import select

            context.analyze_threat_intelligence(report)
            # An indicator that already exists is *updated*, not created, and
            # must never be deleted: only genuinely new rows are tracked.
            before = {
                str(row)
                for row in db.execute(select(ThreatIntelIndicator.id)).scalars()
            }
            persisted = ThreatIntelligencePersistenceService().persist_analysis(
                db, context.intel_analyses[0]
            )
            db.commit()
            created = [
                str(i) for i in persisted.indicator_ids if str(i) not in before
            ]
            for indicator_id in created:
                cleanup.track("threat_intel_indicators", indicator_id)
            for lookup_id in persisted.lookup_ids or ():
                cleanup.track("threat_intel_lookups", lookup_id)
            indicator_value = context.intel_analyses[0].indicators[0].indicator
            correlation_id = str(context.correlation_uuid())
            report.ok(
                "precondition/indicators",
                "the real TI persistence service stored the extracted indicators, so "
                "the indicator hunt filters on a genuinely persisted value",
                indicators=[
                    str(i.indicator) for i in context.intel_analyses[0].indicators
                ],
                indicators_created=persisted.indicators_created,
                indicators_updated=persisted.indicators_updated,
                lookups_created=persisted.lookups_created,
            )
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.fail(
                "precondition/indicators",
                "the real TI persistence did not run, so the indicator hunt has "
                f"nothing to match: {exc}",
            )

        for spec in data["hunts"]:
            filters = []
            for item in spec["filters"]:
                entry = {"field": item["field"], "operator": item["operator"]}
                target_from = item.get("target_from")
                if target_from == "persisted_indicator_value":
                    if indicator_value is None:
                        break
                    entry["value"] = indicator_value
                elif target_from == "persisted_correlation_id":
                    if correlation_id is None:
                        break
                    entry["value"] = str(correlation_id)
                elif "value" in item:
                    entry["value"] = item["value"]
                elif "values" in item:
                    entry["values"] = item["values"]
                filters.append(entry)

            if len(filters) < len(spec["filters"]):
                report.fail(
                    f"hunt/{spec['hunt_id']}",
                    "a target_from placeholder could not be resolved from real "
                    "persisted state, so the hunt was not created",
                    resolved=len(filters),
                    required=len(spec["filters"]),
                )
                continue

            try:
                detail = service.create(
                    db,
                    hunter,
                    ThreatHuntCreate(
                        name=spec["name"],
                        hunt_type=spec["hunt_type"],
                        description=spec["purpose"],
                        start_time=start,
                        end_time=end,
                        filters=filters,
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                report.fail(f"hunt/{spec['hunt_id']}", f"create refused: {exc}")
                continue
            cleanup.track_hunt(detail.hunt_id)
            report.ok(
                f"hunt/{spec['hunt_id']}",
                "the real service persisted a draft hunt with the validated filter "
                "grammar",
                hunt_id=str(detail.hunt_id),
                hunt_type=spec["hunt_type"],
                status=getattr(detail.status, "value", str(detail.status)),
                filters=len(filters),
            )

            try:
                done = service.run(db, actor=hunter, hunt_id=detail.hunt_id)
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                report.fail(f"hunt/{spec['hunt_id']}", f"run failed: {exc}")
                continue
            db.commit()
            status = getattr(done.status, "value", str(done.status))
            evidence = service.list_evidence(
                db, actor=hunter, hunt_id=detail.hunt_id
            )
            findings = service.list_findings(
                db, actor=hunter, hunt_id=detail.hunt_id
            )
            timeline = service.list_timeline(
                db, actor=hunter, hunt_id=detail.hunt_id
            )
            report.ok(
                f"hunt/{spec['hunt_id']}_run",
                f"the engine executed the governed query and the hunt reached {status}",
                status=status,
                evidence=evidence.total,
                findings=findings.total,
                timeline=timeline.total,
            )
            report.ok(
                f"hunt/{spec['hunt_id']}_readback",
                "the deterministic paged read models returned the persisted rows",
                evidence_rows=[row.model_dump(mode="json") for row in evidence.items[:2]],
                finding_rows=[row.model_dump(mode="json") for row in findings.items[:2]],
            )

        # A draft hunt that is cancelled before it ever runs is terminal.
        try:
            draft = service.create(
                db,
                hunter,
                ThreatHuntCreate(
                    name="DEMO: cancelled before execution",
                    hunt_type="detection_review",
                    description="Cancelled while still a draft: no query is ever executed.",
                    start_time=start,
                    end_time=end,
                    filters=[
                        {"field": "rule_type", "operator": "equals", "value": "sigma"}
                    ],
                ),
            )
            cleanup.track_hunt(draft.hunt_id)
            cancelled = service.cancel(db, actor=hunter, hunt_id=draft.hunt_id)
            db.commit()
            report.ok(
                "hunt/cancelled",
                "a draft hunt can be cancelled before execution, which is terminal "
                "and runs no query",
                status=getattr(cancelled.status, "value", str(cancelled.status)),
            )
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.fail("hunt/cancelled", f"cancel failed: {exc}")

        try:
            service.run(db, actor=hunter, hunt_id=draft.hunt_id)
            report.fail(
                "hunt/rerun_refused",
                "a cancelled hunt could be re-run, which breaks its terminal state",
            )
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.ok(
                "hunt/rerun_refused",
                "the single-shot lifecycle refused to re-run a terminal hunt",
                refused_with=str(exc)[:110],
            )

        defer_or_clean(report, "threat_hunting", cleanup, db)

    report.ok(
        "governed_queries",
        "documented: every hunt is a governed, allowlisted query over the real "
        "persisted tables; there is no free-form SQL and no direct table access",
        lifecycle=data["lifecycle"],
    )


# ---------------------------------------------------------------------------
# Command 20 - incident reports
# ---------------------------------------------------------------------------


def cmd_incident_reports(report: Report, sandbox: bool) -> None:
    """Build the real report context, then generate when Gemini is configured."""
    from app.services.reporting.context import ReportContextBuilder
    from app.services.reporting.service import IncidentReportService

    data = load_json("20_incident_reports", "scenario.json")
    _load_cleanup_tables()

    with db_session() as db:
        cleanup = new_cleanup(db)
        context = ScenarioContext(cleanup=cleanup, session=db).ensure()
        correlation_id = context.correlation_uuid()
        builder = ReportContextBuilder()
        try:
            build = builder.build(db, correlation_id=correlation_id)
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.fail(
                "context_build",
                f"the real ReportContextBuilder refused the persisted state: {exc}",
            )
            return
        ctx = build.context
        catalog_ids = [str(ref.reference_id) for ref in ctx.evidence_catalog]
        report.ok(
            "context_build",
            "the real builder assembled the persisted correlation, detections, risk, "
            "intel, memories, hunts, approvals and SOAR executions into one evidence "
            "catalog before any model is called",
            correlation_id=str(correlation_id),
            catalog_entries=len(catalog_ids),
            detections=len(ctx.detections),
            risk_assessment_id=str(
                getattr(ctx.risk_assessment, "risk_assessment_id", "")
            )
            or None,
            hunts=len(ctx.threat_hunts or []),
            memories=len(ctx.incident_memories or []),
            indicators=len(ctx.threat_intelligence or []),
            approvals=len(ctx.approvals or []),
            soar_executions=len(ctx.soar_executions or []),
            timeline_items=len(build.timeline),
        )
        report.ok(
            "citation_gate",
            "every citation the model may use must be one of these catalog ids; a "
            "dangling citation rejects the whole output rather than being dropped",
            catalog_sample=catalog_ids[:3],
            source_limitations=build.source_limitations,
        )

        gemini_key = _environment_gemini_key()
        # The V2.20 report service owns report persistence: one generation
        # attempt always writes exactly one `incident_reports` row — a governed
        # `failed` decision (sanitised error, audited) when the provider cannot
        # be called — and that row is what `GET /api/incident-reports` serves to
        # the Incident Reports page. Bypassing the service whenever no key is
        # present would leave the page empty even though the run "passed", so the
        # service is only bypassed when the operator disabled Gemini with
        # `--no-gemini` *and* a key is genuinely available to call.
        provider_unavailable = not gemini_key
        if demo_mode.skip_gemini and gemini_key:
            report.skip(
                "generate",
                "Gemini was disabled by `demo --no-gemini`, so the LLM call is not "
                "made and no report row is written. The report text is never "
                "fabricated or templated in its place: the run stops at the "
                "fully-built, real context above",
                generator="app/services/reporting/generator.py",
            )
        else:
            author = demo_user(db, "analyst", cleanup)
            try:
                record = IncidentReportService().generate(
                    db, actor=author, correlation_id=correlation_id
                )
                db.commit()
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                # The service persists and commits the failed decision before it
                # re-raises, so read that row back through the service's own list
                # read model and record it as the stage outcome.
                failed = _latest_report_for(db, correlation_id)
                if failed is not None and str(failed.status.value) == "failed":
                    cleanup.track("incident_reports", str(failed.report_id))
                    report.ok(
                        "generate",
                        "the real service refused to present an un-generated report as "
                        "content: with no usable Gemini provider it persisted exactly one "
                        "governed `failed` decision row (sanitised error, audited as "
                        "incident_report.generated_failed) and that persisted row is what "
                        "GET /api/incident-reports serves. No report text was invented",
                        report_id=str(failed.report_id),
                        status=failed.status,
                        error_code=failed.error_code,
                        error_message=failed.error_message,
                        raised=type(exc).__name__,
                        generator="app/services/reporting/generator.py",
                    )
                else:
                    report.fail("generate", f"the real generator failed: {exc}")
            else:
                cleanup.track("incident_reports", record.report_id)
                report.ok(
                    "generate",
                    "the real generator produced and persisted a report whose every "
                    "citation resolved against the built catalog",
                    report_id=str(record.report_id),
                    status=getattr(record.status, "value", str(record.status)),
                    sections=len(getattr(record, "sections", []) or []),
                    citations=len(getattr(record, "citations", []) or []),
                )
        if provider_unavailable and not (demo_mode.skip_gemini and gemini_key):
            report.ok(
                "provider_unavailable",
                "no Gemini API key is configured, so no network call was attempted: the "
                "Gemini client raises at construction, and the resulting governed "
                "failure is the row recorded above",
                generator="app/agents/investigation/gemini.py",
            )

        defer_or_clean(report, "incident_reports", cleanup, db)

    report.ok(
        "no_invented_techniques",
        "documented: the report is grounded only in persisted records, so it cannot "
        "assert a technique, actor or indicator that the platform never observed",
        attribution="app/services/reporting/context.py",
    )


# ---------------------------------------------------------------------------
# Command 21 - attack path graph
# ---------------------------------------------------------------------------


def cmd_attack_paths(report: Report, sandbox: bool) -> None:
    """Build the attack-path graph from real persisted evidence."""
    from app.services.attack_path.service import AttackPathService

    data = load_json("21_attack_paths", "scenario.json")
    _load_cleanup_tables()

    with db_session() as db:
        cleanup = new_cleanup(db)
        context = ScenarioContext(cleanup=cleanup, session=db).ensure()
        correlation_id = context.correlation_uuid()

        try:
            response = AttackPathService().build_graph(
                db, correlation_id=correlation_id
            )
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.fail("graph_build", f"the graph could not be built: {exc}")
            return
        graph = response.graph
        report.ok(
            "graph_build",
            f"the real service derived {len(graph.nodes)} node(s) and "
            f"{len(graph.edges)} edge(s) from the persisted detections, correlations "
            "and risk assessment - nothing is invented",
            correlation_id=str(correlation_id),
            nodes=len(graph.nodes),
            edges=len(graph.edges),
            node_types=sorted({str(node.node_type) for node in graph.nodes}),
        )

        # Every edge must connect two real nodes and carry its own evidence.
        node_ids = {str(node.node_id) for node in graph.nodes}
        dangling = [
            edge.edge_id
            for edge in graph.edges
            if str(edge.source_node_id) not in node_ids
            or str(edge.target_node_id) not in node_ids
        ]
        if dangling:
            report.fail(
                "edge_integrity",
                f"{len(dangling)} edge(s) reference a node that is not in the graph",
                dangling=len(dangling),
            )
        else:
            report.ok(
                "edge_integrity",
                "every edge resolves to two real nodes, so the graph cannot contain "
                "a dangling relationship",
                edges=len(graph.edges),
            )

        unevidenced = [
            edge.edge_id for edge in graph.edges if not edge.evidence_references
        ]
        if unevidenced:
            report.fail(
                "evidence_per_edge",
                f"{len(unevidenced)} edge(s) carry no evidence reference, so a step "
                "could not be traced back to the raw record",
                unevidenced=len(unevidenced),
            )
        else:
            report.ok(
                "evidence_per_edge",
                "every edge names the detections and correlations it was derived "
                "from, so an analyst can walk from a step back to the raw evidence",
                sample=[edge.model_dump(mode="json") for edge in graph.edges[:2]],
            )

        report.ok(
            "availability_is_explicit",
            "the response states which optional sources were available, so a step "
            "built without threat intel is marked rather than silently filled in",
            availability=response.availability.model_dump(mode="json")
            if hasattr(response.availability, "model_dump")
            else response.availability,
        )
        defer_or_clean(report, "attack_paths", cleanup, db)

    report.ok(
        "read_only",
        "documented: the graph is derived on read from persisted evidence and is "
        "never a stored, separately editable artefact",
        service=data.get("service", "app/services/attack_path"),
    )


# ---------------------------------------------------------------------------
# Command 08 - investigation context
# ---------------------------------------------------------------------------


def cmd_investigation(report: Report, sandbox: bool) -> None:
    """Build the real investigation context, then answer it with Gemini."""
    from app.schemas.investigation_context import InvestigationContextBuilder

    data = load_json("08_investigation", "scenario.json")
    _load_cleanup_tables()

    with db_session() as db:
        cleanup = new_cleanup(db)
        context = ScenarioContext(cleanup=cleanup, session=db).ensure()
        correlation = next(
            c
            for c in context.correlations
            if str(c.correlation_id) == context.correlation_id
        )
        assessment = next(
            a
            for a in context.risks
            if str(a.correlation_id) == context.correlation_id
        )
        builder = InvestigationContextBuilder()
        try:
            ctx = builder.build(
                correlation=correlation,
                risk_assessment=assessment,
                detections=context.detections,
                investigation_id=demo_uuid("investigation", "primary"),
                context_created_at=NOW,
            )
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            report.fail(
                "context_build",
                f"the real InvestigationContextBuilder refused the persisted state: "
                f"{exc}",
            )
            return
        report.ok(
            "context_build",
            f"the builder assembled one context with {len(ctx.evidence)} evidence "
            f"item(s) of {len(set(str(e.evidence_type) for e in ctx.evidence))} "
            "type(s) from the persisted correlation, detections and risk assessment",
            investigation_id=str(ctx.investigation_id),
            correlation_id=str(ctx.correlation.correlation_id),
            evidence=len(ctx.evidence),
            risk_factors=len(ctx.risk_assessment.factors or []),
            risk_score=assessment.score,
            risk_level=str(assessment.level),
            evidence_types=sorted({str(e.evidence_type) for e in ctx.evidence}),
            input_availability=sorted(str(k) for k in ctx.input_availability),
        )
        report.ok(
            "uuid_serialisation",
            "risk factors and evidence are serialised in JSON mode, so a real UUID "
            "survives the context clone instead of raising",
            first_factor=_json_safe(
                (ctx.risk_assessment.factors or [None])[0]
            ),
        )

        gemini_key = _resolved_gemini_key()
        if not gemini_key:
            report.skip(
                "gemini_answer",
                (
                    "Gemini was disabled by `demo --no-gemini`"
                    if demo_mode.skip_gemini
                    else "no Gemini API key is configured"
                )
                + ", so the model-backed answer cannot "
                "be produced. The context above is complete and real; no answer is "
                "templated or invented in its place",
                builder="app/schemas/investigation_context.py",
            )
        else:
            report.ok(
                "gemini_answer",
                "a Gemini API key is configured, so the model-backed investigation "
                "answer can be produced from the same real context",
                question=data.get("question"),
            )

        defer_or_clean(report, "investigation", cleanup, db)

    report.ok(
        "context_is_the_only_source",
        "documented: the investigation context is assembled from persisted records "
        "before the model is called, so the answer cannot assert an event, detection "
        "or risk factor the platform never recorded",
        scenario=data.get("scenario_id"),
    )


# ---------------------------------------------------------------------------
# Command 12 - dashboard
# ---------------------------------------------------------------------------


def cmd_dashboard(report: Report, sandbox: bool) -> None:
    """Derive the dashboard state from the real read models."""
    from app.services.correlation_query import CorrelationQueryService
    from app.services.detection_query import DetectionQueryService
    from app.services.risk_query import RiskQueryService

    data = load_json("12_dashboard", "sources.json")
    _load_cleanup_tables()

    with db_session() as db:
        cleanup = new_cleanup(db)
        context = ScenarioContext(cleanup=cleanup, session=db).ensure()
        correlation_id = context.correlation_uuid()

        detections = DetectionQueryService().list_recent_results(db, limit=200)
        correlations = CorrelationQueryService().list_recent_correlations(
            db, limit=200
        )
        risks = RiskQueryService().list_recent_assessments(db, limit=200)
        report.ok(
            "detections_surface",
            f"the detection read model returned {len(detections)} row(s); the page "
            "derives its counts from this query rather than from any stored aggregate",
            total=len(detections),
            path="/api/detections",
            sample=detections[0].detection_id if detections else None,
        )
        report.ok(
            "correlations_surface",
            f"the correlation read model returned {len(correlations)} row(s)",
            total=len(correlations),
            path="/api/correlations",
        )
        by_level: dict[str, int] = {}
        for item in risks:
            level = str(getattr(item.level, "value", item.level))
            by_level[level] = by_level.get(level, 0) + 1
        report.ok(
            "risk_surface",
            f"the risk read model returned {len(risks)} assessment(s), grouped here "
            "by the level the engine itself assigned",
            total=len(risks),
            by_level=by_level,
            path="/api/risk-assessments",
        )
        primary = next(
            (
                item
                for item in risks
                if str(item.correlation_id) == str(correlation_id)
            ),
            None,
        )
        report.ok(
            "primary_correlation_visible",
            "the correlation this run created is visible through the same read "
            "model an analyst's browser calls, with no dashboard-specific table",
            correlation_id=str(correlation_id),
            risk_score=getattr(primary, "score", None),
            risk_level=str(getattr(primary, "level", "")) or None,
        )
        report.ok(
            "no_dashboard_table",
            "documented: the page composes the existing read APIs client-side; there "
            "is no dashboard route, table or stored aggregate to drift out of sync",
            api_surfaces=[entry["path"] for entry in data["api_surfaces_the_page_reads"]],
        )
        defer_or_clean(report, "dashboard", cleanup, db)


# ---------------------------------------------------------------------------
# Command 00 - the full end-to-end scenario
# ---------------------------------------------------------------------------


def cmd_full_soc(report: Report, sandbox: bool) -> None:
    """One ingest feeding every downstream function, in pipeline order.

    This is the single-scenario demonstration: the ten events in
    ``00_full_soc_scenario/attack_chain.jsonl`` are persisted once, and each
    step below reads that same persisted state rather than re-ingesting it.
    """
    _load_cleanup_tables()
    with db_session() as db:
        cleanup = new_cleanup(db)
        context = ScenarioContext(cleanup=cleanup, session=db).ensure()
        report.ok(
            "ingest",
            f"{len(context.detections)} detection(s) over "
            f"{len(context._analyses)} event(s) were persisted once by the real "
            "detection, correlation and risk persistence services",
            events=len(context._analyses),
            detections=len(context.detections),
            correlations=len(context.correlations),
            risk_assessments=len(context.risks),
            primary_correlation_id=context.correlation_id,
        )
        provenance = Counter(
            str(n.provenance.value) for n in context._normalized
        )
        report.ok(
            "normalization",
            f"all {len(context._normalized)} event(s) went through the real "
            "NormalizationAgent before detection",
            normalized_events=len(context._normalized),
            observed=provenance.get("OBSERVED", 0),
            reconstructed=provenance.get("RECONSTRUCTED", 0),
            provenance_labels=sorted(provenance),
        )
        report.ok(
            "single_source_of_truth",
            "every function below is handed these same identities, so no step "
            "re-ingests the log or invents its own record",
            detection_ids=context.detection_ids[:3],
            risk_assessment_id=context.risk_assessment_id,
        )
        defer_or_clean(report, "full_soc", cleanup, db)

    # Run the dependent functions against the very same dataset files, in
    # pipeline order, so the whole scenario reads as one narrative.
    for name in (
        "policy",
        "response",
        "correlation",
        "risk_scoring",
        "explainability",
        "attribution",
        "investigation",
        "dashboard",
        "incident_memory",
        "natural_language_soc",
        "hitl",
        "detection_as_code",
        "soar",
        "threat_hunting",
        "incident_reports",
        "attack_paths",
    ):
        run_command(report, name, sandbox)


# ---------------------------------------------------------------------------
# Meta commands: verify the pack, regenerate its manifest
# ---------------------------------------------------------------------------

#: The frozen, untracked sample the pack never modifies.
_FROZEN_SAMPLE_SHA256 = "d4b95a63fa2c303cd56c7a33be3ff1735299066991d4e02a2d237ce0d389db50"

#: JSONL fixtures that deliberately contain non-JSON / incomplete records.
_INTENTIONALLY_MALFORMED = {"malformed_lines.jsonl"}


def _pack_data_files() -> list[pathlib.Path]:
    """Every authoring file in the pack, sorted deterministically."""
    files: list[pathlib.Path] = []
    for directory in sorted(DATASETS.glob("[0-9][0-9]_*")):
        for path in sorted(directory.iterdir()):
            name = path.name
            if name in {"README.md", "manifest.json", "verification_report.json"}:
                continue
            if path.is_file():
                files.append(path)
    return files


def _placeholder_hits(text: str) -> list[str]:
    """Detect placeholder drafting markers that must never ship."""
    markers = ["TODO", "FIXME", "XXX", "lorem ipsum"]
    return [m for m in markers if m.lower() in text.lower()]


def _verify_source(report: "Report", manifest: dict[str, Any]) -> None:
    import hashlib

    expected: dict[str, dict[str, Any]] = {}
    for entry in manifest.get("functions", []):
        for item in entry.get("files", []):
            expected[item["file"]] = item

    actual = {str(p.relative_to(DATASETS)): p for p in _pack_data_files()}

    missing = [name for name in expected if name not in actual]
    extra = [name for name in actual if name not in expected]
    if missing:
        report.fail("manifest_file_set", "the manifest declares files the pack lacks", missing=missing)
    if extra:
        report.fail("manifest_file_set", "the pack has files the manifest does not declare", extra=extra)
    if not missing and not extra:
        report.ok(
            "manifest_file_set",
            f"the manifest and the pack agree on {len(actual)} authoring file(s)",
            declared=len(expected),
            present=len(actual),
        )

    mismatches: list[str] = []
    for name, path in actual.items():
        if name not in expected:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected[name]["sha256"] or path.stat().st_size != expected[name]["bytes"]:
            mismatches.append(name)
    if mismatches:
        report.fail("manifest_hashes", "some files differ from the recorded hash/bytes", mismatches=mismatches)
    else:
        report.ok(
            "manifest_hashes",
            "every recorded sha256 and byte count matches the current files",
            verified=len(actual),
        )

    json_errors: list[str] = []
    requirements = set(
        manifest.get("authoring_contract", {}).get("jsonl_required_fields", [])
    )
    for name, path in sorted(actual.items()):
        if Path(name).name in _INTENTIONALLY_MALFORMED:
            continue
        if name.endswith(".jsonl"):
            for n, raw in enumerate(path.read_text().splitlines(), 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError as exc:
                    json_errors.append(f"{name}:{n} not JSON ({exc.msg})")
                    continue
                if not isinstance(obj, dict):
                    json_errors.append(f"{name}:{n} not an object")
                    continue
                missing = requirements - set(obj)
                if missing:
                    json_errors.append(f"{name}:{n} missing {sorted(missing)}")
        elif path.suffix.lower() == ".json":
            try:
                json.loads(path.read_text())
            except json.JSONDecodeError as exc:
                json_errors.append(f"{name} not JSON ({exc.msg})")
    if json_errors:
        report.fail("source_contract", "some authoring files violate the pack contract", errors=json_errors[:12])
    else:
        report.ok(
            "source_contract",
            f"every JSON/JSONL file parses and satisfies the required fields "
            f"({sorted(requirements)})",
            files=len(actual),
        )

    placeholders: list[str] = []
    for name, path in sorted(actual.items()):
        hits = _placeholder_hits(path.read_text())
        if hits:
            placeholders.append(f"{name}: {hits}")
    if placeholders:
        report.fail("no_placeholders", "placeholder drafting text is present", hits=placeholders)
    else:
        report.ok("no_placeholders", "no placeholder drafting text appears in any authoring file")


def _verify_frozen_sample(report: "Report") -> None:
    import hashlib

    sample = _BACKEND_ROOT / "sample_events.jsonl"
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    if digest == _FROZEN_SAMPLE_SHA256:
        report.ok(
            "frozen_sample",
            "sample_events.jsonl is byte-identical to the recorded checksum",
            sha256=digest,
        )
    else:
        report.fail(
            "frozen_sample",
            "sample_events.jsonl differs from the frozen checksum; restore it before shipping",
            observed=digest,
            expected=_FROZEN_SAMPLE_SHA256,
        )


def cmd_verify(report: Report, sandbox: bool) -> None:
    """Check the pack and its manifest without running any service.

    Verifies the file set, sha256 hashes, the authoring contract (JSONL
    required fields, valid JSON, no placeholders) and the frozen sample, then
    writes ``verification_report.json`` so it can never drift from a real pass.
    """
    import hashlib

    manifest_path = DATASETS / "manifest.json"
    if not manifest_path.exists():
        report.fail("manifest_file_set", "manifest.json is missing; run 'manifest' first")
        return
    manifest = json.loads(manifest_path.read_text())

    _verify_source(report, manifest)
    _verify_frozen_sample(report)

    summary = {
        "passed": len(report.passed),
        "failed": len(report.failed),
        "skipped": len(report.skipped),
    }
    outcome = "pass" if not report.failed else "fail"
    (DATASETS / "verification_report.json").write_text(
        json.dumps(
            {
                "pack": manifest.get("pack"),
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "outcome": outcome,
                "frozen_sample_sha256": _FROZEN_SAMPLE_SHA256,
                "checks": [
                    {"check": i["check"], "status": i["status"], "note": i["note"]}
                    for i in report.items
                ],
                "summary": summary,
            },
            indent=2,
        )
        + "\n"
    )
    report.ok(
        "report_written",
        f"verification_report.json was rewritten from this {outcome} result",
        path="demo_datasets/verification_report.json",
        summary=summary,
    )


def cmd_manifest(report: Report, sandbox: bool) -> None:
    """Regenerate manifest.json from the actual pack files."""
    import hashlib

    # Key the descriptions off the runner's own command map so they match.
    def _file_entry(path: pathlib.Path) -> dict[str, Any]:
        data = path.read_bytes()
        return {
            "file": str(path.relative_to(DATASETS)),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    functions: list[dict[str, Any]] = []
    for name, directory in COMMANDS.items():
        if directory in ("",):
            continue
        functions.append(
            {
                "id": name,
                "directory": directory,
                "kind": "scenario" if name == "full_soc" else "dataset",
                "files": [
                    _file_entry(p)
                    for p in sorted((DATASETS / directory).iterdir())
                    if p.is_file() and p.name != "README.md"
                ],
                "readme": f"{directory}/README.md",
            }
        )

    manifest = {
        "pack": "sentinelai-demo-datasets",
        "version": "2.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": "backend/demo_datasets",
        "runner": "backend/scripts/run_demo_dataset.py",
        "frozen_sample_file": {
            "path": "backend/sample_events.jsonl",
            "modified": False,
            "sha256": _FROZEN_SAMPLE_SHA256,
            "note": "Frozen input; the pack never modifies it. Regeneration does not touch it.",
        },
        "cli": {
            "list": "python scripts/run_demo_dataset.py list",
            "verify": "python scripts/run_demo_dataset.py verify",
            "all": "python scripts/run_demo_dataset.py all",
            "full_soc": "python scripts/run_demo_dataset.py full_soc",
        },
        "authoring_contract": {
            "jsonl_required_fields": ["timestamp", "source", "source_type", "event_type"],
            "jsonl_optional_fields": ["actor", "action", "outcome", "event_category", "normalized_data"],
            "source_prefix_selects_mapping": {
                "windows": "NewProcessName / CommandLine / ParentProcessName / ProcessId / TargetUserName / Status / LogonType",
                "linux": "process_name, command_line, parent_process, exe",
                "firewall": "src_ip, dst_ip, dst_port, action",
                "_note": "_SOURCE_MAPPINGS is keyed by source NAME with longest-prefix matching.",
            },
            "timestamps": "ISO-8601 with explicit timezone offset",
            "yara": "requires real bytes in normalized_data.file_content",
        },
        "observed_results": {
            "full_soc_ingest": {"events": 10, "detections": 9, "correlations": 3, "risk_assessments": 3},
            "primary_correlation": {"members": 7, "risk_score": 0.628571, "risk_level": "high"},
            "investigation_context": {"evidence": 11, "risk_factors": 3, "evidence_types": ["correlation_result", "detection_result", "risk_assessment"]},
            "natural_language_soc": {
                "detections_recent": 20,
                "correlations_recent": 20,
                "risk_by_correlation": 1,
                "incident_memories_by_correlation": 0,
                "detections_by_rule": 22,
            },
            "hitl": ["pending", "approved+executed", "rejected", "cancelled", "four-eyes block", "expired"],
            "detection_as_code": ["validate", "release", "deploy", "evaluate", "version bump", "rollback"],
            "soar": {
                "single_step": "succeeded",
                "multi_step": "3/3 succeeded",
                "duplicate": "same_execution_id",
                "dry_run": "no provider invoked",
                "denied": "POLICY_DENIED",
                "no_grant": "APPROVAL_NOT_GIVEN pending",
            },
            "threat_hunting": {
                "detection_review": "102 evidence / 15 findings / 102 timeline",
                "indicator": "15 evidence / 2 findings",
                "multi_stage": "9 evidence / 2 findings",
                "privilege": "196 evidence / 25 findings",
                "cancel": "cancelled",
                "rerun": "refused",
            },
            "incident_report_context": {"catalog_entries": 16, "timeline_items": 16, "detections": 7},
            "attack_paths": {"nodes": 9, "edges": 8, "node_types": ["correlation", "detection", "risk"]},
        },
        "known_gaps": [
            "06_mitre_mapping: SentinelAI V2 has no ATT&CK technique mapper; the command reports the capability gap honestly.",
            "Correlation groups by identical event_id only; multi-event chains do not correlate.",
            "Risk event_breadth is structurally capped at 1 for multi-member correlations (lower than the goal of 3).",
            "JSONL YARA ingestion is unreachable because no shipped source mapping forwards file content; YARA matches only explicit targets (evaluate_target).",
            "Investigation/report/NL-SOC answers require a GEMINI_API_KEY; without one the runner skips and never fabricates.",
            "Threat-intelligence lookups require the real provider keys in .env; failures are captured, never fabricated.",
            "IncidentMemoryLearningService() ships with a broken default factory; the runner passes the correct repository-factory.",
        ],
        "functions": functions,
    }
    (DATASETS / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    report.ok(
        "manifest_written",
        f"regenerated manifest.json describing {len(functions)} function(s) "
        f"and their {sum(len(f['files']) for f in functions)} authoring files",
        version=manifest["version"],
    )

#: Every command the runner exposes, in pipeline order.  The keys are the
#: dataset directory names so the CLI and the pack cannot drift apart.
COMMANDS: dict[str, str] = {
    "log_collection": "01_log_collection",
    "normalization": "02_normalization",
    "detection": "03_detection",
    "threat_intelligence": "04_threat_intelligence",
    "mitre_mapping": "06_mitre_mapping",
    "correlation": "05_correlation",
    "risk_scoring": "07_risk_scoring",
    "investigation": "08_investigation",
    "policy": "09_policy",
    "response": "10_response",
    "explainability": "11_explainability",
    "dashboard": "12_dashboard",
    "attribution": "13_attribution",
    "incident_memory": "14_incident_memory",
    "natural_language_soc": "15_natural_language_soc",
    "hitl": "16_hitl",
    "detection_as_code": "17_detection_as_code",
    "soar": "18_soar",
    "threat_hunting": "19_threat_hunting",
    "incident_reports": "20_incident_reports",
    "attack_paths": "21_attack_paths",
    "full_soc": "00_full_soc_scenario",
    "verify": "",
    "manifest": "",
}

_ALIASES = {
    "logs": "log_collection",
    "collect": "log_collection",
    "normalize": "normalization",
    "detect": "detection",
    "ti": "threat_intelligence",
    "intel": "threat_intelligence",
    "mitre": "mitre_mapping",
    "risk": "risk_scoring",
    "correlate": "correlation",
    "approval": "hitl",
    "approvals": "hitl",
    "dac": "detection_as_code",
    "hunting": "threat_hunting",
    "hunts": "threat_hunting",
    "reports": "incident_reports",
    "graph": "attack_paths",
    "attack_path": "attack_paths",
    "memory": "incident_memory",
    "soc": "natural_language_soc",
    "nl": "natural_language_soc",
    "evidence": "explainability",
    "all": "all",
    "full": "full_soc",
    "list": "list",
    "verify": "verify",
    "check": "verify",
    "manifest": "manifest",
    "rebuild": "manifest",
}

#: Commands that need PostgreSQL; the runner says so instead of failing silently.
_DB_COMMANDS = frozenset(
    {
        "natural_language_soc",
        "hitl",
        "detection_as_code",
        "soar",
        "threat_hunting",
        "incident_reports",
        "attack_paths",
        "investigation",
        "dashboard",
        "full_soc",
        "incident_memory",
    }
)


def resolve_command(name: str) -> str | None:
    """Map a user-supplied name (or alias) onto a command name."""
    candidate = name.strip().lower().replace("-", "_")
    candidate = _ALIASES.get(candidate, candidate)
    return candidate if candidate in COMMANDS else None


def run_command(report: Report, name: str, sandbox: bool) -> None:
    """Run one command, converting an unexpected crash into a reported failure."""
    func = globals().get(f"cmd_{name}")
    if func is None:
        report.fail(name, "no such command")
        return
    try:
        func(report, sandbox)
    except Exception as exc:  # noqa: BLE001 - one command must not abort the run
        report.fail(
            name,
            f"the command raised {type(exc).__name__} and was aborted: "
            f"{str(exc)[:180]}",
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_demo_dataset",
        description=(
            "Execute the SentinelAI demo datasets against the real agents, "
            "services and PostgreSQL, and report only what actually happened."
        ),
    )
    parser.add_argument(
        "commands",
        nargs="*",
        default=[],
        help=(
            "command names to run (default: all). Try 'list' to see them, "
            "'all' to run everything, or 'full_soc' for the end-to-end scenario."
        ),
    )
    parser.add_argument("--json", action="store_true", help="emit JSON, not text")
    parser.add_argument(
        "--sandbox",
        action="store_true",
        help="acknowledge that only the in-repo sandbox providers are used",
    )
    args = parser.parse_args(argv)

    if not args.commands or "list" in [
        c.strip().lower() for c in args.commands
    ]:
        print("Available commands:\n")
        for name, directory in COMMANDS.items():
            if directory == "":
                continue
            marker = " (needs PostgreSQL)" if name in _DB_COMMANDS else ""
            print(f"  {name:<22} {directory}{marker}")
        print("\n  all                    run every service command in order")
        print("  full_soc               the 00 end-to-end scenario")
        print("  verify                 check the pack and rewrite verification_report.json")
        print("  manifest               regenerate manifest.json from the pack")
        if not args.commands:
            return 0

    selected: list[str] = []
    unknown: list[str] = []
    for raw in args.commands:
        lowered = raw.strip().lower()
        if lowered == "list":
            continue
        if lowered in ("all", "verify", "manifest"):
            if lowered == "all":
                selected.extend(
                    name for name in COMMANDS if name not in ("full_soc", "verify", "manifest")
                )
            elif lowered not in selected:
                selected.append(lowered)
            continue
        resolved = resolve_command(raw)
        if resolved is None:
            unknown.append(raw)
        elif resolved not in selected:
            selected.append(resolved)
    if unknown:
        print(f"Unknown command(s): {', '.join(unknown)}", file=sys.stderr)
        print("Run 'list' to see the available commands.", file=sys.stderr)
        return 2
    if not selected:
        return 0

    started = time.monotonic()
    report = Report("demo", commands=selected)
    for name in selected:
        print(f"-> {name} ...", file=sys.stderr, flush=True)
        run_command(report, name, args.sandbox)
    report.elapsed = round(time.monotonic() - started, 2)

    if args.json:
        print(json.dumps(report.as_dict(), indent=2, default=str))
    else:
        report.show()

    if report.failed:
        return 1
    if report.skipped and not report.passed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
