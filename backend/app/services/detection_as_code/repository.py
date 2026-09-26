"""Detection-as-Code persistence repository (V2.17).

Write-side operations back the lifecycle service and read-side operations
back the query/API layer.  Entity- and column-level only — the repository
has no knowledge of validation or lifecycle *semantics*, services compose
them.

Contract rules honoured here (mirrors ``app/repositories/detection.py``):

* The repository does **not** commit.  Transaction boundaries are owned by
  the calling service so a lifecycle action persists atomically.
* Versions are immutable once validated: the repository refuses to mutate a
  version row touched by validation/release (only enabled/validation fields
  may change, and only by the validation/lifecycle service, never by a
  generic caller).
* Reads are deterministic: every list orders by ``rule_id`` then semantic
  version, so page/ordering boundaries never duplicate or skip rows.
* Identities are passed in from the domain (``version_id`` / ``release_id``
  / ``change_id``), never generated here — determinism is a domain concern.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.detection_rule_change import DetectionRuleChangeRow
from app.models.detection_rule_release import DetectionRuleReleaseRow
from app.models.detection_rule_version import DetectionRuleVersionRow
from app.schemas.detection_as_code import compare_versions


# ---------------------------------------------------------------------------
# Rule versions
# ---------------------------------------------------------------------------


def get_version(
    session: Session, rule_id: str, version: str
) -> DetectionRuleVersionRow | None:
    """Return the version row for (rule_id, version) or None."""
    return session.scalar(
        select(DetectionRuleVersionRow).where(
            DetectionRuleVersionRow.rule_id == rule_id,
            DetectionRuleVersionRow.version == version,
        )
    )


def get_version_by_identity(
    session: Session, version_id: uuid.UUID
) -> DetectionRuleVersionRow | None:
    """Return the version row for a deterministic version identity or None."""
    return session.scalar(
        select(DetectionRuleVersionRow).where(
            DetectionRuleVersionRow.version_id == version_id
        )
    )


def list_versions(session: Session, rule_id: str) -> list[DetectionRuleVersionRow]:
    """All versions for a rule, newest semantic version first."""
    rows = list(
        session.scalars(
            select(DetectionRuleVersionRow).where(
                DetectionRuleVersionRow.rule_id == rule_id
            )
        )
    )
    rows.sort(key=lambda row: tuple(map(int, row.version.split("."))), reverse=True)
    return rows


def latest_version(
    session: Session, rule_id: str
) -> DetectionRuleVersionRow | None:
    """Newest semantic version row for a rule, or None."""
    rows = list_versions(session, rule_id)
    return rows[0] if rows else None


def count_distinct_rules(session: Session) -> int:
    """Number of distinct governed rule ids with at least one version row."""
    return int(
        session.scalar(
            select(func.count(func.distinct(DetectionRuleVersionRow.rule_id)))
        )
        or 0
    )


def list_all_rules_latest(session: Session) -> list[DetectionRuleVersionRow]:
    """Latest version row per governed rule, deterministic by rule_id."""
    rows = list(session.scalars(select(DetectionRuleVersionRow)))
    by_rule: dict[str, DetectionRuleVersionRow] = {}
    for row in rows:
        current = by_rule.get(row.rule_id)
        if current is None or (sort_key(row.version) > sort_key(current.version)):
            by_rule[row.rule_id] = row
    return [by_rule[rule_id] for rule_id in sorted(by_rule)]


# ---------------------------------------------------------------------------
# Releases
# ---------------------------------------------------------------------------


def get_release(
    session: Session, rule_id: str, version: str
) -> DetectionRuleReleaseRow | None:
    """Return the release row for (rule_id, version) or None."""
    return session.scalar(
        select(DetectionRuleReleaseRow).where(
            DetectionRuleReleaseRow.rule_id == rule_id,
            DetectionRuleReleaseRow.version == version,
        )
    )


def list_releases(
    session: Session, rule_id: str
) -> list[DetectionRuleReleaseRow]:
    """All release rows for a rule, newest semantic version first."""
    rows = list(
        session.scalars(
            select(DetectionRuleReleaseRow).where(
                DetectionRuleReleaseRow.rule_id == rule_id
            )
        )
    )
    rows.sort(key=lambda row: tuple(map(int, row.version.split("."))), reverse=True)
    return rows


def deployed_release(
    session: Session, rule_id: str
) -> DetectionRuleReleaseRow | None:
    """The currently deployed release row for a rule, or None."""
    return session.scalar(
        select(DetectionRuleReleaseRow).where(
            DetectionRuleReleaseRow.rule_id == rule_id,
            DetectionRuleReleaseRow.deployment_state == "deployed",
        )
    )


def all_deployed_releases(session: Session) -> list[DetectionRuleReleaseRow]:
    """Every deployed release across all rules (registry snapshot input)."""
    rows = list(
        session.scalars(
            select(DetectionRuleReleaseRow).where(
                DetectionRuleReleaseRow.deployment_state == "deployed"
            )
        )
    )
    rows.sort(key=lambda row: (row.rule_id, row.version))
    return rows


# ---------------------------------------------------------------------------
# Changes ledger
# ---------------------------------------------------------------------------


def get_change(
    session: Session, change_id: uuid.UUID
) -> DetectionRuleChangeRow | None:
    """Return the change row for a deterministic change identity or None."""
    return session.scalar(
        select(DetectionRuleChangeRow).where(
            DetectionRuleChangeRow.change_id == change_id
        )
    )


def list_changes(session: Session, rule_id: str) -> list[DetectionRuleChangeRow]:
    """All change rows for a rule, oldest first (append-only ledger)."""
    return list(
        session.scalars(
            select(DetectionRuleChangeRow)
            .where(DetectionRuleChangeRow.rule_id == rule_id)
            .order_by(DetectionRuleChangeRow.created_at.asc())
        )
    )


# ---------------------------------------------------------------------------
# Deterministic helper used by ordering everywhere
# ---------------------------------------------------------------------------


def sort_key(version: str):
    return tuple(map(int, version.split(".")))


def semantic_compare(left: str, right: str) -> int:
    """Compare two strict semantic versions (-1/0/1)."""
    return compare_versions(left, right)


__all__ = [
    "get_version",
    "get_version_by_identity",
    "list_versions",
    "latest_version",
    "count_distinct_rules",
    "list_all_rules_latest",
    "get_release",
    "list_releases",
    "deployed_release",
    "all_deployed_releases",
    "get_change",
    "list_changes",
    "sort_key",
    "semantic_compare",
]