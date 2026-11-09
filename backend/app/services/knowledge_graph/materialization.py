"""Recoverable, no-schema knowledge-graph materialization.

Automatic materialization must be reliable without adding any persistent
state (no new table, no migration).  This module makes that possible by
treating the **persisted graph itself as the recovery ledger**:

* A correlation whose build failed leaves *no* correlation node behind.  The
  builder only commits at the very end, and every caller rolls back on
  failure, so "the correlation node is absent" is a durable marker that the
  graph still needs to be built.  Recovery therefore needs no outbox table:
  it is derived, at any time, by diffing V2 state against the graph.
* Staleness (supporting evidence such as risk assessments, incident memory,
  approvals, SOAR executions, reports, hunts, or threat-intel lookups arriving
  *after* the correlation was materialized) is detected the same way, by
  re-deriving the expected subgraph from real V2 rows and asking whether every
  expected node and edge is already persisted.  No inference is used: the
  expected rows come from the same deterministic derivation the builder uses.

Everything here is bounded by ``max_correlations`` and never raises for a
graph failure, so it can be used both as a post-commit side effect and as an
operator-driven recovery command.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.correlation_result import CorrelationResult
from app.models.knowledge_graph import KnowledgeGraphEdge, KnowledgeGraphNode
from app.services.knowledge_graph.builder import (
    DEFAULT_MAX_CORRELATIONS,
    BuildResult,
    KnowledgeGraphBuilder,
)
from app.services.knowledge_graph.vocabulary import NodeType, deterministic_node_id

logger = logging.getLogger(__name__)

#: Materializes one correlation's subgraph from the caller's session.  Returns
#: the builder result when available (used only for reporting).  Injected for
#: testability.
GraphMaterializer = Callable[[Session, uuid.UUID], "BuildResult | None"]

#: Operator-facing retry hint, kept byte-identical to the message emitted on
#: the correlation-persistence path so a single grep finds every failure.
RETRY_HINT = "build-knowledge-graph --correlation-id"


def materialize_correlation_graph(
    db: Session, correlation_id: uuid.UUID
) -> BuildResult:
    """Default hook: idempotently upsert one correlation's graph subgraph.

    Correlation-scoped, so it never prunes shared event/indicator nodes other
    correlations still reference.
    """
    return KnowledgeGraphBuilder().build_for_correlation(db, correlation_id)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphRefreshSummary:
    """Outcome of one :func:`refresh_correlation_graphs` invocation.

    Scan bookkeeping (*total_correlations*, *examined_count*,
    *unexamined_count*) is filled in by
    :func:`reconcile_correlation_graphs`, whose ``limit`` bounds how many
    correlations the recovery scan actually examines.  A summary produced
    from an explicit id list (the post-commit refresh paths) carries zeros
    and is never considered truncated, because nothing was scanned.
    """

    requested: tuple[uuid.UUID, ...] = ()
    materialized: tuple[uuid.UUID, ...] = ()
    failed: tuple[uuid.UUID, ...] = ()
    nodes_derived: int = 0
    edges_derived: int = 0
    #: Total correlations present in persistence when the scan ran.
    total_correlations: int = 0
    #: How many correlations the bounded scan actually examined.
    examined_count: int = 0
    #: ``total_correlations - examined_count``: work the scan never reached.
    unexamined_count: int = 0

    @property
    def failure_count(self) -> int:
        return len(self.failed)

    @property
    def truncated(self) -> bool:
        """True when the scan hit its cap and correlations remain unexamined.

        Deliberately independent of :attr:`failed`: a capped scan and a
        materialization failure are different outcomes and must never be
        reported through the same flag.
        """
        return self.unexamined_count > 0

    @property
    def outcome_status(self) -> str:
        """``FAIL`` on any materialization failure, ``PARTIAL`` on a capped
        scan with unexamined correlations, otherwise ``PASS``."""
        if self.failed:
            return "FAIL"
        if self.truncated:
            return "PARTIAL"
        return "PASS"

    @property
    def is_empty(self) -> bool:
        return not self.materialized and not self.failed

    def as_build_dict(self, scope: str) -> dict:
        """Same shape as :meth:`BuildResult.as_dict` for the CLI contract.

        ``truncated`` reports *scan capping only* (correlations left
        unexamined by ``--max-correlations``); materialization failures are
        reported separately through ``failed_count`` /
        ``failed_correlation_ids`` and drive ``status = "FAIL"``.
        """
        return {
            "status": self.outcome_status,
            "scope": scope,
            "correlation_count": len(self.materialized),
            "correlation_ids": [str(c) for c in self.materialized[:25]],
            "node_count": self.nodes_derived,
            "edge_count": self.edges_derived,
            "nodes_created": 0,
            "nodes_updated": 0,
            "nodes_pruned": 0,
            "edges_created": 0,
            "edges_updated": 0,
            "edges_pruned": 0,
            "truncated": self.truncated,
            "truncated_reason": (
                (
                    f"scan reached max_correlations; "
                    f"{self.unexamined_count} correlation(s) remain unexamined"
                )
                if self.truncated
                else None
            ),
            "prune_skipped": True,
            "prune_skipped_reason": (
                "recovery builds are correlation-scoped and never prune"
            ),
            "requested_count": len(self.requested),
            "materialized_count": len(self.materialized),
            "failed_count": len(self.failed),
            "failed_correlation_ids": [str(c) for c in self.failed[:25]],
            "total_correlations": self.total_correlations,
            "examined_count": self.examined_count,
            "unexamined_count": self.unexamined_count,
            "note": (
                "Recovery materialization from persisted V2 state. No LLM, RAG, "
                "or inference was used to create any relationship."
            ),
        }


# ---------------------------------------------------------------------------
# Isolated refresh
# ---------------------------------------------------------------------------


def refresh_correlation_graphs(
    db: Session,
    correlation_ids: Iterable[uuid.UUID],
    *,
    materializer: GraphMaterializer | None = None,
) -> GraphRefreshSummary:
    """Materialize each correlation, isolating every failure.

    This never raises: a failure is logged with its correlation id (and the
    retry hint), the failed graph's uncommitted writes are rolled back, and
    the remaining correlations are still processed.  It is safe to call after
    a commit that must not be undone.
    """
    hook = materializer or materialize_correlation_graph
    seen: set[uuid.UUID] = set()
    requested: list[uuid.UUID] = []
    materialized: list[uuid.UUID] = []
    failed: list[uuid.UUID] = []
    nodes = edges = 0

    for correlation_id in correlation_ids:
        if correlation_id in seen:
            continue
        seen.add(correlation_id)
        requested.append(correlation_id)
        try:
            result = hook(db, correlation_id)
        except Exception:
            failed.append(correlation_id)
            logger.warning(
                "knowledge graph materialization failed for correlation_id=%s; "
                "retry with `%s %s`",
                correlation_id,
                RETRY_HINT,
                correlation_id,
                exc_info=True,
            )
            db.rollback()
        else:
            materialized.append(correlation_id)
            if result is not None:
                nodes += result.node_count
                edges += result.edge_count

    return GraphRefreshSummary(
        requested=tuple(requested),
        materialized=tuple(materialized),
        failed=tuple(failed),
        nodes_derived=nodes,
        edges_derived=edges,
    )


# ---------------------------------------------------------------------------
# Recovery enumeration (no maintenance state required)
# ---------------------------------------------------------------------------


def _scan_correlation_ids(
    db: Session, limit: int
) -> tuple[list[uuid.UUID], int]:
    """First ``limit`` correlation ids in deterministic order, plus the total.

    The extra row probe (``limit + 1``) and the exact ``COUNT`` let callers
    distinguish "the cap covered everything" from "the cap silently hid
    correlations from the scan" without a second full enumeration.
    """
    bounded = max(1, int(limit))
    rows = db.execute(
        select(CorrelationResult.correlation_id)
        .order_by(CorrelationResult.correlation_id)
        .limit(bounded + 1)
    ).scalars().all()
    total = int(
        db.execute(
            select(func.count()).select_from(CorrelationResult)
        ).scalar_one()
    )
    return list(rows[:bounded]), total


def _bounded_correlation_ids(
    db: Session, limit: int
) -> list[uuid.UUID]:
    return _scan_correlation_ids(db, limit)[0]


def _unmaterialized_among(
    db: Session, correlation_ids: Sequence[uuid.UUID]
) -> list[uuid.UUID]:
    if not correlation_ids:
        return []
    node_ids = {
        deterministic_node_id(NodeType.CORRELATION, str(c)): c
        for c in correlation_ids
    }
    persisted = set(
        db.scalars(
            select(KnowledgeGraphNode.id).where(
                KnowledgeGraphNode.id.in_(list(node_ids))
            )
        ).all()
    )
    return [
        correlation_id
        for node_id, correlation_id in node_ids.items()
        if node_id not in persisted
    ]


def unmaterialized_correlation_ids(
    db: Session, *, limit: int = DEFAULT_MAX_CORRELATIONS
) -> list[uuid.UUID]:
    """Correlations with no persisted graph node.

    This is the durable recovery marker: a failed or interrupted build leaves
    no correlation node, so absence is a reliable "needs materialization"
    signal without any dedicated state table.
    """
    correlation_ids = _bounded_correlation_ids(db, limit)
    return _unmaterialized_among(db, correlation_ids)


def _persisted_ids(db: Session, model, ids: Sequence[uuid.UUID]) -> set[uuid.UUID]:
    if not ids:
        return set()
    return set(
        db.scalars(select(model.id).where(model.id.in_(list(ids)))).all()
    )


def _stale_among(
    db: Session, correlation_ids: Sequence[uuid.UUID]
) -> list[uuid.UUID]:
    builder = KnowledgeGraphBuilder()
    stale: list[uuid.UUID] = []
    for correlation_id in correlation_ids:
        nodes, edges = builder._derive_with_db(db, [correlation_id])  # noqa: SLF001
        if not nodes:
            # The correlation row itself was not resolvable; nothing to do.
            continue
        expected_node_ids = {node["id"] for node in nodes}
        expected_edge_ids = {edge["id"] for edge in edges}
        if expected_node_ids - _persisted_ids(db, KnowledgeGraphNode, sorted(expected_node_ids)):
            stale.append(correlation_id)
            continue
        if expected_edge_ids - _persisted_ids(db, KnowledgeGraphEdge, sorted(expected_edge_ids)):
            stale.append(correlation_id)
    return stale


def stale_correlation_ids(
    db: Session, *, limit: int = DEFAULT_MAX_CORRELATIONS
) -> list[uuid.UUID]:
    """Correlations whose persisted graph is missing expected nodes or edges.

    The expected subgraph is re-derived from real V2 state with the same
    deterministic builder derivation used for materialization; a correlation
    is *stale* when any expected node or edge is not yet persisted.  This is
    how supporting evidence added after the first build is detected without
    any per-correlation maintenance state.
    """
    return _stale_among(db, _bounded_correlation_ids(db, limit))


def correlations_needing_refresh(
    db: Session,
    *,
    limit: int = DEFAULT_MAX_CORRELATIONS,
    include_stale: bool = True,
) -> list[uuid.UUID]:
    """Correlations to (re)materialize.

    ``include_stale=False`` is the cheap recovery-only mode (missing
    correlation node); ``include_stale=True`` also re-examines correlations
    whose expected graph has since grown.
    """
    if not include_stale:
        return unmaterialized_correlation_ids(db, limit=limit)
    return stale_correlation_ids(db, limit=limit)


def reconcile_correlation_graphs(
    db: Session,
    *,
    limit: int = DEFAULT_MAX_CORRELATIONS,
    include_stale: bool = True,
    materializer: GraphMaterializer | None = None,
) -> GraphRefreshSummary:
    """Materialize every missing-or-stale correlation, isolating failures.

    ``limit`` bounds the *scan*: the first ``limit`` correlations (in
    deterministic id order) are examined, and the summary reports the exact
    total so callers can tell a complete scan from a capped one.  Scan
    truncation never hides materialization failures and vice versa — both
    are reported independently on the returned summary.
    """
    scanned, total = _scan_correlation_ids(db, limit)
    if include_stale:
        correlation_ids = _stale_among(db, scanned)
    else:
        correlation_ids = _unmaterialized_among(db, scanned)
    summary = refresh_correlation_graphs(
        db, correlation_ids, materializer=materializer
    )
    return GraphRefreshSummary(
        requested=summary.requested,
        materialized=summary.materialized,
        failed=summary.failed,
        nodes_derived=summary.nodes_derived,
        edges_derived=summary.edges_derived,
        total_correlations=total,
        examined_count=len(scanned),
        unexamined_count=max(0, total - len(scanned)),
    )


__all__ = [
    "GraphMaterializer",
    "GraphRefreshSummary",
    "RETRY_HINT",
    "correlations_needing_refresh",
    "materialize_correlation_graph",
    "reconcile_correlation_graphs",
    "refresh_correlation_graphs",
    "stale_correlation_ids",
    "unmaterialized_correlation_ids",
]
