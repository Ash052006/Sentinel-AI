"""Evidence catalog and engine-derived facts — V3.23.

This module is where the non-negotiable evidence rule is *enforced* rather than
merely documented.  It has two responsibilities:

1. **Build the closed evidence catalog.**  Every reference an agent is allowed
   to cite is derived from the bounded V3.22 graph.  The set is closed: a
   reference outside it does not exist for the purposes of this debate, so a
   fabricated identifier has nowhere to land.

2. **Derive the FACTS.**  Facts are computed here, mechanically, from the
   persisted V2 entities the graph already represents.  A provider never
   supplies a fact — there is no field for one in the model output contract.
   That means even a fully compromised model cannot assert "the event contained
   PowerShell execution": it could only reach that statement as a *hypothesis*
   or an evidenced *observation*, which is exactly the distinction the contract
   requires.

The catalog is bounded by the V3.22 graph bounds, so a debate can never reason
over an unbounded evidence surface.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from app.agents.debate.exceptions import (
    DebateBoundsError,
    DebateContextError,
    DebateEvidenceError,
)
from app.agents.debate.vocabulary import (
    DEFAULT_BOUNDS,
    DebateBounds,
    deterministic_fact_id,
)
from app.schemas.debate import DebateFact, EvidenceReference
from app.schemas.security_event import Provenance
from app.services.knowledge_graph.queries import BoundedGraph
from app.services.knowledge_graph.vocabulary import NodeType

#: Provenance carried on a fact computed from each node type.  This is the
#: provenance of the *underlying V2 entity*, never of the fact as reasoning.
_NODE_TYPE_PROVENANCE: dict[str, Provenance] = {
    NodeType.EVENT.value: Provenance.OBSERVED,
    NodeType.DETECTION.value: Provenance.DETECTED,
    NodeType.CORRELATION.value: Provenance.CORRELATED,
    NodeType.RISK_ASSESSMENT.value: Provenance.RISK_ASSESSED,
}


@dataclass(frozen=True)
class CatalogEntry:
    """One resolvable piece of evidence in the bounded graph."""

    reference: str
    entity_kind: str
    node_id: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: str | None = None


class EvidenceCatalog:
    """A closed, bounded set of resolvable evidence references.

    The catalog is the sole authority on what may be cited.  ``resolve``
    validates a reference and returns the typed :class:`EvidenceReference`;
    anything unknown raises :class:`DebateEvidenceError` so the caller can
    reject the whole output rather than silently dropping a fabricated citation.
    """

    def __init__(self, entries: dict[str, CatalogEntry]) -> None:
        self._entries = dict(entries)

    # -- Construction --------------------------------------------------------

    @classmethod
    def from_graph(
        cls,
        graph: BoundedGraph,
        *,
        bounds: DebateBounds = DEFAULT_BOUNDS,
    ) -> "EvidenceCatalog":
        """Build the catalog from a bounded V3.22 traversal.

        Only graph *nodes* are citable.  An edge is a relationship justified by
        persisted rows, and its ``source_reference`` is a row reference rather
        than an entity identity, so edges are context rather than evidence
        handles.
        """
        if graph is None:
            raise DebateContextError(
                "an evidence catalog requires a bounded graph; received None"
            )
        if len(graph.nodes) > bounds.max_evidence_references:
            raise DebateBoundsError(
                f"graph supplies {len(graph.nodes)} nodes which exceeds "
                f"max_evidence_references={bounds.max_evidence_references}"
            )

        entries: dict[str, CatalogEntry] = {}
        for node in graph.nodes:
            reference = str(node.get("source_reference") or "").strip()
            node_id = str(node.get("id") or "").strip()
            entity_kind = str(node.get("node_type") or "").strip()
            if not reference or not node_id or not entity_kind:
                # A node without a resolvable identity cannot be cited; the V3.22
                # builder guarantees these, so skipping is defence in depth.
                continue
            entries[reference] = CatalogEntry(
                reference=reference,
                entity_kind=entity_kind,
                node_id=node_id,
                label=str(node.get("label") or ""),
                metadata=dict(node.get("metadata") or {}),
                observed_at=node.get("observed_at"),
            )
        return cls(entries)

    # -- Access --------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, reference: object) -> bool:
        return reference in self._entries

    @property
    def references(self) -> list[str]:
        """All citable references, deterministically ordered."""
        return sorted(self._entries)

    @property
    def entries(self) -> list[CatalogEntry]:
        """All catalog entries as a read-only list, ordered by reference."""
        return [self._entries[ref] for ref in sorted(self._entries)]

    def entry(self, reference: str) -> CatalogEntry | None:
        return self._entries.get(reference)

    def resolve(self, reference: str) -> EvidenceReference:
        """Resolve *reference*, or raise :class:`DebateEvidenceError`."""
        entry = self._entries.get(reference)
        if entry is None:
            raise DebateEvidenceError(
                f"evidence reference {reference!r} does not resolve to any "
                "entity in the supplied knowledge graph; fabricated evidence "
                "references are rejected"
            )
        return EvidenceReference(
            reference=entry.reference,
            entity_kind=entry.entity_kind,
            node_id=entry.node_id,
        )

    def resolve_all(self, references: list[str]) -> list[EvidenceReference]:
        """Resolve every reference or fail; never partially resolve."""
        return [self.resolve(reference) for reference in references]

    def resolve_optional(self, references: list[str]) -> list[EvidenceReference]:
        """Resolve references, dropping ones outside the catalog.

        Only used for *internally derived* references (facts the engine itself
        computed from a graph that changed between build and read), never for
        model output — model output must fail closed via :meth:`resolve_all`.
        """
        resolved: list[EvidenceReference] = []
        for reference in references:
            entry = self._entries.get(reference)
            if entry is not None:
                resolved.append(
                    EvidenceReference(
                        reference=entry.reference,
                        entity_kind=entry.entity_kind,
                        node_id=entry.node_id,
                    )
                )
        return resolved

    def by_kind(self, entity_kind: str) -> list[CatalogEntry]:
        """Entries of one node type, deterministically ordered by reference."""
        return sorted(
            (e for e in self._entries.values() if e.entity_kind == entity_kind),
            key=lambda e: e.reference,
        )

    def kind_counts(self) -> dict[str, int]:
        """Reference count per node type, keys sorted."""
        counts = Counter(entry.entity_kind for entry in self._entries.values())
        return {kind: counts[kind] for kind in sorted(counts)}

    def missing_kinds(
        self, required: tuple[str, ...]
    ) -> dict[str, int]:
        """Which of *required* node types the graph supplies zero of."""
        counts = self.kind_counts()
        return {kind: 0 for kind in sorted(required) if counts.get(kind, 0) == 0}


# ---------------------------------------------------------------------------
# Graph snapshot digest
# ---------------------------------------------------------------------------


def graph_snapshot_digest(graph: BoundedGraph) -> str:
    """Stable digest of the bounded graph.

    Two identical graph snapshots produce the same digest, which combined with
    the configuration digest yields a deterministic debate identity — the basis
    of idempotency.  Ordering is canonical (sorted nodes, sorted edges, sorted
    keys) so database row order cannot influence it.
    """
    payload = {
        "root_node_id": str(graph.root_node_id) if graph.root_node_id else None,
        "nodes": sorted(
            (dict(node) for node in graph.nodes), key=lambda n: str(n.get("id"))
        ),
        "edges": sorted(
            (dict(edge) for edge in graph.edges), key=lambda e: str(e.get("id"))
        ),
        "node_count": graph.node_count,
        "edge_count": graph.edge_count,
        "truncated": bool(graph.truncated),
        "truncated_reason": graph.truncated_reason,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Engine-derived facts
# ---------------------------------------------------------------------------


def derive_facts(
    graph: BoundedGraph,
    catalog: EvidenceCatalog,
) -> list[DebateFact]:
    """Mechanically derive every FACT the debate may rely on.

    These statements are generated from the persisted entities the graph
    represents — never from a model.  Each cites the exact evidence it was
    computed from, so an auditor can independently re-derive it.  Ordering is
    deterministic (by normalized statement) so identical graphs yield identical
    fact lists.
    """
    facts: list[DebateFact] = []

    def add(
        statement: str,
        references: list[str],
        provenance: Provenance | None = None,
    ) -> None:
        resolved = catalog.resolve_optional(references)
        if not resolved:
            # A fact with no resolvable citation would be unciteable, which
            # would make it unusable and unauditable.  Skip rather than emit.
            return
        facts.append(
            DebateFact(
                fact_id=str(deterministic_fact_id(statement)),
                statement=statement,
                evidence_references=resolved,
                provenance=provenance,
            )
        )

    counts = catalog.kind_counts()

    # -- Scope facts -------------------------------------------------------
    scope = (
        f"The bounded knowledge graph for this correlation contains "
        f"{graph.node_count} entities and {graph.edge_count} relationships."
    )
    if graph.root_node_id:
        add(
            scope,
            [f"correlation:{_root_correlation_id(graph, catalog)}"]
            if _root_correlation_id(graph, catalog)
            else [],
        )
    else:
        add(scope, [])

    if graph.truncated:
        add(
            f"The graph traversal was truncated (reason: "
            f"{graph.truncated_reason}); entities beyond the bound were not "
            f"available to this debate.",
            [],
        )
    else:
        add(
            "The graph traversal completed without hitting any node, edge, or "
            "depth bound.",
            [],
        )

    for kind in sorted(counts):
        entries = catalog.by_kind(kind)
        add(
            f"The graph contains {counts[kind]} {kind} "
            f"entit{'y' if counts[kind] == 1 else 'ies'}.",
            [entry.reference for entry in entries],
            _NODE_TYPE_PROVENANCE.get(kind),
        )

    # -- Shared-event fact (the headline V3.22 property) -------------------
    for event_entry in catalog.by_kind(NodeType.EVENT.value):
        produced = _produced_detections(graph, event_entry.node_id)
        if not produced:
            continue
        detections = catalog.by_kind(NodeType.DETECTION.value)
        cited = [event_entry.reference] + [
            d.reference
            for d in detections
            if d.node_id in {pid for pid in produced}
        ]
        rule_ids = sorted(
            {
                str(catalog.entry(ref).metadata.get("rule_id"))
                for ref in cited
                if catalog.entry(ref) is not None
                and catalog.entry(ref).metadata.get("rule_id")
            }
        )
        rule_clause = (
            f" contributed by {len(rule_ids)} distinct detection rule"
            f"{'s' if len(rule_ids) != 1 else ''}"
            if rule_ids
            else ""
        )
        add(
            f"{len(produced)} persisted DETECTION results reference the same "
            f"persisted event identifier ({event_entry.reference})"
            f"{rule_clause}. These are detections of one underlying event, not "
            f"{len(produced)} separate events.",
            cited,
            Provenance.DETECTED,
        )

    # -- Per-detection facts ----------------------------------------------
    for detection in catalog.by_kind(NodeType.DETECTION.value):
        metadata = detection.metadata
        attributes = [
            f"rule_id={metadata.get('rule_id')}"
            for _ in [0]
            if metadata.get("rule_id")
        ]
        if metadata.get("severity"):
            attributes.append(f"severity={metadata.get('severity')}")
        if metadata.get("confidence") is not None:
            attributes.append(f"confidence={metadata.get('confidence')}")
        if metadata.get("matched") is not None:
            attributes.append(f"matched={metadata.get('matched')}")
        if not attributes:
            add(
                f"A persisted DETECTION result exists with no allowlisted "
                f"attributes recorded on the graph node.",
                [detection.reference],
                Provenance.DETECTED,
            )
            continue
        add(
            f"A persisted DETECTION result recorded {'; '.join(attributes)}.",
            [detection.reference],
            Provenance.DETECTED,
        )

    # -- Correlation fact --------------------------------------------------
    for correlation in catalog.by_kind(NodeType.CORRELATION.value):
        metadata = correlation.metadata
        attributes = []
        if metadata.get("status"):
            attributes.append(f"status={metadata.get('status')}")
        if metadata.get("confidence") is not None:
            attributes.append(f"correlation confidence={metadata.get('confidence')}")
        if metadata.get("timestamp"):
            attributes.append(f"timestamp={metadata.get('timestamp')}")
        add(
            f"The persisted correlation result recorded "
            f"{'; '.join(attributes) if attributes else 'no allowlisted attributes'}."
            " A correlation is an analytical conclusion about the relationship "
            "between detections; it is not itself an observation and carries no "
            "verdict.",
            [correlation.reference],
            Provenance.CORRELATED,
        )

    # -- Risk assessment fact ---------------------------------------------
    for risk in catalog.by_kind(NodeType.RISK_ASSESSMENT.value):
        metadata = risk.metadata
        attributes = []
        if metadata.get("level"):
            attributes.append(f"level={metadata.get('level')}")
        if metadata.get("score") is not None:
            attributes.append(f"score={metadata.get('score')}")
        if metadata.get("confidence") is not None:
            attributes.append(f"assessment confidence={metadata.get('confidence')}")
        add(
            f"The persisted risk assessment recorded "
            f"{'; '.join(attributes) if attributes else 'no allowlisted attributes'}."
            " A risk assessment expresses how dangerous the correlated "
            "activity appears and how confident SentinelAI is; it is not a "
            "verdict and is not evidence of malicious intent.",
            [risk.reference],
            Provenance.RISK_ASSESSED,
        )

    # Deterministic ordering, deduplicated by statement.
    deduped: dict[str, DebateFact] = {}
    for fact in facts:
        deduped.setdefault(fact.statement, fact)
    return sorted(deduped.values(), key=lambda f: f.statement)


def _produced_detections(graph: BoundedGraph, event_node_id: str) -> list[str]:
    """Detection node ids reachable from *event_node_id* by produced_detection."""
    return sorted(
        {
            edge["target_node_id"]
            for edge in graph.edges
            if edge.get("relationship_type") == "produced_detection"
            and edge.get("source_node_id") == event_node_id
        }
    )


def _root_correlation_id(graph: BoundedGraph, catalog: EvidenceCatalog) -> str | None:
    for node in graph.nodes:
        if node.get("id") == str(graph.root_node_id) and node.get("node_type") == (
            NodeType.CORRELATION.value
        ):
            return str(node.get("source_id"))
    return None


# ---------------------------------------------------------------------------
# Evidence gaps
# ---------------------------------------------------------------------------

#: Node types an analyst would expect to reason over.  When the graph supplies
#: none, the debate reports a gap rather than letting the absence pass
#: unnoticed.
EXPECTED_NODE_TYPES: tuple[str, ...] = (
    NodeType.DETECTION.value,
    NodeType.EVENT.value,
    NodeType.RISK_ASSESSMENT.value,
    NodeType.THREAT_INDICATOR.value,
    NodeType.INCIDENT_MEMORY.value,
)


def derive_evidence_gaps(
    catalog: EvidenceCatalog,
    unavailable_entity_types: dict[str, str] | None = None,
) -> list[str]:
    """Describe, deterministically, what the debate could not reason over."""
    gaps: list[str] = []
    missing = catalog.missing_kinds(EXPECTED_NODE_TYPES)
    for kind in sorted(missing):
        gaps.append(
            f"No {kind} entity exists in the supplied graph, so this debate "
            f"could not evaluate any {kind}-based reasoning."
        )
    for name in sorted(unavailable_entity_types or {}):
        gaps.append(unavailable_entity_types[name])
    return sorted(set(gaps))


__all__ = [
    "EXPECTED_NODE_TYPES",
    "CatalogEntry",
    "EvidenceCatalog",
    "derive_evidence_gaps",
    "derive_facts",
    "graph_snapshot_digest",
]