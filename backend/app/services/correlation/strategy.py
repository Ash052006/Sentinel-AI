"""Correlation strategies — Step 10B.

Defines the strategy abstraction consumed by the Correlation Agent and
the first deterministic baseline strategy (same-event correlation).

Detection answers *"what individual detection rules matched this
event?"*.  Correlation answers *"which detections/events are related?"*
— for Step 10B that answer is deliberately minimal and deterministic:
two detections are correlated when and only when they originate from the
*same source event* (identical ``event_id``).

Design principles:

* **Strategy abstraction** — the agent consumes a
  :class:`CorrelationStrategy`; the baseline
  :class:`DeterministicCorrelationStrategy` is the first implementation.
  Future strategies (temporal, entity, graph, ML-assisted) can be added
  without rewriting the agent.
* **Deterministic partition** — every input belongs to exactly one
  :class:`CorrelationGroup`.  Groups preserve first-seen input order;
  members preserve batch order.  No unordered collections drive output.
* **Explainable** — every group carries a ``signal`` naming the exact
  deterministic reason its members are related.
* **No invented semantics** — timestamps, rule ids, severities,
  confidences, evidence, and metadata are never compared, aggregated,
  scored, or reused as grouping signals.
* **Pure & non-mutating** — the strategy never mutates its inputs and
  never depends on state outside the supplied sequence.
* **In-memory only** — no database, repository, API, message bus,
  external service, graph store, or external AI.

Relationship to the pipeline::

    DetectionCorrelationBatch            (Step 9I)
        -> CorrelationAgent              (Step 10B)
            -> CorrelationStrategy       (this module)
                -> CorrelationGroup[]
                    -> CorrelationResult (Step 10A)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol, Sequence

from app.schemas.detection_correlation import DetectionCorrelationInput
from app.services.correlation.exceptions import CorrelationInputError

#: Grouping signal: a group whose members share the same source event.
SIGNAL_SHARED_EVENT = "shared_event_id"

#: Grouping signal: a detection sharing no event with any other input.
SIGNAL_STANDALONE = "standalone_detection"


# ---------------------------------------------------------------------------
# Correlation group (strategy output unit)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationGroup:
    """One deterministic partition of the batch's detections.

    Attributes:
        members: The grouped ``DetectionCorrelationInput`` records, in
            batch order — never deduplicated and never reordered.
        signal: The exact deterministic reason the members are related
            (``SIGNAL_SHARED_EVENT`` or ``SIGNAL_STANDALONE`` for the
            baseline strategy).
        event_id: The event that defines the group — the shared event
            for ``SIGNAL_SHARED_EVENT`` groups, the member's own event
            for ``SIGNAL_STANDALONE`` groups.
    """

    members: tuple[DetectionCorrelationInput, ...]
    signal: str
    event_id: uuid.UUID


# ---------------------------------------------------------------------------
# Strategy contract
# ---------------------------------------------------------------------------


class CorrelationStrategy(Protocol):
    """Strategy contract consumed by the Correlation Agent.

    A strategy deterministically partitions a sequence of correlation
    inputs into ordered :class:`CorrelationGroup` objects.  It must:

    * be deterministic (same inputs always produce equivalent groups, in
      the same order);
    * be stateless (operate only on the supplied inputs);
    * never mutate its inputs;
    * raise :class:`CorrelationInputError` for records that are not
      ``DetectionCorrelationInput``;
    * raise any other exception only for genuine strategy failures (the
      agent converts those into :class:`CorrelationStrategyError`).
    """

    name: str

    def correlate(
        self,
        inputs: Sequence[DetectionCorrelationInput],
    ) -> list[CorrelationGroup]:
        """Partition *inputs* into correlation groups, in stable order."""
        ...


# ---------------------------------------------------------------------------
# Baseline deterministic strategy
# ---------------------------------------------------------------------------


class DeterministicCorrelationStrategy:
    """Baseline deterministic strategy — same-event correlation.

    Establishes correlation through exactly one signal: the ``event_id``
    shared by two or more detections.  Two detections belong to the same
    correlation **if and only if** they carry the same ``event_id``;
    every detection that shares no event with any other input forms its
    own standalone correlation (Step 10A permits single-member results).

    Deliberately **not** used as grouping signals:

    * ``timestamp`` / temporal proximity — no time window is configured;
      temporal proximity alone never establishes correlation.
    * ``rule_id`` / ``rule_type`` / ``rule_version`` — a rule firing on
      independent events is a property of the rule, not a relationship
      between detections; grouping on it would over-correlate.
    * ``severity`` / ``confidence`` — never aggregated or reinterpreted.
    * ``evidence`` / ``metadata`` — never compared or interpreted.
    * ``detection_id`` — identity, not a relationship.

    Complexity: O(n) time and O(n) space — a single indexed pass groups
    by ``event_id``; there are no pairwise comparisons.
    """

    name = "deterministic_same_event"

    def correlate(
        self,
        inputs: Sequence[DetectionCorrelationInput],
    ) -> list[CorrelationGroup]:
        """Partition *inputs* deterministically by ``event_id``.

        Groups follow first-seen input order; each group's members keep
        the batch order.  Every input belongs to exactly one group:
        a shared-event group when another input carries the same
        ``event_id``, otherwise a standalone group.

        Raises:
            CorrelationInputError: if any element is not a
                ``DetectionCorrelationInput``.
        """
        group_index_by_event: dict[uuid.UUID, int] = {}
        members_by_group: list[list[DetectionCorrelationInput]] = []

        for index, item in enumerate(inputs):
            if not isinstance(item, DetectionCorrelationInput):
                raise CorrelationInputError(
                    "correlation input at position"
                    f" {index} is not a"
                    " DetectionCorrelationInput;"
                    " received"
                    f" {type(item).__module__}"
                    f".{type(item).__qualname__}"
                )
            event_idx = group_index_by_event.get(item.event_id)
            if event_idx is None:
                group_index_by_event[item.event_id] = (
                    len(members_by_group)
                )
                members_by_group.append([item])
            else:
                members_by_group[event_idx].append(item)

        groups: list[CorrelationGroup] = []
        for members in members_by_group:
            shared = len(members) > 1
            groups.append(
                CorrelationGroup(
                    members=tuple(members),
                    signal=(
                        SIGNAL_SHARED_EVENT
                        if shared
                        else SIGNAL_STANDALONE
                    ),
                    event_id=members[0].event_id,
                )
            )
        return groups