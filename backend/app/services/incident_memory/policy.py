"""Incident Memory deterministic extraction policy — Step 16 foundation.

Defines *when* memory is produced and *how it is assembled* without any
inference.  The policy answers three deterministic questions:

1. **Sufficiency** (:func:`memory_satisfied`) — is there enough explicitly
   supplied, provenance-grounded structured information to produce a memory
   of a given :class:`~app.schemas.incident_memory.MemoryType`?
2. **Canonical ordering** (:data:`MEMORY_TYPE_ORDER`) — the fixed order in
   which satisfiable memories are emitted, so identical input always yields
   identical output order.
3. **Assembly** (:func:`memory_for_type`) — how one memory record is built:
   cloning the exact supplied facts (never inferring), preserving every
   source reference and original provenance, and stamping injected
   identity (``memory_id``) and time (``created_at``).

Key rules:

* **Nothing is inferred.**  A memory contains exactly the sources,
  indicators, entities, techniques, findings, actions, and outcome the
  caller supplied.  No summary is fabricated "because a correlation
  exists", and no attacker/indicator/technique/verdict is invented.
* **Provenance-grounded.**  A type-specific memory is emitted only when
  **every** one of that type's content items references at least one
  source.  Referenceless items are not silently dropped into memory; when
  such items exist, that memory type is simply not satisfiable (a valid
  zero-output, not an exception).
* **Sufficiency is per-type and independent.**  Empty input emits no
  memories.  A summary with no sources emits no ``incident_summary``
  memory.  Confidence, risk, detection severity, and attribution play no
  role in sufficiency.
* **Deterministic.**  Lists keep input order; ids of sources and content
  items are carried over as supplied (memory_id + created_at are injected
  by the caller of :func:`memory_for_type`); metadata is policy-built and
  free of timestamps/identities.  Assembled memories are independent deep
  copies: mutating the input after extraction never mutates the memory.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

from app.schemas.incident_memory import (
    IncidentMemory,
    MemoryAction,
    MemoryEntity,
    MemoryFinding,
    MemoryIndicator,
    MemoryOutcome,
    MemorySource,
    MemoryTechnique,
    MemoryType,
)
from app.services.incident_memory.input import IncidentMemoryInput

#: Policy label recorded in every memory's metadata.
POLICY_NAME = "deterministic_incident_memory_signals_v1"

#: Canonical emission order (the enum declaration order).
MEMORY_TYPE_ORDER: tuple[MemoryType, ...] = tuple(MemoryType)

#: Decision paths recorded in metadata (explainability).
DECISION_TITLE_AND_SUMMARY = "incident_summary_with_source_grounding"
DECISION_ALL_INDICATORS_GROUNDED = "all_indicators_source_grounded"
DECISION_ALL_TECHNIQUES_GROUNDED = "all_techniques_source_grounded"
DECISION_ALL_FINDINGS_GROUNDED = "all_findings_source_grounded"
DECISION_ACTIONS_OR_OUTCOME_GROUNDED = "actions_or_outcome_source_grounded"
DECISION_NO_SUMMARY = "no_summary_to_remember"
DECISION_NO_SOURCES = "no_source_grounding"
DECISION_EMPTY_CONTENT = "no_supported_content"

_ContentModel = (
    MemoryIndicator | MemoryEntity | MemoryTechnique | MemoryFinding | MemoryAction |
    MemorySource | MemoryOutcome
)


def _clone(item: _ContentModel) -> _ContentModel.__class__:
    """Independent deep copy of a content record (JSON round-trip).

    Guarantees the assembled memory never shares mutable state with the
    input the caller supplied.
    """
    return type(item).model_validate_json(item.model_dump_json())


def _items_reference_source(item: _ContentModel) -> bool:
    return bool(getattr(item, "source_ids", ()))


def memory_satisfied(
    memory_type: MemoryType, input_data: IncidentMemoryInput
) -> bool:
    """Whether *input_data* has sufficient grounded info for *memory_type*.

    Pure and deterministic; never raises for "not enough" — it returns
    ``False``.
    """
    if memory_type is MemoryType.INCIDENT_SUMMARY:
        return bool(input_data.summary) and bool(input_data.sources)
    if memory_type is MemoryType.INDICATOR_OBSERVATION:
        return bool(input_data.indicators) and all(
            _items_reference_source(item) for item in input_data.indicators
        )
    if memory_type is MemoryType.ATTACK_PATTERN:
        return bool(input_data.techniques) and all(
            _items_reference_source(item) for item in input_data.techniques
        )
    if memory_type is MemoryType.INVESTIGATION_FINDING:
        return bool(input_data.findings) and all(
            _items_reference_source(item) for item in input_data.findings
        )
    if memory_type is MemoryType.MITIGATION_OUTCOME:
        actions_grounded = bool(input_data.actions) and all(
            _items_reference_source(item) for item in input_data.actions
        )
        outcome_grounded = bool(
            input_data.outcome
        ) and bool(input_data.outcome.source_ids)
        return actions_grounded or outcome_grounded
    return False


def satisfied_memory_types(
    input_data: IncidentMemoryInput,
    memory_types: tuple[MemoryType, ...] | None = None,
) -> tuple[MemoryType, ...]:
    """Canonically ordered tuple of satisfiable memory types.

    *memory_types*, when given, restricts the candidate set (an unsupported
    value raises elsewhere; this function filters to what is satisfiable).
    """
    candidates = memory_types if memory_types is not None else MEMORY_TYPE_ORDER
    ordered = [t for t in MEMORY_TYPE_ORDER if t in candidates]
    return tuple(t for t in ordered if memory_satisfied(t, input_data))


def decision_reason(
    memory_type: MemoryType, input_data: IncidentMemoryInput
) -> str:
    """Deterministic, human-readable reason for a satisfiable type.

    Also used when unsatisfiable, so ``build_policy_metadata`` can describe
    the absence deterministically.
    """
    if memory_type is MemoryType.INCIDENT_SUMMARY:
        if not input_data.summary:
            return DECISION_NO_SUMMARY
        if not input_data.sources:
            return DECISION_NO_SOURCES
        return DECISION_TITLE_AND_SUMMARY
    if memory_type is MemoryType.INDICATOR_OBSERVATION:
        if not input_data.indicators:
            return DECISION_EMPTY_CONTENT
        return DECISION_ALL_INDICATORS_GROUNDED
    if memory_type is MemoryType.ATTACK_PATTERN:
        if not input_data.techniques:
            return DECISION_EMPTY_CONTENT
        return DECISION_ALL_TECHNIQUES_GROUNDED
    if memory_type is MemoryType.INVESTIGATION_FINDING:
        if not input_data.findings:
            return DECISION_EMPTY_CONTENT
        return DECISION_ALL_FINDINGS_GROUNDED
    if memory_type is MemoryType.MITIGATION_OUTCOME:
        if not input_data.actions and not input_data.outcome:
            return DECISION_EMPTY_CONTENT
        return DECISION_ACTIONS_OR_OUTCOME_GROUNDED
    return DECISION_EMPTY_CONTENT


def build_policy_metadata(
    memory_type: MemoryType, input_data: IncidentMemoryInput
) -> dict[str, object]:
    """Policy-built memory metadata (JSON-safe, secret-free, deterministic).

    Contains only counts, the policy label, the memory type, and the
    decision — never timestamps, identities, or content copied from items.
    """
    return {
        "policy": POLICY_NAME,
        "memory_type": memory_type.value,
        "decision": decision_reason(memory_type, input_data),
        "source_count": len(input_data.sources),
        "indicator_count": len(input_data.indicators),
        "entity_count": len(input_data.entities),
        "technique_count": len(input_data.techniques),
        "finding_count": len(input_data.findings),
        "action_count": len(input_data.actions),
        "has_outcome": input_data.outcome is not None,
    }


def memory_for_type(
    input_data: IncidentMemoryInput,
    memory_type: MemoryType,
    *,
    timestamp: datetime,
    uuid_factory: Callable[[], uuid.UUID],
) -> IncidentMemory:
    """Assemble one :class:`IncidentMemory` of *memory_type*.

    Pure assembly: the memory carries exactly the input's facts, with
    content restricted to the type's own record set.  ``summary`` is only
    carried on ``INCIDENT_SUMMARY`` memories; ``title`` (explicit input)
    is carried on every memory.  Source and content item ids are preserved
    as supplied; only ``memory_id`` is minted by *uuid_factory* and
    ``created_at`` stamped from *timestamp*.

    Every content record in the result is an independent copy; the input
    is never mutated and no mutable state is shared with it.
    """
    if memory_type is MemoryType.INCIDENT_SUMMARY:
        indicators: list[MemoryIndicator] = []
        entities: list[MemoryEntity] = []
        techniques: list[MemoryTechnique] = []
        findings: list[MemoryFinding] = []
        actions: list[MemoryAction] = []
        outcome: MemoryOutcome | None = None
        summary = input_data.summary
    elif memory_type is MemoryType.INDICATOR_OBSERVATION:
        indicators = [_clone(i) for i in input_data.indicators]
        entities, techniques, findings, actions, outcome, summary = (
            [], [], [], [], None, None
        )
    elif memory_type is MemoryType.ATTACK_PATTERN:
        techniques = [_clone(i) for i in input_data.techniques]
        indicators, entities, findings, actions, outcome, summary = (
            [], [], [], [], None, None
        )
    elif memory_type is MemoryType.INVESTIGATION_FINDING:
        findings = [_clone(i) for i in input_data.findings]
        indicators, entities, techniques, actions, outcome, summary = (
            [], [], [], [], None, None
        )
    else:  # MITIGATION_OUTCOME
        actions = [_clone(i) for i in input_data.actions]
        outcome = (
            _clone(input_data.outcome)
            if input_data.outcome is not None
            else None
        )
        indicators, entities, techniques, findings, summary = (
            [], [], [], [], None
        )

    return IncidentMemory(
        memory_id=uuid_factory(),
        memory_type=memory_type,
        title=input_data.title,
        summary=summary,
        correlation_id=input_data.correlation_id,
        sources=[_clone(s) for s in input_data.sources],
        indicators=indicators,
        entities=entities,
        techniques=techniques,
        findings=findings,
        actions=actions,
        outcome=outcome,
        confidence=input_data.confidence,
        created_at=timestamp,
        metadata=build_policy_metadata(memory_type, input_data),
    )