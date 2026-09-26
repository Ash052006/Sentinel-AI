"""Incident Memory Learning & Consolidation service (Step 22).

Deterministically consolidates **already-persisted** incident memories into
structured, reusable historical lessons.  This is a read-only analysis of
history: it never calls an LLM / RAG / vector store, never writes to the
database, exposes no API, never mutates memory, and produces no policy,
playbook, rule, detection, response, threat-intel or model changes.

Architecture boundary — **query-only consumption**::

    incident_memories (Step 17 persistence)
        -> IncidentMemoryQueryService (Step 18, read-only)
            -> IncidentMemoryLearningService (this module, read-only)
                -> IncidentMemoryLearningResult

The learning service composes **only** :class:`IncidentMemoryQueryService`
methods (``list_memories``).  It holds no SQLAlchemy session/model/repository
dependency and never calls ``add``/``delete``/``flush``/``commit``/
``rollback``; a caller-owned ``db`` object is passed through verbatim to the
query service exactly as the Step 18 convention requires.  A query-service
factory is injected for testability and the instance is type-checked at the
last possible moment so the boundary can never be bypassed.

Deterministic strategy
----------------------
* **Same memories in, same lessons out.**  Identical corpora produce
  byte-identical ``IncidentMemoryLearningResult`` JSON (modulo the injected
  ``uuid_factory``/``clock``, exactly like the Step 16 extractor).
* **Explicit incident-memory fields only.**  Patterns are read off the Step
  16/18 contract: ``memory_type``, structured ``indicators`` /
  ``techniques`` / ``actions``, explicit ``outcomes`` (a bounded free
  ``outcome_status`` string, never interpreted as success/failure), and
  ``sources`` provenance.  Anything the contract cannot express (event
  categories, detection rule identifiers) is out of scope and is never
  fabricated.
* **Canonical grouping.**  Patterns group by ``(learning_type, pattern_key)``
  with a canonical key construction; groups are enumerated in enum order and
  key-sorted; every ``supporting_memory_ids`` list is ascending and
  duplicate-free; no database row order, Python set iteration or dict
  insertion order is ever relied upon.
* **Distinct-memory occurrence counts.**  ``occurrence_count`` counts the
  distinct supporting memories (a memory exhibiting a pattern twice still
  supports it once), keeping every count comparable across corpora.
* **Confidence is support-count-derived only** and documented
  mathematically (see :data:`LEARNING_CONFIDENCE_SATURATION`); it is
  independent from memory/risk/detection/investigation/attribution
  confidence.

Outcome consolidation
---------------------
A supporting memory either carries an explicit Step 16 outcome (non-empty
``outcomes``) or is *missing* one.  ``explicit_outcome_count`` and
``missing_outcome_count`` always sum to ``occurrence_count``; the unique
explicit ``outcome_status`` strings are preserved alongside one another —
conflicting statuses are **never** resolved by majority and missing is never
converted to a success/failure.

Bounds & safety
---------------
* All bounds are rejection bounds (never silent truncation): the input
  corpus cap, the per-record supporting-reference cap and the output-record
  cap refuse the operation when exceeded.
* Fail-closed, secret-safe: the assembled outcome is re-scanned with the
  canonical credential-shaped patterns (kept in lock-step with
  ``app/agents/investigation/_safety.py`` — re-declared here so this layer
  stays dependency-light and never imports the AI provider graph).  A match
  raises :class:`IncidentMemoryLearningSafetyError`; nothing is logged raw
  and no error message ever echoes memory or secret content.
* Immutability: source records, query results and supporting lists are never
  mutated; every assembled record is an independent validated model.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from app.schemas.incident_memory_learning import (
    IncidentMemoryLearning,
    IncidentMemoryLearningResult,
    LearningOutcomeInfo,
    LearningType,
    MAX_LEARNING_OUTPUT_RECORDS,
    MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES,
)
from app.schemas.incident_memory_query import (
    IncidentMemoryPage,
    IncidentMemoryRecord,
)
from app.services.incident_memory_query import (
    IncidentMemoryQueryService,
    MAX_PAGE_SIZE,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------

#: Policy label recorded in every learning record's metadata.
POLICY_NAME = "deterministic_incident_memory_learning_v1"

#: Confidence saturation — the distinct-memory occurrence count at which a
#: consolidation's support-derived confidence reaches 1.0.
#:
#: .. math::
#:
#:     confidence(occurrence\_count) = min(1.0, occurrence\_count / 5)
#:
#: Monotonic, deterministic, bounded to ``[0.0, 1.0]`` and derived *only*
#: from explicit support — never from memory/risk/detection/investigation/
#: attribution confidence.
LEARNING_CONFIDENCE_SATURATION = 5

#: Confidence formula, recorded verbatim in run metadata for explainability.
CONFIDENCE_FORMULA = (
    "min(1.0, occurrence_count / LEARNING_CONFIDENCE_SATURATION)"
)

#: Hard cap on the persisted-memory corpus a single consolidation may read.
#: A larger corpus is REFUSED (never truncated).
MAX_LEARNING_INPUT_MEMORIES = 5000

#: Minimum distinct-memory occurrence count for a group to become a learning
#: record.  A single occurrence is a fact, not a recurring lesson.
DEFAULT_MIN_OCCURRENCES = 2


class _PatternHit:
    """One explicit pattern occurrence read off an incident-memory record."""

    __slots__ = ("learning_type", "pattern_key", "pattern_value")

    def __init__(
        self,
        learning_type: LearningType,
        pattern_key: str,
        pattern_value: str,
    ) -> None:
        self.learning_type = learning_type
        self.pattern_key = pattern_key
        self.pattern_value = pattern_value


def _pattern_hits(record: IncidentMemoryRecord) -> list[_PatternHit]:
    """Read every explicit pattern occurrence from one memory record.

    Uses only fields present in the Step 16/18 incident-memory contract:
    ``memory_type``, per-item structured ``indicators`` (``indicator_type`` +
    ``value``), ``techniques`` (``technique_code``), ``actions``
    (``action_type``), explicit ``outcomes`` (``outcome_status``), and
    per-source ``sources`` provenance.  Anything else — event categories,
    detection rule identifiers, prose — is out of scope and never read.
    """
    hits: list[_PatternHit] = [
        _PatternHit(
            LearningType.RECURRING_MEMORY_TYPE,
            f"memory_type={record.memory_type.value}",
            record.memory_type.value,
        )
    ]
    for indicator in record.indicators:
        indicator_type = indicator.get("indicator_type")
        value = indicator.get("value")
        if isinstance(indicator_type, str) and isinstance(value, str):
            hits.append(
                _PatternHit(
                    LearningType.RECURRING_INDICATOR,
                    f"indicator_type={indicator_type}|value={value}",
                    value,
                )
            )
    for technique in record.techniques:
        code = technique.get("technique_code")
        if isinstance(code, str):
            hits.append(
                _PatternHit(
                    LearningType.RECURRING_TECHNIQUE,
                    f"technique_code={code}",
                    code,
                )
            )
    for action in record.actions:
        action_type = action.get("action_type")
        if isinstance(action_type, str):
            hits.append(
                _PatternHit(
                    LearningType.RECURRING_ACTION,
                    f"action_type={action_type}",
                    action_type,
                )
            )
    if record.outcomes:
        outcome_status = record.outcomes.get("outcome_status")
        if isinstance(outcome_status, str):
            hits.append(
                _PatternHit(
                    LearningType.RECURRING_OUTCOME,
                    f"outcome_status={outcome_status}",
                    outcome_status,
                )
            )
    for source in record.sources:
        provenance = source.get("provenance")
        if isinstance(provenance, str):
            hits.append(
                _PatternHit(
                    LearningType.RECURRING_SOURCE_PROVENANCE,
                    f"source_provenance={provenance}",
                    provenance,
                )
            )
    return hits


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class IncidentMemoryLearningError(Exception):
    """Raised when an incident-memory consolidation cannot be produced.

    Instances never contain credentials, raw evidence, raw memory payloads,
    raw database/SQL error text, or tracebacks — only safe, generic
    contextual wording.  The underlying exception is preserved as
    ``__cause__`` for server-side logging.
    """


class IncidentMemoryLearningInputValidationError(IncidentMemoryLearningError):
    """Raised when consolidation input cannot be validated safely.

    Raised *before* any query work: an unusable clock / uuid_factory, an
    invalid ``min_occurrences``, a non-:class:`IncidentMemoryQueryService`
    provider, an undersized/broken query result, or an over-cap corpus /
    support-set / output all land here (refuse, never truncate).
    """


class IncidentMemoryLearningQueryError(IncidentMemoryLearningError):
    """Raised when the underlying query service cannot satisfy the read.

    The original failure is chained; the message stays generic and never
    repeats driver/SQL text.
    """


class IncidentMemoryLearningStrategyError(IncidentMemoryLearningError):
    """Raised when the deterministic consolidation pipeline fails unexpectedly.

    The original cause is preserved through the ``__cause__`` chain; the
    message is deliberately generic and never repeats the underlying
    exception's content.
    """


class IncidentMemoryLearningOutputValidationError(IncidentMemoryLearningError):
    """Raised when an assembled learning record fails contract re-validation.

    The consolidation never downgrades a genuine failure into a partial or
    empty result.
    """


class IncidentMemoryLearningSafetyError(
    IncidentMemoryLearningError, ValueError
):
    """Credential-shaped content was detected in learning output (fail closed).

    Subclasses both ``IncidentMemoryLearningError`` and ``ValueError``
    (mirroring ``IncidentMemorySafetyError``).  Secrets are rejected, never
    redacted.
    """


# ---------------------------------------------------------------------------
# Secret-safety scan (re-declared canonical patterns, dependency-light)
# ---------------------------------------------------------------------------

#: Credential-shaped substrings, kept in lock-step with the canonical set in
#: ``app/agents/investigation/_safety.py`` (and every staged schema).  The
#: block is re-declared here so this layer never imports the AI-provider
#: graph.
_SECRET_PATTERNS = (
    "api_key",
    "authorization",
    "bearer",
    "secret",
    "password",
    "cookie",
    "session_token",
    "jwt",
)

#: Credential-shaped *value* patterns scanned at the service boundary.
_SECRET_VALUE_PATTERNS = re.compile(
    r"(?<![A-Za-z0-9])(?:api[_-]?key|authorization|bearer|secret|password|"
    r"cookie|session[_-]?token|jwt)(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def _assert_learning_output_secret_free(payload: Any) -> None:
    """Fail-closed secret scan over a serialized learning payload.

    Serializes the whole payload and scans for credential-shaped *value*
    patterns plus the canonical substring set — the same defence-in-depth
    grid the Step 16 extractor applies.  Shape-based: benign-looking values
    that merely match the patterns are still rejected — secrets are rejected,
    never redacted.
    """
    for value in _string_values(payload):
        match = _SECRET_VALUE_PATTERNS.search(value)
        if match is not None:
            raise IncidentMemoryLearningSafetyError(
                "incident memory learning output must not contain "
                "secret-shaped content; secrets are rejected, never redacted"
            )
    serialized = json.dumps(payload, sort_keys=True).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern in serialized:
            raise IncidentMemoryLearningSafetyError(
                "incident memory learning output must not contain "
                "secret-shaped content; secrets are rejected, never redacted"
            )


def _string_values(obj: Any, acc: list[str] | None = None) -> list[str]:
    """Collect every string in a JSON-safe structure (deterministic scan)."""
    if acc is None:
        acc = []
    if isinstance(obj, dict):
        for value in obj.values():
            _string_values(value, acc)
    elif isinstance(obj, list):
        for value in obj:
            _string_values(value, acc)
    elif isinstance(obj, str):
        acc.append(obj)
    return acc


# ---------------------------------------------------------------------------
# Consolidation service
# ---------------------------------------------------------------------------


class IncidentMemoryLearningService:
    """Deterministic, read-only consolidation of persisted incident memories.

    Consumes memory exclusively through an injected
    :class:`~app.services.incident_memory_query.IncidentMemoryQueryService`
    (created from the injected factory with the caller-owned ``db``).  The
    service is stateless; every call produces an independent
    :class:`IncidentMemoryLearningResult`.

    Args:
        query_service_factory: Optional factory mapping a caller-owned DB
            connection/context object to an
            :class:`IncidentMemoryQueryService`; defaults to the real query
            service.  Injected for testability — tests may supply a fake
            query service, but it must still be an
            :class:`IncidentMemoryQueryService` instance so the boundary can
            never be widened.
    """

    def __init__(
        self,
        query_service_factory: Callable[
            [Any], IncidentMemoryQueryService
        ] = IncidentMemoryQueryService,
    ) -> None:
        self._query_service_factory = query_service_factory

    def consolidate(
        self,
        db: Any,
        *,
        clock: datetime | None = None,
        uuid_factory: Callable[[], uuid.UUID] | None = None,
        min_occurrences: int = DEFAULT_MIN_OCCURRENCES,
    ) -> IncidentMemoryLearningResult:
        """Consolidate the bounded persisted-memory corpus into lessons.

        Arguments mirror the Step 16 extractor's injection pattern:

        * ``clock`` — timezone-aware instant stamped as every learning
          record's ``created_at`` and the result envelope's (default:
          ``datetime.now(timezone.utc)``).
        * ``uuid_factory`` — minted ``learning_id`` values (default:
          :func:`uuid.uuid4`).
        * ``min_occurrences`` — minimum distinct-memory support for a group
          to be emitted as a lesson.

        Raises
        ------
        IncidentMemoryLearningInputValidationError:
            unusable ``clock`` / ``uuid_factory`` / ``min_occurrences``, an
            unusable query-service factory, a provider that is not an
            ``IncidentMemoryQueryService``, a corpus larger than
            :data:`MAX_LEARNING_INPUT_MEMORIES`, an inconsistent query
            result, or a resolved group / record count exceeding its cap
            (refuse, never truncate).
        IncidentMemoryLearningQueryError:
            the underlying query service failed (sanitized, chained).
        IncidentMemoryLearningSafetyError:
            secret-shaped content detected in the assembled output.
        IncidentMemoryLearningOutputValidationError:
            an assembled record failed contract re-validation.
        IncidentMemoryLearningStrategyError:
            any unexpected consolidation failure (chained to its cause).
        """
        if clock is None:
            clock = datetime.now(timezone.utc)
        if not isinstance(clock, datetime) or (
            clock.tzinfo is None or clock.tzinfo.utcoffset(clock) is None
        ):
            raise IncidentMemoryLearningInputValidationError(
                "clock must be a timezone-aware datetime instance"
            )
        if uuid_factory is None:
            uuid_factory = uuid.uuid4
        if not callable(uuid_factory):
            raise IncidentMemoryLearningInputValidationError(
                "uuid_factory must be callable"
            )
        try:
            if isinstance(min_occurrences, bool):
                raise TypeError()
            min_occurrences_int = int(min_occurrences)
        except (TypeError, ValueError) as exc:
            raise IncidentMemoryLearningInputValidationError(
                "min_occurrences must be an integer"
            ) from exc
        if min_occurrences_int != min_occurrences:
            raise IncidentMemoryLearningInputValidationError(
                "min_occurrences must be an integer"
            )
        if min_occurrences_int < 1:
            raise IncidentMemoryLearningInputValidationError(
                "min_occurrences must be >= 1"
            )
        if min_occurrences_int > MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES:
            raise IncidentMemoryLearningInputValidationError(
                "min_occurrences must not exceed "
                f"{MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES}"
            )

        try:
            query = self._query_service_factory(db)
        except Exception as exc:
            raise IncidentMemoryLearningInputValidationError(
                "the query-service factory must be callable and produce an "
                "IncidentMemoryQueryService"
            ) from exc
        if not isinstance(query, IncidentMemoryQueryService):
            raise IncidentMemoryLearningInputValidationError(
                "consolidation requires an IncidentMemoryQueryService; "
                "the injected provider is not one"
            )

        records = self._load_corpus(query, db)
        if len(records) > MAX_LEARNING_INPUT_MEMORIES:
            raise IncidentMemoryLearningInputValidationError(
                "incident memory learning refuses corpora larger than "
                f"{MAX_LEARNING_INPUT_MEMORIES} memories; refusing rather "
                "than silently truncating the historical record"
            )

        try:
            learnings = self._consolidate_records(
                records,
                clock=clock,
                uuid_factory=uuid_factory,
                min_occurrences=min_occurrences_int,
            )
        except IncidentMemoryLearningError:
            raise
        except Exception as exc:
            raise IncidentMemoryLearningStrategyError(
                "incident memory learning consolidation failed unexpectedly"
            ) from exc
        if len(learnings) > MAX_LEARNING_OUTPUT_RECORDS:
            raise IncidentMemoryLearningInputValidationError(
                "incident memory learning refuses results larger than "
                f"{MAX_LEARNING_OUTPUT_RECORDS} records; refusing rather "
                "than silently truncating the consolidation"
            )

        try:
            result = IncidentMemoryLearningResult(
                memory_count=len(records),
                record_count=len(learnings),
                records=learnings,
                metadata={
                    "policy": POLICY_NAME,
                    "confidence_formula": CONFIDENCE_FORMULA,
                    "confidence_saturation": LEARNING_CONFIDENCE_SATURATION,
                    "min_occurrences": min_occurrences_int,
                    "max_input_memories": MAX_LEARNING_INPUT_MEMORIES,
                    "max_supporting_references": (
                        MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES
                    ),
                    "max_output_records": MAX_LEARNING_OUTPUT_RECORDS,
                },
                created_at=clock,
            )
        except ValidationError as exc:
            raise IncidentMemoryLearningOutputValidationError(
                "the assembled learning result failed contract re-validation"
            ) from exc
        _assert_learning_output_secret_free(result.model_dump(mode="json"))
        return result

    # ------------------------------------------------------------------
    # Corpus loading (query-service only)
    # ------------------------------------------------------------------

    @staticmethod
    def _load_corpus(
        query: IncidentMemoryQueryService, db: Any
    ) -> list[IncidentMemoryRecord]:
        """Load the full persisted corpus through the query service only.

        Pages ``list_memories`` (bounded pages, deterministic ordering) until
        ``total`` is reached.  *)
        """
        try:
            first = query.list_memories(db, page=1, page_size=MAX_PAGE_SIZE)
            total = first.total
            collected = list(first.items)
            page = 1
            while len(collected) < total:
                page += 1
                next_page: IncidentMemoryPage = query.list_memories(
                    db, page=page, page_size=MAX_PAGE_SIZE
                )
                if not next_page.items:
                    raise IncidentMemoryLearningInputValidationError(
                        "incident memory query returned an incomplete page; "
                        "consolidation refuses an inconsistent corpus"
                    )
                collected.extend(next_page.items)
            if len(collected) != total:
                raise IncidentMemoryLearningInputValidationError(
                    "incident memory query returned an inconsistent corpus; "
                    "consolidation refuses it"
                )
            return collected
        except IncidentMemoryLearningError:
            raise
        except Exception as exc:
            logger.warning(
                "Incident memory learning query failed: %s", exc
            )
            raise IncidentMemoryLearningQueryError(
                "incident memory learning could not read incident memories"
            ) from exc

    # ------------------------------------------------------------------
    # Deterministic consolidation
    # ------------------------------------------------------------------

    @staticmethod
    def _consolidate_records(
        records: list[IncidentMemoryRecord],
        *,
        clock: datetime,
        uuid_factory: Callable[[], uuid.UUID],
        min_occurrences: int,
    ) -> list[IncidentMemoryLearning]:
        """Consolidate the corpus into deterministic learning records.

        Deterministic by construction: induction over the input order feeds
        into canonical groups; groups are emitted in enum order then key
        order; supporting ids are always ascending and duplicate-free.  No
        set/dict/Db insertion order is ever relied on.
        """
        groups: dict[tuple[LearningType, str], set[uuid.UUID]] = {}
        values: dict[tuple[LearningType, str], str] = {}
        memory_types: dict[uuid.UUID, str] = {}
        memory_created: dict[uuid.UUID, datetime] = {}
        memory_has_outcome: dict[uuid.UUID, bool] = {}
        memory_outcome_statuses: dict[uuid.UUID, set[str]] = {}
        correlation_derived: set[uuid.UUID] = set()

        for record in records:
            memory_id = record.memory_id
            memory_types[memory_id] = record.memory_type.value
            memory_created[memory_id] = record.created_at
            memory_has_outcome[memory_id] = bool(record.outcomes)
            if record.correlation_id is not None:
                correlation_derived.add(memory_id)
            statuses: set[str] = set()
            if record.outcomes:
                status_value = record.outcomes.get("outcome_status")
                if isinstance(status_value, str):
                    statuses.add(status_value)
            memory_outcome_statuses[memory_id] = statuses
            for hit in _pattern_hits(record):
                key = (hit.learning_type, hit.pattern_key)
                group = groups.get(key)
                if group is None:
                    group = set()
                    groups[key] = group
                    values[key] = hit.pattern_value
                group.add(memory_id)

        learnings: list[IncidentMemoryLearning] = []
        for learning_type in LearningType:
            typed_keys = sorted(
                (key for key in groups if key[0] is learning_type),
                key=lambda key: key[1],
            )
            for key in typed_keys:
                supports = groups[key]
                order = sorted(supports)
                if len(order) < min_occurrences:
                    continue
                if len(order) > MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES:
                    raise IncidentMemoryLearningInputValidationError(
                        "incident memory learning refuses a consolidated "
                        f"pattern supported by more than "
                        f"{MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES} "
                        "memories; refusing rather than silently dropping "
                        "supporting evidence"
                    )
                explicit = sum(1 for mid in order if memory_has_outcome[mid])
                missing = len(order) - explicit
                statuses: set[str] = set()
                for mid in order:
                    statuses |= memory_outcome_statuses[mid]
                outcome_statuses = sorted(statuses)
                _assert_learning_output_secret_free(
                    {
                        "pattern_key": key[1],
                        "pattern_value": values[key],
                        "outcome_statuses": outcome_statuses,
                    }
                )
                try:
                    outcome = LearningOutcomeInfo(
                        explicit_outcome_count=explicit,
                        missing_outcome_count=missing,
                        outcome_statuses=outcome_statuses,
                    )
                    seen = [memory_created[mid] for mid in order]
                    learning = IncidentMemoryLearning(
                        learning_id=uuid_factory(),
                        learning_type=learning_type,
                        pattern_key=key[1],
                        pattern_value=values[key],
                        supporting_memory_ids=order,
                        occurrence_count=len(order),
                        first_seen=min(seen),
                        last_seen=max(seen),
                        outcome=outcome,
                        confidence=min(
                            1.0, len(order) / LEARNING_CONFIDENCE_SATURATION
                        ),
                        metadata={
                            "policy": POLICY_NAME,
                            "learning_type": learning_type.value,
                            "min_occurrences": min_occurrences,
                            "supporting_memory_types": sorted(
                                {memory_types[mid] for mid in order}
                            ),
                            "any_correlation_derived": any(
                                mid in correlation_derived for mid in order
                            ),
                        },
                        created_at=clock,
                    )
                except ValidationError as exc:
                    raise IncidentMemoryLearningOutputValidationError(
                        "an assembled learning record failed contract "
                        "re-validation"
                    ) from exc
                learnings.append(learning)
        return learnings