"""Detection persistence service (Step 9F-B).

Translates a Step 9E :class:`~app.schemas.detection_agent.DetectionAnalysis`
into PostgreSQL persistence operations using the Step 9F-A contract models
(:class:`~app.models.detection_result.DetectionResult`,
:class:`~app.models.detection_rule_failure.DetectionRuleFailure`) through
the :class:`~app.repositories.detection.DetectionRepository`.

Pipeline:::

    DetectionAnalysis
        ↓  (this service)
    DetectionResult        (one row per matched result, keyed by detection_id)
        ↓
    DetectionRuleFailure   (one row per rule/engine failure)

Behavioural guarantees
----------------------
* **No rule execution.**  The service never parses, compiles, or evaluates
  detection rules; it only persists a completed analysis.
* **Transactional.**  All work for one analysis commits in a single
  ``Session.commit()``; any failure rolls the unit back and raises a safe
  :class:`DetectionPersistenceError` (no partial state).
* **Idempotent.**  Re-persisting the same analysis reuses existing rows.
  Successful matches are identified by their unique ``detection_id``;
  failures by ``(event_id, engine, rule_id, error_type, error_message)``.
  Legitimate re-evaluations (fresh ``detection_id`` values) are preserved
  as historical rows.
* **Provenance.**  Every row is stored with ``Provenance.DETECTED`` — never
  ``observed``/``enriched``/``reconstructed`` (enforced by CHECK constraint).
* **Secret-safe.**  Error messages are sanitized and structured
  evidence/metadata is recursively key-redacted before persistence.  No API
  keys, authorization headers, cookies, credentials, raw rule source, or
  raw event payloads are ever stored.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.models.detection_result import DetectionResult
from app.models.detection_rule_failure import DetectionRuleFailure
from app.repositories.detection import DetectionRepository
from app.schemas.detection_agent import DetectionAnalysis
from app.schemas.security_event import Provenance

logger = logging.getLogger(__name__)

#: Hard cap on serialized structured evidence/metadata (defense in depth).
_MAX_EVIDENCE_CHARS = 262_144

#: Hard cap on persisted error messages (defense in depth).
_MAX_ERROR_MESSAGE_CHARS = 4_000

#: Marker substituted for detected credentials anywhere in persisted data.
_REDACTED = "<redacted>"

#: ``rule_version`` fallback when a result carries no rule version.
_UNKNOWN_RULE_VERSION = "unknown"


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class DetectionPersistenceError(Exception):
    """Raised when a detection analysis cannot be persisted.

    Instances never contain credentials, raw rule content, raw event
    payloads, or raw database/SQL error text — only safe contextual
    identifiers such as the event UUID.
    """

    def __init__(self, event_id: uuid.UUID | None = None, reason: str = "") -> None:
        message = "Failed to persist detection analysis"
        if event_id is not None:
            message += f" for event {event_id}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.event_id = event_id


class DetectionPersistenceValidationError(DetectionPersistenceError):
    """Raised when an analysis cannot be mapped to persistence rows safely.

    Used for pre-commit validation failures (e.g. evidence exceeding the
    bounded size) that must abort the analysis transaction.
    """


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionPersistenceResult:
    """Summary of one ``persist_analysis`` invocation."""

    event_id: uuid.UUID
    result_ids: tuple[uuid.UUID, ...]
    failure_ids: tuple[uuid.UUID, ...]
    results_created: int = 0
    results_skipped: int = 0
    failures_created: int = 0
    failures_skipped: int = 0

    @property
    def is_empty(self) -> bool:
        """True when nothing was persisted (e.g. an empty analysis)."""
        return not (self.results_created or self.failures_created)


# ---------------------------------------------------------------------------
# Secret-safe sanitization
# ---------------------------------------------------------------------------

#: Labeled credential patterns inside error messages, e.g.
#: ``api_key=...``, ``x-api-key: ...``, ``token=...``.  Single-token
#: credentials are redacted together with their label.
_SECRET_LABEL_PATTERN = re.compile(
    r"(?i)((?:set-cookie|cookie|password|passwd|secret|token|api[_-]?key|"
    r"apikey|access[_-]?key|x[_-]?api[_-]?key)\s*[:=]\s*)[^\s,;]+"
)

#: ``Authorization: Bearer <token>`` / ``Authorization: Basic <creds>`` —
#: redacts the scheme and the credential together.
_AUTHORIZATION_PATTERN = re.compile(
    r"(?i)(authorization\s*[:=]\s*)(?:(?:bearer|basic)\s+)?[a-z0-9._~+/=-]+"
)

#: Bare ``Bearer`` / ``Basic`` credential tokens in error text.
_CREDENTIAL_TOKEN_PATTERN = re.compile(
    r"(?i)\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{16,}"
)

#: 64-char opaque tokens (e.g. leaked SHA-256-like API keys).
_BARE_TOKEN_PATTERN = re.compile(r"\b[0-9a-fA-F]{64}\b")

#: JWT-shaped tokens: the standard ``eyJ`` header magic followed by the
#: base64url header/payload/segments (dot-separated for a full JWT, or a
#: bare header in truncated/log text).
_JWT_TOKEN_PATTERN = re.compile(r"\beyJ[a-zA-Z0-9_./+=~-]{8,}")


def sanitize_error_message(message: str) -> str:
    """Return a secret-safe, bounded version of *message*.

    The Step 9E :class:`~app.schemas.detection_agent.DetectionFailure`
    contract already requires secret-safe messages; this is a second,
    defense-in-depth gate at the persistence boundary.  It redacts labeled
    credential values, ``Authorization`` headers (including Bearer/Basic
    tokens), bare credential tokens, JWT-shaped tokens, and 64-char opaque
    tokens, then truncates to a bounded length.
    """
    if not message:
        return message
    scrubbed = _SECRET_LABEL_PATTERN.sub(
        lambda match: f"{match.group(1)}{_REDACTED}", message
    )
    scrubbed = _AUTHORIZATION_PATTERN.sub(
        lambda match: f"{match.group(1)}{_REDACTED}", scrubbed
    )
    scrubbed = _CREDENTIAL_TOKEN_PATTERN.sub(_REDACTED, scrubbed)
    scrubbed = _BARE_TOKEN_PATTERN.sub(_REDACTED, scrubbed)
    scrubbed = _JWT_TOKEN_PATTERN.sub(_REDACTED, scrubbed)
    return scrubbed.strip()[:_MAX_ERROR_MESSAGE_CHARS]


#: Structured-evidence keys whose values are credentials and must be redacted.
_SECRET_KEY_PATTERN = re.compile(
    r"(?i)^(?:api[_-]?key|apikey|authorization|auth[_-]?header|set[_-]?cookie|"
    r"cookie|password|passwd|secret|token|access[_-]?key|client[_-]?secret)$"
)


def _redact_structured(value: Any) -> Any:
    """Recursively redact credential values inside structured JSON data."""
    if isinstance(value, dict):
        return {
            key: (_REDACTED if _SECRET_KEY_PATTERN.match(str(key)) else _redact_structured(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_structured(item) for item in value]
    return value


def _prepare_structured(data: dict | None, *, field: str) -> dict | None:
    """Redact credentials and enforce the bounded-size rule for JSON columns."""
    if data is None:
        return None
    redacted = _redact_structured(data)
    serialized = len(json.dumps(redacted))
    if serialized > _MAX_EVIDENCE_CHARS:
        raise DetectionPersistenceValidationError(
            reason=f"{field} exceeds the {_MAX_EVIDENCE_CHARS}-character persistence bound"
        )
    return redacted


# ---------------------------------------------------------------------------
# Persistence service
# ---------------------------------------------------------------------------


class DetectionPersistenceService:
    """Coordinates persistence of a Step 9E analysis through the repository.

    Args:
        repository_factory: Optional repository factory; defaults to
            :class:`DetectionRepository`.  Injected for testability.
        clock: Optional UTC time source; used when a failure carries no
            timestamp (failures get a persistence-clock ``failed_at``).
            Defaults to ``datetime.now(timezone.utc)``.
    """

    def __init__(
        self,
        repository_factory: Callable[[Session], DetectionRepository] = DetectionRepository,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository_factory = repository_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def persist_analysis(
        self,
        db: Session,
        analysis: DetectionAnalysis,
    ) -> DetectionPersistenceResult:
        """Persist *analysis* atomically and return a summary.

        One logical transaction: every result and failure is staged, a
        single ``commit()`` publishes them together, and any failure rolls
        the unit back before a safe exception propagates.
        """
        try:
            return self._persist(db, analysis)
        except DetectionPersistenceError:
            db.rollback()
            raise
        except Exception as exc:  # database errors / unexpected conditions
            logger.warning(
                "detection persistence failed for event=%s (%s)",
                analysis.event_id,
                type(exc).__name__,
            )
            db.rollback()
            raise DetectionPersistenceError(event_id=analysis.event_id) from exc

    # -- internal -----------------------------------------------------------

    def _persist(
        self,
        db: Session,
        analysis: DetectionAnalysis,
    ) -> DetectionPersistenceResult:
        repo = self._repository_factory(db)
        event_id = analysis.event_id
        now = self._clock()

        # 1. Persist matched results (idempotent by unique detection_id).
        results_created = results_skipped = 0
        result_rows: list[DetectionResult] = []

        for result in analysis.results:
            if repo.get_result_by_detection_id(result.detection_id) is not None:
                results_skipped += 1
                continue
            row = DetectionResult(
                event_id=event_id,
                detection_id=result.detection_id,
                rule_id=result.rule_id,
                rule_type=result.rule_type,
                rule_version=result.metadata.rule_version or _UNKNOWN_RULE_VERSION,
                severity=result.severity,
                matched=result.matched,
                confidence=result.confidence,
                evidence=_prepare_structured(
                    result.evidence.model_dump(mode="python"),
                    field="evidence",
                ),
                result_metadata=_prepare_structured(
                    result.metadata.model_dump(mode="python"),
                    field="result_metadata",
                ),
                detected_at=result.timestamp,
                provenance=Provenance.DETECTED.value,
            )
            repo.add(row)
            result_rows.append(row)
            results_created += 1

        # 2. Persist rule/engine failures (idempotent by identity tuple).
        failures_created = failures_skipped = 0
        failure_rows: list[DetectionRuleFailure] = []

        for failure in analysis.failures:
            safe_message = sanitize_error_message(failure.message)
            if (
                repo.find_existing_failure(
                    event_id=event_id,
                    engine=failure.engine,
                    rule_id=failure.rule_id,
                    error_type=failure.error_type,
                    error_message=safe_message,
                )
                is not None
            ):
                failures_skipped += 1
                continue
            row = DetectionRuleFailure(
                event_id=event_id,
                engine=failure.engine,
                rule_id=failure.rule_id,
                error_type=failure.error_type,
                error_message=safe_message,
                failed_at=now,
                provenance=Provenance.DETECTED.value,
            )
            repo.add(row)
            failure_rows.append(row)
            failures_created += 1

        # 3. Stage; flush so UUIDs are materialized for the summary.
        if result_rows or failure_rows:
            db.flush()
            db.commit()

        return DetectionPersistenceResult(
            event_id=event_id,
            result_ids=tuple(row.id for row in result_rows),
            failure_ids=tuple(row.id for row in failure_rows),
            results_created=results_created,
            results_skipped=results_skipped,
            failures_created=failures_created,
            failures_skipped=failures_skipped,
        )


def persist_analysis(
    db: Session,
    analysis: DetectionAnalysis,
) -> DetectionPersistenceResult:
    """Convenience wrapper: persist *analysis* with a default service.

    Equivalent to ``DetectionPersistenceService().persist_analysis(
    db, analysis)``.
    """
    return DetectionPersistenceService().persist_analysis(db, analysis)