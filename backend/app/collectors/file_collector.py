"""File-based security log collector.

Reads a local JSON Lines (NDJSON) file — one JSON object per line — and
converts each valid record into a :class:`SecurityEvent`.

Design responsibilities:

* **Collection** — open, read, parse.
* **Validation** — delegate to :class:`SecurityEvent`.
* **Preservation** — store the entire original record in ``raw_data``.

The collector does **not** normalise, enrich, or reconstruct data.  Those
are separate pipeline stages.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from app.collectors.base import BaseCollector, CollectionError, CollectionResult
from app.schemas.security_event import Provenance, SecurityEvent

logger = logging.getLogger(__name__)


class FileLogCollector(BaseCollector):
    """Collect security events from a local JSON Lines file.

    Each non-empty line must contain a single JSON object with at least
    the fields required by :class:`SecurityEvent`:

    * ``timestamp`` — ISO-8601, timezone-aware
    * ``source`` — non-empty string
    * ``source_type`` — valid :class:`SourceType` value
    * ``event_type`` — non-empty string

    The entire original JSON object is preserved verbatim as ``raw_data``
    on the resulting :class:`SecurityEvent`.
    """

    def __init__(self, file_path: str | Path) -> None:
        self._file_path = Path(file_path)
        self._collected_events: list[SecurityEvent] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect(self) -> CollectionResult:
        """Read and validate all records from the configured file.

        Returns a :class:`CollectionResult` with collected events,
        statistics, and per-line error details for any records that failed.

        Raises ``FileNotFoundError``, ``PermissionError``, or ``OSError``
        for systemic filesystem problems (as distinct from per-record
        malformation which is captured in the result).
        """
        logger.info("Collection started: source=%s", self._file_path)

        self._collected_events = []
        errors: list[CollectionError] = []
        total = 0

        with open(self._file_path, encoding="utf-8") as fh:
            for line_number, raw_line in enumerate(fh, start=1):
                stripped = raw_line.strip()

                # Skip blank lines — they are not records.
                if not stripped:
                    continue

                total += 1
                error = self._process_line(line_number, stripped)
                if error is not None:
                    errors.append(error)

        successful = len(self._collected_events)
        logger.info(
            "Collection completed: total=%d successful=%d failed=%d",
            total,
            successful,
            len(errors),
        )

        return CollectionResult(
            events=list(self._collected_events),
            total_records=total,
            successful_records=successful,
            failed_records=len(errors),
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _process_line(self, line_number: int, raw_line: str) -> CollectionError | None:
        """Parse one JSON line and attempt SecurityEvent construction.

        On success the event is appended to ``_collected_events`` and
        ``None`` is returned.  On failure a :class:`CollectionError` is
        returned instead.
        """
        # --- JSON parsing ---
        try:
            record: dict[str, Any] = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            logger.debug(
                "Line %d: invalid JSON — %s", line_number, type(exc).__name__,
            )
            return CollectionError(
                line_number=line_number,
                reason=f"Invalid JSON: {type(exc).__name__}",
            )

        if not isinstance(record, dict):
            return CollectionError(
                line_number=line_number,
                reason="Record is not a JSON object",
            )

        # --- Build SecurityEvent payload ---
        event_payload: dict[str, Any] = {
            "timestamp": record.get("timestamp"),
            "source": record.get("source", ""),
            "source_type": record.get("source_type", ""),
            "event_type": record.get("event_type", ""),
            "raw_data": record,
            "provenance": Provenance.OBSERVED,
            "metadata": {
                "collector": "file_collector",
                "line_number": line_number,
            },
        }

        # --- Validate via SecurityEvent ---
        try:
            event = SecurityEvent(**event_payload)
        except Exception as exc:
            reason = _summarise_validation_error(exc)
            logger.debug(
                "Line %d: validation failed — %s", line_number, reason,
            )
            return CollectionError(
                line_number=line_number,
                reason=reason,
            )

        self._collected_events.append(event)
        return None


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------

def _summarise_validation_error(exc: Exception) -> str:
    """Extract a safe, human-readable summary from a validation error.

    Never returns raw field values or sensitive content.
    """
    if hasattr(exc, "errors") and callable(exc.errors):
        try:
            validation_errors = exc.errors()
            if validation_errors:
                first = validation_errors[0]
                loc = " → ".join(str(part) for part in first.get("loc", []))
                msg = first.get("msg", str(type(exc).__name__))
                return f"{loc}: {msg}" if loc else msg
        except Exception:
            pass
    return type(exc).__name__