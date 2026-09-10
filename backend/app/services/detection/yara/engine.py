"""YARA Detection Engine — Step 9D.

Evaluates YARA rules against explicitly supplied content bytes and
produces deterministic, auditable :class:`DetectionResult` objects.

Security
--------
* Never dynamically executes Python code from rules or content.
* Never launches external processes.
* Never downloads rules or payloads.
* Never reads arbitrary filesystem paths from event data.
* All YARA source and target content is treated as untrusted input.
* YARA compilation is performed via ``yara.compile(source=...)`` only.

Unsupported (documented)
------------------------
* ``import`` modules (math, pe, elf, etc.).
* ``include`` directives.
* External variables (``externals``).
* ``yara.compile(filepath=...)`` — never reads files from disk.
* ``yara.load()`` — compiles from source, never from pre-compiled
  binaries.
* Filesystem access from event data — ``file.path`` is **never** opened.

Relationship to the pipeline::

    NormalizedSecurityEvent / YaraTarget
        -> YaraDetectionEngine.evaluate() / evaluate_target()
            -> YaraDetectionReport
                -> DetectionResult (matches only)
"""

from __future__ import annotations

import re
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

import yara as _yara

from app.schemas.detection import (
    DetectionEvidence,
    DetectionMetadata,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    RuleType,
)
from app.schemas.normalized_event import NormalizedSecurityEvent
from app.schemas.security_event import Provenance
from app.services.detection.yara.exceptions import (
    InvalidYaraTargetError,
    MalformedYaraRuleError,
)
from app.services.detection.yara.target_adapter import (
    YaraTarget,
    to_yara_target,
)

_CACHE_MAX_SIZE = 512

# Deterministic sentinel event UUID for content that has no originating
# security event (e.g. a standalone bytes target).  DetectionResult
# requires a UUID; using a fixed sentinel keeps results deterministic.
_NO_EVENT_ID = _uuid.UUID("00000000-0000-0000-0000-000000000000")


# ───────────────────────────────────────────────────────────────────────
# Result containers
# ───────────────────────────────────────────────────────────────────────


class YaraDetectionReport:
    """Aggregated report from :meth:`YaraDetectionEngine.evaluate`."""

    __slots__ = (
        "results", "failures", "rules_total",
        "rules_evaluated", "rules_ignored",
        "evaluated_rule_ids", "target_event_id",
    )

    def __init__(
        self, *, results: list[DetectionResult],
        failures: list[YaraRuleFailure], rules_total: int,
        rules_evaluated: int, rules_ignored: int,
        evaluated_rule_ids: tuple[str, ...], target_event_id: Any,
    ) -> None:
        self.results = results
        self.failures = failures
        self.rules_total = rules_total
        self.rules_evaluated = rules_evaluated
        self.rules_ignored = rules_ignored
        self.evaluated_rule_ids = evaluated_rule_ids
        self.target_event_id = target_event_id


class YaraRuleFailure:
    """Records a single rule's evaluation failure."""

    __slots__ = ("rule_id", "error_type", "message")

    def __init__(self, rule_id: str, error_type: str, message: str) -> None:
        self.rule_id = rule_id
        self.error_type = error_type
        self.message = message

    def __repr__(self) -> str:
        return (
            f"YaraRuleFailure(rule_id={self.rule_id!r}, "
            f"error_type={self.error_type!r})"
        )


# ───────────────────────────────────────────────────────────────────────
# Engine
# ───────────────────────────────────────────────────────────────────────


class YaraDetectionEngine:
    """Evaluates YARA rules against content bytes.

    Stateless apart from a compiled-rule cache keyed by
    ``(rule_id, version)``.  Does **not** hold a registry reference.
    """

    def __init__(self) -> None:
        self._compiled_cache: dict[tuple[str, str], _yara.Rules] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        event: NormalizedSecurityEvent,
        rules: list[DetectionRule],
    ) -> YaraDetectionReport:
        """Evaluate YARA rules against a normalised event.

        Extracts file-content bytes from ``normalized_data``.
        If no applicable content is present, an ``invalid_target``
        failure is returned — the filesystem is **never** accessed.
        """
        event_id = event.event_id if event is not None else None
        if event is None:
            return _make_target_failure(
                rules, "<event>", "Event must not be None", None,
            )
        try:
            target = to_yara_target(event)
        except InvalidYaraTargetError as exc:
            return _make_target_failure(
                rules, "<event>", str(exc), event_id,
            )
        return self.evaluate_target(target, rules)

    def evaluate_target(
        self,
        target: YaraTarget,
        rules: list[DetectionRule],
    ) -> YaraDetectionReport:
        """Evaluate YARA rules against an explicit :class:`YaraTarget`.

        Compiles each rule, matches against target content, and
        produces structured results.  Malformed rules produce explicit
        failures without discarding valid results from other rules.
        """
        if target is None:
            return _make_target_failure(
                rules, "<target>", "Target must not be None", None,
            )
        if (not isinstance(target.content, (bytes, bytearray))
                or len(target.content) == 0):
            return _make_target_failure(
                rules, "<target>",
                "Target content is empty or not bytes",
                target.origin_event_id,
            )

        results: list[DetectionResult] = []
        failures: list[YaraRuleFailure] = []
        evaluated_ids: list[str] = []
        now = datetime.now(timezone.utc)

        for rule in rules:
            if rule.rule_type != RuleType.YARA:
                continue
            if not rule.enabled:
                continue
            evaluated_ids.append(rule.rule_id)

            source = _extract_source(rule)
            if source is None:
                failures.append(YaraRuleFailure(
                    rule_id=rule.rule_id, error_type="malformed_rule",
                    message=f"YARA rule '{rule.rule_id}' has no valid "
                            "string content in DetectionRule.content",
                ))
                continue

            unsupported = _check_unsupported(rule.rule_id, source)
            if unsupported is not None:
                failures.append(unsupported)
                continue

            compiled = None
            try:
                compiled = self._compile(rule.rule_id, rule.version, source)
            except MalformedYaraRuleError as exc:
                failures.append(YaraRuleFailure(
                    rule_id=rule.rule_id,
                    error_type="malformed_rule",
                    message=str(exc),
                ))
                continue
            if compiled is None:
                continue

            try:
                yara_matches = compiled.match(data=target.content)
            except Exception as exc:
                failures.append(YaraRuleFailure(
                    rule_id=rule.rule_id, error_type="match_error",
                    message=f"YARA rule '{rule.rule_id}' match failed: "
                            f"{type(exc).__name__}",
                ))
                continue

            if not yara_matches:
                continue

            for yara_match in yara_matches:
                evidence = _build_evidence(yara_match, target)
                confidence = _severity_to_confidence(rule.severity)
                result_event_id = (
                    target.origin_event_id
                    if target.origin_event_id is not None
                    else _NO_EVENT_ID
                )
                results.append(DetectionResult(
                    event_id=result_event_id,
                    rule_id=rule.rule_id,
                    rule_type=RuleType.YARA,
                    matched=True,
                    severity=rule.severity,
                    confidence=confidence,
                    evidence=evidence,
                    timestamp=now,
                    metadata=DetectionMetadata(extra={
                        "engine": "yara",
                        "yara_rule_name": yara_match.rule,
                        "yara_namespace": yara_match.namespace,
                    }),
                    provenance=Provenance.DETECTED,
                ))

        return YaraDetectionReport(
            results=results, failures=failures,
            rules_total=len(rules),
            rules_evaluated=len(evaluated_ids),
            rules_ignored=len(rules) - len(evaluated_ids),
            evaluated_rule_ids=tuple(evaluated_ids),
            target_event_id=target.origin_event_id,
        )

    # ------------------------------------------------------------------
    # Compilation
    # ------------------------------------------------------------------

    def _compile(
        self, rule_id: str, version: str, source: str,
    ) -> _yara.Rules | None:
        """Compile a YARA rule, using the cache when available.

        Returns compiled rules on success, ``None`` on failure (the
        caller records the failure).
        """
        cache_key = (rule_id, version)
        if cache_key in self._compiled_cache:
            return self._compiled_cache[cache_key]
        try:
            compiled = _yara.compile(source=source)
        except _yara.SyntaxError as exc:
            raise MalformedYaraRuleError(
                rule_id,
                reason=f"YARA syntax error: {exc}",
            ) from exc
        except Exception as exc:
            raise MalformedYaraRuleError(
                rule_id,
                reason=f"compilation error: {type(exc).__name__}: {exc}",
            ) from exc
        if len(self._compiled_cache) >= _CACHE_MAX_SIZE:
            self._compiled_cache.clear()
        self._compiled_cache[cache_key] = compiled
        return compiled


# ───────────────────────────────────────────────────────────────────────
# Module-level helpers
# ───────────────────────────────────────────────────────────────────────


def _make_target_failure(
    rules: list[DetectionRule],
    failure_rule_id: str,
    message: str,
    event_id: Any,
) -> YaraDetectionReport:
    """Create a report with a single target-level failure."""
    return YaraDetectionReport(
        results=[],
        failures=[YaraRuleFailure(
            rule_id=failure_rule_id,
            error_type="invalid_target",
            message=message,
        )],
        rules_total=len(rules),
        rules_evaluated=0,
        rules_ignored=0,
        evaluated_rule_ids=(),
        target_event_id=event_id,
    )


def _extract_source(rule: DetectionRule) -> str | None:
    """Extract YARA source string from a DetectionRule."""
    content = rule.content
    if content is None:
        return None
    if isinstance(content, str):
        stripped = content.strip()
        return stripped if len(stripped) > 0 else None
    return None


def _check_unsupported(
    rule_id: str, source: str,
) -> YaraRuleFailure | None:
    """Pre-scan YARA source for unsupported constructs."""
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped == "":
            continue
        if re.match(r"\bimport\s+\w+", stripped):
            return YaraRuleFailure(
                rule_id=rule_id,
                error_type="unsupported_feature",
                message=f"YARA rule '{rule_id}' uses 'import' — "
                        "YARA module imports are not supported",
            )
        if re.match(r'\binclude\s+"', stripped):
            return YaraRuleFailure(
                rule_id=rule_id,
                error_type="unsupported_feature",
                message=f"YARA rule '{rule_id}' uses 'include' — "
                        "YARA include directives are not supported",
            )
    return None


def _build_evidence(
    yara_match: _yara.Match, target: YaraTarget,
) -> DetectionEvidence:
    """Build structured :class:`DetectionEvidence` from a YARA match.

    Evidence is deterministic and derived from the actual YARA match.
    No raw file content is included — only identifiers, offsets,
    lengths, and safe metadata.
    """
    matched_conditions: list[str] = []
    matched_strings: list[dict[str, Any]] = []

    for string_match in yara_match.strings:
        identifier = string_match.identifier
        matched_conditions.append(f"strings:{identifier}")
        for inst in string_match.instances:
            matched_strings.append({
                "identifier": identifier,
                "offset": inst.offset,
                "matched_length": inst.matched_length,
            })

    rule_references: dict[str, Any] = {}
    if yara_match.meta:
        for key, value in yara_match.meta.items():
            if isinstance(value, (str, int, float, bool)):
                rule_references[key] = value
            else:
                rule_references[key] = str(value)

    matched_fields: dict[str, str] = {}
    if target.file_name:
        matched_fields["file.name"] = target.file_name
    matched_fields["content"] = "(bytes scanned)"

    detection_context: dict[str, Any] = {
        "matched_strings": matched_strings,
    }
    if yara_match.tags:
        detection_context["tags"] = list(yara_match.tags)
    if target.extra:
        detection_context["target_extra"] = dict(target.extra)

    return DetectionEvidence(
        matched_conditions=matched_conditions,
        matched_fields=matched_fields,
        rule_references=rule_references,
        detection_context=detection_context,
    )


def _severity_to_confidence(severity: DetectionSeverity) -> float:
    """Map severity to a deterministic base confidence value.

    Consistent with the Sigma engine convention for cross-engine
    uniformity.
    """
    return {
        DetectionSeverity.CRITICAL: 1.0,
        DetectionSeverity.HIGH: 0.9,
        DetectionSeverity.MEDIUM: 0.7,
        DetectionSeverity.LOW: 0.5,
    }.get(severity, 0.5)
