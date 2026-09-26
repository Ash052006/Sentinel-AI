"""Sigma Detection Engine — Step 9C.

Evaluates Sigma rules against normalised SentinelAI security events.
Produces deterministic, auditable :class:`DetectionResult` objects.

Supported: ``and``/``or``/``not``, ``1 of them``/``all of them``,
wildcard (``*``/``?``), ``|contains``, ``|startswith``, ``|endswith``,
``|cased`` (case-sensitive).

Unsupported (rejected explicitly): ``|re``, ``|base64``, numeric
comparison, ``near``, ``count()``, correlation rules, ``service``/
``definition`` logsource fields, ``SigmaNull``.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timezone
from typing import Any

import sigma.conditions as sc
from sigma.collection import SigmaCollection
from sigma.types import (
    SigmaCasedString,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
)

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
from app.services.detection.registry import DetectionRuleRegistry
from app.services.detection.sigma.event_adapter import to_evaluation_dict
from app.services.detection.sigma.exceptions import (
    InvalidEventDataError,
    MalformedSigmaRuleError,
    UnsupportedSigmaFeatureError,
)

_VALID_LOGSOURCE_KEYS = frozenset({"category", "product"})


# ───────────────────────────────────────────────────────────────────────
# Result containers
# ───────────────────────────────────────────────────────────────────────


class SigmaDetectionReport:
    """Aggregated report from :meth:`SigmaDetectionEngine.evaluate`."""

    __slots__ = (
        "results", "failures", "rules_total",
        "rules_evaluated", "rules_ignored",
        "evaluated_rule_ids", "event_id",
    )

    def __init__(
        self, *, results: list[DetectionResult],
        failures: list[SigmaRuleFailure], rules_total: int,
        rules_evaluated: int, rules_ignored: int,
        evaluated_rule_ids: tuple[str, ...], event_id: Any,
    ) -> None:
        self.results = results
        self.failures = failures
        self.rules_total = rules_total
        self.rules_evaluated = rules_evaluated
        self.rules_ignored = rules_ignored
        self.evaluated_rule_ids = evaluated_rule_ids
        self.event_id = event_id


class SigmaRuleFailure:
    """Records a single rule's evaluation failure."""

    __slots__ = ("rule_id", "error_type", "message")

    def __init__(self, rule_id: str, error_type: str, message: str) -> None:
        self.rule_id = rule_id
        self.error_type = error_type
        self.message = message

    def __repr__(self) -> str:
        return (
            f"SigmaRuleFailure(rule_id={self.rule_id!r}, "
            f"error_type={self.error_type!r})"
        )


# ───────────────────────────────────────────────────────────────────────
# Engine
# ───────────────────────────────────────────────────────────────────────


class SigmaDetectionEngine:
    """Evaluates Sigma rules against :class:`NormalizedSecurityEvent`.

    The engine is stateless apart from an optional parsed-rule cache
    keyed by ``(rule_id, version)``.
    """

    def __init__(
        self,
        registry: DetectionRuleRegistry | None = None,
        *,
        engine_version: str = "1.0.0",
    ) -> None:
        self._registry = registry
        self._engine_version = engine_version
        self._parsed_cache: dict[tuple[str, str], SigmaCollection] = {}

    # -- public API -------------------------------------------------------

    def evaluate(
        self,
        event: NormalizedSecurityEvent,
        rules: list[DetectionRule] | None = None,
        *,
        clock: datetime | None = None,
    ) -> SigmaDetectionReport:
        """Evaluate *event* against Sigma rules."""
        if event is None:
            raise InvalidEventDataError("event must not be None")

        now = clock or datetime.now(timezone.utc)

        if rules is None:
            if self._registry is not None:
                rules = self._registry.find_enabled_by_type(RuleType.SIGMA)
            else:
                rules = []

        sigma_rules, ignored = _partition_rules(rules)

        event_dict, _collisions = to_evaluation_dict(event)

        results: list[DetectionResult] = []
        failures: list[SigmaRuleFailure] = []
        evaluated_ids: list[str] = []

        for rule in sigma_rules:
            try:
                parsed = self._get_parsed(rule)
                matched, evidence_data = self._evaluate_parsed(
                    parsed, event_dict
                )
                if matched:
                    results.append(
                        self._build_result(rule, event, evidence_data, now)
                    )
                evaluated_ids.append(rule.rule_id)
            except MalformedSigmaRuleError as exc:
                failures.append(
                    SigmaRuleFailure(rule.rule_id, "malformed_rule", str(exc))
                )
            except UnsupportedSigmaFeatureError as exc:
                failures.append(
                    SigmaRuleFailure(
                        rule.rule_id, "unsupported_feature", str(exc)
                    )
                )
            except Exception:
                failures.append(
                    SigmaRuleFailure(
                        rule.rule_id, "internal_error",
                        f"Unexpected error evaluating rule {rule.rule_id}",
                    )
                )

        return SigmaDetectionReport(
            results=results,
            failures=failures,
            rules_total=len(sigma_rules) + ignored,
            rules_evaluated=len(sigma_rules),
            rules_ignored=ignored,
            evaluated_rule_ids=tuple(evaluated_ids),
            event_id=event.event_id,
        )

    # -- parsing ----------------------------------------------------------

    def _get_parsed(self, rule: DetectionRule) -> SigmaCollection:
        cache_key = (rule.rule_id, rule.version)
        if cache_key in self._parsed_cache:
            return self._parsed_cache[cache_key]
        parsed = _parse_rule(rule)
        self._parsed_cache[cache_key] = parsed
        return parsed

    # -- evaluation -------------------------------------------------------

    def _evaluate_parsed(
        self, parsed: SigmaCollection, event_dict: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        rule = parsed.rules[0]
        _validate_logsource(rule)
        _validate_condition_tree(rule)

        matched_fields: dict[str, str] = {}
        matched_conditions: list[str] = []

        for pc in rule.detection.parsed_condition:
            if _eval_node(pc.parsed, event_dict, matched_fields):
                matched_conditions.append(pc.condition)
                break

        evidence = {
            "matched_fields": matched_fields,
            "matched_conditions": matched_conditions,
        }
        return bool(matched_conditions), evidence

    # -- result construction ----------------------------------------------

    def _build_result(
        self, rule: DetectionRule, event: NormalizedSecurityEvent,
        evidence_data: dict[str, Any], now: datetime,
    ) -> DetectionResult:
        matched_fields = evidence_data.get("matched_fields", {})
        matched_conditions = evidence_data.get("matched_conditions", [])

        evidence = DetectionEvidence(
            matched_conditions=matched_conditions,
            matched_fields=dict(matched_fields),
            detection_context={
                "engine": "sigma",
                "engine_version": self._engine_version,
            },
        )

        severity = rule.severity
        confidence = _severity_to_confidence(severity)

        return DetectionResult(
            event_id=event.event_id,
            rule_id=rule.rule_id,
            rule_type=RuleType.SIGMA,
            matched=True,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            timestamp=now,
            metadata=DetectionMetadata(engine_version=self._engine_version),
            provenance=Provenance.DETECTED,
        )


# ───────────────────────────────────────────────────────────────────────
# Module-level helpers
# ───────────────────────────────────────────────────────────────────────


def _partition_rules(
    rules: list[DetectionRule],
) -> tuple[list[DetectionRule], int]:
    """Separate enabled SIGMA rules from the rest."""
    sigma: list[DetectionRule] = []
    ignored = 0
    for r in rules:
        if r.rule_type == RuleType.SIGMA and r.enabled:
            sigma.append(r)
        else:
            ignored += 1
    sigma.sort(key=lambda r: r.rule_id)
    return sigma, ignored


def _parse_rule(rule: DetectionRule) -> SigmaCollection:
    """Parse a DetectionRule's content into a SigmaCollection."""
    content = rule.content
    if content is None:
        raise MalformedSigmaRuleError(rule.rule_id, reason="no content")
    try:
        if isinstance(content, dict):
            return SigmaCollection.from_dicts([content])
        if isinstance(content, str):
            return SigmaCollection.from_yaml(content)
        raise MalformedSigmaRuleError(
            rule.rule_id,
            reason=f"content type {type(content).__name__} not supported",
        )
    except MalformedSigmaRuleError:
        raise
    except Exception as exc:
        raise MalformedSigmaRuleError(
            rule.rule_id, reason=str(exc)
        ) from exc


def _validate_logsource(rule: Any) -> None:
    """Reject rules with unsupported logsource fields."""
    if rule.logsource is None:
        return
    logsource_dict = rule.logsource.to_dict()
    for key in logsource_dict:
        if key not in _VALID_LOGSOURCE_KEYS:
            if logsource_dict[key] is not None:
                raise UnsupportedSigmaFeatureError(
                    rule.title or "unknown",
                    feature=f"logsource field '{key}'",
                )


def _validate_condition_tree(rule: Any) -> None:
    """Pre-validate the condition tree for unsupported constructs."""
    for pc in rule.detection.parsed_condition:
        _check_node_supported(pc.parsed, rule)


def _check_node_supported(node: Any, rule: Any) -> None:
    """Walk the condition tree, raising on unsupported constructs."""
    rule_id = rule.title or "unknown"
    if isinstance(node, sc.ConditionFieldEqualsValueExpression):
        if isinstance(node.value, SigmaRegularExpression):
            raise UnsupportedSigmaFeatureError(
                rule_id, feature="regex value (|re modifier)")
        if isinstance(node.value, SigmaNumber):
            raise UnsupportedSigmaFeatureError(
                rule_id, feature="numeric value comparison")
        if isinstance(node.value, SigmaString):
            return
        raise UnsupportedSigmaFeatureError(
            rule_id,
            feature=f"unsupported value type {type(node.value).__name__}",
        )
    if isinstance(node, (sc.ConditionAND, sc.ConditionOR)):
        for arg in node.args:
            _check_node_supported(arg, rule)
        return
    if isinstance(node, sc.ConditionNOT):
        _check_node_supported(node.args[0], rule)


def _eval_node(
    node: Any,
    event_dict: dict[str, Any],
    matched_fields: dict[str, str],
) -> bool:
    """Recursively evaluate a condition tree node against an event dict."""
    if isinstance(node, sc.ConditionAND):
        return all(
            _eval_node(arg, event_dict, matched_fields) for arg in node.args
        )
    if isinstance(node, sc.ConditionOR):
        return any(
            _eval_node(arg, event_dict, matched_fields) for arg in node.args
        )
    if isinstance(node, sc.ConditionNOT):
        return not _eval_node(node.args[0], event_dict, matched_fields)
    if isinstance(node, sc.ConditionFieldEqualsValueExpression):
        return _eval_field_match(node, event_dict, matched_fields)
    if isinstance(node, sc.ConditionIdentifier):
        raise UnsupportedSigmaFeatureError(
            "condition",
            feature=f"unresolved identifier '{node.identifier}'",
        )
    raise UnsupportedSigmaFeatureError(
        "condition", feature=f"unsupported node type {type(node).__name__}"
    )


def _eval_field_match(
    node: sc.ConditionFieldEqualsValueExpression,
    event_dict: dict[str, Any],
    matched_fields: dict[str, str],
) -> bool:
    """Evaluate a single field-value expression."""
    field = node.field
    value = node.value
    event_value = event_dict.get(field)
    if event_value is None:
        return False
    if isinstance(value, SigmaRegularExpression):
        raise UnsupportedSigmaFeatureError(
            "condition", feature="regex value (|re modifier)")
    if isinstance(value, SigmaNumber):
        raise UnsupportedSigmaFeatureError(
            "condition", feature="numeric value comparison")
    if isinstance(value, SigmaString):
        case_sensitive = isinstance(value, SigmaCasedString)
        pattern = str(value)
        event_str = str(event_value)
        if _wildcard_match(pattern, event_str, case_sensitive):
            matched_fields[field] = event_str
            return True
        return False
    # Fallback
    if str(event_value).lower() == str(value).lower():
        matched_fields[field] = str(event_value)
        return True
    return False


def _wildcard_match(pattern: str, text: str, case_sensitive: bool) -> bool:
    """Match *pattern* (Sigma wildcards ``*``/``?``) against *text*.

    Uses ``fnmatch.translate`` to build a regex, giving reliable
    case-sensitive behaviour even on Windows where ``fnmatch.fnmatch``
    is case-insensitive.
    """
    regex_str = fnmatch.translate(pattern)
    flags = 0 if case_sensitive else re.IGNORECASE
    return bool(re.fullmatch(regex_str, text, flags))


def _severity_to_confidence(severity: DetectionSeverity) -> float:
    """Map severity to a deterministic base confidence value."""
    return {
        DetectionSeverity.CRITICAL: 1.0,
        DetectionSeverity.HIGH: 0.9,
        DetectionSeverity.MEDIUM: 0.7,
        DetectionSeverity.LOW: 0.5,
    }.get(severity, 0.5)
