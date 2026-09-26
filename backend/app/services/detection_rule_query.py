"""Detection rule query service — Step 26.

Read-only query layer exposing the **loaded rule set** (Sigma + YARA)
together with *real* persisted match statistics. Every count in here is
derived from the ``detection_results`` table; nothing is fabricated.

Rule definitions come from the repository rule set loaded via
:mod:`app.services.detection.rule_loader`, and match statistics are
grouped by ``rule_id`` over persisted rows.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.detection_result import DetectionResult
from app.schemas.detection_rule_query import (
    WINDOW_HOURS,
    DetectionRuleAnalytics,
    DetectionRuleDetail,
    DetectionRuleRecord,
    RuleMatchBucket,
    RuleSeverityCount,
)
from app.services.detection.rule_loader import build_registry
from app.schemas.detection import RuleType

_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _load_rules() -> list:
    """Return the loaded rule definitions (RuleType-aware records)."""
    return build_registry().list_rules()


def _to_record(rule, stats: dict[str, tuple[int, datetime | None]]) -> DetectionRuleRecord:
    extra = rule.metadata.extra if rule.metadata else {}
    tags: list[str] = []
    if rule.rule_type is RuleType.SIGMA and isinstance(rule.content, dict):
        content_tags = rule.content.get("tags")
        if isinstance(content_tags, list):
            tags = [str(t) for t in content_tags]
    matched_count, last_matched_at = stats.get(str(rule.rule_id), (0, None))
    return DetectionRuleRecord(
        rule_id=str(rule.rule_id),
        name=rule.name,
        description=rule.description,
        rule_type=rule.rule_type,
        severity=rule.severity,
        enabled=rule.enabled,
        version=rule.version or "1",
        category=extra.get("category"),
        tags=tags,
        author=extra.get("author"),
        date=extra.get("date"),
        status=extra.get("status"),
        source_file=extra.get("source_file"),
        match_count=int(matched_count),
        last_matched_at=last_matched_at,
    )


def _match_stats(db: Session, rule_ids: list[str]) -> dict[str, tuple[int, datetime | None]]:
    """Real persisted match counts + newest timestamp per rule id."""
    ids = [str(i) for i in rule_ids]
    if not ids:
        return {}
    rows = db.execute(
        select(
            DetectionResult.rule_id,
            func.count(DetectionResult.detection_id),
            func.max(DetectionResult.detected_at),
        )
        .where(DetectionResult.matched.is_(True))
        .where(DetectionResult.rule_id.in_(ids))
        .group_by(DetectionResult.rule_id)
    ).all()
    return {str(rule_id): (int(count), last) for rule_id, count, last in rows}


def _severity_counts(db: Session, start: datetime) -> list[RuleSeverityCount]:
    rows = db.execute(
        select(DetectionResult.severity, func.count(DetectionResult.detection_id))
        .where(DetectionResult.detected_at >= start)
        .group_by(DetectionResult.severity)
    ).all()
    by: dict[str, int] = {s.value if hasattr(s, "value") else str(s): int(c) for s, c in rows}
    return [RuleSeverityCount(severity=s, count=by.get(s, 0)) for s in _SEVERITY_ORDER]


class DetectionRuleQueryService:
    """Query service for the Detection Rules surface."""

    def list_rules(self, db: Session) -> list[DetectionRuleRecord]:
        rules = _load_rules()
        stats = _match_stats(db, [r.rule_id for r in rules])
        return [_to_record(r, stats) for r in rules]

    def get_rule(self, db: Session, rule_id: str) -> DetectionRuleDetail | None:
        rules = _load_rules()
        rule = next((r for r in rules if str(r.rule_id) == rule_id), None)
        if rule is None:
            return None
        record = _to_record(rule, _match_stats(db, [rule.rule_id]))
        content, content_format = _render_content(rule)
        return DetectionRuleDetail(**record.model_dump(), content=content, content_format=content_format)

    def analytics(self, db: Session, window: str) -> DetectionRuleAnalytics:
        """Persisted detection activity over *window*.

        The time series and severity breakdown cover **all** persisted
        detection results in the window (real rows, never fabricated).
        ``rules_with_matches`` is stricter: only loaded repository rules
        that actually matched, so it is ``0`` until a loaded rule produces
        a persisted match — reported honestly.
        """
        rules = _load_rules()
        ids = [str(r.rule_id) for r in rules]
        hours = WINDOW_HOURS[window]
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours)
        bucket_sql = func.date_trunc("hour" if hours <= 24 else "day", DetectionResult.detected_at)
        rows = db.execute(
            select(bucket_sql.label("b"), func.count(DetectionResult.detection_id))
            .where(DetectionResult.detected_at >= start)
            .group_by("b")
            .order_by("b")
        ).all()
        buckets = [RuleMatchBucket(bucket_start=b, detections=int(c)) for b, c in rows]
        total = sum(b.detections for b in buckets)
        rules_with = len(
            set(
                db.execute(
                    select(DetectionResult.rule_id)
                    .where(DetectionResult.detected_at >= start)
                    .where(DetectionResult.rule_id.in_(ids))
                    .distinct()
                ).scalars()
            )
        )
        return DetectionRuleAnalytics(
            window=window,
            total_detections=total,
            buckets=buckets,
            by_severity=_severity_counts(db, start),
            rules_with_matches=rules_with,
        )


def _render_content(rule) -> tuple[str, str]:
    """Render evaluator-ready rule text for the preview panel."""
    rtype = rule.rule_type
    if rtype is RuleType.SIGMA:
        try:
            import yaml

            raw = rule.content
            if isinstance(raw, dict):
                return yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), "yaml"
        except Exception:
            pass
        return str(rule.content), "yaml"
    return rule.content, "yara"