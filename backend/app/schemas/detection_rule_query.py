"""Detection rule read model — Step 26.

Read-only transport contract for the Detection Rules management surface.
It is a **query/management view only**: rules are defined by the
repository rule set loaded through
:class:`~app.services.detection.rule_loader`, and this contract simply
serialises those definitions together with *real* match statistics from
the persisted detection results.

No field here is fabricated: ``match_count`` and ``last_matched_at`` come
from the ``detection_results`` table, ``content`` is the exact rule
definition the engine evaluates, and the analytics payload is computed
from persisted detection activity.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.detection import DetectionSeverity, RuleType

#: Supported analytics windows in hours.
WINDOW_HOURS = {
    "1h": 1,
    "6h": 6,
    "24h": 24,
    "7d": 24 * 7,
    "30d": 24 * 30,
}


class DetectionRuleRecord(BaseModel):
    """One loaded detection rule plus its real persisted match statistics."""

    rule_id: str = Field(..., description="Stable unique rule identifier.")
    name: str = Field(..., description="Human-readable rule name.")
    description: str = Field(..., description="What the rule detects.")
    rule_type: RuleType = Field(..., description="sigma | yara")
    severity: DetectionSeverity = Field(..., description="Rule severity.")
    enabled: bool = Field(..., description="Whether the rule is active.")
    version: str = Field(..., description="Rule content version.")
    category: str | None = Field(
        default=None,
        description="Management category (Sigma logsource or 'file' for YARA).",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Freeform rule classification tags.",
    )
    author: str | None = Field(default=None)
    date: str | None = Field(default=None)
    status: str | None = Field(
        default=None,
        description="Rule lifecycle status (stable/experimental/...).",
    )
    source_file: str | None = Field(
        default=None,
        description="Repository path the rule was loaded from.",
    )
    match_count: int = Field(
        default=0,
        description="Real persisted matches for this rule (0 when none).",
    )
    last_matched_at: datetime | None = Field(
        default=None,
        description="Newest persisted match timestamp, if any.",
    )


class DetectionRuleDetail(DetectionRuleRecord):
    """A rule record plus its evaluator-ready content for preview."""

    content: str = Field(
        ...,
        description=(
            "Rule definition text: YAML for Sigma, source for YARA. "
            "Safe to display; never executed by the client."
        ),
    )
    content_format: str = Field(..., description="'yaml' | 'yara'")


class RuleSeverityCount(BaseModel):
    """Persisted matches grouped by severity."""

    severity: str = Field(..., description="low | medium | high | critical")
    count: int = Field(default=0, description="Real persisted match count.")


class RuleMatchBucket(BaseModel):
    """One time bucket of persisted detection activity."""

    bucket_start: datetime = Field(..., description="Bucket start instant.")
    detections: int = Field(..., description="Real number of persisted results.")


class DetectionRuleAnalytics(BaseModel):
    """Detection activity over a bounded window, from persisted data only."""

    window: str = Field(..., description="Requested window: 1h/6h/24h/7d/30d")
    total_detections: int = Field(..., description="Real total in the window.")
    buckets: list[RuleMatchBucket] = Field(
        default_factory=list,
        description="Time buckets, oldest first.",
    )
    by_severity: list[RuleSeverityCount] = Field(
        default_factory=list,
        description="Window matches grouped by severity.",
    )
    rules_with_matches: int = Field(
        default=0,
        description="Number of loaded rules that matched in the window.",
    )