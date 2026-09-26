"""Deterministic result formatter for the Natural Language SOC response — Step 23.

The Natural Language SOC interface intentionally does **not** build a second
LLM call to summarize results.  Instead it returns a deterministic,
human-readable ``note`` plus deterministic ``semantics`` labels that describe
what the returned records are.  The formatter:

* never fabricates findings, never invents security conclusions, and never
  claims anything is present when the results are empty;
* preserves existing semantics — e.g. incident memories are explicitly
  labelled historical, never presented as current observations;
* is a pure function of the validated intent and the executed outcome, so
  identical inputs always produce identical text.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas.soc_query import (
    SOCExecutionMode,
    SOCQueryIntent,
    SOCResource,
)

_RESOURCE_LABELS: dict[SOCResource, str] = {
    SOCResource.DETECTIONS: "detections",
    SOCResource.CORRELATIONS: "correlations",
    SOCResource.RISK_ASSESSMENTS: "risk assessments",
    SOCResource.INCIDENT_MEMORIES: "incident memories",
}

#: Deterministic semantic labels describing what a resource's results are.
_SEMANTICS: dict[SOCResource, tuple[str, ...]] = {
    SOCResource.DETECTIONS: ("detection_results",),
    SOCResource.CORRELATIONS: ("correlation_results",),
    SOCResource.RISK_ASSESSMENTS: ("risk_assessment_results",),
    SOCResource.INCIDENT_MEMORIES: (
        "incident_memories",
        "historical_incident_memory_not_current_observation",
    ),
}


@dataclass(frozen=True)
class SOCOutcome:
    """The deterministic outcome of one validated intent's execution.

    Produced by the executor; consumed by the formatter and the API
    response assembly.  Never holds SQLAlchemy objects — ``items`` holds
    JSON-safe serialized read models.
    """

    found: bool
    count: int
    total: int | None = None
    items: list[dict] = field(default_factory=list)
    applied_filters: list[str] = field(default_factory=list)


def build_note(intent: SOCQueryIntent, outcome: SOCOutcome) -> str:
    """Deterministic human-readable summary (never LLM-generated)."""
    label = _RESOURCE_LABELS[intent.resource]
    applied = {f.split("=", 1)[0]: f.split("=", 1)[1] for f in outcome.applied_filters}

    if len(applied) == 1 and "risk_level" in applied:
        risk_note = f" filtered by risk level {applied['risk_level']}"
    else:
        risk_note = ""

    if intent.mode is SOCExecutionMode.EXACT_LOOKUP:
        if outcome.found:
            return f"Found the requested {_singular(label)} (1 result)."
        return f"No {label} found for the requested identifier."

    if intent.mode is SOCExecutionMode.RECENT_FEED:
        if not outcome.found:
            return f"No {label} matched."
        return f"Returned {outcome.count} recent {label}.{risk_note}"

    # PAGED_QUERY
    page = intent.pagination.page
    if not outcome.found:
        return f"No {label} matched on page {page}."
    total = outcome.total if outcome.total is not None else outcome.count
    return f"Returned {outcome.count} of {total} {label} on page {page}."


def _singular(label: str) -> str:
    for prefix, singular in (
        ("assessments", "assessment"),
        ("memories", "memory"),
        ("detections", "detection"),
        ("correlations", "correlation"),
    ):
        if label == prefix or label.endswith(" " + prefix):
            return label[: -len(prefix)] + singular
    return label


def build_semantics(intent: SOCQueryIntent, outcome: SOCOutcome) -> list[str]:
    """Deterministic labels describing what the result records are.

    Includes the explicit historical-memory marker for incident memories so
    they are never presented as current security observations.
    """
    return list(_SEMANTICS[intent.resource])


def format_response(
    intent: SOCQueryIntent,
    outcome: SOCOutcome,
) -> tuple[str, list[str]]:
    """Return ``(note, semantics)`` for a validated intent and outcome."""
    return build_note(intent, outcome), build_semantics(intent, outcome)


__all__ = [
    "SOCOutcome",
    "build_note",
    "build_semantics",
    "format_response",
]