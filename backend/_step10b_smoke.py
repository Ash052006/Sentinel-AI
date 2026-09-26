"""Smoke test for the Step 10B CorrelationAgent (throwaway)."""
import json
import uuid
from datetime import datetime, timezone

from app.agents.correlation import CorrelationAgent
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.detection_correlation import (
    DetectionCorrelationBatch,
    DetectionCorrelationBatchMetadata,
    DetectionCorrelationInput,
)
from app.schemas.security_event import Provenance
from app.services.correlation.exceptions import (
    CorrelationInputError,
    CorrelationStrategyError,
)
from app.services.correlation.strategy import DeterministicCorrelationStrategy

FIXED = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
OUT = []


def inp(det_id: str, ev_id: str, ts=FIXED):
    return DetectionCorrelationInput(
        detection_id=uuid.UUID(det_id),
        event_id=uuid.UUID(ev_id),
        timestamp=ts,
        rule_id="sigma-credential-access-001",
        rule_type=RuleType.SIGMA,
        rule_version="1.2.3",
        severity=DetectionSeverity.HIGH,
        confidence=0.9,
        evidence={"matched_conditions": ["condition_1"]},
        metadata={"rule_version": "1.2.3"},
        provenance=Provenance.DETECTED,
    )


def batch(*items):
    records = list(items)
    return DetectionCorrelationBatch(
        detections=records,
        metadata=DetectionCorrelationBatchMetadata(record_count=len(records)),
    )


D1, D2, D3 = (
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
    "33333333-3333-3333-3333-333333333333",
)
E1, E2 = (
    "44444444-4444-4444-4444-444444444444",
    "55555555-5555-5555-5555-555555555555",
)

results = CorrelationAgent().analyze(
    batch(
        inp(D1, E1),
        inp(D2, E1),
        inp(D3, E2),
    ),
    clock=FIXED,
)
OUT.append(f"count={len(results)}")
for r in results:
    OUT.append(
        json.dumps(
            {
                "correlation_id": str(r.correlation_id),
                "detection_ids": [str(m.detection_id) for m in r.members],
                "event_ids": [str(m.event_id) for m in r.members],
                "status": r.status.value,
                "confidence": r.confidence,
                "evidence": r.evidence,
                "metadata": r.metadata,
                "timestamp": r.timestamp.isoformat(),
                "provenance": r.provenance.value,
            },
            sort_keys=True,
        )
    )

# determinism
r1 = CorrelationAgent().analyze(
    batch(inp(D1, E1), inp(D2, E1)), clock=FIXED
)
r2 = CorrelationAgent().analyze(
    batch(inp(D1, E1), inp(D2, E1)), clock=FIXED
)
OUT.append(
    "deterministic="
    + str(
        [r.detection_ids for r in r1]
        == [r.detection_ids for r in r2]
        and [r.evidence for r in r1] == [r.evidence for r in r2]
        and [r.timestamp for r in r1] == [r.timestamp for r in r2]
    )
)

# empty batch
OUT.append(f"empty={CorrelationAgent().analyze(batch(), clock=FIXED)}")

# failure isolation
try:
    CorrelationAgent().analyze("nope", clock=FIXED)
except CorrelationInputError as exc:
    OUT.append(f"input-error={type(exc).__name__}: ok")


class Exploding:
    name = "exploding"

    def correlate(self, items):
        raise RuntimeError("x")


try:
    CorrelationAgent(strategy=Exploding()).analyze(
        batch(inp(D1, E1)), clock=FIXED
    )
except CorrelationStrategyError as exc:
    OUT.append(
        f"strategy-error={type(exc).__name__}: cause={type(exc.__cause__).__name__}"
    )

with open("_step10b_smoke.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(OUT))
print("wrote _step10b_smoke.txt")