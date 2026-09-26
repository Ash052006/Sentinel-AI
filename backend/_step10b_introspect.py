"""Throwaway introspection for Step 10B — prints exact model fields."""
from app.schemas.detection_correlation import (
    DetectionCorrelationInput,
    DetectionCorrelationBatch,
    DetectionCorrelationBatchMetadata,
)
from app.schemas.correlation import CorrelationResult, CorrelationMember, CorrelationStatus

for label, model in (
    ("DetectionCorrelationInput", DetectionCorrelationInput),
    ("DetectionCorrelationBatch", DetectionCorrelationBatch),
    ("DetectionCorrelationBatchMetadata", DetectionCorrelationBatchMetadata),
    ("CorrelationResult", CorrelationResult),
    ("CorrelationMember", CorrelationMember),
    ("CorrelationStatus", CorrelationStatus),
):
    print(f"== {label} ==")
    if isinstance(model, type) and hasattr(model, "model_fields"):
        for n, f in model.model_fields.items():
            print(
                f"  {n}: {f.annotation} | required={f.is_required()} | "
                f"default={f.default!r} | factory={f.default_factory}"
            )
    else:
        print(f"  values: {[(m.name, m.value) for m in model]}")
    print()