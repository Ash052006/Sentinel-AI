# Attack mapping (NOT IMPLEMENTED)

Document, honestly, that the backend contains no MITRE ATT&CK mapping implementation.

## Inputs

- `rule_references_example.json`
- `workflow.json`

## Observed / expected behaviour

No mapping. This directory intentionally demonstrates the absence rather than simulating a mapping engine.

## Run

```bash
cat demo_datasets/06_attack_mapping/workflow.json
```

## Why this directory is empty of behaviour

Verified by inspection of the whole backend:

- `app/services/` - no MITRE/mapping module
- `app/models/` - no technique model
- `app/api/routes/` - no MITRE route

The only related surface is the free-form
`DetectionEvidence.rule_references: dict[str, Any]`, which nothing
populates automatically. A real detection produces an empty dict
there. This pack deliberately does NOT invent a mapping engine and
does NOT ship fabricated technique ids.
