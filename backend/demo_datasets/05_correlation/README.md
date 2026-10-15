# Correlation

Produce a genuine multi-member correlation from real detections.

## Inputs

- `focused_event.jsonl (1 record)`
- `workflow.json (batch contract)`

## Observed / expected behaviour

1 multi-member correlation: 7 members, 1 distinct event, risk 0.628571 (high). Provenance is DETECTED for every member.

## Run

```bash
python scripts/run_demo_dataset.py correlation demo_datasets/05_correlation/focused_event.jsonl
```

## Critical limitation

`DeterministicCorrelationStrategy` groups detections by **identical
`event_id` only** (signal `shared_event_id`). There is no host-,
user- or time-window-based grouping.

**Consequence:** a multi-*event* attack chain does NOT produce a
correlation. A multi-member correlation is only possible when 2+
rules match the *same* event - which is what `focused_event.jsonl`
does (7 rules, 1 event).
