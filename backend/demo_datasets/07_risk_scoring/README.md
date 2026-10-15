# Risk scoring

Score real correlations with the deterministic risk engine.

## Inputs

- `workflow.json (engine contract + observed result)`

## Observed / expected behaviour

member_count=7 -> score 0.628571 -> level high.

## Run

```bash
python scripts/run_demo_dataset.py correlation demo_datasets/05_correlation/focused_event.jsonl
```
