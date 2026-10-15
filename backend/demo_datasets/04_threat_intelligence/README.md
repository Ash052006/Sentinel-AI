# Threat intelligence

Extract indicators from a real normalized event and run the configured providers against them.

## Inputs

- `indicator_events.jsonl (1 record with url, hostname, file_hash)`

## Observed / expected behaviour

2 indicators extracted (hash + url). Verified live: 4 lookups attempted, 3 succeeded, 1 failed (AlienVault OTX timeout, retryable) - failures are isolated, never fabricated.

## Run

```bash
python scripts/run_demo_dataset.py threat_intelligence demo_datasets/04_threat_intelligence/indicator_events.jsonl
```
