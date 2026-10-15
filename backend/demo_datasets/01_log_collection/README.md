# Log collection

Exercise FileLogCollector: JSON Lines parsing, per-line record isolation, blank-line skipping and malformed-line reporting.

## Inputs

- `windows_security_events.jsonl (5 records)`
- `linux_events.jsonl (1 record)`
- `firewall_events.jsonl (4 records)`
- `malformed_mixed.jsonl (5 lines: 2 valid, 3 deliberately broken)`

## Observed / expected behaviour

Collection totals plus an error entry per bad line. Malformed lines are isolated: one bad line never aborts the run.

## Run

```bash
python scripts/run_demo_dataset.py detection demo_datasets/01_log_collection/windows_security_events.jsonl
```
