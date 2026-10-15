# Detection

Exercise the Sigma and YARA engines through the real pipeline, including a false-positive control.

## Inputs

- `multi_rule_process.jsonl - 1 record that trips 7 Sigma rules`
- `yara_artifact.jsonl - 1 record carrying real file bytes`
- `clean_baseline.jsonl - benign Excel automation record`

## Observed / expected behaviour

multi_rule_process.jsonl -> 7 detections; yara_artifact.jsonl -> 1 YARA match (Sentry_PowerShell_Artifact); clean_baseline.jsonl -> 0 detections (verified false-positive control).

## Run

```bash
python scripts/run_demo_dataset.py detection demo_datasets/03_detection/multi_rule_process.jsonl
```

## Verified limitations

1. **YARA requires real bytes.** The adapter only reads
   `normalized_data.file_content` (or `file.content_bytes`,
   `file.raw_content`, `raw_file_content`). A file path is NOT content.
   Without bytes the engine reports an `invalid_target` failure, which
   is correct behaviour and not an error.
2. **Some shipped Sigma rules are unreachable through this pipeline.**
   Rules that match on `DestinationProtocol` or `rule_name` only fire
   when those keys are supplied via `normalized_data`.
