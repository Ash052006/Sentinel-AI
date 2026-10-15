# Event normalization

Show the deterministic source-to-schema mapping, including the two behaviours that most often surprise users.

## Inputs

- `windows_native_fields.jsonl - Windows-native Security field names`
- `linux_snake_case.jsonl - Linux snake_case field names`
- `firewall_fields.jsonl - firewall field names`
- `unmapped_source.jsonl - source that matches no mapping`
- `explicit_overrides.jsonl - top-level action/outcome/event_category bridge`

## Observed / expected behaviour

A NormalizedSecurityEvent per record, plus the two verified limitations below.

## Run

```bash
python scripts/run_demo_dataset.py detection demo_datasets/02_event_normalization/explicit_overrides.jsonl
```

## Verified limitations

1. **The mapping registry is keyed by `source` NAME, not `source_type`.**
   `_SOURCE_MAPPINGS` contains only `windows`, `linux` and `firewall`,
   matched exactly then by longest prefix. A record whose `source` is
   `siem-gateway-01` gets an *empty* mapping: process/file/actor fields
   are silently dropped (`unmapped_source.jsonl` demonstrates this -
   0 detections).
2. **`WINDOWS_MAPPING` defines no `action_fields`.**
   `action` therefore survives only because `ingest_service.
   apply_explicit_fields` bridges it from the top level. `linux` and
   `firewall` map `action` natively.
3. `event_type` must be a key of `_DEFAULT_CATEGORY_MAP`
   (`process_creation`, `logon`, `network_connection`, ...) or you must
   set `event_category` explicitly; anything else normalises to `other`
   and matches almost nothing.
