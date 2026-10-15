# SentinelAI Demo Dataset Pack

One organized, executable dataset pack covering the 21 frozen SentinelAI
functions plus a full end-to-end SOC scenario.

Everything here is produced by running the real application code. No output
record, detection, correlation, risk score or provider result is hand-written:
the datasets are **inputs and workflow specifications only**, and the runner
calls the same services the HTTP API calls. Every command cleans up the rows it
creates, so a full run leaves PostgreSQL byte-for-byte the way it found it.

## Layout

```
backend/demo_datasets/
  README.md                  <- you are here
  manifest.json              <- machine-readable index (regenerate with `manifest`)
  verification_report.json   <- output of the last `verify` pass
  00_full_soc_scenario/      <- 10-event intrusion chain feeding every function
  01_log_collection/         <- collector + malformed-line handling
  02_normalization/          <- source-specific field mapping
  03_detection/              <- Sigma + YARA + true-negative controls
  04_threat_intelligence/    <- indicator extraction + live providers
  05_correlation/            <- real multi-member correlation
  06_mitre_mapping/          <- MITRE: NOT IMPLEMENTED (documented honestly)
  07_risk_scoring/           <- deterministic risk engine
  08_investigation/          <- real investigation context + Gemini answer
  09_policy/                 <- real policy decisions
  10_response/               <- real response executor
  11_explainability/         <- provenance-chain invariants
  12_dashboard/              <- dashboard composed from real read APIs
  13_attribution/            <- attribution hypotheses (never facts)
  14_incident_memory/        <- memory extract / persist / consolidate
  15_natural_language_soc/   <- allow-listed + Gemini SOC queries
  16_hitl/                   <- real approval lifecycle
  17_detection_as_code/      <- validate/release/deploy/bump/rollback
  18_soar/                   <- real SOAR engine with sandboxed providers
  19_threat_hunting/         <- governed hunts with persisted evidence
  20_incident_reports/       <- report context + citation gate
  21_attack_paths/           <- evidence-grounded attack-path graph
```

## Running it

```bash
cd backend
.venv/bin/python scripts/run_demo_dataset.py list        # show every command
.venv/bin/python scripts/run_demo_dataset.py all         # run all 21 commands, in order
.venv/bin/python scripts/run_demo_dataset.py full_soc    # the 00 end-to-end scenario
.venv/bin/python scripts/run_demo_dataset.py detection   # one function
.venv/bin/python scripts/run_demo_dataset.py verify      # check the pack + rewrite verification_report.json
.venv/bin/python scripts/run_demo_dataset.py manifest    # regenerate manifest.json from the pack
.venv/bin/python scripts/run_demo_dataset.py all --json  # machine-readable report
```

Exit status: `0` when every check passed, `1` when any check failed, `2` for an
unknown command. Commands that need PostgreSQL say so in `list`. The `--sandbox`
flag acknowledges that only the in-repo mock/offline providers are used.

## Observed results (last verified run)

Command       | Result
------------- | --------------------------------------------------------------
`all`         | 159 passed, 0 failed, 3 skipped (the 3 are Gemini-gated, never fabricated)
`full_soc`    | 137 passed, 0 failed, 3 skipped; the same persisted state feeds every step
`verify`      | pack + manifest + authoring contract + frozen sample all pass

Pipeline facts observed from the real services:

- `00_full_soc_scenario` ingests 10 events once → 9 detections → 3 correlations
  → 3 risk assessments. The primary correlation has 7 members and risk
  `0.628571 HIGH`.
- Detection: 4 Sigma-positive / 2 YARA-positive fixtures match; the negative,
  YARA-negative and clean-baseline fixtures match nothing.
- Risk fixtures land exactly at `0.276190 LOW`, `0.485714 MEDIUM` and
  `0.700000 HIGH`.
- Investigation context: 11 evidence items across 3 layers, 3 risk factors, and
  JSON-mode serialisation keeps real UUIDs intact.
- Natural-language SOC (offline path): detections recent 20, correlations
  recent 20, risk by correlation 1, incident memories by correlation 0,
  detections by rule 22.
- HITL: pending → approved+executed, rejected (no execution), cancelled,
  four-eyes block (self-approval refused), and lazy expiry all pass.
- Detection-as-code: validate / release / deploy / evaluate / version bump /
  rollback pass against a throwaway clone; the shipped 53-rule manifest is never
  touched.
- SOAR: single-step success, 3-step containment success, duplicate returns the
  same execution id, dry-run invokes no provider, denied → `POLICY_DENIED`,
  no-grant → `APPROVAL_NOT_GIVEN` pending.
- Threat hunting: all four governed hunts complete with persisted evidence
  (102/15, 15/2, 9/2, 196/25), cancel works, rerunning a terminal hunt is
  refused.
- Incident reports: report context builds a 16-entry evidence catalog from
  persisted records; generation is Gemini-gated and never fabricated.
- Attack paths: 9 nodes, 8 edges, every edge evidence-grounded, 3 node types.

## Authoring contract

- Every `.jsonl` line must be JSON with `timestamp`, `source`, `source_type`
  and `event_type`. Timestamps are ISO-8601 with an explicit timezone offset.
- `source_prefix_selects_mapping`: `windows`, `linux` and `firewall` prefixes
  select the source mapping; anything else yields an empty mapping.
- YARA detection requires real bytes in `normalized_data.file_content`; the
  JSONL ingestion path cannot supply them (no shipped mapping forwards file
  content), so YARA matches only explicit `evaluate_target` calls.
- `08_investigation`, `13_attribution`, `20_incident_reports` and
  `21_attack_paths` carry `<...>` identifiers that the runner substitutes with
  the identities the real pipeline mints — no evidence id is ever fabricated.
- `verify` enforces all of this: file set, hashes, parseability, required
  fields, placeholder-scan, and the frozen `sample_events.jsonl` checksum.

## Known gaps (reported, never hidden)

- **MITRE ATT&CK**: the backend has no technique mapper; `06_mitre_mapping`
  reports the capability gap without inventing techniques.
- **Correlation** groups by identical `event_id`, so multi-event chains do not
  correlate.
- **Risk event_breadth** is structurally capped at 1 for multi-member
  correlations (the goal is 3), so multi-member risk runs on volume/diversity.
- **YARA ingestion** is unreachable over JSONL; the gap is documented and the
  working `evaluate_target` path is demonstrated instead.
- **LLM answers** (investigation, NL-SOC, incident reports) require
  `GEMINI_API_KEY`; without one the runner skips and never invents text.
- **Threat-intel lookups** require the real provider keys in `.env`; failures
  are captured in the report, never fabricated.
- **Learning** `IncidentMemoryLearningService()` ships with a broken default
  factory; the runner passes the correct repository factory from the call site.

## Frozen sample

`backend/sample_events.jsonl` is intentionally untouched by the pack. Its
sha256 is recorded in `manifest.json` and enforced by `verify`:
`d4b95a63fa2c303cd56c7a33be3ff1735299066991d4e02a2d237ce0d389db50`.