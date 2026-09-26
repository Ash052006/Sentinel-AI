# Threat Attribution Contract (Step 14)

## 1. Purpose and scope

Step 14 defines the **Threat Attribution domain contract only**. It does
not determine attribution, calculate attribution confidence, call an LLM,
query RAG knowledge, persist attribution assessments, expose an API, or
perform response or mitigation.

The product being delivered is a validated Pydantic schema contract that a
future attribution engine can fill: structured, bounded, secret-safe,
deterministic domain models for attribution hypotheses and assessments,
rooted in the existing pipeline's provenance and reference conventions.

"Step 14 defines the Threat Attribution domain contract only. It does not determine attribution, calculate attribution confidence, call an LLM, query RAG knowledge, persist attribution assessments, expose an API, or perform response or mitigation."

## 2. Contract boundaries

The contract is deliberately non-cognitive:

- It contains **no attribution logic** — no graph/timeline analysis, no
  TTP matching, no confidence formulas, no provider scoring.
- It calls **no external systems** — no LLM, no Qdrant, no HTTP, no Kafka.
- It persists **nothing** — no models, no tables, no migrations (alembic
  head unchanged at `4a6c8d0e1f2a`).
- It exposes **no API or event handlers**.
- It defines **no response or mitigation** behaviour.

The contract **does not assume attribution is always possible**: an
assessment is not required to name a confident actor.  The explicit
`AttributionStatus` covers failure-averse outcomes.

## 3. Domain models

Four models plus two enums are defined in
`app/schemas/threat_attribution.py`:

- `AttributionStatus` (enum) — `attributed`, `partially_supported`,
  `uncertain`, `insufficient_evidence`, `conflicting`, `unattributed`.
- `AttributionTargetType` (enum) — `threat_actor`, `threat_group`,
  `malware_family`, `campaign`, `infrastructure`, `technique_cluster`,
  `unknown`.
- `AttributionEvidence` — a typed, provenance-aware reference to an
  existing pipeline object.
- `AttributionHypothesis` — a single evidence-grounded hypothesis with a
  per-hypothesis confidence and supporting/conflicting evidence lists.
- `AttributionAssessment` — the root: correlation-anchored, status-bearing,
  hypothesis/evidence containers, metadata, timestamp, pinned provenance.

No builder or factory exists in the contract; a future engine constructs
these models directly.  Exactly five model types are used — nothing more.

## 4. Status vs confidence vs evidence

Three independent concepts are kept strictly separate:

| Concept | Field | Meaning | Derived from? |
|---|---|---|---|
| Status | `AttributionAssessment.status` | categorical outcome | never derived |
| Confidence | `AttributionHypothesis.confidence` | per-hypothesis belief `[0,1]` | never derived, not a score |
| Evidence | `supporting_evidence_ids` / `conflicting_evidence_ids` | citations | never derived |

The contract never converts confidence into status (a `0.8` hypothesis can
sit under an `uncertain` assessment), never aggregates hypothesis counts,
and never converts any other score (risk, detection, correlation,
investigation, relevance) into attribution confidence.  There is exactly
one confidence concept.  Nothing here computes, sums, averages, or weighs
anything.

## 5. Target representation

Each hypothesis names a `target_type` (enum) and a `target_identifier`
(bounded, stripped, secret-scanned string, `<= 256` chars).  Identifiers
are opaque names/symbols.  The contract bounds and rejects; it never
truncates, normalizes, validates against a threat-intel registry, or
resolves identifiers.

## 6. Confidence validation

`confidence` must be:

- a finite float in `[0.0, 1.0]` (enforced by bounds plus a finiteness
  check that rejects `NaN` and `±Infinity`);
- not a boolean (a coercion of `True -> 1.0` is rejected at the raw-input
  boundary before Pydantic coercion);
- independent of every risk/detection/investigation/relevance score in the
  pipeline.  No conversion formula exists in this contract.

## 7. Evidence model and references

Attribution evidence is a reference to an object that already exists in the
pipeline — it is never embedded data and never re-derived:

- `OBSERVED`, `ENRICHED`, `RECONSTRUCTED` ⇒ requires `event_id`
- `DETECTED` ⇒ requires `detection_id`
- `CORRELATED` ⇒ requires `correlation_id`
- `RISK_ASSESSED` ⇒ requires `risk_assessment_id`
- `AI_GENERATED` ⇒ requires `investigation_id` (the authoritative
  `InvestigationResult.investigation_id`; no synthesized result id)
- `ATTRIBUTION_ASSESSED` ⇒ **forbidden** on evidence

A provenance category cannot be attached without its matching source
identity.  AI-generated reasoning is therefore never automatically treated
as source evidence; it is only *referenced* with explicit `AI_GENERATED`
provenance, and its role must be defensible.

## 8. Conflicting evidence

Evidence may conflict: a hypothesis carries both `supporting_evidence_ids`
and `conflicting_evidence_ids`.  The contract:

- preserves both lists verbatim (order and duplicates, mirroring the
  Step 12A duplicate-preservation decision);
- rejects a reference that appears on **both** sides of the same
  hypothesis (a contradiction that cannot be resolved here);
- performs **no auto-resolution** — determining which side weighs more is
  the future engine's job, never this contract's.

## 9. Provenance

Attribution uses the existing global `Provenance` enum
(`app/schemas/security_event.py`); no duplicate provenance enum is created.

Adding a new value was genuinely necessary (the enum elsewhere pins only
source-derived categories, and attribution output is neither source
telemetry nor AI investigation output), so the change was made:

- **additively** — `ATTRIBUTION_ASSESSED = "attribution_assessed"` was
  appended; no prior value redefined;
- **documented** in the enum docstring, distinguishing attribution output
  from observations/findings;
- **pinned** — `AttributionHypothesis` and `AttributionAssessment` are
  locked to `ATTRIBUTION_ASSESSED` (a hypothesis/assessment cannot be
  silently mislabelled as observed/other provenance);
- **forbidden on evidence** — attribution hypotheses are conclusions, not
  sources, so `ATTRIBUTION_ASSESSED` is rejected on `AttributionEvidence`
  and on the Step 12A `InvestigationEvidence` (which is hardened so the
  new value cannot leak into investigation evidence either).

Regression tests verify all seven prior provenance values remain intact.

## 10. Timestamps and timezone handling

`AttributionAssessment.timestamp`:

- is **required** and timezone-aware; naive datetimes are rejected;
- rejects numeric/bool coercion (Pydantic otherwise silently interprets a
  float as an epoch timestamp — the contract refuses that coercion);
- is supplied explicitly by the caller — there is no hidden clock — so
  identical inputs serialize identically (determinism);
- is never used as evidence and never contributes to confidence.

## 11. Identifiers

All identity fields (`attribution_assessment_id`, `correlation_id`,
`evidence_id`, `hypothesis_id`, and every reference field) are `uuid4`
values required to be real UUIDs.  IDs are application/domain-generated
(`uuid4` defaults create fresh values per object) and never `None`.
`correlation_id` anchors the assessment to the pipeline exactly as in the
Step 11A risk and Step 12A investigation contracts; `investigation_id` is
the authoritative Step 12A result identifier.

## 12. Metadata

All three `metadata` fields (evidence, hypothesis, assessment) accept
JSON-compatible dictionaries only, and are:

- **bounded in depth** (`<= 8` container levels) and **bounded in size**
  (`<= 4096` serialized bytes);
- **cloned** on input so caller mutations never alias into the model
  (immutability);
- **secret-scanned** and rejected (never redacted);
- rejected if they contain cycles, sets, bytes, arbitrary objects,
  `NaN`, `Infinity`, or non-string keys.

Metadata is passive storage; it holds no semantics the contract enforces.

## 13. Secret safety

The canonical eight-pattern set is enforced: `api_key`, `authorization`,
`bearer`, `secret`, `password`, `cookie`, `session_token`, `jwt`.

The scan serializes content and matches patterns against the serialized
text (matching the Step 13 canonical approach), so secret-shaped **values**
are caught exactly like secret-shaped keys.  Scanning applies at every
level: target identifiers, evidence types, hypothesis metadata, evidence
metadata, assessment metadata, and whole-hypothesis/assignment
serializations.  Secrets are **rejected, never redacted**.  Helper
implementation is re-declared locally (each staged contract stays
self-contained and testable in isolation) and kept in lock-step with the
canonical set.

## 14. JSON safety

Every metadata payload must survive `json.dumps` and the structural check:

- `json.dumps` first — rejects sets, bytes, arbitrary objects, and
  reference cycles (a cyclic dict cannot reach the recursion);
- structural check second — rejects `NaN`, `Infinity`, excessive depth.

There is no `eval`/`exec`/`compile`/`pickle` usage anywhere in the
contract.  Non-finite numbers can never be serialized.

## 15. Immutability and determinism

- Nested inputs (metadata dicts/lists, hypothesis/evidence lists) are
  deep-cloned on construction; mutating the caller's objects afterwards
  never changes the model.
- No hidden clock, no sorting, no deduplication: list order and
  duplicates are preserved exactly as supplied.
- Identical inputs (including explicit IDs and the caller-supplied
  timestamp) produce byte-identical `model_dump_json()` output
  (asserted by the determinism tests).

## 16. Unknown-field policy

The contract follows the established SentinelAI default
(`extra = "ignore"`): unknown fields passed anywhere in an assessment are
silently ignored.  This is the policy already asserted by the Step 12A
`TestUnknownFields`; `extra = "forbid"` is deliberately **not** introduced
here so the contract stays consistent with every prior staged schema.

## 17. Dependency isolation and offline capability

`app/schemas/threat_attribution.py` imports only stdlib (`json`, `uuid`,
`enum`, `datetime`, `math`, `typing`, `__future__`), `pydantic`, and the
existing `app.schemas.security_event` module.  It imports no FastAPI,
SQLAlchemy, Qdrant, Kafka, HTTP, or LLM SDK at module scope; importing the
module must not pull in `qdrant_client` or any framework (verified by
subprocess tests).  The contract is fully offline-capable — the RAG layer,
Gemini client, HTTP clients, and database layers are equally unusable and
unused from this module.

## 18. Configuration, bounds, and reference limits

Bounds are hard-coded, not configurable:

| Constant | Value | Applied to |
|---|---|---|
| `MAX_ATTRIBUTION_HYPOTHESES` | `10` | `AttributionAssessment.hypotheses` |
| `MAX_ATTRIBUTION_EVIDENCE_ITEMS` | `250` | `AttributionAssessment.evidence` |
| `MAX_ATTRIBUTION_TARGET_IDENTIFIER_LENGTH` | `256` | `target_identifier` |
| `MAX_ATTRIBUTION_LABEL_LENGTH` | `512` | `evidence_type` and label text |
| `MAX_ATTRIBUTION_METADATA_DEPTH` | `8` | metadata container depth |
| `MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES` | `4096` | metadata serialized size |

Values that exceed a bound are **rejected, never truncated**.  No new
runtime configuration was added; `requirements.txt` is unchanged (the
contract needs only the existing `pydantic`).

## 19. Testing strategy and coverage

`tests/unit/test_attribution_contract.py` (134 tests) covers the sixteen
required categories:

1. enums — status and target-type values, value serialization, invalid
   rejection;
2. valid assessment — full round-trip with all seven provenance types;
3. target validation — blank/whitespace/non-string/oversized, never
   truncated;
4. confidence — bounds, finiteness, boolean rejection, non-derivation;
5. status — all six values, never derived from confidence or counts;
6. evidence references — provenance-to-reference map, mismatch rejection,
   local resolution;
7. conflicting evidence — preserved, same-side ban, duplicates kept;
8. provenance — additive member, all prior values regression, pinning,
   Step 12A hardening regression;
9. secret safety — all eight patterns across identifiers, labels, and the
   three metadata levels;
10. JSON safety — sets, bytes, arbitrary objects, `NaN`, `Infinity`,
    cycles, non-string keys;
11. immutability — nested inputs never aliased;
12. determinism — identical inputs yield identical JSON; timestamp is
    required (no hidden clock); order preserved;
13. timestamps — naive rejected, aware accepted, numeric coercion
    rejected;
14. unknown fields — ignored at every level;
15. boundaries — hypothesis/evidence/metadata depth/size/label limits;
16. security isolation — no forbidden module imports, offline import
    check, stdlib-only source scan.

Regression is run against Step 12A contract/context, Step 12B context
builder, Step 12C agent/prompt/Gemini integration, Step 13 knowledge
modules, and the detection/correlation/risk/threat-intel/enrichment
suites; the full backend suite is green (`3162 passed, 2 skipped`), and
`compileall` is clean.

## 20. Operational notes

- The database schema is untouched: `alembic current`/`alembic heads`
  remain `4a6c8d0e1f2a` and `alembic check` reports no new upgrade
  operations.
- This step is contract-only and adds no endpoints, no handlers, no
  services, no repository rows, and no engine.  A future Step must build
  the *attribution engine* on top of this contract; this step must not be
  mistaken for one.

"Attribution hypotheses are assessments over available evidence and must not be treated as independently observed security facts."