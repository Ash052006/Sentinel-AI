# Investigation Context Builder (Step 12B)

## 1. Purpose and scope

Step 12B constructs the input representation for the future AI Investigation Agent: a bounded, validated `InvestigationContext` assembled deterministically from the existing SentinelAI domain outputs (a Step 10A `CorrelationResult`, an optional Step 11A `RiskAssessment`, detection records, a Step 8A `ThreatIntelligenceAnalysis`, and enrichment results).

Step 12B constructs a bounded, provenance-preserving investigation context; it does not investigate, infer, persist, expose, or act on security events.

The builder performs **no analysis**. It carries structured data from earlier pipeline phases into a single validated object; it does not reason, score, infer, find, observe, alert, or respond. It contains no AI, LLM, Ollama, LangChain/LangGraph, embedding/vector, prompt-template, or model-call logic; no persistence; no API routes; no Kafka integration; and no agent, incident, MITRE, alerting, or response logic. Those layers are future phases and must not leak into this module.

The single most important invariant of the builder:

Security telemetry is treated as untrusted data, never as instructions.

## 2. Definitions and reading guide

- **Investigation Context** — the complete Step 12B output: the anchored correlation, optional risk assessment, detections, threat-intelligence analysis, enrichments, event-provenance inventory, input-availability record, mechanical evidence records, and bookkeeping metadata.
- **Carried data** — structured fields transferred from a source contract into the context through an explicit allowlist. The builder never serializes a whole source object.
- **Provenance pin** — an enforced provenance classification on a context item (e.g. a detection is always `DETECTED`). Pins are validated by the context contract and can never be overwritten by source values.
- **Source origin** — the provenance of the *event* a value was extracted from (`OBSERVED` / `ENRICHED` / `RECONSTRUCTED`), declared by the caller for TI indicators only. It is never fabricated.
- **Input availability** — the explicit record of whether each optional input was provided, explicitly empty, or omitted.
- **Bound** — a documented constant that caps list sizes, string lengths, payload depth/size, and the total context size. Bounds reject; they never truncate.
- **Refuse-to-carry** — the secret policy: any credential-shaped content is refused rather than carried into the AI context.
- **Evidence** — the Step 12A `InvestigationEvidence` records mechanically derived to index each carried source.

## 3. Module structure

The builder lives in `backend/app/schemas/investigation_context.py` and is re-exported from `app/schemas/__init__.py`. Following the repository convention for pure adapters/contracts, the module is a dependency-light schema module: stdlib + Pydantic + existing SentinelAI domain schemas only. There is no SQLAlchemy, FastAPI, Kafka, HTTP client, or AI framework import at module scope.

Public surface:

- `InvestigationContextBuilder` — stateless builder; `build()` is its only public entry point.
- `InvestigationContext` and its section models (`CorrelationContext`, `CorrelationMemberContext`, `RiskContext`, `DetectionContext`, `IndicatorContext`, `ProviderResultContext`, `ProviderLookupContext`, `ProviderFailureContext`, `ThreatIntelligenceContext`, `EnrichmentContext`, `EventProvenanceContext`).
- `ContextInputAvailability` and `InputAvailability`.
- `InvestigationContextError(ValueError)` and `InvestigationContextBoundError(InvestigationContextError)`.
- Bounds constants (`MAX_*`) documented in Section 9.

## 4. Supported source inputs

`build()` accepts, all existing SentinelAI contracts:

| Parameter | Source contract | Enforcement |
|---|---|---|
| `correlation` | `CorrelationResult` (Step 10A) | Required; wrong type raises `TypeError`. |
| `risk_assessment` | `RiskAssessment` (Step 11A) | Optional single object. |
| `detections` | `DetectionCorrelationInput` / `DetectionCorrelationBatch` / matched `DetectionResult` / `DetectionResultRecord`, or an iterable of those | Unmatched `DetectionResult` refused (existing `to_correlation_input` semantics). |
| `threat_intelligence` | `ThreatIntelligenceAnalysis` (Step 8A) | Optional single object. |
| `enrichments` | iterable of `EnrichmentResult` (also accepts a single result) | Wrong item type raises `TypeError`. |
| `event_provenance` | `Mapping[event_id, Provenance]` | Values must be `Provenance`. |
| `metadata` | `Mapping[str, Any]` | Reserved bookkeeping keys refused; payload bounded. |
| `investigation_id` / `context_created_at` | identity + clock | Injectable for deterministic builds; auto-generated when omitted. |

Each source is mapped through an explicit field allowlist. The builder never calls `model_dump()` (or `model_dump_json()`) on a source object, so future internal fields of those contracts can never leak into the AI context.

## 5. Context structure

`InvestigationContext` carries:

- `investigation_id`, `context_created_at` — bookkeeping identity and clock. The timestamp is explicitly **not** security evidence.
- `input_availability` — Section 6.
- `correlation` — required, Section 7.
- `risk_assessment` — optional, Section 8.
- `detections` — allowlisted detection records in source order.
- `threat_intelligence` — indicators, provider results, skipped lookups, isolated failures, execution counters.
- `enrichments` — allowlisted enrichment results in source order.
- `event_provenance` — declared event-record provenance for referenced events, sorted by `event_id` (Section 11).
- `evidence` — mechanical Step 12A evidence records (Section 13).
- `metadata` — bookkeeping (`context_schema_version`, `truncation`) merged with caller metadata.

The model validates JSON compatibility, secret safety, metadata bounds, section bounds, and the total serialized-size bound on every construction, using only Pydantic validators — never `eval`/`exec`/`pickle`.

## 6. Input availability

`ContextInputAvailability` records, for each optional input, one of:

- `PROVIDED` — at least one item / an object was supplied.
- `NONE_FOUND` — an explicitly empty set was supplied (an observed absence).
- `NOT_PROVIDED` — the parameter was omitted (absence is never an observed fact).

`correlation` is always `PROVIDED` in a valid context. An empty `ThreatIntelligenceAnalysis` is "provided, no indicators", never "no threat intelligence exists" — its internal emptiness is read from its own structural fields.

## 7. Correlation context

`CorrelationContext` / `CorrelationMemberContext` replicate the correlation's identity, status, confidence, evidence, timestamp, and members in source order, preserving duplicates. Members carry the correlation's own `CORRELATED` provenance — never a member detection's. Both envelope and member pin `CORRELATED`: the context contract rejects any other value, so no source can relabel correlation conclusions.

## 8. Risk context

`RiskContext` carries the assessment's `score`, `level`, `confidence`, factors, and evidence **verbatim**. The builder never recalculates the score, never derives the level from the score, and never merges risk score with confidence. Factors and evidence are deep-cloned JSON payloads. Provenance is pinned to `RISK_ASSESSED`.

## 9. Bounds — the reject policy

All limits are explicit constants in the module and are documented. If a limit is exceeded the context is **refused** with an error naming the section and the constant; security evidence is never silently truncated.

| Constant | Limit |
|---|---|
| `MAX_CORRELATION_MEMBERS` | 1000 |
| `MAX_DETECTIONS` | 500 |
| `MAX_TI_INDICATORS` | 500 |
| `MAX_TI_PROVIDER_RESULTS` | 500 (provider results + skipped lookups) |
| `MAX_TI_FAILURES` | 250 |
| `MAX_ENRICHMENTS` | 500 |
| `MAX_EVENT_PROVENANCE_ENTRIES` | 2048 |
| `MAX_STRING_LENGTH` | 4096 |
| `MAX_METADATA_DEPTH` | 8 container levels |
| `MAX_METADATA_SERIALIZED_BYTES` | 64 KiB per payload |
| `MAX_CONTEXT_TOTAL_BYTES` | 512 KiB total serialized |
| `MAX_EVIDENCE_ITEMS` | 2 + 500 + 500 + 500 = 1502 |

Count/list bounds are enforced by the builder before construction and raise `InvestigationContextBoundError` directly. Field-level bounds (string length, payload depth/size, total size) are enforced by the context model's validators and surface as a Pydantic `ValidationError` (a `ValueError` subclass) whose message names the exact bound constant. Both guarantee deterministic rejection without truncation.

## 10. Secret safety — refuse-to-carry

The repository-wide refuse-to-carry policy (`api_key`, `authorization`, `bearer`, `secret`) is preserved. At this AI trust boundary it is extended additively with the credential families Step 12B explicitly requires: `password`, `cookie`, `session_token`, `jwt`.

The extended pattern set applies to every structured payload carried into the context (correlation evidence, detection evidence/metadata, risk factors/evidence, provider payloads, enrichment values, TI metadata, caller metadata). Detection is case-insensitive and recurses into nested payloads. Any match raises a secret-screening `ValueError`; the context is refused. Earlier contracts are unchanged — this is an additive extension at this boundary only.

## 11. Event provenance inventory

`event_provenance` accepts a caller-declared mapping from referenced `event_id` to the event record's own `Provenance`. Only events actually referenced by the carried sources are projected, and the inventory is sorted by `str(event_id)` for deterministic serialization.

The provenance is preserved verbatim. A `RECONSTRUCTED` event stays `RECONSTRUCTED`; it is never downgraded to `OBSERVED`. Events whose provenance was not declared are omitted entirely (an absence is never an observed fact). `EventProvenanceContext` accepts the full provenance enumeration; no value is relabelled.

For TI indicators, the declared source origin is used only when the *empirical* values are `OBSERVED`, `ENRICHED`, or `RECONSTRUCTED`. An undeclared origin leaves the indicator's provenance `None` — explicitly undeclared, never asserted. Declaring an unsupported origin (e.g. `AI_GENERATED`) on the TI event is refused, because source-backed evidence can never be AI-generated.

## 12. Provenance pinning summary

| Carried item | Provenance | Enforced |
|---|---|---|
| Correlation + members | `CORRELATED` | pinned |
| Risk assessment | `RISK_ASSESSED` | pinned |
| Detections | `DETECTED` | pinned |
| Enrichments | `ENRICHED` | pinned |
| TI provider results | `ENRICHED` | pinned |
| TI indicators | source origin or `None` | validated set `OBSERVED/ENRICHED/RECONSTRUCTED/None` |
| TI skipped lookups | none (bookkeeping, not evidence) | no provenance claim |
| Event records | verbatim from declared mapping | preserved |

## 13. Evidence derivation

The context derives Step 12A `InvestigationEvidence` records mechanically:

- one per correlation (`CORRELATED` → `correlation_id`),
- one per risk assessment when present (`RISK_ASSESSED` → `risk_assessment_id`),
- one per detection (`DETECTED` → `detection_id`),
- one per TI indicator whose source-event provenance was declared (`OBSERVED`/`ENRICHED`/`RECONSTRUCTED` → `event_id`),
- one per TI provider result (`ENRICHED` → `event_id`).

Skipped lookups and undeclared-origin indicators are **not** evidence: the builder never fabricates an observed claim. Each `evidence_id` is derived deterministically (uuid5 under fixed namespace) from the source identity, so identical inputs produce identical evidence identifiers.

The context never creates findings or observations: those are investigation output (Step 12C) and are structurally out of scope for `InvestigationContext`.

## 14. DATA != INSTRUCTION

Attacker-controlled strings (log fields, command lines, indicator values, provider result payloads, enrichment values, provider failure messages, metadata) enter the pipeline from untrusted telemetry. The builder carries them verbatim as **structured data**:

- they are never wrapped in prompt/system/developer instructions,
- they are never concatenated into a control string,
- they can never alter context policy, provenance, bounds, ordering, availability, or evidence derivation,
- no prompt-injection heuristics or LLM detection are used,
- the context defines no `instructions`, `prompt`, `system`, or `developer` field.

An injected string may change the value of a structured payload field and nothing else. The separator and instruction vocabulary of telemetry is irrelevant to the context's meaning because nothing downstream ever interprets these strings as instructions.

## 15. Determinism and immutability

- Identical inputs produce byte-identical serialization: `investigation_id` and `context_created_at` are injectable; source order is preserved; `event_provenance` is sorted; evidence ids are deterministic; no current-time or random value enters the security content.
- The builder never mutates a source and never shares mutable state with one. Every structured payload is deep-cloned (JSON round-trip) at the boundary. Correlations, risk factors/evidence, detection evidence/metadata, provider payloads, enrichment values, and merged metadata are all returned as independent copies.
- Duplicates are preserved and sources are never reordered or deduplicated.

## 16. Dependency isolation

The module imports only stdlib (`json`, `uuid`, `datetime`, `enum`, `typing`), Pydantic, and existing SentinelAI schema/service-type modules (`app.schemas.*`, `app.services.threat_intelligence.types`). There are no imports of AI frameworks, HTTP clients, persistence, message buses, or orchestration libraries, and no dynamic loading of any kind.

## 17. Error model

- Wrong source types raise `TypeError` with the received type's module path.
- Source-contract violations (e.g. an unmatched detection) propagate the existing `ValueError` semantics of `to_correlation_input`.
- Bound violations raise `InvestigationContextBoundError` (from the builder) or a Pydantic `ValidationError` naming the constant (from the context model). Both are `ValueError` subclasses.
- Error messages are sanitized: they contain section names, constant names, and counts only — never payload content, credentials, or internal state.

## 18. Constructed example

Correlation-only context:

```python
ctx = InvestigationContextBuilder().build(
    correlation=correlation_result,          # Step 10A
    investigation_id=uuid.UUID(...),
    context_created_at=datetime.now(timezone.utc),
)
# ctx.correlation.status      == CorrelationStatus.CANDIDATE
# ctx.input_availability      == ContextInputAvailability(
#     correlation=PROVIDED,
#     risk_assessment=NOT_PROVIDED,
#     detections=NOT_PROVIDED,
#     threat_intelligence=NOT_PROVIDED,
#     enrichments=NOT_PROVIDED)
# ctx.evidence                == [InvestigationEvidence(CORRELATED)]
# ctx.metadata                == {"context_schema_version": "1.0.0", "truncation": []}
```

A full context additionally supplies `risk_assessment`, `detections`, `threat_intelligence`, `enrichments`, and — when the provenance of referenced events is known — `event_provenance` so that TI indicators carry their true source origin.

## 19. Consistency with earlier contracts

Step 12B is a pure consumer of the existing contracts. It modifies none of them; it reuses `to_correlation_input` for detection transport and the Step 12A `InvestigationEvidence` contract for evidence. The additive secret-pattern extension (Section 10) exists only inside this module. `Provenance` values, `RiskLevel`, `RuleType`, `DetectionSeverity`, `CorrelationStatus`, `IndicatorType`, and the empirical-provenance semantics are all reused unchanged.

## 20. Testing and boundaries

Testing lives in `backend/tests/unit/test_investigation_context_builder.py` and covers: context construction golden paths; required-input enforcement; correlation member order/duplicates; risk score/level/confidence preservation (never recalculated); every detection source form and rejection paths; TI indicators, provider results, skipped lookups, and failures; enrichment forms; every provenance value including `RECONSTRUCTED`-stays-`RECONSTRUCTED`; input-availability distinctions; every boundary at exact-max and max+1; string/payload/total-size caps; refuse-to-carry for all base and extended secret patterns; immutability in both directions; byte-identical determinism; DATA-INSTRUCTION separation for injected strings; dependency isolation (AST import scan); and the error model.

Non-goals (out of scope, must not be added to this module): AI/LLM reasoning, findings and observations, persistence, API endpoints, Kafka integration, incident/response/MITRE logic, and any investigation behavior. Step 12B stays a deterministic, bounded, provenance-preserving contract and builder.