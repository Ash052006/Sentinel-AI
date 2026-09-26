# Threat Attribution Engine (Step 15)

## 1. Purpose

The Threat Attribution Engine is the SentinelAI step that turns explicit,
structured attribution signals into a deterministic, explainable, validated
Threat Attribution Assessment. It is the runtime companion of the Step 14
attribution contract (`app/schemas/threat_attribution.py`), and it consumes
that contract's `AttributionAssessment` output while producing assessments
only from signals it is explicitly handed.

Step 15 implements deterministic, evidence-grounded threat attribution only. It does not call an LLM, query RAG, persist attribution assessments, expose an API, or perform response or mitigation.

## 2. Required reading and trusted inputs

| Document | Trusted for |
| --- | --- |
| `docs/development/threat_attribution_contract.md` (Step 14) | Data model, bounds, provenance map |
| `app/schemas/threat_attribution.py` | Contract enums and validation |
| `app/schemas/security_event.py` | `Provenance` enum |
| `app/schemas/risk.py` | `RiskLevel` (observation-only context) |
| `app/services/risk/engine.py` | Deterministic engine/strategy conventions |
| `app/agents/correlation.py` | Clock-injection convention |

The only inputs the policy may consult are the structured claims of a
`ThreatAttributionInput`. Everything else in the pipeline (detection
metadata, risk score, investigation confidence, RAG retrieval) is explicitly
outside the attribution decision.

## 3. Architecture

```
ThreatAttributionEngine
   ├── _validate_input        (contract, semantic bounds, metadata margin)
   ├── _assert_no_secrets     (fail-closed serialization scan)
   ├── clock / uuid_factory   (injectable; default utc, uuid4)
   └── strategy.assess(
            ThreatAttributionInput,
            timestamp=..., uuid_factory=...)
             └── DeterministicAttributionStrategy
                  ├── attribution_confidence(s, c)   (Fraction, closed form)
                  ├── assess_status(...)              (evidence-state status)
                  └── AttributionAssessment           (Step 14 contract)
   └── output re-validation   (model_dump_json → model_validate_json)
```

The engine is one module (`engine.py`) plus a policy module (`policy.py`)
and an input contract module (`input.py`). There are no databases, queues,
message brokers, HTTP clients, vector stores, or AI clients anywhere in the
module graph.

## 4. Input contract

`ThreatAttributionInput` (in `app/services/threat_attribution/input.py`)
is the explicit structured attribution signal:

```python
ThreatAttributionInput(
    correlation_id: uuid.UUID,                 # required pipeline anchor
    claims: list[AttributionClaim] = [],       # max 250
    context: AttributionContext | None = None, # observation-only
)
```

`AttributionClaim` is one structured statement:

```python
AttributionClaim(
    claim_id: uuid.UUID,
    target_type: AttributionTargetType,        # explicit named category
    target_identifier: str,                    # bounded, max 256 chars
    relationship: AttributionRelation,          # SUPPORTS | CONFLICTS
    evidence_type: str,                        # bounded machine label
    provenance: Provenance,                    # source-backed only
    event_id | detection_id | correlation_id |
      risk_assessment_id | investigation_id,   # provenance-matched ref
    metadata: dict,                            # JSON-safe, bounded
)
```

`AttributionContext` (risk level, investigation confidence, RAG document
count) is validated, bounded, cloned, and scanned — but the policy never
reads it. It exists to let callers attach surrounding pipeline state
without letting it influence attribution.

## 5. Attribution signals

An attribution signal is a structured claim. The engine accepts no other
signal type. The Step 15 inspection audited the completed SentinelAI
contracts for a usable structured attribution target field and found none:

* **Detection** (`DetectionResult`): has `severity`, freeform `tags`, and
  raw detection metadata — no `threat_actor` / `malware_family` / `campaign`.
* **Threat intel providers** (AbuseIPDB, AlienVault OTX, Gemini 12C):
  payloads are generic, untrusted dicts; provider "labels" are prose, not
  attribution.
* **Correlation** (Step 9): correlation records carry triggers, patterns,
  and member events — no target field.
* **Risk** (Step 11B): `RiskLevel` is low/medium/high/critical — a
  severity, not an attribution.
* **Investigation** (Steps 12A/12B): findings carry `AI_GENERATED`-prose
  hypotheses, not structured actors.
* **RAG knowledge** (Step 13): chunks are free text, never used here.

Therefore no URL, IP, hash, geolocation, or detection label is transformed
into an attribution target. The only structured attribution signals are the
claims handed to the engine, and the engine never fabricates a candidate.

## 6. Candidate generation

All candidate targets are callsite-declared: a target exists as a
hypothesis only if at least one `SUPPORTS` claim names it. The engine does
not generate candidates from risk, detection severity, threat-intel text,
RAG relevance, or prose. A claim with `target_type = unknown` is rejected
as an unsupported signal (`UnsupportedAttributionSignalError`).

## 7. Evidence requirements

* Every claim becomes exactly one `AttributionEvidence` record, in claim
  order, one-to-one (duplicates preserved with distinct evidence ids).
* Every claim's provenance must match its source reference, per the Step 14
  provenance-to-reference map; `ATTRIBUTION_ASSESSED` is forbidden as a
  claim/e-vidence provenance (attribution is a conclusion, never a source).
* Claim metadata is copied (never mutated) and stamped with the
  `claim_id` for traceability; the copy is re-checked against the 4096-byte
  Step 14 bound before any evidence is built.
* The engine re-validates its own output through the Step 14 contract, so
  an assessment can never carry an unresolved evidence reference.

## 8. Conflict handling

Conflicts are preserved, never auto-resolved:

1. A target with both supporting and conflicting claims produces one
   hypothesis carrying both id lists.
2. A hypothesis may never cite the same evidence id on both sides.
3. Two or more distinct supported targets produce `CONFLICTING` status:
   with no relationship semantics available, the deterministic engine must
   not silently choose between candidates.

## 9. Status semantics

Status is derived strictly from the evidence state (documented order of
checks, `assess_status` in `policy.py`):

| Condition | Status |
| --- | --- |
| `claim_count == 0` | `INSUFFICIENT_EVIDENCE` |
| evidence exists, nothing supported | `UNATTRIBUTED` |
| any supported target has conflicting claims | `CONFLICTING` |
| two or more distinct supported targets | `CONFLICTING` |
| single supported target, `s >= 2` | `ATTRIBUTED` |
| single supported target, `s == 1` | `PARTIALLY_SUPPORTED` |

`ATTRIBUTED` is therefore a statement about evidence sufficiency, not about
risk, confidence, or RAG. A single supporting signal is never enough to
declare attribution.

## 10. Confidence semantics

Hypothesis confidence is computed ONLY from the target's own signal counts
using a documented closed form (exact `Fraction` arithmetic, published to
six decimal places):

    confidence = (s / (s + c)) * min(s, CONFIDENCE_SATURATION) / CONFIDENCE_SATURATION

* monotone increasing in supporting signals `s`;
* decreasing in conflicting signals `c`;
* saturates at `CONFIDENCE_SATURATION = 3` supporting signals (three
  supports ⇒ confidence 1.0 with no conflicts);
* always in `[0, 1]`, never NaN/Inf, never a transformed risk/investigation/
  RAG value;
* published values are reproducible from the evidence alone.

The status is never a function of confidence, and confidence is never a
function of anything other than signal counts.

## 11. Risk independence

* `AttributionContext.risk_level` is observation-only; the policy never
  reads it.
* Tests prove outputs are identical for `risk_level` = None / low / medium /
  high / critical.
* A `CRITICAL` risk does not raise a `PARTIALLY_SUPPORTED` single-signal
  result, and a `LOW` risk does not downgrade an `ATTRIBUTED` result.

## 12. Investigation-confidence independence

* `AttributionContext.investigation_confidence` is observation-only.
* Tests prove outputs are identical for 0.0 / 0.5 / 1.0 / None.
* Attribution is never borrowed from an investigation's own confidence in
  its AI-generated hypothesis prose (Step 12B) — those are `AI_GENERATED`
  findings and are treated purely as source evidence with their own
  `investigation_id`, not as attribution authority.

## 13. RAG independence

* The engine never connects to RAG, never queries a vector store, and never
  reads retrieval text.
* `AttributionContext.rag_documents_retrieved` is a count only and is never
  consulted.
* Tests prove outputs are identical for counts 0 / 1 / 500 / None, and that
  a rich context with no claims still yields `INSUFFICIENT_EVIDENCE`.
* RAG cannot "help" attribution: relevance, snippets, and retrieval counts
  are outside the decision entirely.

## 14. Deterministic policy

Identical inputs with the same injected clock and uuid factory produce
byte-identical `model_dump_json()` output, because:

* grouping is a single pass over claims in input order;
* candidates are sorted by `(target_type.value, target_identifier)`;
* evidence ids are assigned in claim order;
* confidence uses exact rational arithmetic;
* metadata carries only counts, the policy label, and the decision path
  (no timestamps, identities, or copied content);
* inputs are never mutated.

The policy label is `deterministic_attribution_signals_v1` and is recorded
in every assessment's metadata.

## 15. Explainability

Every assessment is self-contained evidence:

* every hypothesis cites its supporting (and conflicting) evidence ids;
* every evidence record retains its provenance and source reference;
* every evidence record carries the originating `claim_id`;
* assessment metadata records the decision path, claim count, supported
  target count, and the policy constants used.

An analyst can re-derive the entire decision from the assessment alone.

## 16. Provenance

* Assessments and hypotheses are pinned to `ATTRIBUTION_ASSESSED` by the
  Step 14 contract.
* Evidence retains its source provenance (`OBSERVED`, `ENRICHED`,
  `RECONSTRUCTED`, `DETECTED`, `CORRELATED`, `RISK_ASSESSED`,
  `AI_GENERATED`) and provenance-matched reference.
* Attribution is an evidence-based assessment and must not be represented as independently observed fact.  Assessments and hypotheses are never
  emitted as observed telemetry; only the underlying evidence is.

## 17. Security

* Secret safety is fail-closed: the whole input is serialized and scanned
  for sensitive keys and secret-value patterns (AWS/Azure keys, GitHub
  tokens, `sk-*`, Google API keys, Slack tokens, `long:suffix` pairs).
* Any match raises `AttributionSafetyError`; there is no redaction, no
  partial result, and no path to continue with a sanitized copy.
* Hyphenated hashes (e.g., SHA-256) are not false-flagged.
* Every exception message is sanitized: raw input, target identifiers,
  evidence payloads, credentials, and stacks never appear.
* The dependency-isolation AST test forbids network, DB, queue, vector,
  AI, `subprocess`, and `eval`/`exec`/`compile` anywhere in the package.

## 18. Error handling

| Condition | Exception |
| --- | --- |
| not a `ThreatAttributionInput` / bad clock | `InvalidAttributionInputError` |
| >250 claims, >10 supported targets, metadata margin | `InvalidAttributionInputError` |
| `target_type = unknown` claim | `UnsupportedAttributionSignalError` |
| secret material anywhere in input | `AttributionSafetyError` (also `ValueError`) |
| strategy failure | `AttributionStrategyError` (chained) |
| non-assessment or contract-invalid output | `AttributionOutputValidationError` |
| unresolved / missing evidence references | `AttributionEvidenceReferenceError` |

All derive from `AttributionError`. A genuine engine failure is always
distinguishable from a deliberate "insufficient evidence" result: the
latter is returned as `INSUFFICIENT_EVIDENCE` / `UNATTRIBUTED` on a valid
assessment, never raised as an exception.

## 19. Testing and complexity

* `tests/unit/test_threat_attribution.py` covers the 20 required
  categories (construction, input validation, no-attribution, single/multi
  candidate, conflicts, duplicates, same-evidence-both-sides, confidence,
  risk/investigation/RAG independence, provenance, explainability,
  determinism, immutability, secret safety, error taxonomy, dependency
  isolation, bounds/performance).
* Engine work is O(n) in claims: one pass to bucket, one pass to build
  evidence, one pass to build hypotheses; the only intentional sort is the
  candidate ordering over distinct supported targets (≤ 10).
* The full backend suite is run after any Step 15 change.

## 20. Non-goals

Step 15 does not implement AI attribution (no LLM/Gemini calls), RAG
retrieval, persistence of assessments, an API/frontend for attribution,
response or mitigation, incident management, knowledge-graph construction,
multi-agent debate, attack prediction, playbook generation, digital twin,
or autonomous purple-teaming. Those remain future SentinelAI steps.

## 21. Future AI-attribution boundary

A future AI-powered attribution step (e.g., Gemini-based narrative
hypotheses akin to Step 12B) is subject to the Step 14 provenance rule: its
output would be emitted as `AI_GENERATED` source evidence carrying an
`investigation_id`, never as `ATTRIBUTION_ASSESSED` conclusions, and the
engine would still only attribute from explicit structured claims. This
boundary is enforced by the input contract, which rejects
`ATTRIBUTION_ASSESSED` as a claim provenance, so no future step can feed an
AI "attribution" back into the deterministic engine as a source signal
without an explicit, named claim.