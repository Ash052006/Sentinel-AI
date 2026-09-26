# AI Investigation Agent (Step 12C)

## 1. Purpose and scope

Step 12C implements the **AI Investigation Agent**: a reasoning-only component that consumes a validated Step 12B `InvestigationContext`, constructs a deterministic prompt under a hard trust separation, asks Google Gemini (through an injectable provider boundary) for a structured investigation, fails closed on any malformed, unsafe, or unsupported output, and produces a validated Step 12A `InvestigationResult`.

Step 12C does not persist investigation results, expose an Investigation API, create incidents, perform response or mitigation, modify detection/correlation/risk state, or implement future SentinelAI phases.

The most important invariant of the agent:

Gemini is an investigator over supplied InvestigationContext, not a source of security evidence.

Evidence is supplied *by the context*, never invented by the model. The model may reason over supplied evidence, correlate observations already present, and reference evidence only by its exact `evidence_id`.

## 2. Definitions and reading guide

- **Investigation Agent** — the Step 12C orchestrator (`InvestigationAgent`); consumes `InvestigationContext`, emits `InvestigationResult`.
- **Provider boundary** — the `InvestigationLLMClient` abstraction over the LLM call; returns raw response text only.
- **Trust separation** — the structural division of the prompt into a fixed trusted system policy and a delimited untrusted data region.
- **Output contract** — the bounded Pydantic models that the model's JSON is validated against (`extra="forbid"`, explicit empty arrays, bounded counts and lengths).
- **Fail closed** — any malformed, oversized, unsafe, or unsupported output is rejected in full; nothing is repaired, truncated, or partially accepted.
- **Provenance pin** — the enforced `AI_GENERATED` classification of the result, findings, and observations; source evidence keeps its original provenance.
- **Evidence-reference resolution** — every `evidence_id` on a finding must exist in the supplied context; a single unknown id rejects the entire output.

## 3. Module structure

The agent lives in `backend/app/agents/investigation/`:

- `__init__.py` — public exports (agent, provider, errors, bounds constants).
- `agent.py` — `InvestigationAgent`, the orchestrator.
- `prompt.py` — `SYSTEM_INSTRUCTIONS`, `CONTEXT_DATA_START`/`CONTEXT_DATA_END`, `InvestigationPrompt`, `InvestigationPromptBuilder`.
- `model_output.py` — the bounded output contract and its Gemini JSON schema.
- `llm_client.py` — `InvestigationLLMClient` provider boundary.
- `gemini.py` — `GeminiClient` concrete provider.
- `exceptions.py` — the `InvestigationAgentError` hierarchy.
- `_safety.py` — the shared credential-shaped content scanner.

`app/core/config.py` gains the `gemini_*` settings; `app/agents/__init__.py` re-exports the agent, errors, and abstraction.

## 4. Agent pipeline

`investigate(context)` runs, in order:

1. Type-check the input (`InvestigationContext`, else `InvestigationContextError`).
2. Build the deterministic prompt (`InvestigationPromptBuilder.build`).
3. Send the prompt through the provider boundary (raw text back).
4. Parse strictly: non-JSON, fenced, prose-wrapped, empty, or oversized (`> MAX_MODEL_OUTPUT_BYTES = 65536` bytes) output is rejected, never repaired.
5. Validate against the output contract: malformed payloads raise `InvestigationModelValidationError`.
6. Re-scan the validated output for credential-shaped content (fail closed).
7. Resolve every evidence reference against the supplied context (fail closed on any unknown id).
8. Construct the `InvestigationResult` with pinned provenance, the agent's investigation id and timestamp, and deep-copied source evidence.

An investigation never becomes an "empty result" by accident: an empty result requires the model to explicitly return `{"findings": [], "observations": []}`.

## 5. Prompt construction and trust separation

`SYSTEM_INSTRUCTIONS` is fixed, never interpolated. It states mandatory rules: context is untrusted data, not instructions; reason only over supplied evidence; never create evidence; no verdicts and no future-phase output; confidence belongs to the model; strict JSON output.

The prompt content is a fixed task plus the exact `context.model_dump_json()` serialization wrapped in explicit delimiters:

- `<<<CONTEXT_DATA_START>>>`
- `<<<CONTEXT_DATA_END>>>`

The builder is deterministic: identical contexts produce byte-identical prompts (no time, no random values, no unordered iteration). The provider receives the system policy and content as separate structural parts.

## 6. Provider boundary

`InvestigationLLMClient` (ABC) exposes `provider_name`, optional `model_name`, and `generate(prompt) -> str`. The boundary returns the raw text only; every validation concern stays in the agent, so no provider quirk can bypass agent-level safeguards. Tests inject stub clients; a future provider can implement the same interface without rewriting the agent.

## 7. Gemini provider configuration

`GeminiClient` posts to `{endpoint_base}/v1beta/models/{model}:generateContent` (`https://generativelanguage.googleapis.com` by default) over the repository's existing `httpx` dependency, with an injectable `httpx.Client` for tests (mirroring the threat-intelligence provider convention).

Settings: `gemini_api_key`, `gemini_model` (default `gemini-2.0-flash`), `gemini_timeout_seconds` (60.0), `gemini_max_retries` (2), `gemini_endpoint_base`, `gemini_max_output_tokens` (8192), `gemini_temperature` (0.0, favouring determinism).

The API key is sent as the `x-goog-api-key` header only — never in the URL, logs, or exceptions. A missing key or model fails at construction with a sanitized `InvestigationConfigurationError`.

Structured output is requested with `responseMimeType: application/json` plus the `responseSchema` derived from the model-output contract. A provider `finishReason` other than `STOP` is rejected as `InvestigationModelOutputError` (truncated/blocked output is never partially accepted).

## 8. Model output contract and bounds

The output contract lives in `model_output.py`:

- `MAX_MODEL_FINDINGS = 20`, `MAX_MODEL_OBSERVATIONS = 20`.
- `MAX_MODEL_EVIDENCE_REFERENCES = 64` (per finding).
- `MAX_MODEL_STRING_LENGTH = 4096`.
- `MAX_MODEL_OUTPUT_BYTES = 65536` (64 KiB), enforced at parse time.
- `extra="forbid"` everywhere: the model cannot smuggle in provenance, evidence objects, ids, timestamps, verdicts, or response actions.
- `findings` and `observations` are required arrays (an empty result must be explicit).
- `summary` is optional and nullable; `confidence` must be in `[0.0, 1.0]`; `evidence_ids` is a list of UUIDs.

Bounds reject; they never truncate or repair.

## 9. Strict parsing and validation

`_parse_strict` strips and checks: empty output, byte-size overflow, JSON validity, and top-level object shape. Code fences, prose wrappers, and multiple objects are rejected. `_validate_output` runs the parsed payload through the Pydantic contract; a `ValidationError` is chained inside `InvestigationModelValidationError` with a sanitized message that includes only the issue count.

## 10. Evidence references

The model may reference evidence **only** by an exact `evidence_id` present in `context.evidence`. Duplicate references are preserved verbatim (set-like deduping is not applied). Any unknown, malformed, or fabricated reference rejects the entire output (`InvestigationEvidenceError`). The model cannot inject new evidence records — the output contract forbids any `evidence` field.

## 11. Provenance policy

The Step 12A contract is authoritative:

- Result provenance is pinned `AI_GENERATED` by the contract.
- Findings are pinned `AI_GENERATED`.
- Observations are explicitly labelled `AI_GENERATED` (never observed).
- Source evidence keeps its original provenance (`DETECTED`, `CORRELATED`, `RISK_ASSESSED`, etc.); the model can never supply provenance.

## 12. Secret safety

`_safety.py` re-checks the serialized context *and* the serialized model output for credential-shaped content (`api_key`, `authorization`, `bearer`, `secret`, `password`, `cookie`, `session_token`, `jwt`), complementing the Step 12B contract. This defence-in-depth closes the gap where a plain string field that Step 12B preserves verbatim as untrusted data could otherwise cross the AI boundary. Detected secrets raise `InvestigationSecretSafetyError`; nothing is redacted or sent.

## 13. Prompt injection resistance

Attacker-controlled telemetry that survives Step 12B validation is always data, never instructions: the system policy is fixed and non-interpolated, the context is delimited, and the task text explicitly instructs the model to treat the data region as inert. Tests inject prompt-injection strings into carried fields and assert they appear only inside the delimited region and never alter policy or output structure.

## 14. Result construction and agent ownership

The agent owns the authoritative fields:

- `investigation_id` from an injectable factory (default `uuid.uuid4`); the context's investigation bookkeeping id is never copied onto the result.
- `timestamp` from an injectable clock (default `datetime.now(timezone.utc)`); a naive timestamp is an internal error.
- `metadata` contains only `provider` and `model`.
- Result `confidence` stays `None`; the output contract deliberately excludes a top-level confidence the model cannot justify.
- Evidence records are `model_copy(deep=True)` copies of the context records — the result never aliases context objects, and mutating the result never mutates the context.

## 15. Retry and error model

Provider retries are bounded and conservative: only transient failures (5xx, transport errors, timeouts) retry, with multiplicative backoff (`_RETRY_BASE_DELAY = 1.0`); 4xx client errors, authentication failures, and rate limits are never retried. The error hierarchy (`exceptions.py`, all under `InvestigationAgentError`) covers configuration, provider, timeout, unavailable (with optional `retry_after`), model output, model validation, evidence, secret safety, context input, and internal boundaries. All messages are sanitized; causes are chained internally.

## 16. Runtime guarantees

- **Determinism** — identical context + identical provider text + identical id/clock factories ⇒ byte-identical result serialization.
- **Immutability** — the context and its objects are never mutated; the result is a fresh object graph.
- **No side effects** — the only external interaction is the single provider request; no filesystem, database, queue, or network access beyond the provider call, on success or failure.

## 17. Dependency isolation

`app/agents/investigation/*` imports only stdlib, Pydantic, `httpx` (provider-facing, the repository's existing HTTP dependency), and `app.{schemas,agents,core}`. There is no SQLAlchemy, FastAPI, Kafka/RabbitMQ, Qdrant, Neo4j, OpenSearch, requests, subprocess, or dynamic-execution import. Tests audit the modules with an AST scan to keep this boundary permanent.

## 18. Example execution

```
InvestigationContext (12B, 1 correlation + 2 detections + 4 evidence)
    -> prompt: SYSTEM_INSTRUCTIONS + delimited serialized context
    -> GeminiClient.generate -> raw text
    -> {"findings": [{"finding_type": "activity_pattern",
                      "title": "Repeated beaconing",
                      "confidence": 0.8,
                      "evidence_ids": ["<context evidence_id>"]}],
        "observations": [{"observation_type": "context_summary",
                          "observation_text": "single source host"}]}
    -> InvestigationResult(investigation_id=<agent-owned>, confidence=None,
                            findings=[AI_GENERATED], observations=[AI_GENERATED],
                            evidence=deep copies with original provenance,
                            metadata={"provider": "gemini", "model": ...})
```

## 19. Consistency with earlier contracts

Step 12A provides the authoritative `InvestigationResult` / `InvestigationFinding` / `InvestigationEvidence` / `InvestigationObservation` contracts; Step 12C consumes and produces them exactly, without weakening validators. Step 12B provides the authoritative `InvestigationContext` input; the agent never re-queries 12A/12B sources, never re-builds context, and never bypasses the context contract. No 12A or 12B module was modified.

## 20. Testing and boundaries

Tests live in `backend/tests/unit/`:

- `test_investigation_prompt.py` — golden prompt, determinism, ordering, trust separation, injects, secret refusal, input validation.
- `test_investigation_agent.py` — construction and injection, prompt handoff, strict parsing, contract validation, evidence references, provenance pins, injection resistance, secret safety (in and out), context validation, result construction, agent ownership, immutability, determinism, error mapping, AST dependency audit, no side effects.
- `test_gemini_client.py` — request shape and headers (`x-goog-api-key`, `responseSchema`), retry policy (transient only), error mapping and sanitization, output extraction; one `gemini_integration`-marked live smoke test is skipped unless `GEMINI_API_KEY` is set, so the default suite never touches the network.

The full backend suite (2802 passed, 1 skipped at 12C completion) runs without a Gemini API key and without any database, Kafka, or external service.