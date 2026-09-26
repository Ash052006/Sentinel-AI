# Investigation Knowledge & RAG Layer (Step 13)

## 1. Purpose and scope

Step 13 adds a controlled background-knowledge retrieval layer for the Step 12C AI
Investigation Agent: security knowledge documents are validated, sanity-checked for
credential-shaped content, chunked, deterministically embedded, indexed in a vector
store, and retrieved as a bounded, timestamped **reference context** that the agent
attaches to its prompt as reference material — never as evidence.

Retrieved knowledge is background reference material and is never treated as observed security evidence.

This step does not implement incident management, response or mitigation, threat attribution, knowledge graphs, multi-agent debate, attack prediction, AI playbook generation, digital twins, autonomous purple teaming, or other future SentinelAI phases.

There is no public RAG API or frontend, no Kafka/RabbitMQ transport, no separate graph
database, and no arbitrary web scraping and URL fetching: documents are placed by the
platform and treated strictly as data (their text is never evaluated as instructions).

## 2. Definitions and reading guide

- **Knowledge document** — the ingestion input: a validated source text plus `source`,
  `title`, `knowledge_type`, and JSON-compatible metadata.
- **Knowledge chunk** — one bounded unit of document text produced by the chunker.
- **Index record** — a chunk plus its embedding vector, ready for the vector store.
- **Knowledge item** — one retrieved result (chunk content plus relevance score).
- **Knowledge context** (`InvestigationKnowledgeContext`) — the bounded retrieval result
  handed to the investigation agent; pinned to background-reference semantics.
- **Reference material** — knowledge supplied to the model purely for context; it can
  never enter the evidence list or be referenced as an `evidence_id`.
- **Fail closed** — any out-of-contract, oversized, or secret-containing value is
  rejected outright; nothing is truncated, repaired, or silently dropped.
- **Reject-not-truncate** — the hard bound policy: sources and items that exceed their
  contract are refused rather than clipped.

## 3. Module structure

The layer spans schemas, a self-contained service package, and the 12C integration:

- `backend/app/schemas/knowledge.py` — `KnowledgeType`, `KnowledgeDocument`,
  `KnowledgeChunk`, `KnowledgeIndexRecord`, `KnowledgeItem`, all length/count/depth
  bounds, and the shared credential-shaped content scanner.
- `backend/app/schemas/knowledge_context.py` — `KnowledgeRetrievalMetadata`,
  `InvestigationKnowledgeContext`, retrieval bounds, and the keyword-only
  `build_investigation_knowledge_context(...)` factory.
- `backend/app/services/knowledge/` — `safety.py` (scanner), `exceptions.py`
  (`KnowledgeLayerError` family), `chunking.py`, `ingestion.py`, `embeddings.py`,
  `vector_store.py` (abstraction + strict input contract), `qdrant_store.py` (Qdrant
  wrapper), `retriever.py`, and a light `__init__.py`.
- 12C integration: `investigation/prompt.py` (knowledge delimiters and reference
  labeling), `investigation/gemini.py` (separate knowledge request part),
  `investigation/agent.py` (`investigate(context, knowledge_context=None)`).
- Tests: `backend/tests/unit/test_knowledge_*.py` plus the shared, uncolllected helper
  module `tests/unit/knowledge_test_helpers.py`.

Nothing in the investigation or RAG layers talks to Qdrant directly; the Qdrant client
is imported lazily and only inside `qdrant_store.py`.

## 4. Data model and validation

`KnowledgeType` enumerates MITRE-ATT&CK techniques, CVEs, YARA-threat-intel, and sigma
rule knowledge as a closed set. The four content models build on one same core
disciplines:

- every scalar field is length-bounded (`MAX_KNOWLEDGE_SOURCE_LENGTH=256`,
  `MAX_KNOWLEDGE_TITLE_LENGTH=512`, `MAX_CHUNK_CONTENT_LENGTH=8000`,
  `MAX_KNOWLEDGE_DOCUMENT_CONTENT_LENGTH=1_000_000` characters);
- metadata must be JSON-compatible and bounded (`MAX_KNOWLEDGE_METADATA_SERIALIZED_BYTES
  = 4 KiB`, `MAX_KNOWLEDGE_METADATA_DEPTH=8`);
- counts are bounded (`MAX_CHUNKS_PER_DOCUMENT=10_000`, `MAX_KNOWLEDGE_ITEMS=50`);
- every model serializes itself and runs the secret scanner (see Section 7), so no
  credential-shaped text can enter the system at any schema boundary.

`KnowledgeIndexRecord` adds a validated, finite embedding vector of exactly the provider
dimension; `KnowledgeItem` carries `knowledge_id`, source, title, content,
`knowledge_type`, `relevance_score` (float), and metadata.

## 5. Retrieval context contract

`InvestigationKnowledgeContext` wraps a bounded, ordered `items` list and
`KnowledgeRetrievalMetadata` (query string, `top_k`, optional `knowledge_types`,
`total_results`, tz-aware `retrieved_at`, `provider`, `payload_bytes`). Invariants:

- retrieval must never exceed its requested bound: `len(items) == top_k` is enforced,
  so an oversized, undersized, or truncated result cannot be smuggled through;
- `top_k` is bounded by `MAX_RETRIEVAL_TOP_K=10` and the serialized JSON payload by
  `MAX_RAG_CONTEXT_PAYLOAD_BYTES=128 KiB` (an unreachable hard ceiling under valid
  inputs, kept as defense in depth);
- `is_background_reference` is pinned `True` by the schema — knowledge can never be
  reclassified into evidence;
- `build_investigation_knowledge_context(*, items, query, top_k, knowledge_types,
  retrieved_at, provider)` is keyword-only and performs the same span checks.

## 6. Dependency isolation and offline capability

The normal suite must run fully offline. The design guarantees:

- no RAG service module imports Qdrant, Neo4j, Kafka, FastAPI, SQLAlchemy, or any
  HTTP/AI SDK at module scope (enforced by an AST scan of the package);
- `import app.services.knowledge` and `import app.schemas.knowledge[_context]` do not
  pull `qdrant_client` into `sys.modules` (verified in a fresh interpreter);
- the default embedding provider is a deterministic, offline,
  projection-based provider, so the whole pipeline is exercisable without any network;
- only the opt-in `rag_integration`-marked live Qdrant smoke test touches the network,
  gated on `QDRANT_URL` being set (mirrors the `gemini_integration` convention).

## 7. Content safety layer

`safety.py` wraps the schema scanner's `_SECRET_PATTERNS` (a fixed set of eight
credential-shaped markers) behind the public `assert_no_secrets` / `contains_secret`
API and the `KnowledgeSafetyError` subtype. The scanner operates on serialized JSON so
it covers every field including nested metadata, and it is applied at five independent
boundaries: document, chunk, item, index record, and the prompt knowledge section. A
single marker (e.g. a token named `password`) rejects the whole value; the pattern list
is never exposed in messages or logs. Credential-shaped content therefore cannot reach
any prompt, embedding, or vector store in any form.

## 8. Chunking

`chunking.py` implements a whitespace-aware chunker: interior windows are cut at the
last whitespace within `chunk_size` (inclusive), the final window takes the whole
remainder, and overlap is only applied between interior windows. Guarantees:

- termination even when a tail window would overlap the previous cut
  (`if cut == n: break`) and when a single token exceeds `chunk_size`;
- no content loss: the full text is always a subsequence of the concatenated chunks;
- bounds `DEFAULT_CHUNK_SIZE=4000`, `DEFAULT_CHUNK_OVERLAP=200`, hard caps
  `MAX_CHUNK_SIZE=8000`, `MAX_CHUNK_OVERLAP=1000`;
- chunk ids, indexes, and metadata are deterministic and provenance-preserving.

## 9. Ingestion pipeline

`KnowledgeDocumentIngester` validates the input document (refusing empty, secret-shaped,
or out-of-contract content), chunks it, and returns validated `KnowledgeChunk`
sequences with monotonically increasing `index` values. The docstring-level alias
`MAX_RETRIEVAL_TOP_K` lives with the other retrieval bounds in `knowledge_context.py`.
Deviations map to `KnowledgeIngestionError`; ingestion is a pure function of its input
and performs no I/O.

## 10. Embeddings

`embeddings.py` defines:

- `DeterministicEmbeddingProvider` — the offline default: a seeded, reproducible
  feature-hash projection of the tokenized text into a fixed dimension. Same text →
  same vector, so pipelines and tests are byte-deterministic;
- `create_embedding_provider(dimension)` — configuration keyed on `settings`.
  (An externally-configured provider seam exists for future real embeddings; behavior
  outside the deterministic provider is out of scope for this step.)
- `validate_embedding_vector(...)` — every vector must be a finite, non-empty sequence
  of floats of the store dimension, else `KnowledgeEmbeddingError`.

## 11. Vector-store abstraction and contract

`KnowledgeVectorStore` is the only storage/search seam. The shared
`_InputContract.check_search_inputs` is used by every concrete store and the recording
test fake, and enforces: a validated embedding vector, `limit` within
`[1, MAX_RETRIEVAL_TOP_K]`, `knowledge_types` being a real sequence of `KnowledgeType`
members (scalars and strings refused), and — downstream — result scores strictly inside
`[-1.0, 1.0]`. Every violation raises a sanitized `KnowledgeVectorStoreError`.

## 12. Qdrant-backed store

`QdrantKnowledgeVectorStore` wraps the Qdrant client:

- lazy client resolution from `settings` (`qdrant_url`, `qdrant_api_key`,
  `qdrant_timeout_seconds`, `qdrant_collection`) or explicit constructor args;
- auto-creates the collection with a cosine `VectorParams` contract when missing and
  never recreates an existing one;
- upserts `PointStruct`-valid payloads (string ids, content, knowledge type value,
  metadata) and returns the stored count;
- rebuilds search hits into `KnowledgeItem` values, failing closed on missing or
  malformed ids/payloads and on out-of-contract scores;
- resolves credentials on construction only and never logs them.

## 13. Retriever

`InvestigationKnowledgeRetriever` is the read-side facade:

- validates the query (non-blank, `<= MAX_KNOWLEDGE_QUERY_LENGTH=4096`), `top_k`
  bounds, and knowledge-type filters before any store call;
- embeds the query through the provider, calls the store, and detects when a store
  violates its own contract (e.g. returning more items than requested → rejects);
- deterministically (re)orders results by `(-score, str(knowledge_id))`, so identical
  inputs yield byte-identical contexts;
- requires the configured `retrieved_at` to be tz-aware; builds final metadata with
  `total_results`, the provider's `store_name` in `provider`, and `payload_bytes`;
- accepts zero-result retrievals as valid; refuses to modify retrieved content.

## 14. Knowledge representation separation

Three distinct object families never mix:

1. **Observed evidence** — `InvestigationEvidence` values in the context, carrying
   `evidence_id` and provenance founded on `DETECTED`/reported observations.
2. **Retrieved knowledge** — `KnowledgeItem` values inside `InvestigationKnowledgeContext`
   (no `evidence_id`, no `provenance`, pinned as background reference).
3. **AI-generated output** — `InvestigationResult` findings with `AI_GENERATED`
   provenance that may reference evidence only by existing `evidence_id`.

A knowledge id can never satisfy an evidence reference, and no retrieved item ever
appears in the result's evidence list. The prompt renders knowledge in its own delimited
region, separated from the context/evidence region.

## 15. Prompt integration into Step 12C

`prompt.py` changes:

- `InvestigationPrompt` now carries `knowledge_content: str` (default empty);
- `KNOWLEDGE_DATA_START` / `KNOWLEDGE_DATA_END` delimiters bound the knowledge region,
  introduced by the fixed label "Look-up knowledge (retrieved security knowledge,
  supplied for reference only)";
- `SYSTEM_INSTRUCTIONS` gains rule 7 "RETRIEVED KNOWLEDGE IS REFERENCE MATERIAL ONLY.";
- `InvestigationPromptBuilder.build(context, knowledge_context=None)` type-checks the
  knowledge context, serializes items deterministically, runs the knowledge section
  through the secret scanner (raising `InvestigationSecretSafetyError` on any match),
  and renders sections without knowledge when none is supplied.

`agent.py` accepts `knowledge_context` (rejecting non-context types with
`InvestigationContextError`) and logs the retrieved item count; `gemini.py`
`_build_payload` appends the knowledge as its own second text part only when present,
so the single-part request shape (and its 12C regression tests) is preserved.

## 16. Prompt-injection and trust-boundary defence

Because retrieved text is untrusted, injection resistance is structural rather than
Socratic:

- knowledge lives only between its delimiters, so "ignore previous instructions …"
  cannot reach the system policy, the task, or the context/evidence region — the
  `system_instruction` is byte-identical with and without knowledge;
- no part of the knowledge serialization can name an evidence id used by the context;
- the injection test matrix covers instruction overrides, schema rewrites, command
  execution phrases, and fake evidence ids, asserting containment inside the knowledge
  region;
- the existing 12C prompt/agent/gemini regressions continue to pass unchanged.

## 17. Secret handling end-to-end

The secret scanner is a hard gate at every trust boundary, tested as a single pipeline
in `test_knowledge_secret_safety.py`: document ingestion, the embedding provider, index
record construction, and the prompt builder each independently refuse credential-shaped
content (e.g. bearer tokens, API keys, session tokens, passwords). Bypassing one
layer (e.g. constructing a context without validation) is still caught by the next down
stream, so no credential-shaped text can reach an embedding, a vector store payload, or
a model prompt.

## 18. Configuration and reference bounds

`app/core/config.py` supplies Qdrant settings (`qdrant_url`, `qdrant_api_key`,
`qdrant_timeout_seconds`, `qdrant_collection`) and the embedding dimension. Reference
constants:

| Name | Value |
| --- | --- |
| `MAX_RETRIEVAL_TOP_K` | `10` |
| `MAX_KNOWLEDGE_QUERY_LENGTH` | `4096` |
| `MAX_RAG_CONTEXT_PAYLOAD_BYTES` | `128 KiB` |
| `MAX_CHUNK_CONTENT_LENGTH` / `MAX_CHUNK_SIZE` | `8000` |
| `MAX_CHUNK_OVERLAP` | `1000` |
| `DEFAULT_CHUNK_SIZE` | `4000` |
| `DEFAULT_CHUNK_OVERLAP` | `200` |
| `MAX_CHUNKS_PER_DOCUMENT` | `10_000` |
| `MAX_KNOWLEDGE_DOCUMENT_CONTENT_LENGTH` | `1_000_000` |
| `MAX_KNOWLEDGE_ITEMS` | `50` |
| `MAX_KNOWLEDGE_SOURCE_LENGTH` | `256` |
| `MAX_KNOWLEDGE_TITLE_LENGTH` | `512` |
| `MAX_KNOWLEDGE_METADATA_SERIALIZED_BYTES` | `4 KiB` |
| `MAX_KNOWLEDGE_METADATA_DEPTH` | `8` |

## 19. Testing strategy and coverage

The suite is offline and deterministic (fixed ids, timestamps, and the deterministic
embedding provider via `knowledge_test_helpers.py`). Coverage rows:

- contract: field bounds, JSON-compatible/deep metadata, secret refusal, reject-not-
  truncate, item count capping;
- context contract: builder keyword-only signature, top-k equality enforcement,
  payload ceiling and its unreachability under valid inputs, tz-aware metadata;
- safety: scanner boundaries, `KnowledgeSafetyError`, schema-level `ValidationError`
  wrapping;
- chunking: short/long/unbroken-token/overlap termination, boundedness, no-loss
  subsequence property;
- ingestion and embeddings: validation, deterministic vectors;
- vector store and Qdrant store: input contract, payload mapping, collection
  auto-creation, fail-closed rebuild and scores, sanitized errors;
- retriever: query/top-k/filter bounds, deterministic ordering, store-contract
  detection, metadata/payload accounting, naive-timestamp rejection;
- dependency isolation: AST top-level import scan plus fresh-interpreter `sys.modules`
  checks; secret safety end-to-end;
- 12C integration: agent dispatch and JSON serialization of the agent result;
- prompt injection and knowledge/evidence separation; a live `rag_integration` Qdrant
  smoke test is skipped by default.

## 20. Operational notes and deployment

- Run the live smoke test with `pytest -m rag_integration -q` with `QDRANT_URL` set;
  the collection contract is cosine and the wrapper keeps it consistent.
- The deterministic embedding provider keeps CI byte-deterministic; swapping in a real
  provider happens behind `create_embedding_provider` without touching the store or
  retriever.
- The whole knowledge pipeline rejects rather than truncates; operators must not
  silently clip documents to fit.
- No database migration is required: this step is schema/service/test only and the
  Alembic head is unchanged.