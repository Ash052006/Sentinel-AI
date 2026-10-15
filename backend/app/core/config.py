from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Closed vocabulary of reasoning providers SentinelAI can talk to.
#:
#: This is deliberately a *closed* set rather than a free-form string.  An
#: unknown provider must fail at configuration time, because the alternative —
#: silently degrading to whatever provider happens to be configured — would let
#: a typo produce a debate attributed to a reasoning backend that never ran.
LLMProvider = Literal["gemini", "groq"]


class Settings(BaseSettings):
    app_name: str = "SentinelAI"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = True

    host: str = "0.0.0.0"
    port: int = 8000

    database_url: str = ""

    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    log_level: str = "INFO"

    # Kafka
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_security_events_topic: str = "security-events"
    kafka_consumer_group: str = "sentinelai-development"

    # VirusTotal Threat Intelligence Provider
    virustotal_api_key: str = ""
    virustotal_timeout_seconds: float = 30.0

    # AbuseIPDB Threat Intelligence Provider
    abuseipdb_api_key: str = ""
    abuseipdb_timeout_seconds: float = 30.0

    # AlienVault OTX Threat Intelligence Provider
    otx_api_key: str = ""
    otx_timeout_seconds: float = 30.0

    # Gemini AI Investigation Provider (Step 12C)
    # The model name is a replaceable configuration value, never a
    # source-code constant inside the agent.  Missing keys fail at
    # GeminiClient construction with a sanitized configuration error.
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.8-flash"
    gemini_timeout_seconds: float = 60.0
    # Bounded retry budget for *transient* provider failures only (HTTP 5xx,
    # HTTP 429, transport errors, timeouts).  Genuine 4xx client errors and
    # authentication failures are never retried.  The default is sized for the
    # free-tier rate limiter, whose overload window routinely outlasts a
    # three-attempt budget: a limit that clears in a few seconds must be
    # survived rather than reported to the caller as the provider being down.
    gemini_max_retries: int = 4
    gemini_endpoint_base: str = (
        "https://generativelanguage.googleapis.com"
    )
    gemini_max_output_tokens: int = 8192
    gemini_temperature: float = 0.0

    # -- Reasoning-provider selection -------------------------------------
    # Which cloud LLM backs the V3.23 debate agents (and, where applicable, the
    # investigation agent).  Selection is *deployment* configuration: it is
    # never accepted from an API client, so the debate API cannot be turned
    # into a model-routing control surface.
    #
    # One provider serves one debate end to end.  There is deliberately no
    # cross-provider fallback: a provider that fails produces a governed
    # failure, because a debate silently completed by a *different* model than
    # the one recorded in its metadata would be unreproducible and would
    # misattribute reasoning to a backend that never contributed to it.
    llm_provider: LLMProvider = "gemini"

    # Groq LLM Provider (second cloud reasoning backend).
    # Follows the Gemini provider conventions exactly: model name is
    # configuration, never a source constant; the key is read from the
    # environment, never logged, never placed in an exception message, and a
    # missing key fails at GroqClient construction with a sanitized
    # configuration error.
    groq_api_key: str = ""
    # Groq model identifiers are namespace-qualified ("openai/gpt-oss-120b").
    # The unprefixed form is not a valid Groq model id.
    groq_model: str = "openai/gpt-oss-120b"
    groq_timeout_seconds: float = 60.0
    # Bounded retry budget for *transient* failures only (HTTP 5xx, HTTP 429,
    # HTTP 498 flex-tier capacity, transport errors, timeouts).  Authentication
    # failures and other genuine 4xx client errors are never retried, because
    # repeating them cannot succeed and would only multiply latency.
    groq_max_retries: int = 4
    groq_endpoint_base: str = "https://api.groq.com"
    groq_max_output_tokens: int = 8192
    groq_temperature: float = 0.0
    # Groq's gpt-oss models are reasoning models.  Their reasoning budget is
    # billed and timed like output, and a debate issues 15 sequential model
    # calls, so the effort is pinned low by default to keep a single debate
    # comfortably inside the per-request timeout.  "medium" is Groq's default;
    # set explicitly so the value that actually applies is auditable.
    groq_reasoning_effort: Literal["low", "medium", "high"] = "low"

    # Knowledge & RAG Layer (Step 13) — vector store and embedding provider.
    # Connection details are configurable; credentials are never logged and
    # never hard-coded.  A missing URL/api key fails at client construction
    # with a sanitized configuration error, matching the provider pattern.
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str = ""
    qdrant_collection: str = "sentinelai_knowledge"
    qdrant_timeout_seconds: float = 10.0
    embedding_provider: str = "deterministic"
    embedding_model: str = "sentinelai-deterministic-v1"
    embedding_dimension: int = 32
    rag_default_top_k: int = 5

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    @field_validator("llm_provider", "groq_reasoning_effort", mode="before")
    @classmethod
    def _reject_unknown_provider_values(cls, value: object) -> object:
        """Normalize case but never *guess* a provider.

        ``Literal`` alone would reject ``"Groq"``, which is a confusing way to
        learn about a typo.  Lower-casing first accepts the obvious casing
        variants, and anything still outside the closed vocabulary still fails
        here — loudly, at configuration time — rather than at the first model
        call or, worse, by silently resolving to some other provider.
        """
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @model_validator(mode="after")
    def _validate_production_settings(self) -> "Settings":
        """Enforce stricter requirements when running in production."""
        if self.environment == "production":
            if not self.jwt_secret:
                raise ValueError(
                    "JWT_SECRET must be set in production"
                )
            if not self.database_url:
                raise ValueError(
                    "DATABASE_URL must be set in production"
                )
            if self.debug:
                raise ValueError(
                    "DEBUG must be False in production"
                )
            # The *selected* provider must be usable.  Boot-time failure is
            # strictly better than a process that starts healthy and then
            # fails every single debate request with a provider error.
            if self.llm_provider == "gemini" and not self.gemini_api_key:
                raise ValueError(
                    "LLM_PROVIDER=gemini requires GEMINI_API_KEY in production"
                )
            if self.llm_provider == "groq" and not self.groq_api_key:
                raise ValueError(
                    "LLM_PROVIDER=groq requires GROQ_API_KEY in production"
                )
        return self


settings = Settings()