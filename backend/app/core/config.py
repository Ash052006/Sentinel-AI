from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

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
        return self


settings = Settings()