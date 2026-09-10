import logging
import sys

from app.core.config import settings

# Sensitive keywords that should never appear in log output.
_SENSITIVE_PATTERNS = ("password", "secret", "token", "authorization", "cookie")


class _SensitiveFilter(logging.Filter):
    """Redact log records that accidentally contain sensitive keywords."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            lower = record.msg.lower()
            for pattern in _SENSITIVE_PATTERNS:
                if pattern in lower:
                    record.msg = record.msg.replace(
                        record.msg, "[REDACTED - sensitive data filtered]"
                    )
                    break
        return True


def configure_logging() -> None:
    """Configure application-wide logging.

    * Outputs to stdout so container/orchestrator log collectors can capture it.
    * Applies a filter that scrubs messages containing sensitive keywords.
    * Respects the ``LOG_LEVEL`` setting.
    """
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    handler.addFilter(_SensitiveFilter())

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove any existing handlers to avoid duplicate output.
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

