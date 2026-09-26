"""Natural Language SOC (Step 23) — controlled, read-only SOC query interface.

Packaged services layered above the *existing* read-only query services.
The public entry point is :class:`~app.services.soc.engine.SOCQueryService`;
the allowlist is :mod:`app.services.soc.registry`.
"""

from app.services.soc.errors import (  # noqa: F401
    SOCConfigurationError,
    SOCError,
    SOCExecutionError,
    SOCInputValidationError,
    SOCIntentValidationError,
    SOCInternalError,
    SOCModelOutputError,
    SOCModelValidationError,
    SOCParserError,
    SOCProviderError,
    SOCProviderTimeoutError,
    SOCProviderUnavailableError,
    SOCSafetyError,
)
from app.services.soc.executor import SOCQueryExecutor  # noqa: F401
from app.services.soc.engine import SOCQueryService  # noqa: F401
from app.services.soc.parser import (  # noqa: F401
    SOCIntentParser,
    SOCParseResult,
    build_candidate,
    parse_strict,
    validate_candidate,
)

__all__ = [
    "SOCQueryService",
    "SOCQueryExecutor",
    "SOCIntentParser",
    "SOCParseResult",
    "build_candidate",
    "parse_strict",
    "validate_candidate",
    "SOCError",
    "SOCConfigurationError",
    "SOCInputValidationError",
    "SOCSafetyError",
    "SOCParserError",
    "SOCModelOutputError",
    "SOCModelValidationError",
    "SOCProviderError",
    "SOCProviderTimeoutError",
    "SOCProviderUnavailableError",
    "SOCIntentValidationError",
    "SOCExecutionError",
    "SOCInternalError",
]