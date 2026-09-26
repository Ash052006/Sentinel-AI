"""Response & Mitigation service layer — Step 25.

Enforces *how a previously-permitted action may be safely executed*.
Everything here is deterministic, policy-gated, secret-safe, and side-
effect-free with respect to the host: real system integrations (firewalls,
EDR, IAM, SOAR, cloud security APIs) are explicitly out of scope for
Version 1 and would implement the same :class:`ResponseProvider` contract.

No policy is made here, no Gemini/SQL/commands are issued, no OS or
filesystem is touched, and no persistence/API is introduced by this
package.
"""

from __future__ import annotations

from app.services.response.contracts import (
    PolicyDecision,
    ResponseActionType,
    ResponseExecutionStatus,
    ResponseRequest,
    ResponseResult,
)
from app.services.response.errors import (
    ResponseError,
    ResponseInternalError,
    ResponsePolicyGateError,
    ResponseProviderError,
    ResponseValidationError,
)
from app.services.response.executor import ResponseExecutor
from app.services.response.providers import (
    MOCK_PROVIDER,
    MockResponseProvider,
    ResponseProvider,
)
from app.services.response.registry import (
    DEFAULT_RESPONSE_REGISTRY,
    ResponseProviderRegistry,
)
from app.services.response.service import ResponseMitigationService

__all__ = [
    "DEFAULT_RESPONSE_REGISTRY",
    "MOCK_PROVIDER",
    "MockResponseProvider",
    "PolicyDecision",
    "ResponseActionType",
    "ResponseError",
    "ResponseExecutionStatus",
    "ResponseExecutor",
    "ResponseInternalError",
    "ResponseMitigationService",
    "ResponsePolicyGateError",
    "ResponseProvider",
    "ResponseProviderError",
    "ResponseProviderRegistry",
    "ResponseRequest",
    "ResponseResult",
    "ResponseValidationError",
]