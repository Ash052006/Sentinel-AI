"""V2.18 — SOAR (Security Orchestration, Automation and Response).

Sandbox/mock orchestration of approved policy-driven response workflows via
declarative, code-registered playbooks.  See ``docs/development/soar_v218.md``.

Boundary (documented):

    V2.18 SOAR uses sandbox/mock providers.  It does NOT perform real-world
    security actions or connect to real external systems.
"""

from app.services.soar.engine import SoarEngine
from app.services.soar.errors import (
    SoarConflictError,
    SoarError,
    SoarInternalError,
    SoarNotFoundError,
    SoarServiceError,
    SoarValidationError,
)
from app.services.soar.gate import SoarPolicyGate
from app.services.soar.playbooks import (
    DEFAULT_SOAR_PLAYBOOK_REGISTRY,
    SoarPlaybookRegistry,
)
from app.services.soar.providers import (
    MockEDRProvider,
    MockFirewallProvider,
    MockIdentityProvider,
    SoarProvider,
    SoarProviderError,
    SoarProviderResult,
    default_providers,
)
from app.services.soar.registry import (
    DEFAULT_SOAR_PROVIDER_REGISTRY,
    SoarProviderRegistry,
    default_provider_registry,
)
from app.services.soar.service import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    SOAR_MUTATION_ROLES,
    SOAR_READ_ROLES,
    SoarService,
)

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_SOAR_PLAYBOOK_REGISTRY",
    "DEFAULT_SOAR_PROVIDER_REGISTRY",
    "MAX_PAGE_SIZE",
    "MockEDRProvider",
    "MockFirewallProvider",
    "MockIdentityProvider",
    "SOAR_MUTATION_ROLES",
    "SOAR_READ_ROLES",
    "SoarConflictError",
    "SoarEngine",
    "SoarError",
    "SoarInternalError",
    "SoarNotFoundError",
    "SoarPlaybookRegistry",
    "SoarPolicyGate",
    "SoarProvider",
    "SoarProviderError",
    "SoarProviderRegistry",
    "SoarProviderResult",
    "SoarService",
    "SoarValidationError",
    "default_provider_registry",
    "default_providers",
]