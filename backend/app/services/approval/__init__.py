"""Human-in-the-Loop approval workflow service package (V2.16).

The service layer behind the approval API: routing REQUIRES_APPROVAL
policy decisions to authorized humans, deterministic persistence, and
conditional, concurrency-safe resolution whose APPROVED grants are handed
to the Step 25 Response layer (approved == authorization, never
execution).
"""

from app.services.approval.errors import (
    ApprovalConflictError,
    ApprovalError,
    ApprovalNotFoundError,
    ApprovalServiceError,
    ApprovalValidationError,
)
from app.services.approval.service import (
    APPROVAL_SOC_ROLES,
    ApprovalGrantVerifier,
    ApprovalService,
    DEFAULT_PAGE_SIZE,
    DEFAULT_RECENT_LIMIT,
    MAX_PAGE_SIZE,
    MAX_RECENT_LIMIT,
)

__all__ = [
    "APPROVAL_SOC_ROLES",
    "ApprovalConflictError",
    "ApprovalError",
    "ApprovalGrantVerifier",
    "ApprovalNotFoundError",
    "ApprovalService",
    "ApprovalServiceError",
    "ApprovalValidationError",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_RECENT_LIMIT",
    "MAX_PAGE_SIZE",
    "MAX_RECENT_LIMIT",
]