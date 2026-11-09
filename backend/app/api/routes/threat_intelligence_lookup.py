"""Manual Threat Intelligence Lookup API.

Provides an authenticated, RBAC-guarded endpoint for SOC analysts to manually
lookup threat intelligence indicators (IP, domain, URL, hash) without requiring
a prior security event.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import string
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.agents.threat_intelligence import (
    ThreatIntelligenceAgent,
    persist_analysis_bound,
)
from app.api.dependencies import get_db, require_role
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import LookupStatus, ThreatIntelLookup
from app.models.user import User
from app.repositories.threat_intelligence import ThreatIntelRepository
from app.services.threat_intel_enrichment import build_provider_registry
from app.services.threat_intelligence.rate_limiter import InMemoryRateLimiter
from app.services.threat_intelligence.registry import ProviderRegistry
from app.services.threat_intelligence.types import IndicatorType, ThreatIndicator
from app.services.threat_intelligence.validation import should_skip_external_lookup
from app.services.threat_intelligence_persistence import (
    canonical_indicator_key,
    sanitize_error_message,
)
from app.services.threat_intelligence_query import (
    indicator_status,
    sanitize_evidence,
)

logger = logging.getLogger(__name__)

router = APIRouter()

_READ_ROLES = ("admin", "analyst", "ciso")
_require_analyst = require_role(*_READ_ROLES)

_DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


_manual_lookup_limiter = InMemoryRateLimiter(requests_per_minute=30)


def get_provider_registry() -> ProviderRegistry:
    """Return the configured ProviderRegistry for threat intelligence lookups."""
    registry, _ = build_provider_registry()
    return registry


def get_rate_limiter() -> InMemoryRateLimiter:
    """Return the configured InMemoryRateLimiter for manual lookup rate limiting."""
    return _manual_lookup_limiter


# ---------------------------------------------------------------------------
# Request & Response Models
# ---------------------------------------------------------------------------


class ManualThreatIntelLookupRequest(BaseModel):
    """Request payload for manual threat intelligence indicator lookup."""

    indicator: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="The indicator value (IP, domain, URL, or hash).",
    )
    indicator_type: str = Field(
        ...,
        description="The indicator category: ip, domain, url, or hash.",
    )


class ManualProviderLookupResult(BaseModel):
    """Execution result for a single threat intelligence provider."""

    provider: str = Field(..., description="Name of the threat intelligence provider.")
    status: str = Field(..., description="Provider lookup outcome: 'success', 'error', or 'skipped'.")
    found: bool | None = Field(None, description="Whether the provider held information on the indicator.")
    confidence: float | None = Field(None, description="Provider confidence in [0.0, 1.0], if reported.")
    evidence: dict[str, Any] | None = Field(None, description="Sanitized, safe provider evidence summary.")
    error_message: str | None = Field(None, description="Secret-safe provider error summary if failed/skipped.")
    performed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the lookup attempt was executed (UTC).",
    )


class ManualThreatIntelLookupResponse(BaseModel):
    """Structured response for a manual threat intelligence indicator lookup."""

    indicator_id: uuid.UUID = Field(..., description="Unique ID of the persisted indicator.")
    indicator_type: str = Field(..., description="Indicator type (ip, domain, url, hash).")
    normalized_indicator_value: str = Field(..., description="Normalized indicator value.")
    canonical_key: str = Field(..., description="Deterministic canonical deduplication key.")
    status: str = Field(..., description="Overall rollup status: 'enriched', 'partial', 'failed', or 'no_lookup'.")
    providers_attempted: int = Field(..., description="Number of providers that executed a lookup attempt.")
    providers_succeeded: int = Field(..., description="Number of successful provider responses.")
    providers_failed: int = Field(..., description="Number of provider failures.")
    providers_skipped: int = Field(..., description="Number of providers skipped (e.g. non-public IP).")
    is_new_indicator: bool = Field(..., description="Whether the indicator was newly created.")
    first_seen: datetime | None = Field(
        default=None,
        description="When the indicator was first observed, if already in database.",
    )
    last_seen: datetime | None = Field(
        default=None,
        description="When the indicator was last observed, if already in database.",
    )
    results: list[ManualProviderLookupResult] = Field(
        default_factory=list,
        description="Detailed results per provider.",
    )


# ---------------------------------------------------------------------------
# Validation & Normalization
# ---------------------------------------------------------------------------


def validate_and_normalize_indicator(
    raw_type: str, raw_value: str
) -> tuple[IndicatorType, str, str]:
    """Validate indicator type and value, returning (IndicatorType, normalized_value, canonical_key).

    Raises HTTPException(422) on malformed or unsupported input.
    """
    clean_type = raw_type.strip().lower()
    try:
        ind_type = IndicatorType(clean_type)
    except ValueError as exc:
        allowed = ", ".join(m.value for m in IndicatorType)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Unsupported indicator type '{raw_type}'. Supported types: {allowed}",
        ) from exc

    val = raw_value.strip()
    if not val:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Indicator value must not be empty or whitespace.",
        )
    if len(val) > 2048:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Indicator value exceeds maximum allowed length of 2048 characters.",
        )

    if ind_type == IndicatorType.IP:
        try:
            ip_obj = ipaddress.ip_address(val)
            normalized = str(ip_obj)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid IP address: '{raw_value}'. Must be a valid IPv4 or IPv6 address.",
            ) from exc

    elif ind_type == IndicatorType.DOMAIN:
        # Reject scheme, path, ports, or spaces
        if "://" in val or "/" in val or ":" in val or " " in val or "\t" in val:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid domain name: '{raw_value}'. Must not contain protocol schemes, slashes, or ports.",
            )
        if len(val) > 253 or not val:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid domain name: '{raw_value}'. Length must be between 1 and 253 characters.",
            )
        labels = val.split(".")
        if len(labels) < 2:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid domain name: '{raw_value}'. Must include at least a domain and top-level domain.",
            )
        for label in labels:
            if not label or not _DOMAIN_LABEL_REGEX.match(label):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Invalid domain name: '{raw_value}'. Label '{label}' contains invalid characters.",
                )
        # Check TLD (last label) is alphabetic or valid punycode
        tld = labels[-1]
        if tld.isdigit() or len(tld) < 2:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid domain name: '{raw_value}'. Top-level domain must be valid.",
            )
        normalized = val.lower()

    elif ind_type == IndicatorType.URL:
        if " " in val or "\t" in val:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid URL: '{raw_value}'. URLs must not contain whitespace.",
            )
        try:
            parsed = urllib.parse.urlsplit(val)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid URL: '{raw_value}'. Failed to parse URL structure.",
            ) from exc

        if parsed.scheme.lower() not in ("http", "https"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid URL: '{raw_value}'. Protocol scheme must be 'http' or 'https'.",
            )
        if not parsed.netloc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid URL: '{raw_value}'. URL must include a host name or network location.",
            )
        normalized = val

    elif ind_type == IndicatorType.HASH:
        clean_hash = val.lower()
        if len(clean_hash) not in (32, 40, 64, 128):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    f"Invalid hash: '{raw_value}'. Length ({len(clean_hash)}) is invalid; "
                    "expected MD5 (32), SHA-1 (40), SHA-256 (64), or SHA-512 (128) hex characters."
                ),
            )
        if not all(c in string.hexdigits for c in clean_hash):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid hash: '{raw_value}'. Must contain hexadecimal characters only.",
            )
        normalized = clean_hash

    canonical_key = canonical_indicator_key(ind_type, normalized)
    return ind_type, normalized, canonical_key


# ---------------------------------------------------------------------------
# Endpoint: POST /api/v1/threat-intelligence/lookup
# ---------------------------------------------------------------------------


@router.post(
    "/lookup",
    response_model=ManualThreatIntelLookupResponse,
    summary="Execute manual threat intelligence lookup",
    description=(
        "Manually triggers threat intelligence provider lookups for an IP address, "
        "domain, URL, or hash without requiring an ingested security event. "
        "Results are persisted honestly in the threat intelligence store."
    ),
)
def manual_threat_intel_lookup(
    request: ManualThreatIntelLookupRequest,
    current_user: User = Depends(_require_analyst),
    db: Session = Depends(get_db),
    registry: ProviderRegistry = Depends(get_provider_registry),
    limiter: InMemoryRateLimiter = Depends(get_rate_limiter),
) -> ManualThreatIntelLookupResponse:
    """Execute manual threat-intelligence lookups across configured providers."""
    # 0. Rate limiting check per authenticated identity
    user_identity = str(getattr(current_user, "id", None) or getattr(current_user, "username", None) or "authenticated_user")
    limit_status = limiter.check(user_identity)
    if not limit_status.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded: maximum {limit_status.limit} manual lookups per minute. "
                f"Please retry after {limit_status.reset_after} seconds."
            ),
            headers={"Retry-After": str(max(1, int(limit_status.reset_after)))},
        )

    # 1. Input validation & normalization
    indicator_type, normalized_value, canonical_key = validate_and_normalize_indicator(
        request.indicator_type, request.indicator
    )

    repo = ThreatIntelRepository(db)
    now = datetime.now(timezone.utc)

    # Check whether the indicator already exists
    existing_row = repo.get_indicator_by_canonical_key(canonical_key)
    is_new_indicator = existing_row is None
    prev_first_seen = existing_row.first_seen_at if existing_row else None
    prev_last_seen = existing_row.last_seen_at if existing_row else None

    # 2. Non-public IP protection check
    should_skip, skip_reason = should_skip_external_lookup(indicator_type, normalized_value)
    if should_skip:
        # Get or create indicator row in the database so it is indexed and searchable
        try:
            indicator_row, _ = repo.get_or_create_indicator(
                value=normalized_value,
                indicator_type=indicator_type,
                canonical_key=canonical_key,
                seen_at=now,
            )
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error("Failed to persist indicator for non-public IP: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to persist threat intelligence indicator record.",
            ) from exc

        # Collect applicable providers to report them as skipped
        matching_providers = registry.find_providers_for(indicator_type)
        provider_results: list[ManualProviderLookupResult] = []
        for provider in matching_providers:
            provider_results.append(
                ManualProviderLookupResult(
                    provider=provider.provider_name,
                    status="skipped",
                    error_message=f"Lookup skipped: {skip_reason}",
                    performed_at=now,
                )
            )

        return ManualThreatIntelLookupResponse(
            indicator_id=indicator_row.id,
            indicator_type=indicator_type.value,
            normalized_indicator_value=normalized_value,
            canonical_key=canonical_key,
            status="no_lookup",
            providers_attempted=0,
            providers_succeeded=0,
            providers_failed=0,
            providers_skipped=len(matching_providers),
            is_new_indicator=is_new_indicator,
            first_seen=prev_first_seen if not is_new_indicator else None,
            last_seen=prev_last_seen if not is_new_indicator else None,
            results=provider_results,
        )

    # 3. Applicable providers check
    matching_providers = registry.find_providers_for(indicator_type)
    if not matching_providers:
        try:
            indicator_row, _ = repo.get_or_create_indicator(
                value=normalized_value,
                indicator_type=indicator_type,
                canonical_key=canonical_key,
                seen_at=now,
            )
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error("Failed to persist indicator when no providers configured: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to persist threat intelligence indicator record.",
            ) from exc

        return ManualThreatIntelLookupResponse(
            indicator_id=indicator_row.id,
            indicator_type=indicator_type.value,
            normalized_indicator_value=normalized_value,
            canonical_key=canonical_key,
            status="no_lookup",
            providers_attempted=0,
            providers_succeeded=0,
            providers_failed=0,
            providers_skipped=0,
            is_new_indicator=is_new_indicator,
            first_seen=prev_first_seen if not is_new_indicator else None,
            last_seen=prev_last_seen if not is_new_indicator else None,
            results=[],
        )

    # 4. Execute provider lookups via ThreatIntelligenceAgent and persist
    agent = ThreatIntelligenceAgent(registry)
    threat_indicator = ThreatIndicator(
        indicator_type=indicator_type,
        value=normalized_value,
    )

    try:
        analysis = agent.analyze_indicator(
            threat_indicator,
            persistence=persist_analysis_bound(db),
        )
    except Exception as exc:
        db.rollback()
        logger.error("Manual threat-intel lookup execution/persistence failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute or persist threat intelligence manual lookup.",
        ) from exc

    # Retrieve the persisted indicator row
    indicator_row = repo.get_indicator_by_canonical_key(canonical_key)
    if indicator_row is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Indicator was not found following manual lookup execution.",
        )

    # Map provider results
    results_list: list[ManualProviderLookupResult] = []
    providers_succeeded = 0
    providers_failed = 0
    providers_skipped = 0

    for assoc in analysis.results:
        if assoc.result is not None:
            providers_succeeded += 1
            results_list.append(
                ManualProviderLookupResult(
                    provider=assoc.provider,
                    status="success",
                    found=assoc.result.found,
                    confidence=assoc.result.confidence,
                    evidence=sanitize_evidence(assoc.result.data),
                    performed_at=assoc.result.timestamp,
                )
            )
        else:
            providers_skipped += 1
            results_list.append(
                ManualProviderLookupResult(
                    provider=assoc.provider,
                    status="skipped",
                    error_message="Lookup skipped for indicator.",
                    performed_at=now,
                )
            )

    for failure in analysis.failures:
        providers_failed += 1
        results_list.append(
            ManualProviderLookupResult(
                provider=failure.provider,
                status="error",
                error_message=sanitize_error_message(failure.message),
                performed_at=now,
            )
        )

    providers_attempted = providers_succeeded + providers_failed
    overall_status = indicator_status(
        lookup_count=providers_attempted,
        success_count=providers_succeeded,
        error_count=providers_failed,
    )

    return ManualThreatIntelLookupResponse(
        indicator_id=indicator_row.id,
        indicator_type=indicator_type.value,
        normalized_indicator_value=normalized_value,
        canonical_key=canonical_key,
        status=overall_status,
        providers_attempted=providers_attempted,
        providers_succeeded=providers_succeeded,
        providers_failed=providers_failed,
        providers_skipped=providers_skipped,
        is_new_indicator=is_new_indicator,
        first_seen=prev_first_seen if not is_new_indicator else None,
        last_seen=prev_last_seen if not is_new_indicator else None,
        results=results_list,
    )
