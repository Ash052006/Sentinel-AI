"""VirusTotal threat-intelligence provider.

Implements the :class:`ThreatIntelProvider` interface for the VirusTotal
API v3.  Supports IP address, domain, URL, and file-hash indicators.

Architecture::

    ThreatIndicator
         |
         v
    VirusTotalProvider.lookup()
         |
         v
    VirusTotal API v3  (via injectable httpx.Client)
         |
         v
    ThreatIntelResult  (provider-neutral)
         |
         v
    EnrichmentResult  (mapped by the future Threat Intelligence Agent)

Security:
    * API key is injected via configuration, never hardcoded.
    * API key never appears in logs, exceptions, or result metadata.
    * HTTP client is injectable for testing without network access.
"""

from __future__ import annotations

import base64
import logging
import time
from typing import Any

import httpx

from app.core.config import settings
from app.services.threat_intelligence.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)
from app.services.threat_intelligence.exceptions import (
    InvalidIndicatorError,
    ProviderLookupError,
    RateLimitError,
    UnsupportedIndicatorTypeError,
)
from app.services.threat_intelligence.types import (
    IndicatorType,
    ThreatIndicator,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# VirusTotal API v3 constants
# ---------------------------------------------------------------------------

_BASE_URL = "https://www.virustotal.com/api/v3"

# Mapping from our IndicatorType to the VT API resource path segment.
_RESOURCE_PATH_MAP: dict[IndicatorType, str] = {
    IndicatorType.IP: "ip_addresses",
    IndicatorType.DOMAIN: "domains",
    IndicatorType.HASH: "files",
    IndicatorType.URL: "urls",
}

# Maximum number of retry attempts for transient (5xx / network) errors.
_MAX_RETRIES = 2
_RETRY_BASE_DELAY = 1.0  # seconds


class _RetryableServerError(ProviderLookupError):
    """Internal marker for transient server-side failures (may be retried).

    Never escapes the provider: consumers always observe a regular
    :class:`ProviderLookupError` after retries are exhausted.
    """

    def __init__(self, status: int) -> None:
        super().__init__("VirusTotal", f"server error (HTTP {status})")
        self.status = status


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal API v3 threat-intelligence provider.

    Parameters:
        api_key: VirusTotal API key.  Must be provided explicitly or
            resolved from ``Settings.virustotal_api_key``.
        timeout_seconds: Per-request timeout in seconds.
        http_client: Optional pre-configured ``httpx.Client``.  When
            ``None`` a client is created internally using the timeout.
    """

    provider_name = "VirusTotal"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout_seconds: float | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        resolved_key = api_key or settings.virustotal_api_key
        if not resolved_key:
            raise ValueError(
                "VirusTotal API key is required.  "
                "Set VIRUSTOTAL_API_KEY in your environment or pass "
                "api_key explicitly."
            )
        self._api_key: str = resolved_key

        self._timeout_seconds: float = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.virustotal_timeout_seconds
        )

        self._owns_client = http_client is None
        self._client: httpx.Client = (
            http_client
            if http_client is not None
            else httpx.Client(timeout=self._timeout_seconds)
        )

    @property
    def supported_indicator_types(self) -> frozenset[IndicatorType]:
        """Types supported by the VirusTotal API v3 resource endpoints."""
        return frozenset(_RESOURCE_PATH_MAP.keys())

    @staticmethod
    def _compute_url_id(url: str) -> str:
        """Compute the VirusTotal URL resource identifier.

        VirusTotal represents URLs as base64url-encoded identifiers
        without trailing ``=`` padding, per the official API v3 contract.
        """
        return (
            base64.urlsafe_b64encode(url.encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )

    def _build_endpoint(self, indicator: ThreatIndicator) -> str:
        """Build the full API endpoint URL for a given indicator."""
        resource_path = _RESOURCE_PATH_MAP[indicator.indicator_type]

        if indicator.indicator_type == IndicatorType.URL:
            resource_id = self._compute_url_id(indicator.value)
        else:
            resource_id = indicator.value

        return f"{_BASE_URL}/{resource_path}/{resource_id}"

    def _build_headers(self) -> dict[str, str]:
        """Return request headers for VirusTotal API authentication."""
        return {"x-apikey": self._api_key}

    # -- Lookup ---------------------------------------------------------------

    def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
        """Perform a VirusTotal API v3 lookup for *indicator*.

        Returns:
            A :class:`ThreatIntelResult` with the provider-neutral
            representation of the VirusTotal response.

        Raises:
            UnsupportedIndicatorTypeError: If the indicator type is not
                supported.
            ProviderLookupError: On API or transport errors.
            RateLimitError: When HTTP 429 is received.
            InvalidIndicatorError: On empty or malformed indicator values.
        """
        self.assert_supports(indicator)

        if not indicator.value or not indicator.value.strip():
            raise InvalidIndicatorError(
                f"Indicator value must not be empty for "
                f"indicator type '{indicator.indicator_type.value}'"
            )

        endpoint = self._build_endpoint(indicator)
        headers = self._build_headers()

        start = time.monotonic()
        logger.info(
            "VirusTotal lookup: type=%s",
            indicator.indicator_type.value,
        )

        response_data = self._request_with_retry(endpoint, headers)

        elapsed = time.monotonic() - start
        logger.info(
            "VirusTotal lookup completed in %.2fs",
            elapsed,
        )

        return self._parse_response(indicator, response_data)

    # -- HTTP request with bounded retry for transient errors -----------------

    def _request_with_retry(
        self,
        endpoint: str,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Execute the HTTP GET with bounded retry for transient failures.

        Retries only on 5xx server errors and transport-level failures
        (connection errors, timeouts).  Client errors (4xx) are never
        retried.
        """
        last_exc: Exception | None = None

        for attempt in range(1, _MAX_RETRIES + 2):
            try:
                response = self._client.get(endpoint, headers=headers)
                return self._handle_response(response)
            except _RetryableServerError as exc:
                last_exc = exc
                logger.warning(
                    "VirusTotal server error (attempt %d/%d): HTTP %d",
                    attempt,
                    _MAX_RETRIES + 1,
                    exc.status,
                )
                if attempt <= _MAX_RETRIES:
                    time.sleep(_RETRY_BASE_DELAY * attempt)
                    continue
                raise ProviderLookupError(
                    self.provider_name,
                    f"server error (HTTP {exc.status})",
                ) from exc
            except (ProviderLookupError, RateLimitError, InvalidIndicatorError):
                raise
            except httpx.TimeoutException as exc:
                last_exc = exc
                logger.warning(
                    "VirusTotal request timed out (attempt %d/%d)",
                    attempt,
                    _MAX_RETRIES + 1,
                )
                if attempt <= _MAX_RETRIES:
                    time.sleep(_RETRY_BASE_DELAY * attempt)
                    continue
                raise ProviderLookupError(
                    self.provider_name,
                    "request timed out",
                ) from exc
            except httpx.HTTPError as exc:
                last_exc = exc
                logger.warning(
                    "VirusTotal transport error (attempt %d/%d): %s",
                    attempt,
                    _MAX_RETRIES + 1,
                    type(exc).__name__,
                )
                if attempt <= _MAX_RETRIES:
                    time.sleep(_RETRY_BASE_DELAY * attempt)
                    continue
                raise ProviderLookupError(
                    self.provider_name,
                    f"transport error: {type(exc).__name__}",
                ) from exc

        raise ProviderLookupError(
            self.provider_name,
            "request failed after retries",
        ) from last_exc
# -- Response handling ----------------------------------------------------

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        """Translate the HTTP response into a data dict or raise."""
        status = response.status_code

        if status == 404:
            # Not-found is a valid business outcome, not a provider error.
            return {"_not_found": True}

        if status == 401:
            raise ProviderLookupError(
                self.provider_name,
                "unauthorized — check API key configuration",
            )

        if status == 403:
            raise ProviderLookupError(
                self.provider_name,
                "forbidden — insufficient API permissions",
            )

        if status == 429:
            retry_after: float | None = None
            retry_header = response.headers.get("Retry-After")
            if retry_header:
                try:
                    retry_after = float(retry_header)
                except (ValueError, TypeError):
                    pass
            raise RateLimitError(self.provider_name, retry_after=retry_after)

        if status == 400:
            raise ProviderLookupError(
                self.provider_name,
                "bad request — malformed indicator or API usage error",
            )

        if status >= 500:
            raise _RetryableServerError(status)

        if status != 200:
            raise ProviderLookupError(
                self.provider_name,
                f"unexpected HTTP status {status}",
            )

        # Parse JSON body.
        try:
            payload = response.json()
        except Exception as exc:
            raise ProviderLookupError(
                self.provider_name,
                "malformed JSON in API response",
            ) from exc

        if not isinstance(payload, dict):
            raise ProviderLookupError(
                self.provider_name,
                "unexpected response structure — expected JSON object",
            )

        # Check for error objects in a 200 response (defensive).
        if "error" in payload:
            error_obj = payload["error"]
            error_msg = ""
            if isinstance(error_obj, dict):
                error_msg = error_obj.get("message", str(error_obj))
            else:
                error_msg = str(error_obj)
            raise ProviderLookupError(
                self.provider_name,
                f"API error: {error_msg}",
            )

        return payload

# -- Result parsing -------------------------------------------------------

    def _parse_response(
        self,
        indicator: ThreatIndicator,
        raw: dict[str, Any],
    ) -> ThreatIntelResult:
        """Convert the raw VT response dict into a ThreatIntelResult."""
        # Handle not-found.
        if raw.get("_not_found"):
            return ThreatIntelResult(
                indicator=indicator,
                provider=self.provider_name,
                found=False,
                data={},
                confidence=None,
                metadata={
                    "resource_type": _RESOURCE_PATH_MAP.get(
                        indicator.indicator_type,
                        indicator.indicator_type.value,
                    ),
                },
            )

        # Extract the data object from the JSON:API response.
        data_obj = raw.get("data")
        if not isinstance(data_obj, dict):
            raise ProviderLookupError(
                self.provider_name,
                "unexpected response — missing 'data' field",
            )

        attributes = data_obj.get("attributes")
        if not isinstance(attributes, dict):
            raise ProviderLookupError(
                self.provider_name,
                "unexpected response — missing 'attributes' field",
            )

        # Build the normalised data payload.
        normalised = self._extract_attributes(
            indicator.indicator_type, attributes,
        )
        normalised["resource_type"] = data_obj.get("type", "unknown")

        return ThreatIntelResult(
            indicator=indicator,
            provider=self.provider_name,
            found=True,
            data=normalised,
            confidence=None,  # VT does not provide a confidence metric.
            metadata={
                "resource_type": data_obj.get("type", "unknown"),
                "vt_id": data_obj.get("id", ""),
            },
        )

    def _extract_attributes(
        self,
        indicator_type: IndicatorType,
        attributes: dict[str, Any],
    ) -> dict[str, Any]:
        """Extract relevant fields from VirusTotal attributes.

        This keeps only safe, structured fields that map to the
        provider-neutral result contract.
        """
        result: dict[str, Any] = {}

        # Last analysis statistics (common across all resource types).
        last_analysis_stats = attributes.get("last_analysis_stats")
        if isinstance(last_analysis_stats, dict):
            result["last_analysis_stats"] = {
                "harmless": last_analysis_stats.get("harmless", 0),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "timeout": last_analysis_stats.get("timeout", 0),
            }

        # Reputation score (if available).
        reputation = attributes.get("reputation")
        if reputation is not None:
            result["reputation"] = reputation

        # Categories (if available).
        categories = attributes.get("categories")
        if isinstance(categories, dict):
            result["categories"] = categories

        # Last analysis date (Unix timestamp).
        last_analysis_date = attributes.get("last_analysis_date")
        if last_analysis_date is not None:
            result["last_analysis_date"] = last_analysis_date

        # Type-specific attributes.
        if indicator_type == IndicatorType.IP:
            self._extract_ip_attributes(attributes, result)
        elif indicator_type == IndicatorType.DOMAIN:
            self._extract_domain_attributes(attributes, result)
        elif indicator_type == IndicatorType.HASH:
            self._extract_file_attributes(attributes, result)
        elif indicator_type == IndicatorType.URL:
            self._extract_url_attributes(attributes, result)

        return result

    @staticmethod
    def _extract_ip_attributes(
        attributes: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        """Extract IP-specific attributes from a VirusTotal response."""
        for field in ("asn", "as_owner", "country", "network", "whois"):
            value = attributes.get(field)
            if value is not None:
                result[field] = value

    @staticmethod
    def _extract_domain_attributes(
        attributes: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        """Extract domain-specific attributes from a VirusTotal response."""
        for field in ("registrar", "whois", "popularity_ranks"):
            value = attributes.get(field)
            if value is not None:
                result[field] = value

    @staticmethod
    def _extract_file_attributes(
        attributes: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        """Extract file/hash-specific attributes from a VirusTotal response."""
        for field in (
            "md5",
            "sha1",
            "sha256",
            "type_description",
            "type_tag",
            "popular_threat_classification",
            "names",
        ):
            value = attributes.get(field)
            if value is not None:
                # Limit 'names' to a safe subset to avoid huge payloads.
                if field == "names" and isinstance(value, list):
                    result[field] = value[:10]
                else:
                    result[field] = value

    @staticmethod
    def _extract_url_attributes(
        attributes: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        """Extract URL-specific attributes from a VirusTotal response."""
        for field in ("url", "title", "final_url"):
            value = attributes.get(field)
            if value is not None:
                result[field] = value

    # -- Cleanup --------------------------------------------------------------

    def close(self) -> None:
        """Close the internal HTTP client if owned by this provider."""
        if self._owns_client and self._client is not None:
            self._client.close()

    def __del__(self) -> None:  # pragma: no cover
        try:
            self.close()
        except Exception:
            pass