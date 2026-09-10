"""AbuseIPDB threat-intelligence provider.

Implements the :class:`ThreatIntelProvider` interface for the AbuseIPDB
API v2.  Supports IP-address indicators only.

Architecture::

    ThreatIndicator
         |
         v
    AbuseIPDBProvider.lookup()
         |
         v
    AbuseIPDB API v2  (via injectable httpx.Client)
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
)
from app.services.threat_intelligence.types import (
    IndicatorType,
    ThreatIndicator,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AbuseIPDB API v2 constants
# ---------------------------------------------------------------------------

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"

# Maximum number of retry attempts for transient (5xx / network) errors.
_MAX_RETRIES = 2
_RETRY_BASE_DELAY = 1.0  # seconds

# Recommended default review window when querying abuse reports.
_MAX_AGE_IN_DAYS = 90

# Deliberately selected report fields to expose.  Additional fields in the
# raw response are ignored so the provider never blindly dumps the payload.
_REPORT_FIELDS: tuple[str, ...] = (
    "ipAddress",
    "ipVersion",
    "isPublic",
    "countryCode",
    "usageType",
    "isp",
    "domain",
    "hostnames",
    "isTor",
    "isCrawler",
    "totalReports",
    "numDistinctUsers",
    "lastReportedAt",
    "isWhitelisted",
    "abuseConfidenceScore",
)

# Maximum number of individual abuse reports to surface in the result.
_REPORT_ITEM_CAP = 10

# Scalar fields kept from each entry in the `reports` array.
_REPORT_ITEM_FIELDS: tuple[str, ...] = (
    "reportedAt",
    "comment",
    "categories",
    "reporterId",
    "reporterCountryCode",
    "reporterCountryName",
)


class _RetryableServerError(ProviderLookupError):
    """Internal marker for transient server-side failures (may be retried).

    Never escapes the provider: consumers always observe a regular
    :class:`ProviderLookupError` after retries are exhausted.
    """

    def __init__(self, status: int) -> None:
        super().__init__("AbuseIPDB", f"server error (HTTP {status})")
        self.status = status


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB API v2 threat-intelligence provider (IP indicators only).

    Parameters:
        api_key: AbuseIPDB API key.  Must be provided explicitly or
            resolved from ``Settings.abuseipdb_api_key``.
        timeout_seconds: Per-request timeout in seconds.
        http_client: Optional pre-configured ``httpx.Client``.  When
            ``None`` a client is created internally using the timeout.
    """

    provider_name = "abuseipdb"

    _supported_types: frozenset[IndicatorType] = frozenset({IndicatorType.IP})

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout_seconds: float | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        resolved_key = api_key or settings.abuseipdb_api_key
        if not resolved_key:
            raise ValueError(
                "AbuseIPDB API key is required.  "
                "Set ABUSEIPDB_API_KEY in your environment or pass "
                "api_key explicitly."
            )
        self._api_key: str = resolved_key

        self._timeout_seconds: float = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.abuseipdb_timeout_seconds
        )

        self._owns_client = http_client is None
        self._client: httpx.Client = (
            http_client
            if http_client is not None
            else httpx.Client(timeout=self._timeout_seconds)
        )

    @property
    def supported_indicator_types(self) -> frozenset[IndicatorType]:
        """AbuseIPDB's ``check`` endpoint supports IP addresses only."""
        return self._supported_types

    # -- Request construction ------------------------------------------------

    def _build_params(self, indicator: ThreatIndicator) -> dict[str, Any]:
        """Build query parameters for the AbuseIPDB ``check`` endpoint."""
        return {
            "ipAddress": indicator.value,
            "maxAgeInDays": _MAX_AGE_IN_DAYS,
        }

    def _build_headers(self) -> dict[str, str]:
        """Return request headers for AbuseIPDB API authentication."""
        return {
            "Key": self._api_key,
            "Accept": "application/json",
        }

    # -- Lookup ---------------------------------------------------------------

    def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
        """Perform an AbuseIPDB API v2 lookup for *indicator*.

        Returns:
            A :class:`ThreatIntelResult` with the provider-neutral
            representation of the AbuseIPDB response.  Absence of a threat
            report is returned as ``found=False`` (not an error).

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

        params = self._build_params(indicator)
        headers = self._build_headers()

        start = time.monotonic()
        logger.info(
            "AbuseIPDB lookup: type=%s",
            indicator.indicator_type.value,
        )

        response_data = self._request_with_retry(params, headers)

        elapsed = time.monotonic() - start
        logger.info(
            "AbuseIPDB lookup completed in %.2fs",
            elapsed,
        )

        return self._parse_response(indicator, response_data)

    # -- HTTP request with bounded retry for transient errors -----------------

    def _request_with_retry(
        self,
        params: dict[str, Any],
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
                response = self._client.get(
                    _BASE_URL, params=params, headers=headers,
                )
                return self._handle_response(response)
            except _RetryableServerError as exc:
                last_exc = exc
                logger.warning(
                    "AbuseIPDB server error (attempt %d/%d): HTTP %d",
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
                    "AbuseIPDB request timed out (attempt %d/%d)",
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
                    "AbuseIPDB transport error (attempt %d/%d): %s",
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

        if status == 401:
            raise ProviderLookupError(
                self.provider_name,
                "unauthorized -- check API key configuration",
            )

        if status == 403:
            raise ProviderLookupError(
                self.provider_name,
                "forbidden -- insufficient API permissions",
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
                "bad request -- malformed indicator or API usage error",
            )

        if status == 404:
            raise ProviderLookupError(
                self.provider_name,
                "not found -- resource unavailable",
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
                "unexpected response structure -- expected JSON object",
            )

        # Check for error objects in a 200 response (defensive).
        if "errors" in payload:
            errors = payload["errors"]
            error_msg = ""
            if isinstance(errors, list) and errors:
                first = errors[0]
                if isinstance(first, dict):
                    error_msg = first.get("detail", str(first))
                else:
                    error_msg = str(first)
            else:
                error_msg = str(errors)
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
        """Convert the raw AbuseIPDB response dict into a ThreatIntelResult.

        Per the official AbuseIPDB API v2 documentation, the ``check``
        endpoint returns the report fields directly underneath the ``data``
        object (there is no nested ``report`` key).  An IP with no abuse
        reports is still a successful response whose ``totalReports`` is 0
        (or whose ``reports`` array is empty) -- that is a valid business
        outcome reported as ``found=False``, never an error.
        """
        data_obj = raw.get("data")
        if not isinstance(data_obj, dict):
            raise ProviderLookupError(
                self.provider_name,
                "unexpected response -- missing 'data' field",
            )

        # Build the normalised data payload from the report object.
        normalised = self._extract_report(data_obj)

        # `totalReports` (when present) decides whether an abuse report
        # exists for the queried address.
        total_reports = data_obj.get("totalReports", 0)
        if isinstance(total_reports, bool) or not isinstance(
            total_reports, (int, float),
        ):
            total_reports = 0
        found = total_reports > 0

        return ThreatIntelResult(
            indicator=indicator,
            provider=self.provider_name,
            found=found,
            data=normalised,
            # AbuseIPDB's abuseConfidenceScore is an abuse-confidence metric
            # for a report window.  It is NOT a SentinelAI confidence score
            # in [0.0, 1.0], so we deliberately leave confidence=None rather
            # than inventing a mapping.  See docs.
            confidence=None,
            metadata={
                "resource_type": "abuseipdb-ip",
            },
        )

    def _extract_report(self, report: dict[str, Any]) -> dict[str, Any]:
        """Extract the safe, structured fields from an AbuseIPDB report."""
        result: dict[str, Any] = {}

        for field in _REPORT_FIELDS:
            value = report.get(field)
            if value is not None:
                result[field] = value

        # The `reports` array is copied verbatim when present (including an
        # empty list, matching the real API) and trimmed to a bounded subset
        # when large, so it never dominates the result payload.
        reports = report.get("reports")
        if isinstance(reports, list):
            result["reports"] = [
                self._normalise_report_item(item)
                for item in reports[:_REPORT_ITEM_CAP]
            ]

        return result

    @staticmethod
    def _normalise_report_item(item: Any) -> dict[str, Any]:
        """Normalise a single entry from the ``reports`` array.

        Only a small, deliberately chosen set of scalar fields is kept.
        Anything else in the raw report entry (including potential free-form
        content) is dropped so the provider never exposes the whole
        underlying payload.
        """
        if not isinstance(item, dict):
            return {}

        normalised: dict[str, Any] = {}
        for field in _REPORT_ITEM_FIELDS:
            value = item.get(field)
            if value is not None:
                normalised[field] = value
        return normalised

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