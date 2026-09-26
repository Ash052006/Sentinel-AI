"""AlienVault OTX threat-intelligence provider.

Implements the :class:`ThreatIntelProvider` interface for the AlienVault
OTX API v1 (hosted by LevelBlue OTX).  Supports IP (IPv4 and IPv6),
domain, URL, and file-hash indicators.

Architecture::

    ThreatIndicator
         |
         v
    AlienVaultOTXProvider.lookup()
         |
         v
    AlienVault OTX API v1  (via injectable httpx.Client)
         |
         v
    ThreatIntelResult  (provider-neutral)
         |
         v
    EnrichmentResult  (mapped by the future Threat Intelligence Agent)

This provider only retrieves and structures external intelligence.  It
never produces a security verdict itself.

Security:
    * API key is injected via configuration, never hardcoded.
    * API key never appears in logs, exceptions, or result metadata.
    * Indicator values are percent-encoded before being placed in the
      request path so they cannot escape their path component.
    * Only a deliberately selected, bounded set of response fields is
      exposed; the raw OTX response is never returned.
    * HTTP client is injectable for testing without network access.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any
from urllib.parse import quote

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
# AlienVault OTX API v1 constants
# ---------------------------------------------------------------------------

_API_V1_BASE_URL = "https://otx.alienvault.com/api/v1"

# OTX resource slugs used to build ``/indicators/{slug}/{value}/general``
# paths.  These match the official OTX ``IndicatorType`` definitions
# (``IPv4``, ``IPv6``, ``domain``, ``url``; every file-hash family shares
# the ``file`` slug).
_IPV4_SLUG = "IPv4"
_IPV6_SLUG = "IPv6"

_TYPE_SLUGS: dict[IndicatorType, str] = {
    IndicatorType.DOMAIN: "domain",
    IndicatorType.HASH: "file",
    IndicatorType.URL: "url",
}

# The ``general`` section is the primary indicator-intelligence endpoint.
_GENERAL_SECTION = "general"

# Maximum number of retry attempts for transient (5xx / network) errors.
_MAX_RETRIES = 2
_RETRY_BASE_DELAY = 1.0  # seconds

# Bounds applied while normalising the OTX response body so the provider
# never returns an unbounded payload.
_MAX_PULSES = 10
_MAX_PULSE_LIST_ENTRIES = 20
_MAX_PULSE_REFERENCES = 10
_MAX_RELATED_ENTRIES = 10
_MAX_VALIDATION_ENTRIES = 10

# Scalar fields deliberately selected from each pulse.  Everything else in
# a pulse is dropped so huge nested pulse objects never reach the result.
_PULSE_SCALAR_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "description",
    "created",
    "modified",
    "adversary",
    "TLP",
    "indicator_count",
)

# List-valued pulse fields that could otherwise dominate the payload.  Each
# list is trimmed to ``_MAX_PULSE_LIST_ENTRIES``.
_PULSE_LIST_FIELDS: tuple[str, ...] = (
    "tags",
    "references",
    "targeted_countries",
    "malware_families",
    "attack_ids",
    "industries",
)

# Scalar fields kept from each ``validation`` entry.
_VALIDATION_FIELDS: tuple[str, ...] = ("source", "message", "name")


class _RetryableServerError(ProviderLookupError):
    """Internal marker for transient server-side failures (may be retried).

    Never escapes the provider: consumers always observe a regular
    :class:`ProviderLookupError` after retries are exhausted.
    """

    def __init__(self, status: int) -> None:
        super().__init__("AlienVault OTX", f"server error (HTTP {status})")
        self.status = status


class AlienVaultOTXProvider(ThreatIntelProvider):
    """AlienVault OTX API v1 threat-intelligence provider.

    Parameters:
        api_key: OTX API key.  Must be provided explicitly or resolved
            from ``Settings.otx_api_key``.
        timeout_seconds: Per-request timeout in seconds.
        http_client: Optional pre-configured ``httpx.Client``.  When
            ``None`` a client is created internally using the timeout.
    """

    provider_name = "AlienVault OTX"

    _supported_types: frozenset[IndicatorType] = frozenset({
        IndicatorType.IP,
        IndicatorType.DOMAIN,
        IndicatorType.URL,
        IndicatorType.HASH,
    })

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout_seconds: float | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        resolved_key = api_key or settings.otx_api_key
        if not resolved_key:
            raise ValueError(
                "AlienVault OTX API key is required.  "
                "Set OTX_API_KEY in your environment or pass "
                "api_key explicitly."
            )
        self._api_key: str = resolved_key

        self._timeout_seconds: float = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.otx_timeout_seconds
        )

        self._owns_client = http_client is None
        self._client: httpx.Client = (
            http_client
            if http_client is not None
            else httpx.Client(timeout=self._timeout_seconds)
        )

    @property
    def supported_indicator_types(self) -> frozenset[IndicatorType]:
        """Types supported by the OTX indicator ``general`` endpoints."""
        return self._supported_types

    # -- Request construction ------------------------------------------------

    def _build_headers(self) -> dict[str, str]:
        """Return request headers for OTX API authentication."""
        return {
            "X-OTX-API-KEY": self._api_key,
            "Accept": "application/json",
        }

    @staticmethod
    def _ip_slug(value: str) -> str:
        """Return the OTX slug for *value* after validating it as an IP.

        Uses the standard library ``ipaddress`` module (never string
        heuristics) and raises :class:`InvalidIndicatorError` for
        malformed addresses before any network access.

        Raises:
            InvalidIndicatorError: If *value* is not a valid IPv4/IPv6
                address.
        """
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise InvalidIndicatorError(
                "indicator value is not a valid IPv4 or IPv6 address"
            ) from exc
        return _IPV4_SLUG if parsed.version == 4 else _IPV6_SLUG

    def _build_url(self, indicator: ThreatIndicator) -> str:
        """Build the OTX ``general`` endpoint URL for *indicator*.

        The indicator value is treated as untrusted input and is fully
        percent-encoded (``urllib.parse.quote(value, safe="")``) so it can
        never escape its intended single path component -- particularly
        important for URL indicators containing ``:``, ``/``, ``?``,
        ``&``, ``#``, ``%`` or spaces.
        """
        if indicator.indicator_type == IndicatorType.IP:
            slug = self._ip_slug(indicator.value)
        else:
            slug = _TYPE_SLUGS[indicator.indicator_type]

        encoded_value = quote(indicator.value, safe="")
        return (
            f"{_API_V1_BASE_URL}/indicators/{slug}/{encoded_value}/"
            f"{_GENERAL_SECTION}"
        )

    # -- Lookup ---------------------------------------------------------------

    def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
        """Perform an OTX API v1 lookup for *indicator*.

        Returns:
            A :class:`ThreatIntelResult` with the provider-neutral
            representation of the OTX response.  An indicator with no
            associated OTX pulses/intelligence is returned as
            ``found=False`` (not an error).

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

        # Validate IPs up-front so malformed addresses fail before any
        # network access.
        if indicator.indicator_type == IndicatorType.IP:
            self._ip_slug(indicator.value)

        url = self._build_url(indicator)
        headers = self._build_headers()

        start = time.monotonic()
        logger.info(
            "AlienVault OTX lookup: type=%s",
            indicator.indicator_type.value,
        )

        response_data = self._request_with_retry(url, headers)

        elapsed = time.monotonic() - start
        logger.info(
            "AlienVault OTX lookup completed in %.2fs",
            elapsed,
        )

        return self._parse_response(indicator, response_data)

    # -- HTTP request with bounded retry for transient errors -----------------

    def _request_with_retry(
        self,
        url: str,
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
                response = self._client.get(url, headers=headers)
                return self._handle_response(response)
            except _RetryableServerError as exc:
                last_exc = exc
                logger.warning(
                    "AlienVault OTX server error (attempt %d/%d): HTTP %d",
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
                    "AlienVault OTX request timed out (attempt %d/%d)",
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
                    "AlienVault OTX transport error (attempt %d/%d): %s",
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
                "not found -- no OTX record for this indicator",
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

        # Defensive: OTX surfaces API errors inside a HTTP 200 body as a
        # top-level ``detail`` string without an ``indicator`` field.
        if isinstance(payload.get("detail"), str) and "indicator" not in payload:
            raise ProviderLookupError(
                self.provider_name,
                "API error",
            )

        return payload

    # -- Result parsing -------------------------------------------------------

    def _parse_response(
        self,
        indicator: ThreatIndicator,
        raw: dict[str, Any],
    ) -> ThreatIntelResult:
        """Convert the raw OTX response dict into a ThreatIntelResult.

        Only a deliberately selected allow-list of fields is exposed and
        every collection is capped -- the raw OTX response is never stored
        or returned.  Parsing is indicator-aware because the exact fields
        differ by endpoint (IP geo fields, domain whois links, etc.).
        """
        parsed: dict[str, Any] = {}

        # Indicator echoed by OTX and the OTX type/language string.
        echoed_indicator = raw.get("indicator")
        if isinstance(echoed_indicator, str) and echoed_indicator:
            parsed["indicator"] = echoed_indicator
        if isinstance(raw.get("type"), str):
            parsed["otx_type"] = raw["type"]

        # Raw reputation integer when present (factual provider data -- it
        # is never turned into a malicious/benign verdict or confidence).
        reputation = raw.get("reputation")
        if isinstance(reputation, int) and not isinstance(reputation, bool):
            parsed["reputation"] = reputation

        validation = raw.get("validation")
        if isinstance(validation, list):
            parsed["validation"] = self._normalise_validation(validation)

        pulse_info = raw.get("pulse_info")
        if isinstance(pulse_info, dict):
            parsed["pulse_info"] = self._normalise_pulse_info(pulse_info)

        # Indicator-specific fields.
        if indicator.indicator_type == IndicatorType.IP:
            self._extract_ip_fields(raw, parsed)
        elif indicator.indicator_type == IndicatorType.DOMAIN:
            self._extract_domain_fields(raw, parsed)

        return ThreatIntelResult(
            indicator=indicator,
            provider=self.provider_name,
            found=self._compute_found(raw),
            data=parsed,
            # OTX provides no SentinelAI-compatible confidence score and we
            # deliberately do not invent one from pulse counts, reputation,
            # or any other OTX signal.  See docs.
            confidence=None,
            metadata={
                "resource_type": "otx-indicator",
                "otx_api_version": "v1",
            },
        )

    @staticmethod
    def _compute_found(raw: dict[str, Any]) -> bool:
        """``found`` = OTX returned associated pulses for the indicator.

        Pulse count is OTX's own intelligence signal: a response with zero
        pulses means no associated OTX intelligence and is reported as
        ``found=False``.  The presence of validation/whitelist metadata
        alone does not count as intelligence.
        """
        pulse_info = raw.get("pulse_info")
        count = 0
        if isinstance(pulse_info, dict):
            raw_count = pulse_info.get("count", 0)
            if isinstance(raw_count, bool):
                raw_count = 0
            if isinstance(raw_count, (int, float)):
                count = int(raw_count)
        return count > 0

    def _normalise_pulse_info(
        self, pulse_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Normalise ``pulse_info`` with a strict allow-list and caps."""
        result: dict[str, Any] = {}

        count = pulse_info.get("count", 0)
        if isinstance(count, bool):
            count = 0
        if isinstance(count, (int, float)):
            result["count"] = int(count)

        references = pulse_info.get("references")
        if isinstance(references, list):
            result["references"] = [
                ref for ref in references
                if isinstance(ref, str)
            ][:_MAX_PULSE_REFERENCES]

        pulses = pulse_info.get("pulses")
        if isinstance(pulses, list):
            result["pulses"] = [
                self._normalise_pulse(pulse)
                for pulse in pulses
                if isinstance(pulse, dict)
            ][:_MAX_PULSES]

        related = pulse_info.get("related")
        if isinstance(related, dict):
            result["related"] = self._normalise_related(related)

        return result

    @staticmethod
    def _normalise_related(related: dict[str, Any]) -> dict[str, Any]:
        """Normalise ``pulse_info.related``, capping each category list."""
        result: dict[str, Any] = {}
        for group_name in ("alienvault", "other"):
            group = related.get(group_name)
            if isinstance(group, dict):
                normalised_group: dict[str, Any] = {}
                for category in ("adversary", "malware_families", "industries"):
                    items = group.get(category)
                    if isinstance(items, list):
                        normalised_group[category] = items[:_MAX_RELATED_ENTRIES]
                result[group_name] = normalised_group
        return result

    @staticmethod
    def _normalise_pulse(pulse: dict[str, Any]) -> dict[str, Any]:
        """Normalise a single pulse entry using a strict allow-list.

        Scalar fields are copied verbatim; list fields are trimmed to a
        bounded length; the author is reduced to its username; anything
        else (including free-form content) is dropped.
        """
        result: dict[str, Any] = {}

        for field in _PULSE_SCALAR_FIELDS:
            value = pulse.get(field)
            if value is not None:
                result[field] = value

        for field in _PULSE_LIST_FIELDS:
            value = pulse.get(field)
            if isinstance(value, list):
                result[field] = value[:_MAX_PULSE_LIST_ENTRIES]

        author = pulse.get("author")
        if isinstance(author, dict) and author.get("username"):
            result["author"] = {"username": author["username"]}

        return result

    @staticmethod
    def _normalise_validation(validation: list[Any]) -> list[Any]:
        """Normalise the ``validation`` array with an allow-list and cap."""
        result: list[Any] = []
        for entry in validation[:_MAX_VALIDATION_ENTRIES]:
            if not isinstance(entry, dict):
                continue
            normalised: dict[str, Any] = {}
            for field in _VALIDATION_FIELDS:
                value = entry.get(field)
                if value is not None:
                    normalised[field] = value
            result.append(normalised)
        return result

    @staticmethod
    def _extract_ip_fields(
        raw: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        """Extract the bounded IP-specific geo fields from an OTX response."""
        for field in ("asn", "city", "country_code", "country_name"):
            value = raw.get(field)
            if value is not None:
                result[field] = value
        for field in ("latitude", "longitude"):
            value = raw.get(field)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                result[field] = value

    @staticmethod
    def _extract_domain_fields(
        raw: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        """Extract the bounded domain-specific fields from an OTX response."""
        for field in ("whois", "alexa"):
            value = raw.get(field)
            if isinstance(value, str) and value:
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