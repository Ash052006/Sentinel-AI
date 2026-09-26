"""Tests for the AbuseIPDB threat-intelligence provider.

Covers provider basics, API-key security, request construction (endpoint,
query parameters, authentication/Accept headers), IP lookups, result
contract, response field mapping, missing/empty data handling, unsupported
indicator types, HTTP error handling, rate limiting, bounded retry
behaviour, timeouts, response safety, no-network safety, and deterministic
parsing.

Every test uses a mocked/injected HTTP client (``httpx.MockTransport``) --
no real network requests are ever made.
"""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from app.core.config import settings
from app.services.threat_intelligence import (
    AbuseIPDBProvider,
    IndicatorType,
    InvalidIndicatorError,
    ProviderLookupError,
    RateLimitError,
    ThreatIndicator,
    ThreatIntelProvider,
    ThreatIntelResult,
    UnsupportedIndicatorTypeError,
)
import app.services.threat_intelligence.abuseipdb as abuseipdb_module

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

SECRET_KEY = "test-abuseipdb-key"

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

IP_VALUE = "118.25.6.39"
DOMAIN_VALUE = "evil-example.com"
HASH_VALUE = (
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)
URL_VALUE = "https://evil-example.com/malware/payload.exe?token=abc"


def _indicator(
    itype: IndicatorType = IndicatorType.IP,
    value: str = IP_VALUE,
) -> ThreatIndicator:
    return ThreatIndicator(indicator_type=itype, value=value)


def _make_client(handler):
    """Build an ``httpx.Client`` with a mock transport (no network)."""
    return httpx.Client(transport=httpx.MockTransport(handler))


def _ok_json(payload: dict):
    """Return a handler producing a 200 JSON response."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload, request=request)
    return handler


IP_RESPONSE = {
    "data": {
        "ipAddress": IP_VALUE,
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 100,
        "countryCode": "CN",
        "countryName": "China",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
        "domain": "tencent.com",
        "hostnames": [IP_VALUE],
        "isTor": False,
        "isCrawler": False,
        "totalReports": 5,
        "numDistinctUsers": 3,
        "lastReportedAt": "2018-09-03T02:08:26+00:00",
        "reports": [
            {
                "reportedAt": "2018-09-03T02:08:26+00:00",
                "comment": "Port scanning detected",
                "categories": [15, 18],
                "reporterId": 1,
                "reporterCountryCode": "US",
                "reporterCountryName": "United States",
                "extraLargeField": "must not leak",
            },
            {
                "reportedAt": "2018-09-03T01:00:00+00:00",
                "comment": "Brute force attack",
                "categories": [18],
                "reporterId": 2,
                "reporterCountryCode": "DE",
                "reporterCountryName": "Germany",
            },
        ],
    }
}

EMPTY_RESPONSE = {
    "data": {
        "ipAddress": IP_VALUE,
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 0,
        "countryCode": "CN",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
        "domain": "tencent.com",
        "hostnames": [IP_VALUE],
        "isTor": False,
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
        "reports": [],
    }
}

# A response that carries additional fields the provider must never blindly
# expose (e.g. secrets or unknown nested structures).
RAW_LEAKY_RESPONSE = {
    "data": {
        "ipAddress": IP_VALUE,
        "abuseConfidenceScore": 75,
        "totalReports": 2,
        "numDistinctUsers": 2,
        "countryCode": "US",
        # Not part of the deliberate field allow-list:
        "countryName": "United States",
        "secretNote": {"internal": "do-not-expose"},
        "fullRawDump": "sensitive server data",
        "reports": [
            {
                "reportedAt": "2018-09-03T02:08:26+00:00",
                "comment": "ok",
                "categories": [15],
                "reporterId": 1,
                "reporterCountryCode": "US",
                "reporterCountryName": "United States",
                "reporterEmail": "reporter@example.com",
            },
        ],
    }
}

# ===========================================================================
# A. Provider basics
# ===========================================================================

class TestProviderBasics:
    def test_provider_name(self):
        assert AbuseIPDBProvider.provider_name == "abuseipdb"

    def test_supported_indicator_types(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({})),
        )
        try:
            types = provider.supported_indicator_types
            assert types == frozenset({IndicatorType.IP})
            assert IndicatorType.IP in types
            assert IndicatorType.DOMAIN not in types
            assert IndicatorType.URL not in types
            assert IndicatorType.HASH not in types
        finally:
            provider.close()

    def test_is_threat_intel_provider(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({})),
        )
        try:
            assert isinstance(provider, ThreatIntelProvider)
        finally:
            provider.close()

    def test_supports_ip_only(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({})),
        )
        try:
            assert provider.supports(IndicatorType.IP)
            assert not provider.supports(IndicatorType.DOMAIN)
            assert not provider.supports(IndicatorType.URL)
            assert not provider.supports(IndicatorType.HASH)
        finally:
            provider.close()

    def test_default_timeout_is_bounded(self):
        provider = AbuseIPDBProvider(api_key=SECRET_KEY)
        try:
            assert 0 < provider._timeout_seconds < float("inf")
        finally:
            provider.close()


# ===========================================================================
# B. API key security
# ===========================================================================

class TestApiKeySecurity:
    def test_api_key_loaded_from_config(self, monkeypatch):
        monkeypatch.setattr(settings, "abuseipdb_api_key", "cfg-abuseipdb-999")
        provider = AbuseIPDBProvider(
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            assert provider._api_key == "cfg-abuseipdb-999"
            result = provider.lookup(_indicator())
            assert result.provider == "abuseipdb"
        finally:
            provider.close()

    def test_explicit_api_key_takes_precedence(self, monkeypatch):
        monkeypatch.setattr(settings, "abuseipdb_api_key", "cfg-abuseipdb-999")
        provider = AbuseIPDBProvider(
            api_key="explicit-abuseipdb-123",
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            assert provider._api_key == "explicit-abuseipdb-123"
        finally:
            provider.close()

    def test_missing_api_key_fails_safely(self, monkeypatch):
        monkeypatch.setattr(settings, "abuseipdb_api_key", "")
        with pytest.raises(ValueError) as excinfo:
            AbuseIPDBProvider()
        msg = str(excinfo.value)
        assert "API key is required" in msg

    def test_api_key_never_in_exception_from_missing_config(
        self, monkeypatch,
    ):
        monkeypatch.setattr(settings, "abuseipdb_api_key", "")
        with pytest.raises(ValueError) as excinfo:
            AbuseIPDBProvider()
        assert SECRET_KEY not in str(excinfo.value)

    def test_api_key_is_sent_via_key_header(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["key"] = request.headers.get("Key")
            captured["accept"] = request.headers.get("Accept")
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator())
            assert captured["key"] == SECRET_KEY
            assert captured["url"].split("?")[0] == CHECK_URL
        finally:
            provider.close()

    def test_api_key_never_in_logs(self, caplog):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            with caplog.at_level(logging.INFO):
                provider.lookup(_indicator())
            assert SECRET_KEY not in caplog.text
        finally:
            provider.close()

    def test_api_key_never_in_result(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            dumped = json.dumps(result.model_dump(mode="json"))
            assert SECRET_KEY not in dumped
        finally:
            provider.close()

    def test_api_key_not_captured_logged_on_error(self, caplog):
        """A failing lookup must not leak the key into logs or exceptions."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={}, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with caplog.at_level(logging.WARNING):
                with pytest.raises(ProviderLookupError) as excinfo:
                    provider.lookup(_indicator())
            assert SECRET_KEY not in str(excinfo.value)
            assert SECRET_KEY not in caplog.text
        finally:
            provider.close()

# ===========================================================================
# C. Request construction
# ===========================================================================

class TestRequestConstruction:
    def test_correct_endpoint(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator())
            assert captured["url"].split("?")[0] == CHECK_URL
        finally:
            provider.close()

    def test_correct_query_parameters(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["params"] = dict(request.url.params)
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator(IndicatorType.IP, IP_VALUE))
            assert captured["params"] == {
                "ipAddress": IP_VALUE,
                "maxAgeInDays": "90",
            }
        finally:
            provider.close()

    def test_correct_authentication_header(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["key"] = request.headers.get("Key")
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator())
            assert captured["key"] == SECRET_KEY
        finally:
            provider.close()

    def test_correct_accept_header(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["accept"] = request.headers.get("Accept")
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator())
            assert captured["accept"] == "application/json"
        finally:
            provider.close()


# ===========================================================================
# D. Successful IP lookup
# ===========================================================================

class TestIpLookup:
    def test_successful_ip_lookup(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert isinstance(result, ThreatIntelResult)
            assert result.found is True
            assert result.provider == "abuseipdb"
        finally:
            provider.close()

    def test_result_provider_name(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.provider == "abuseipdb"
        finally:
            provider.close()

    def test_result_found_true(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
        finally:
            provider.close()

    def test_indicator_preserved(self):
        indicator = _indicator(IndicatorType.IP, IP_VALUE)
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(indicator)
            assert result.indicator == indicator
            assert result.indicator.indicator_type == IndicatorType.IP
            assert result.indicator.value == IP_VALUE
        finally:
            provider.close()

    def test_result_is_threat_intel_result(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert isinstance(result, ThreatIntelResult)
        finally:
            provider.close()

    def test_ipv6_lookup(self):
        """IPv6 addresses are supported by the AbuseIPDB check endpoint."""
        ipv6 = "2001:4860:4860::8888"

        def handler(request: httpx.Request) -> httpx.Response:
            assert dict(request.url.params)["ipAddress"] == ipv6
            return httpx.Response(
                200,
                json={
                    "data": {
                        "ipAddress": ipv6,
                        "ipVersion": 6,
                        "totalReports": 1,
                        "numDistinctUsers": 1,
                        "reports": [],
                        "isPublic": True,
                    },
                },
                request=request,
            )

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.IP, ipv6))
            assert result.found is True
            assert result.data["ipAddress"] == ipv6
            assert result.data["ipVersion"] == 6
        finally:
            provider.close()

# ===========================================================================
# E. Response field mapping
# ===========================================================================

class TestResponseMapping:
    def test_response_field_mapping(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            data = result.data

            assert data["ipAddress"] == IP_VALUE
            assert data["abuseConfidenceScore"] == 100
            assert data["countryCode"] == "CN"
            assert data["usageType"] == "Data Center/Web Hosting/Transit"
            assert data["isp"] == "Tencent Cloud Computing (Beijing) Co. Ltd"
            assert data["domain"] == "tencent.com"
            assert data["hostnames"] == [IP_VALUE]
            assert data["totalReports"] == 5
            assert data["numDistinctUsers"] == 3
            assert data["lastReportedAt"] == "2018-09-03T02:08:26+00:00"
            assert data["isWhitelisted"] is False
            assert data["isPublic"] is True
            assert data["ipVersion"] == 4
            assert data["isTor"] is False
            assert data["isCrawler"] is False
        finally:
            provider.close()

    def test_reports_array_mapped(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            reports = result.data["reports"]
            assert isinstance(reports, list)
            assert len(reports) == 2
            assert reports[0]["reportedAt"] == "2018-09-03T02:08:26+00:00"
            assert reports[0]["comment"] == "Port scanning detected"
            assert reports[0]["categories"] == [15, 18]
            assert reports[0]["reporterId"] == 1
            assert reports[0]["reporterCountryCode"] == "US"
            assert reports[0]["reporterCountryName"] == "United States"
        finally:
            provider.close()

    def test_unselected_report_item_fields_are_dropped(self):
        """Raw report-item fields outside the allow-list never leak out."""
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            reports = result.data["reports"]
            assert "extraLargeField" not in reports[0]
        finally:
            provider.close()

    def test_missing_optional_fields_are_omitted(self):
        minimal = {
            "data": {
                "ipAddress": IP_VALUE,
                "totalReports": 3,
                "numDistinctUsers": 1,
                "reports": [],
            },
        }
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(minimal)),
        )
        try:
            result = provider.lookup(_indicator())
            data = result.data
            assert data["ipAddress"] == IP_VALUE
            assert data["totalReports"] == 3
            # Absent optional fields must not be fabricated:
            assert "abuseConfidenceScore" not in data
            assert "countryCode" not in data
            assert "usageType" not in data
            assert "isp" not in data
            assert "domain" not in data
            assert "hostnames" not in data
            assert "isTor" not in data
            assert "lastReportedAt" not in data
            assert "isWhitelisted" not in data
        finally:
            provider.close()

    def test_empty_reports_found_false(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(EMPTY_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            # An IP with zero reports is a successful response, not a crash.
            assert result.found is False
            assert result.data["totalReports"] == 0
            assert result.data["reports"] == []
            assert result.indicator.value == IP_VALUE
        finally:
            provider.close()

    def test_absolutely_minimal_data_found_false(self):
        """``data`` without numeric totalReports is treated as not found."""
        minimal = {"data": {"ipAddress": IP_VALUE}}
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(minimal)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is False
            assert result.data["ipAddress"] == IP_VALUE
        finally:
            provider.close()

    def test_raw_response_is_not_blindly_returned(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(RAW_LEAKY_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            data = result.data
            # Deliberately selected fields survive:
            assert data["abuseConfidenceScore"] == 75
            assert data["totalReports"] == 2
            # Anything outside the allow-list is dropped:
            assert "countryName" not in data
            assert "secretNote" not in data
            assert "fullRawDump" not in data
            assert "reporterEmail" not in data["reports"][0]
        finally:
            provider.close()

    def test_reports_trimmed_to_bounded_cap(self):
        many_reports = [
            {
                "reportedAt": f"2018-09-0{i}T00:00:00+00:00",
                "comment": f"report {i}",
                "categories": [15],
                "reporterId": i,
                "reporterCountryCode": "US",
                "reporterCountryName": "United States",
            }
            for i in range(1, 30)
        ]
        payload = {
            "data": {
                "ipAddress": IP_VALUE,
                "totalReports": 29,
                "numDistinctUsers": 5,
                "reports": many_reports,
            },
        }
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(payload)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
            assert len(result.data["reports"]) == 10
        finally:
            provider.close()

# ===========================================================================
# F. Unsupported types & input validation
# ===========================================================================

class TestUnsupportedTypes:
    def test_unsupported_domain(self):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(UnsupportedIndicatorTypeError):
                provider.lookup(_indicator(IndicatorType.DOMAIN, DOMAIN_VALUE))
            assert calls["count"] == 0  # guard raised before any HTTP call
        finally:
            provider.close()

    def test_unsupported_url(self):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(UnsupportedIndicatorTypeError):
                provider.lookup(_indicator(IndicatorType.URL, URL_VALUE))
            assert calls["count"] == 0
        finally:
            provider.close()

    def test_unsupported_hash(self):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(UnsupportedIndicatorTypeError):
                provider.lookup(_indicator(IndicatorType.HASH, HASH_VALUE))
            assert calls["count"] == 0
        finally:
            provider.close()

    def test_unsupported_type_error_details(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            with pytest.raises(UnsupportedIndicatorTypeError) as excinfo:
                provider.lookup(
                    _indicator(IndicatorType.DOMAIN, DOMAIN_VALUE),
                )
            assert "abuseipdb" in str(excinfo.value)
            assert "domain" in str(excinfo.value)
        finally:
            provider.close()

    def test_empty_value_rejected(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            with pytest.raises((InvalidIndicatorError, ValueError)):
                provider.lookup(
                    ThreatIndicator(
                        indicator_type=IndicatorType.IP, value="",
                    ),
                )
        finally:
            provider.close()

    def test_blank_value_rejected(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            with pytest.raises((InvalidIndicatorError, ValueError)):
                provider.lookup(
                    ThreatIndicator(
                        indicator_type=IndicatorType.IP, value="   ",
                    ),
                )
        finally:
            provider.close()

    def test_no_http_call_for_empty_value(self):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises((InvalidIndicatorError, ValueError)):
                provider.lookup(
                    ThreatIndicator(
                        indicator_type=IndicatorType.IP, value="",
                    ),
                )
            assert calls["count"] == 0
        finally:
            provider.close()

# ===========================================================================
# G. HTTP error handling
# ===========================================================================

class TestHttpErrors:
    def test_bad_request(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(400, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "Provider 'abuseipdb' lookup failed" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_unauthorized(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(401, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "unauthorized" in str(excinfo.value)
            assert "check API key" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_forbidden(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(403, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "forbidden" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_429_rate_limit(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(429, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(RateLimitError) as excinfo:
                provider.lookup(_indicator())
            assert "Rate limit exceeded" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_429_rate_limit_with_retry_after(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(
                    429,
                    headers={"Retry-After": "15"},
                    json={},
                    request=req,
                ),
            ),
        )
        try:
            with pytest.raises(RateLimitError) as excinfo:
                provider.lookup(_indicator())
            exc = excinfo.value
            assert exc.retry_after == 15.0
            assert "retry after 15" in str(exc)
        finally:
            provider.close()

    @pytest.mark.parametrize("status", [500, 502, 503])
    def test_server_errors(self, status, monkeypatch):
        # Avoid slowing the test with retry backoff sleeps.
        monkeypatch.setattr(abuseipdb_module, "_MAX_RETRIES", 0)
        monkeypatch.setattr(abuseipdb_module, "_RETRY_BASE_DELAY", 0.0)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(status, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert str(status) in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_malformed_json_body(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=b"not-json{{", request=request,
            )

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "malformed JSON" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_unexpected_status_code(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(418, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "unexpected HTTP status 418" in str(excinfo.value)
        finally:
            provider.close()

    def test_429_is_not_retried(self, monkeypatch):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(429, json={}, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(RateLimitError):
                provider.lookup(_indicator())
            assert calls["count"] == 1
        finally:
            provider.close()

    def test_api_error_object_in_200_response(self):
        """Defensive handling of an ``errors`` block in an HTTP 200 body."""
        error_payload = {
            "errors": [
                {
                    "detail": (
                        "The IP address 'bad' is not a valid "
                        "IPv4/IPv6 address."
                    ),
                    "status": 404,
                },
            ],
        }
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(error_payload)),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "API error" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

# ===========================================================================
# H. Retry & timeout behaviour
# ===========================================================================

class TestRetryBehaviour:
    def test_transient_errors_are_retried_then_fail(self, monkeypatch):
        monkeypatch.setattr(abuseipdb_module, "_MAX_RETRIES", 1)
        monkeypatch.setattr(abuseipdb_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(500, json={}, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(_indicator())
            # 1 initial attempt + 1 retry = 2 calls max.
            assert calls["count"] == 2
        finally:
            provider.close()

    def test_bounded_retry_count(self, monkeypatch):
        """Persistent 5xx errors are retried a bounded number of times only."""
        monkeypatch.setattr(abuseipdb_module, "_MAX_RETRIES", 2)
        monkeypatch.setattr(abuseipdb_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(503, json={}, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(_indicator())
            # _MAX_RETRIES=2 -> at most 3 attempts, never more.
            assert calls["count"] == 3
        finally:
            provider.close()

    def test_transient_error_recovers_on_retry(self, monkeypatch):
        monkeypatch.setattr(abuseipdb_module, "_MAX_RETRIES", 2)
        monkeypatch.setattr(abuseipdb_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            if calls["count"] == 1:
                return httpx.Response(503, json={}, request=request)
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
            assert calls["count"] == 2
        finally:
            provider.close()

    def test_client_errors_are_not_retried(self, monkeypatch):
        """4xx responses must never be retried."""
        monkeypatch.setattr(abuseipdb_module, "_MAX_RETRIES", 5)
        monkeypatch.setattr(abuseipdb_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(400, json={}, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(_indicator())
            assert calls["count"] == 1
        finally:
            provider.close()

    def test_timeout_raises_provider_error(self, monkeypatch):
        monkeypatch.setattr(abuseipdb_module, "_MAX_RETRIES", 0)
        monkeypatch.setattr(abuseipdb_module, "_RETRY_BASE_DELAY", 0.0)

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out", request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "timed out" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_connect_error_raises_provider_error(self, monkeypatch):
        monkeypatch.setattr(abuseipdb_module, "_MAX_RETRIES", 0)
        monkeypatch.setattr(abuseipdb_module, "_RETRY_BASE_DELAY", 0.0)

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "transport error" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_transport_error_recovers_on_retry(self, monkeypatch):
        monkeypatch.setattr(abuseipdb_module, "_MAX_RETRIES", 1)
        monkeypatch.setattr(abuseipdb_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            if calls["count"] == 1:
                raise httpx.ConnectError("refused", request=request)
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
            assert calls["count"] == 2
        finally:
            provider.close()

# ===========================================================================
# I. Timeout & client configuration
# ===========================================================================

class TestTimeoutAndClient:
    def test_timeout_configuration_override(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            timeout_seconds=7.5,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            assert provider._timeout_seconds == 7.5
        finally:
            provider.close()

    def test_timeout_from_settings(self, monkeypatch):
        monkeypatch.setattr(settings, "abuseipdb_timeout_seconds", 12.0)
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            assert provider._timeout_seconds == 12.0
        finally:
            provider.close()

    def test_default_timeout_from_config_constant(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            assert provider._timeout_seconds == settings.abuseipdb_timeout_seconds
            assert provider._timeout_seconds == 30.0
        finally:
            provider.close()

    def test_injected_httpx_client_used(self):
        """The injected client (and its transport) must be the one used."""

        transport = httpx.MockTransport(_ok_json(IP_RESPONSE))
        injected = httpx.Client(transport=transport)
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=injected,
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
            assert provider._client is injected
            # Provider must not close a client it does not own.
            assert provider._owns_client is False
        finally:
            provider.close()
            injected.close()

    def test_provider_owns_internal_client_when_none_injected(self):
        provider = AbuseIPDBProvider(api_key=SECRET_KEY)
        try:
            assert provider._owns_client is True
            assert provider._client is not None
        finally:
            provider.close()

    def test_close_does_not_fail_when_injected_client(self):
        injected = httpx.Client(transport=httpx.MockTransport(_ok_json({})))
        provider = AbuseIPDBProvider(api_key=SECRET_KEY, http_client=injected)
        provider.close()  # must not close the injected client
        injected.close()
        assert True

# ===========================================================================
# J. Result contract
# ===========================================================================

class TestResultContract:
    def test_data_json_compatible(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            dumped = json.dumps(result.model_dump(mode="json"))
            assert "abuseConfidenceScore" in dumped
        finally:
            provider.close()

    def test_confidence_is_none(self):
        """abuseConfidenceScore is NOT mapped onto a confidence value."""
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.data["abuseConfidenceScore"] == 100
            assert result.confidence is None
        finally:
            provider.close()

    def test_timestamp_timezone_aware(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.timestamp.tzinfo is not None
        finally:
            provider.close()

    def test_metadata_contains_no_secret(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            dumped = json.dumps(result.metadata) if result.metadata else ""
            assert SECRET_KEY not in dumped
            assert SECRET_KEY not in json.dumps(result.data)
        finally:
            provider.close()

    def test_metadata_is_marked_abuseipdb_ip(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.metadata == {"resource_type": "abuseipdb-ip"}
        finally:
            provider.close()


# ===========================================================================
# K. No-network safety & deterministic parsing
# ===========================================================================

class TestNoNetworkSafety:
    def test_lookup_uses_injected_client_only(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
        finally:
            provider.close()

    def test_provider_never_invokes_real_http(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("network access attempted")

        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            # The injected MockTransport handler is invoked (no real
            # network).  Its AssertionError proves a mock was used.
            with pytest.raises(AssertionError, match="network access attempted"):
                provider.lookup(_indicator())
        finally:
            provider.close()


class TestDeterministicParsing:
    def test_same_mock_response_yields_equivalent_result(self):
        provider = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            first = provider.lookup(_indicator())
            second = provider.lookup(_indicator())
            # Deterministic: identical responses produce identical outcomes.
            assert first.found == second.found
            assert first.data == second.data
            assert first.confidence == second.confidence
            assert first.provider == second.provider
        finally:
            provider.close()

    def test_field_order_does_not_matter(self):
        payload = IP_RESPONSE["data"]
        reversed_payload = {
            "data": {
                "reports": payload["reports"],
                "lastReportedAt": payload["lastReportedAt"],
                "numDistinctUsers": payload["numDistinctUsers"],
                "totalReports": payload["totalReports"],
                "isCrawler": payload["isCrawler"],
                "isTor": payload["isTor"],
                "hostnames": payload["hostnames"],
                "domain": payload["domain"],
                "isp": payload["isp"],
                "usageType": payload["usageType"],
                "countryName": payload["countryName"],
                "countryCode": payload["countryCode"],
                "abuseConfidenceScore": payload["abuseConfidenceScore"],
                "isWhitelisted": payload["isWhitelisted"],
                "ipVersion": payload["ipVersion"],
                "isPublic": payload["isPublic"],
                "ipAddress": payload["ipAddress"],
            }
        }

        provider_a = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        provider_b = AbuseIPDBProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(reversed_payload)),
        )
        try:
            result_a = provider_a.lookup(_indicator())
            result_b = provider_b.lookup(_indicator())
            assert result_a.data == result_b.data
            assert result_a.found == result_b.found
        finally:
            provider_a.close()
            provider_b.close()
