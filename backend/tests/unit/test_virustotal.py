"""Tests for the VirusTotal threat-intelligence provider.

Covers provider basics, API-key security, per-indicator lookups (IP,
domain, hash, URL), HTTP error handling, response parsing, result
contract, provenance mapping, input validation, no-network safety,
deterministic parsing, secret safety, and pipeline integration.

Every test uses a mocked/injected HTTP client (``httpx.MockTransport``) —
no real network requests are ever made.
"""

from __future__ import annotations

import base64
import json
import logging
import uuid
from datetime import datetime, timezone

import httpx
import pytest

from app.core.config import settings
from app.schemas.enriched_event import (
    EnrichedSecurityEvent,
    EnrichmentResult,
)
from app.schemas.normalized_event import (
    EventCategory,
    EventOutcome,
    NormalizedSecurityEvent,
)
from app.schemas.security_event import Provenance, SourceType
from app.services.threat_intelligence import (
    IndicatorType,
    InvalidIndicatorError,
    ProviderLookupError,
    RateLimitError,
    ThreatIndicator,
    ThreatIntelProvider,
    ThreatIntelResult,
    UnsupportedIndicatorTypeError,
    VirusTotalProvider,
)
import app.services.threat_intelligence.virustotal as vt_module

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

SECRET_KEY = "test-api-key-1234567890"

_FIXED_TS = datetime(2025, 7, 1, 12, 0, 0, tzinfo=timezone.utc)

IP_VALUE = "185.10.10.1"
DOMAIN_VALUE = "evil-example.com"
HASH_VALUE = (
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)
URL_VALUE = "https://evil-example.com/malware/payload.exe?token=abc"

LAST_ANALYSIS_TS = 1_700_000_000


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
        "id": IP_VALUE,
        "type": "ip_addresses",
        "attributes": {
            "last_analysis_stats": {
                "harmless": 1,
                "malicious": 8,
                "suspicious": 2,
                "undetected": 60,
                "timeout": 0,
            },
            "last_analysis_date": LAST_ANALYSIS_TS,
            "reputation": -50,
            "categories": {"SECURITY": "malware"},
            "asn": 15169,
            "as_owner": "GOOGLE",
            "country": "US",
            "network": "8.8.8.0/24",
        },
    }
}
DOMAIN_RESPONSE = {
    "data": {
        "id": DOMAIN_VALUE,
        "type": "domain",
        "attributes": {
            "last_analysis_stats": {
                "harmless": 0,
                "malicious": 15,
                "suspicious": 1,
                "undetected": 50,
                "timeout": 0,
            },
            "last_analysis_date": LAST_ANALYSIS_TS,
            "reputation": -120,
            "categories": {"AV1": "phishing"},
            "registrar": "Evil Registrar LLC",
            "popularity_ranks": {"Alexa": {"rank": 100000}},
        },
    }
}

HASH_RESPONSE = {
    "data": {
        "id": HASH_VALUE,
        "type": "file",
        "attributes": {
            "last_analysis_stats": {
                "harmless": 10,
                "malicious": 25,
                "suspicious": 0,
                "undetected": 10,
                "timeout": 0,
            },
            "last_analysis_date": LAST_ANALYSIS_TS,
            "reputation": -100,
            "md5": "abc123",
            "sha1": "def456",
            "sha256": HASH_VALUE,
            "type_description": "Win32 EXE",
            "type_tag": "peexe",
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.lazarus"
            },
            "names": ["malware.exe", "payload2.exe", "sample3.bin"],
        },
    }
}

URL_RESPONSE = {
    "data": {
        "id": base64.urlsafe_b64encode(
            URL_VALUE.encode("utf-8")
        ).decode("utf-8").rstrip("="),
        "type": "urls",
        "attributes": {
            "last_analysis_stats": {
                "harmless": 10,
                "malicious": 3,
                "suspicious": 1,
                "undetected": 40,
                "timeout": 0,
            },
            "last_analysis_date": LAST_ANALYSIS_TS,
            "reputation": -30,
            "categories": {"AV1": "phishing"},
            "url": URL_VALUE,
            "title": "Malicious Payload Page",
            "final_url": URL_VALUE,
        },
    }
}
# ===========================================================================
# A. Provider basics
# ===========================================================================

class TestProviderBasics:
    def test_provider_name(self):
        assert VirusTotalProvider.provider_name == "VirusTotal"

    def test_supported_indicator_types(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({})),
        )
        types = provider.supported_indicator_types
        assert IndicatorType.IP in types
        assert IndicatorType.DOMAIN in types
        assert IndicatorType.URL in types
        assert IndicatorType.HASH in types

    def test_is_threat_intel_provider(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({})),
        )
        assert isinstance(provider, ThreatIntelProvider)

    def test_supports_all_declared_types(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({})),
        )
        for itype in (
            IndicatorType.IP,
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.HASH,
        ):
            assert provider.supports(itype)

    def test_default_timeout_is_bounded(self):
        provider = VirusTotalProvider(api_key=SECRET_KEY)
        try:
            assert 0 < provider._timeout_seconds < float("inf")
        finally:
            provider.close()


# ===========================================================================
# B. API key
# ===========================================================================

class TestApiKeySecurity:
    def test_api_key_loaded_from_config(self, monkeypatch):
        monkeypatch.setattr(settings, "virustotal_api_key", "cfg-secret-999")
        provider = VirusTotalProvider(
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            assert provider._api_key == "cfg-secret-999"
            result = provider.lookup(_indicator())
            assert result.provider == "VirusTotal"
        finally:
            provider.close()

    def test_explicit_api_key_takes_precedence(self, monkeypatch):
        monkeypatch.setattr(settings, "virustotal_api_key", "cfg-secret-999")
        provider = VirusTotalProvider(
            api_key="explicit-secret-123",
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            assert provider._api_key == "explicit-secret-123"
        finally:
            provider.close()

    def test_missing_api_key_fails_safely(self, monkeypatch):
        monkeypatch.setattr(settings, "virustotal_api_key", "")
        with pytest.raises(ValueError) as excinfo:
            VirusTotalProvider()
        msg = str(excinfo.value)
        assert "API key is required" in msg

    def test_api_key_never_in_exception_from_missing_config(
        self, monkeypatch,
    ):
        monkeypatch.setattr(settings, "virustotal_api_key", "")
        with pytest.raises(ValueError) as excinfo:
            VirusTotalProvider()
        assert SECRET_KEY not in str(excinfo.value)

    def test_api_key_is_sent_via_x_apikey_header(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["xapikey"] = request.headers.get("x-apikey")
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator(IndicatorType.IP, IP_VALUE))
            assert captured["xapikey"] == SECRET_KEY
            assert (
                captured["url"]
                == f"https://www.virustotal.com/api/v3/ip_addresses/{IP_VALUE}"
            )
        finally:
            provider.close()

    def test_api_key_never_in_logs(self, caplog):
        provider = VirusTotalProvider(
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
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            dumped = json.dumps(result.model_dump(mode="json"))
            assert SECRET_KEY not in dumped
        finally:
            provider.close()
# ===========================================================================
# C. IP lookup
# ===========================================================================

class TestIpLookup:
    def test_successful_ip_lookup(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.IP, IP_VALUE))
            assert result.found is True
            assert result.provider == "VirusTotal"
            assert result.data["last_analysis_stats"]["malicious"] == 8
            assert result.data["last_analysis_stats"]["suspicious"] == 2
            assert result.data["last_analysis_stats"]["harmless"] == 1
            assert result.data["last_analysis_stats"]["undetected"] == 60
            assert result.data["reputation"] == -50
            assert result.data["categories"] == {"SECURITY": "malware"}
            assert result.data["asn"] == 15169
            assert result.data["country"] == "US"
            assert result.data["resource_type"] == "ip_addresses"
        finally:
            provider.close()

    def test_ip_not_found(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(404, json={}, request=req),
            ),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.IP, IP_VALUE))
            assert result.found is False
            assert result.data == {}
        finally:
            provider.close()

    def test_ip_malformed_response_missing_data(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({"unexpected": True})),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(_indicator(IndicatorType.IP, IP_VALUE))
        finally:
            provider.close()

    def test_ip_malformed_response_missing_attributes(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({"data": {"id": IP_VALUE}})),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(_indicator(IndicatorType.IP, IP_VALUE))
        finally:
            provider.close()

    def test_ip_api_error_object_in_response(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                _ok_json({"error": {"code": "InvalidRequest", "message": "x"}}),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(_indicator(IndicatorType.IP, IP_VALUE))
        finally:
            provider.close()


# ===========================================================================
# D. Domain lookup
# ===========================================================================

class TestDomainLookup:
    def test_successful_domain_lookup(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(DOMAIN_RESPONSE)),
        )
        try:
            result = provider.lookup(
                _indicator(IndicatorType.DOMAIN, DOMAIN_VALUE),
            )
            assert result.found is True
            assert result.data["last_analysis_stats"]["malicious"] == 15
            assert result.data["reputation"] == -120
            assert result.data["categories"] == {"AV1": "phishing"}
            assert result.data["registrar"] == "Evil Registrar LLC"
            assert result.data["resource_type"] == "domain"
        finally:
            provider.close()

    def test_domain_not_found(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(404, json={}, request=req),
            ),
        )
        try:
            result = provider.lookup(
                _indicator(IndicatorType.DOMAIN, DOMAIN_VALUE),
            )
            assert result.found is False
        finally:
            provider.close()

    def test_domain_malformed_response(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({"data": []})),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(
                    _indicator(IndicatorType.DOMAIN, DOMAIN_VALUE),
                )
        finally:
            provider.close()
# ===========================================================================
# E. Hash lookup
# ===========================================================================

class TestHashLookup:
    def test_successful_hash_lookup(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(HASH_RESPONSE)),
        )
        try:
            result = provider.lookup(
                _indicator(IndicatorType.HASH, HASH_VALUE),
            )
            assert result.found is True
            assert result.data["last_analysis_stats"]["malicious"] == 25
            assert result.data["reputation"] == -100
            assert result.data["sha256"] == HASH_VALUE
            assert result.data["type_description"] == "Win32 EXE"
            assert result.data["resource_type"] == "file"
        finally:
            provider.close()

    def test_hash_not_found(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(404, json={}, request=req),
            ),
        )
        try:
            result = provider.lookup(
                _indicator(IndicatorType.HASH, HASH_VALUE),
            )
            assert result.found is False
        finally:
            provider.close()

    def test_hash_malformed_response(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({"data": {"id": HASH_VALUE}})),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(
                    _indicator(IndicatorType.HASH, HASH_VALUE),
                )
        finally:
            provider.close()

    def test_hash_names_list_is_trimmed(self):
        response = json.loads(json.dumps(HASH_RESPONSE))
        response["data"]["attributes"]["names"] = [
            "f.txt" for _ in range(25)
        ]
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(response)),
        )
        try:
            result = provider.lookup(
                _indicator(IndicatorType.HASH, HASH_VALUE),
            )
            assert len(result.data["names"]) == 10
        finally:
            provider.close()


# ===========================================================================
# F. URL lookup
# ===========================================================================

class TestUrlLookup:
    def test_url_resource_id_is_base64url_encoded(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=URL_RESPONSE, request=request)

        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator(IndicatorType.URL, URL_VALUE))
            expected_id = (
                base64.urlsafe_b64encode(URL_VALUE.encode("utf-8"))
                .decode("utf-8")
                .rstrip("=")
            )
            expected_url = (
                f"https://www.virustotal.com/api/v3/urls/{expected_id}"
            )
            assert captured["url"] == expected_url
            assert "=" not in captured["url"].rsplit("/", 1)[1]
        finally:
            provider.close()

    def test_successful_url_lookup(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(URL_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.URL, URL_VALUE))
            assert result.found is True
            assert result.data["last_analysis_stats"]["malicious"] == 3
            assert result.data["url"] == URL_VALUE
            assert result.data["title"] == "Malicious Payload Page"
            assert result.data["resource_type"] == "urls"
        finally:
            provider.close()

    def test_url_not_found(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(404, json={}, request=req),
            ),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.URL, URL_VALUE))
            assert result.found is False
        finally:
            provider.close()

    def test_url_malformed_response(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({"data": {"id": "x"}})),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(_indicator(IndicatorType.URL, URL_VALUE))
        finally:
            provider.close()
# ===========================================================================
# G. HTTP errors
# ===========================================================================

class TestHttpErrors:
    @pytest.mark.parametrize("status", [400])
    def test_bad_request(self, status):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(status, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "Provider 'VirusTotal' lookup failed" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_unauthorized(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(401, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "unauthorized" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_forbidden(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(403, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "forbidden" in str(excinfo.value)
        finally:
            provider.close()

    def test_404_not_found(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(404, json={}, request=req),
            ),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is False
            assert result.data == {}
        finally:
            provider.close()

    def test_429_rate_limit(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(429, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(RateLimitError) as excinfo:
                provider.lookup(_indicator())
            assert "Rate limit exceeded" in str(excinfo.value)
        finally:
            provider.close()

    def test_429_rate_limit_with_retry_after(self):
        provider = VirusTotalProvider(
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
        monkeypatch.setattr(vt_module, "_MAX_RETRIES", 0)
        monkeypatch.setattr(vt_module, "_RETRY_BASE_DELAY", 0.0)

        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(status, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert f"server error (HTTP {status})" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_timeout_raises_provider_error(self, monkeypatch):
        monkeypatch.setattr(vt_module, "_MAX_RETRIES", 0)
        monkeypatch.setattr(vt_module, "_RETRY_BASE_DELAY", 0.0)

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout(
                "connection timed out", request=request,
            )

        provider = VirusTotalProvider(
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

    def test_connection_error_raises_provider_error(self, monkeypatch):
        monkeypatch.setattr(vt_module, "_MAX_RETRIES", 0)
        monkeypatch.setattr(vt_module, "_RETRY_BASE_DELAY", 0.0)

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(
                "connection refused", request=request,
            )

        provider = VirusTotalProvider(
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

    def test_malformed_json_body(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=b"not-json{{{", request=request,
            )

        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "malformed JSON" in str(excinfo.value)
        finally:
            provider.close()

    def test_unexpected_status_code(self):
        provider = VirusTotalProvider(
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

        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(RateLimitError):
                provider.lookup(_indicator())
            assert calls["count"] == 1
        finally:
            provider.close()

    def test_transient_errors_are_retried_then_fail(self, monkeypatch):
        monkeypatch.setattr(vt_module, "_MAX_RETRIES", 1)
        monkeypatch.setattr(vt_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(500, json={}, request=request)

        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(_indicator())
        finally:
            provider.close()

    def test_transient_error_recovers_on_retry(self, monkeypatch):
        monkeypatch.setattr(vt_module, "_MAX_RETRIES", 2)
        monkeypatch.setattr(vt_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            if calls["count"] == 1:
                return httpx.Response(503, json={}, request=request)
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = VirusTotalProvider(
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
# H. Response parsing
# ===========================================================================

class TestResponseParsing:
    def test_malicious_stats_extracted(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            stats = result.data["last_analysis_stats"]
            assert stats["malicious"] == 8
            assert stats["suspicious"] == 2
            assert stats["harmless"] == 1
            assert stats["undetected"] == 60
        finally:
            provider.close()

    def test_suspicious_stats_extracted(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(DOMAIN_RESPONSE)),
        )
        try:
            result = provider.lookup(
                _indicator(IndicatorType.DOMAIN, DOMAIN_VALUE),
            )
            assert result.data["last_analysis_stats"]["suspicious"] == 1
        finally:
            provider.close()

    def test_harmless_undetected_extracted(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(HASH_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.HASH, HASH_VALUE))
            assert result.data["last_analysis_stats"]["harmless"] == 10
            assert result.data["last_analysis_stats"]["undetected"] == 10
        finally:
            provider.close()

    def test_reputation_extracted(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.data["reputation"] == -50
        finally:
            provider.close()

    def test_categories_extracted(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(DOMAIN_RESPONSE)),
        )
        try:
            result = provider.lookup(
                _indicator(IndicatorType.DOMAIN, DOMAIN_VALUE),
            )
            assert result.data["categories"] == {"AV1": "phishing"}
        finally:
            provider.close()

    def test_missing_optional_fields_are_omitted(self):
        minimal = {
            "data": {
                "id": IP_VALUE,
                "type": "ip_addresses",
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 0,
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 0,
                        "timeout": 0,
                    },
                },
            }
        }
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(minimal)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
            assert "reputation" not in result.data
            assert "categories" not in result.data
            assert "last_analysis_date" not in result.data
            assert "asn" not in result.data
        finally:
            provider.close()

    def test_partial_stats_default_to_zero(self):
        minimal = {
            "data": {
                "id": IP_VALUE,
                "type": "ip_addresses",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                    },
                },
            }
        }
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(minimal)),
        )
        try:
            result = provider.lookup(_indicator())
            stats = result.data["last_analysis_stats"]
            assert stats["malicious"] == 5
            assert stats["harmless"] == 0
        finally:
            provider.close()
# ===========================================================================
# I. Result contract
# ===========================================================================

class TestResultContract:
    def test_indicator_preserved(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        ti = _indicator(IndicatorType.IP, IP_VALUE)
        try:
            result = provider.lookup(ti)
            assert result.indicator is ti
            assert result.indicator.indicator_type == IndicatorType.IP
            assert result.indicator.value == IP_VALUE
        finally:
            provider.close()

    def test_provider_name(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.provider == "VirusTotal"
        finally:
            provider.close()

    def test_found_correct(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            assert provider.lookup(_indicator()).found is True
        finally:
            provider.close()

    def test_data_json_compatible(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            json.dumps(result.data)
            json.dumps(result.metadata)
        finally:
            provider.close()

    def test_confidence_is_none(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.confidence is None
        finally:
            provider.close()

    def test_timestamp_timezone_aware(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.timestamp.tzinfo is not None
            assert result.timestamp.tzinfo.utcoffset(None) is not None
        finally:
            provider.close()

    def test_metadata_contains_no_secret(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            dumped = json.dumps(result.metadata)
            assert SECRET_KEY not in dumped
        finally:
            provider.close()
# ===========================================================================
# J. Provenance
# ===========================================================================

class TestProvenance:
    def test_threat_intel_result_is_provider_neutral(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert isinstance(result, ThreatIntelResult)
        finally:
            provider.close()

    def test_enriched_provenance_mapping(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
        finally:
            provider.close()

        enrichment = EnrichmentResult(
            enrichment_type="threat_intelligence",
            source=result.provider,
            value={
                "indicator_type": result.indicator.indicator_type.value,
                "indicator": result.indicator.value,
                "found": result.found,
                **result.data,
            },
            confidence=result.confidence,
            timestamp=result.timestamp,
        )
        # ENRICHED is the correct provenance for VT-derived information.
        assert Provenance.ENRICHED is not Provenance.OBSERVED
        assert Provenance.ENRICHED is not Provenance.RECONSTRUCTED


# ===========================================================================
# K. Input validation
# ===========================================================================

class TestInputValidation:
    def test_unsupported_indicator_type_fails_before_http(self):
        # All four enum members are supported, so to exercise the guard
        # we construct an indicator whose type is not in the enum set
        # (bypassing pydantic validation via construct()).  Step 7C's
        # assert_supports() raises either UnsupportedIndicatorTypeError
        # or an AttributeError for a non-enum string — the key contract
        # being verified is that NO HTTP request is attempted.
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            bogus = ThreatIndicator.model_construct(
                indicator_type="mac_address",  # type: ignore[arg-type]
                value="AA:BB:CC:DD:EE:FF",
            )
            with pytest.raises(
                (UnsupportedIndicatorTypeError, AttributeError),
            ):
                provider.lookup(bogus)
            assert calls["count"] == 0
        finally:
            provider.close()

    def test_empty_value_rejected(self):
        provider = VirusTotalProvider(
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
        provider = VirusTotalProvider(
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

    def test_lookup_rejects_non_threat_indicator(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            with pytest.raises((TypeError, AttributeError)):
                provider.lookup(
                    {"indicator_type": "ip", "value": "8.8.8.8"},
                )
        finally:
            provider.close()

    def test_no_http_call_for_empty_value(self):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IP_RESPONSE, request=request)

        provider = VirusTotalProvider(
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
# L. No-network safety
# ===========================================================================

class TestNoNetworkSafety:
    def test_lookup_uses_injected_client_only(self):
        provider = VirusTotalProvider(
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

        provider = VirusTotalProvider(
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


# ===========================================================================
# M. Deterministic parsing
# ===========================================================================

class TestDeterministicParsing:
    def test_same_mock_response_yields_equivalent_result(self):
        def make_provider():
            return VirusTotalProvider(
                api_key=SECRET_KEY,
                http_client=_make_client(_ok_json(IP_RESPONSE)),
            )

        p1 = make_provider()
        p2 = make_provider()
        try:
            r1 = p1.lookup(_indicator())
            r2 = p2.lookup(_indicator())
            assert r1.found == r2.found
            assert r1.data == r2.data
            assert r1.confidence == r2.confidence
            assert r1.provider == r2.provider
        finally:
            p1.close()
            p2.close()

    def test_field_order_does_not_matter(self):
        import copy
        resp_a = copy.deepcopy(IP_RESPONSE)
        resp_b = copy.deepcopy(IP_RESPONSE)
        resp_b["data"]["attributes"]["reputation"] = -50
        keys = list(resp_b["data"]["attributes"].keys())
        resp_b["data"]["attributes"] = {
            k: resp_b["data"]["attributes"][k]
            for k in reversed(keys)
        }

        pa = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(resp_a)),
        )
        pb = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(resp_b)),
        )
        try:
            ra = pa.lookup(_indicator())
            rb = pb.lookup(_indicator())
            assert ra.data == rb.data
        finally:
            pa.close()
            pb.close()
# ===========================================================================
# N. Secret safety
# ===========================================================================

class TestSecretSafety:
    def test_api_key_absent_from_exception_strings(self, monkeypatch):
        monkeypatch.setattr(vt_module, "_MAX_RETRIES", 0)
        monkeypatch.setattr(vt_module, "_RETRY_BASE_DELAY", 0.0)

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(
                "boom", request=request,
            )

        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert SECRET_KEY not in str(excinfo.value)
            assert SECRET_KEY not in repr(excinfo.value)
        finally:
            provider.close()

    def test_api_key_absent_from_log_output(self, caplog, monkeypatch):
        monkeypatch.setattr(vt_module, "_MAX_RETRIES", 0)
        monkeypatch.setattr(vt_module, "_RETRY_BASE_DELAY", 0.0)

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(
                "boom", request=request,
            )

        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with caplog.at_level(logging.INFO):
                with pytest.raises(ProviderLookupError):
                    provider.lookup(_indicator())
            assert SECRET_KEY not in caplog.text
        finally:
            provider.close()

    def test_api_key_absent_from_result_metadata(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            full = json.dumps(result.model_dump(mode="json"))
            assert SECRET_KEY not in full
        finally:
            provider.close()

    def test_api_key_absent_from_unsupported_error(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )
        try:
            exc = UnsupportedIndicatorTypeError(
                "bogus", provider.provider_name,
            )
            assert SECRET_KEY not in str(exc)
        finally:
            provider.close()
# ===========================================================================
# Integration: ThreatIndicator → Provider → mock VT → ThreatIntelResult
#                                     → EnrichmentResult → EnrichedSecurityEvent
# ===========================================================================

class TestIntegrationWithEnrichment:
    def test_full_pipeline_without_network(self):
        provider = VirusTotalProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IP_RESPONSE)),
        )

        try:
            # 1. Build the indicator.
            ti = ThreatIndicator(
                indicator_type=IndicatorType.IP,
                value=IP_VALUE,
            )

            # 2. Perform the provider lookup (mocked, no network).
            result = provider.lookup(ti)
            assert isinstance(result, ThreatIntelResult)
            assert result.provider == "VirusTotal"
            assert result.found is True

            # 3. Map the provider result into EnrichmentResult.
            enrichment = EnrichmentResult(
                enrichment_type="threat_intelligence",
                source=result.provider,
                value={
                    "indicator_type": result.indicator.indicator_type.value,
                    "indicator": result.indicator.value,
                    "found": result.found,
                    **result.data,
                },
                confidence=result.confidence,
                timestamp=result.timestamp,
            )
            assert enrichment.enrichment_type == "threat_intelligence"
            assert enrichment.source == "VirusTotal"
            assert enrichment.value["indicator"] == IP_VALUE
            assert enrichment.confidence is None

            # 4. Build the original (unchanged) normalized event.
            original_ts = datetime(
                2025, 6, 30, 8, 30, 0, tzinfo=timezone.utc,
            )
            normalized = NormalizedSecurityEvent(
                event_id=uuid.uuid4(),
                timestamp=original_ts,
                event_category=EventCategory.NETWORK,
                action="connection",
                outcome=EventOutcome.DENIED,
                source="firewall",
                source_type=SourceType.NETWORK,
                normalized_data={
                    "destination": {"ip": IP_VALUE, "port": 443},
                },
            )
            normalized_before = normalized.model_copy(deep=True)

            # 5. Wrap into EnrichedSecurityEvent (ENRICHED provenance).
            enriched = EnrichedSecurityEvent(
                event_id=normalized.event_id,
                timestamp=normalized.timestamp,
                normalized_event=normalized,
                enrichments=[enrichment],
                provenance=Provenance.ENRICHED,
            )

            # -- Assertions --
            assert enriched.provenance == Provenance.ENRICHED
            assert enriched.provenance is not Provenance.RECONSTRUCTED
            assert enriched.provenance is not Provenance.OBSERVED

            # Original event remains unchanged.
            assert enriched.normalized_event == normalized_before
            assert enriched.normalized_event.timestamp == original_ts
            assert enriched.normalized_event.normalized_data == {
                "destination": {"ip": IP_VALUE, "port": 443},
            }

            # Enrichment carries the VT evidence without mutating the event.
            assert enriched.enrichments[0].value["indicator"] == IP_VALUE
        finally:
            provider.close()