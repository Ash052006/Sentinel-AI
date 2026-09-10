"""Tests for the AlienVault OTX threat-intelligence provider.

Covers provider basics, API-key security, request construction (IPv4 /
IPv6 / domain / URL / hash endpoints, authentication and Accept headers),
per-indicator lookups, result contract, response field mapping,
indicator-specific parsing, found semantics, response caps, unsupported
types, invalid inputs, HTTP error handling, rate limiting, bounded retry
behaviour, timeouts, URL/path encoding, response safety, no-network
safety, and deterministic parsing.

Every test uses a mocked/injected HTTP client (``httpx.MockTransport``) --
no real network requests are ever made.
"""

from __future__ import annotations

import json
import logging
from urllib.parse import quote

import httpx
import pytest

from app.core.config import settings
from app.services.threat_intelligence import (
    AlienVaultOTXProvider,
    IndicatorType,
    InvalidIndicatorError,
    ProviderLookupError,
    RateLimitError,
    ThreatIndicator,
    ThreatIntelProvider,
    ThreatIntelResult,
    UnsupportedIndicatorTypeError,
)
import app.services.threat_intelligence.alienvault_otx as otx_module

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

SECRET_KEY = "test-otx-api-key"

BASE_URL = "https://otx.alienvault.com/api/v1"

IP_VALUE = "118.25.6.39"
IPV6_VALUE = "2001:4860:4860::8888"
DOMAIN_VALUE = "evil-example.com"
HASH_VALUE = (
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)
URL_VALUE = "https://evil-example.com/malware/payload.exe?token=abc"
NASTY_URL_VALUE = (
    "https://user:pass@evil-host.com:8443/a b/c?q=1&r=2#frag%20x"
)

IPV4_ENDPOINT = f"{BASE_URL}/indicators/IPv4/{IP_VALUE}/general"
IPV6_ENDPOINT = (
    f"{BASE_URL}/indicators/IPv6/{quote(IPV6_VALUE, safe='')}/general"
)
DOMAIN_ENDPOINT = f"{BASE_URL}/indicators/domain/{DOMAIN_VALUE}/general"
URL_ENDPOINT = f"{BASE_URL}/indicators/url/{quote(URL_VALUE, safe='')}/general"
HASH_ENDPOINT = f"{BASE_URL}/indicators/file/{HASH_VALUE}/general"
NASTY_URL_ENDPOINT = (
    f"{BASE_URL}/indicators/url/{quote(NASTY_URL_VALUE, safe='')}/general"
)


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


# -- Reusable OTX response fixtures (modelled on the real API responses) -----

PULSE_1 = {
    "id": "63d10e46581edfe9bba0da3f",
    "name": "Evil Campaign",
    "description": "Phishing IOCs from campaign X",
    "created": "2023-01-25T11:11:02.458000",
    "modified": "2026-09-04T13:37:56.700000",
    "tags": ["phishing", "scam", "microsoft"],
    "references": ["https://www.example.com/ref/1"],
    "author": {
        "username": "analyst007",
        "id": "222814",
        "avatar_url": "https://otx.alienvault.com/assets/images/default-avatar.png",
        "is_subscribed": False,
        "is_following": False,
    },
    "adversary": "ACME",
    "targeted_countries": ["US", "DE"],
    "malware_families": [
        {
            "id": "ALF:Trojan:Win32/FlyStudio.PA!MTB",
            "display_name": "FlyStudio",
            "target": None,
        },
    ],
    "attack_ids": ["T1045"],
    "industries": ["technology", "finance"],
    "TLP": "green",
    "locked": False,
    "cloned_from": None,
    "export_count": 3674643,
    "indicator_count": 89,
    "indicator_type_counts": {"URL": 16, "hostname": 51, "domain": 22},
    "secretPulseField": "must-not-leak",
}

PULSE_2 = {
    "id": "6a6cdd340cddc013c9488dbb",
    "name": "Uninstall File",
    "description": "Uninstall File left in app folder",
    "created": "2026-07-31T17:36:52.513000",
    "modified": "2026-08-31T00:12:05.881000",
    "tags": ["requesturl"],
    "references": [],
    "author": {
        "username": "second-analyst",
        "id": "410839",
        "avatar_url": "https://otx.alienvault.com/assets/images/default-avatar.png",
        "is_subscribed": False,
        "is_following": False,
    },
    "adversary": "",
    "targeted_countries": [],
    "malware_families": [],
    "attack_ids": [],
    "industries": [],
    "TLP": "white",
    "locked": False,
    "cloned_from": None,
    "export_count": 0,
    "indicator_count": 1,
    "indicator_type_counts": {"FileHash-SHA256": 1},
    "secretPulseField": "must-not-leak",
}

IPV4_RESPONSE = {
    "indicator": IP_VALUE,
    "type": "IPv4",
    "type_title": "IPv4",
    "reputation": 0,
    "asn": "AS45090 Shenzhen Tencent Computer Systems Company Limited",
    "city": None,
    "country_code": "CN",
    "country_name": "China",
    "latitude": None,
    "longitude": None,
    "validation": [
        {
            "source": "whitelist",
            "message": "contained in whitelisted prefix",
            "name": "Whitelisted IP",
        },
        {
            "source": "false_positive",
            "message": "Known False Positive",
            "name": "Known False Positive",
        },
    ],
    "pulse_info": {
        "count": 2,
        "references": ["https://otx.alienvault.com/pulse/63d10e46581edfe9bba0da3f"],
        "pulses": [PULSE_1, PULSE_2],
        "related": {
            "alienvault": {
                "adversary": ["APT41"],
                "malware_families": ["flystudio"],
                "industries": ["technology"],
            },
            "other": {"adversary": [], "malware_families": [], "industries": []},
        },
    },
}

EMPTY_RESPONSE = {
    "indicator": IP_VALUE,
    "type": "IPv4",
    "type_title": "IPv4",
    "reputation": 0,
    "whois": "http://whois.domaintools.com/118.25.6.39",
    "asn": "AS45090 Shenzhen Tencent Computer Systems Company Limited",
    "country_code": "CN",
    "country_name": "China",
    "validation": [
        {
            "source": "whitelist",
            "message": "contained in whitelisted prefix",
            "name": "Whitelisted IP",
        },
    ],
    "pulse_info": {
        "count": 0,
        "pulses": [],
        "references": [],
        "related": {
            "alienvault": {"adversary": [], "malware_families": [], "industries": []},
            "other": {"adversary": [], "malware_families": [], "industries": []},
        },
    },
}

IPV6_RESPONSE = {
    "indicator": IPV6_VALUE,
    "type": "IPv6",
    "type_title": "IPv6",
    "reputation": 0,
    "asn": "AS15169 google llc",
    "country_code": "US",
    "country_name": "United States of America",
    "latitude": 37.751,
    "longitude": -97.822,
    "validation": [],
    "pulse_info": {
        "count": 1,
        "pulses": [PULSE_1],
        "references": [],
        "related": {
            "alienvault": {"adversary": [], "malware_families": [], "industries": []},
            "other": {"adversary": [], "malware_families": [], "industries": []},
        },
    },
}

DOMAIN_RESPONSE = {
    "indicator": DOMAIN_VALUE,
    "type": "domain",
    "type_title": "Domain",
    "whois": "http://whois.domaintools.com/evil-example.com",
    "alexa": "http://www.alexa.com/siteinfo/evil-example.com",
    "validation": [],
    "pulse_info": {
        "count": 3,
        "pulses": [PULSE_1, PULSE_2],
        "references": [],
        "related": {
            "alienvault": {"adversary": [], "malware_families": [], "industries": []},
            "other": {"adversary": [], "malware_families": [], "industries": []},
        },
    },
}

URL_RESPONSE = {
    "indicator": URL_VALUE,
    "type": "url",
    "type_title": "URL",
    "validation": [],
    "pulse_info": {
        "count": 1,
        "pulses": [PULSE_1],
        "references": ["https://otx.alienvault.com/pulse/63d10e46581edfe9bba0da3f"],
        "related": {
            "alienvault": {"adversary": [], "malware_families": [], "industries": []},
            "other": {"adversary": [], "malware_families": [], "industries": []},
        },
    },
}

HASH_RESPONSE = {
    "indicator": HASH_VALUE,
    "type": "sha256",
    "type_title": "FileHash-SHA256",
    "validation": [],
    "pulse_info": {
        "count": 2,
        "pulses": [PULSE_1, PULSE_2],
        "references": [],
        "related": {
            "alienvault": {
                "adversary": ["APT41"],
                "malware_families": [],
                "industries": [],
            },
            "other": {"adversary": [], "malware_families": [], "industries": []},
        },
    },
    # Unselected fields that must never leak out of the provider:
    "analysis": {"sha256": HASH_VALUE, "stored": True},
    "secretNote": "classified",
    "fullRawDump": "raw json dump",
}

# ===========================================================================
# A. Provider basics
# ===========================================================================

class TestProviderBasics:
    def test_provider_name(self):
        assert AlienVaultOTXProvider.provider_name == "AlienVault OTX"

    def test_supported_indicator_types(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({})),
        )
        try:
            types = provider.supported_indicator_types
            assert types == frozenset({
                IndicatorType.IP,
                IndicatorType.DOMAIN,
                IndicatorType.URL,
                IndicatorType.HASH,
            })
            assert IndicatorType.IP in types
            assert IndicatorType.DOMAIN in types
            assert IndicatorType.URL in types
            assert IndicatorType.HASH in types
        finally:
            provider.close()

    def test_is_threat_intel_provider(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({})),
        )
        try:
            assert isinstance(provider, ThreatIntelProvider)
        finally:
            provider.close()

    def test_supports_all_four_types(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json({})),
        )
        try:
            assert provider.supports(IndicatorType.IP)
            assert provider.supports(IndicatorType.DOMAIN)
            assert provider.supports(IndicatorType.URL)
            assert provider.supports(IndicatorType.HASH)
        finally:
            provider.close()

    def test_default_timeout_is_bounded(self):
        provider = AlienVaultOTXProvider(api_key=SECRET_KEY)
        try:
            assert 0 < provider._timeout_seconds < float("inf")
        finally:
            provider.close()

# ===========================================================================
# B. API key security
# ===========================================================================

class TestApiKeySecurity:
    def test_api_key_loaded_from_config(self, monkeypatch):
        monkeypatch.setattr(settings, "otx_api_key", "cfg-otx-999")
        provider = AlienVaultOTXProvider(
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            assert provider._api_key == "cfg-otx-999"
            result = provider.lookup(_indicator())
            assert result.provider == "AlienVault OTX"
        finally:
            provider.close()

    def test_explicit_api_key_takes_precedence(self, monkeypatch):
        monkeypatch.setattr(settings, "otx_api_key", "cfg-otx-999")
        provider = AlienVaultOTXProvider(
            api_key="explicit-otx-123",
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            assert provider._api_key == "explicit-otx-123"
        finally:
            provider.close()

    def test_missing_api_key_fails_safely(self, monkeypatch):
        monkeypatch.setattr(settings, "otx_api_key", "")
        with pytest.raises(ValueError) as excinfo:
            AlienVaultOTXProvider()
        msg = str(excinfo.value)
        assert "API key is required" in msg

    def test_api_key_never_in_exception_from_missing_config(
        self, monkeypatch,
    ):
        monkeypatch.setattr(settings, "otx_api_key", "")
        with pytest.raises(ValueError) as excinfo:
            AlienVaultOTXProvider()
        assert SECRET_KEY not in str(excinfo.value)

    def test_api_key_is_sent_via_x_otx_api_key_header(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["key"] = request.headers.get("X-OTX-API-KEY")
            captured["accept"] = request.headers.get("Accept")
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator())
            assert captured["key"] == SECRET_KEY
            assert captured["url"] == IPV4_ENDPOINT
        finally:
            provider.close()

    def test_accept_header_is_json(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["accept"] = request.headers.get("Accept")
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator())
            assert captured["accept"] == "application/json"
        finally:
            provider.close()

    def test_api_key_never_in_logs(self, caplog):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            with caplog.at_level(logging.INFO):
                provider.lookup(_indicator())
            assert SECRET_KEY not in caplog.text
        finally:
            provider.close()

    def test_api_key_never_in_result(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
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

        provider = AlienVaultOTXProvider(
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
    def test_correct_ipv4_endpoint(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator(IndicatorType.IP, IP_VALUE))
            assert captured["url"] == IPV4_ENDPOINT
        finally:
            provider.close()

    def test_correct_ipv6_endpoint(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=IPV6_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator(IndicatorType.IP, IPV6_VALUE))
            # IPv6 colons must be percent-encoded inside the path.
            assert captured["url"] == IPV6_ENDPOINT
            assert "::" not in captured["url"]
        finally:
            provider.close()

    def test_correct_domain_endpoint(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=DOMAIN_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator(IndicatorType.DOMAIN, DOMAIN_VALUE))
            assert captured["url"] == DOMAIN_ENDPOINT
        finally:
            provider.close()

    def test_correct_url_endpoint(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=URL_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator(IndicatorType.URL, URL_VALUE))
            assert captured["url"] == URL_ENDPOINT
        finally:
            provider.close()

    def test_correct_hash_endpoint(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=HASH_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator(IndicatorType.HASH, HASH_VALUE))
            assert captured["url"] == HASH_ENDPOINT
        finally:
            provider.close()

    def test_url_indicator_is_fully_percent_encoded(self):
        """Raw URL delimiters never reach the request path unencoded."""

        def handler(request: httpx.Request) -> httpx.Response:
            # ``request.url.path`` is decoded by httpx, so inspect the raw
            # (still percent-encoded) path bytes to confirm the indicator
            # value cannot smuggle raw delimiters into the request.
            raw_path = request.url.raw_path.decode("ascii")
            assert "://" not in raw_path
            assert "?q=1" not in raw_path
            assert "&r=2" not in raw_path
            assert "#frag" not in raw_path
            assert "/a b/c" not in raw_path
            assert "user:pass" not in raw_path
            # Every reserved/special character must be percent-encoded.
            for reserved in (":", " ", "?", "&", "#"):
                assert reserved not in raw_path
            return httpx.Response(200, json=URL_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator(IndicatorType.URL, NASTY_URL_VALUE))
        finally:
            provider.close()

    def test_path_encoding_matches_expected_url(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=URL_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            provider.lookup(_indicator(IndicatorType.URL, NASTY_URL_VALUE))
            assert captured["url"] == NASTY_URL_ENDPOINT
        finally:
            provider.close()

    def test_percent_encoded_value_cannot_escape_path(self):
        """A value containing '%2F' is double-encoded into the path."""

        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=URL_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            result = provider.lookup(
                _indicator(IndicatorType.URL, "https://x.com/%2F..%2Fadmin")
            )
            assert result.found is True
            # The '%' itself gets encoded ('%25'), so '..' can never
            # resurface as a path segments separator.
            assert "%2F..%2F" not in captured["url"]
        finally:
            provider.close()

# ===========================================================================
# D. Successful lookups
# ===========================================================================

class TestSuccessfulLookups:
    def test_ipv4_lookup(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.IP, IP_VALUE))
            assert isinstance(result, ThreatIntelResult)
            assert result.found is True
            assert result.data["indicator"] == IP_VALUE
            assert result.data["otx_type"] == "IPv4"
        finally:
            provider.close()

    def test_ipv6_lookup(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV6_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.IP, IPV6_VALUE))
            assert result.found is True
            assert result.data["otx_type"] == "IPv6"
            assert result.data["asn"] == "AS15169 google llc"
        finally:
            provider.close()

    def test_domain_lookup(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(DOMAIN_RESPONSE)),
        )
        try:
            result = provider.lookup(
                _indicator(IndicatorType.DOMAIN, DOMAIN_VALUE)
            )
            assert result.found is True
            assert result.data["otx_type"] == "domain"
            assert result.data["whois"].endswith(DOMAIN_VALUE)
        finally:
            provider.close()

    def test_url_lookup(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(URL_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.URL, URL_VALUE))
            assert result.found is True
            assert result.data["otx_type"] == "url"
            assert result.data["indicator"] == URL_VALUE
        finally:
            provider.close()

    def test_hash_lookup(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(HASH_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.HASH, HASH_VALUE))
            assert result.found is True
            assert result.data["otx_type"] == "sha256"
            assert result.data["indicator"] == HASH_VALUE
        finally:
            provider.close()

    def test_result_provider_name(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.provider == "AlienVault OTX"
        finally:
            provider.close()

    def test_result_found_true(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
        finally:
            provider.close()

    def test_indicator_preserved(self):
        indicator = _indicator(IndicatorType.IP, IP_VALUE)
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(indicator)
            assert result.indicator == indicator
            assert result.indicator.indicator_type == IndicatorType.IP
            assert result.indicator.value == IP_VALUE
        finally:
            provider.close()

    def test_result_is_threat_intel_result(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert isinstance(result, ThreatIntelResult)
        finally:
            provider.close()

# ===========================================================================
# E. Response field mapping
# ===========================================================================

class TestResponseMapping:
    def test_response_field_mapping(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            data = result.data
            assert data["indicator"] == IP_VALUE
            assert data["otx_type"] == "IPv4"
            assert data["reputation"] == 0
            assert data["asn"].startswith("AS45090")
            assert data["country_code"] == "CN"
            assert data["country_name"] == "China"
            assert data["validation"][0]["source"] == "whitelist"
            assert data["pulse_info"]["count"] == 2
        finally:
            provider.close()

    def test_domain_specific_fields(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(DOMAIN_RESPONSE)),
        )
        try:
            result = provider.lookup(
                _indicator(IndicatorType.DOMAIN, DOMAIN_VALUE)
            )
            assert result.data["whois"] == (
                "http://whois.domaintools.com/evil-example.com"
            )
            assert result.data["alexa"].startswith("http://www.alexa.com/")
        finally:
            provider.close()

    def test_pulse_mapping(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            pulses = result.data["pulse_info"]["pulses"]
            assert len(pulses) == 2
            pulse = pulses[0]
            assert pulse["id"] == PULSE_1["id"]
            assert pulse["name"] == "Evil Campaign"
            assert pulse["description"] == "Phishing IOCs from campaign X"
            assert pulse["adversary"] == "ACME"
            assert pulse["TLP"] == "green"
            assert pulse["tags"] == ["phishing", "scam", "microsoft"]
            assert pulse["targeted_countries"] == ["US", "DE"]
            assert pulse["attack_ids"] == ["T1045"]
            assert pulse["indicator_count"] == 89
        finally:
            provider.close()

    def test_author_reduced_to_username(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            author = result.data["pulse_info"]["pulses"][0]["author"]
            assert author == {"username": "analyst007"}
        finally:
            provider.close()

    def test_unselected_pulse_fields_dropped(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            pulse = result.data["pulse_info"]["pulses"][0]
            assert "secretPulseField" not in pulse
            assert "locked" not in pulse
            assert "cloned_from" not in pulse
            assert "export_count" not in pulse
            assert "indicator_type_counts" not in pulse
        finally:
            provider.close()

    def test_pulse_info_count_mapped(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.data["pulse_info"]["count"] == 2
        finally:
            provider.close()

    def test_related_mapping(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            related = result.data["pulse_info"]["related"]
            assert related["alienvault"]["adversary"] == ["APT41"]
            assert related["alienvault"]["malware_families"] == ["flystudio"]
            assert related["other"]["adversary"] == []
        finally:
            provider.close()

    def test_otx_type_mapped(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(HASH_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.HASH, HASH_VALUE))
            assert result.data["otx_type"] == "sha256"
        finally:
            provider.close()

    def test_reputation_passthrough(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.data["reputation"] == 0
        finally:
            provider.close()

    def test_non_integer_reputation_dropped(self):
        payload = dict(IPV4_RESPONSE)
        payload["reputation"] = "not-an-int"
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(payload)),
        )
        try:
            result = provider.lookup(_indicator())
            assert "reputation" not in result.data
        finally:
            provider.close()

    def test_missing_optional_fields_omitted(self):
        minimal = {
            "indicator": IP_VALUE,
            "type": "IPv4",
            "pulse_info": {"count": 1, "pulses": [], "references": []},
        }
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(minimal)),
        )
        try:
            result = provider.lookup(_indicator())
            data = result.data
            assert data["indicator"] == IP_VALUE
            assert data["otx_type"] == "IPv4"
            # Absent optional fields must not be fabricated:
            assert "reputation" not in data
            assert "validation" not in data
            assert "asn" not in data
            assert "country_code" not in data
            assert "country_name" not in data
            assert "city" not in data
            assert result.found is True
        finally:
            provider.close()

# ===========================================================================
# F. Found semantics, response caps & raw-response safety
# ===========================================================================

class TestFoundSemantics:
    def test_empty_response_not_found(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(EMPTY_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is False
            assert result.data["pulse_info"]["count"] == 0
        finally:
            provider.close()

    def test_validation_alone_is_not_found(self):
        """Whitelist/validation metadata with zero pulses is not found."""
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(EMPTY_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.data["validation"]
            assert result.found is False
        finally:
            provider.close()

    def test_count_greater_than_zero_is_found_even_without_pulse_list(self):
        """A positive server-side count means meaningful OTX intelligence."""
        payload = {
            "indicator": IP_VALUE,
            "type": "IPv4",
            "pulse_info": {"count": 5, "pulses": [], "references": []},
        }
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(payload)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
        finally:
            provider.close()

    def test_non_numeric_count_is_treated_as_zero(self):
        payload = {
            "indicator": IP_VALUE,
            "type": "IPv4",
            "pulse_info": {"count": "many", "pulses": []},
        }
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(payload)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is False
        finally:
            provider.close()


class TestResponseCaps:
    def _make_payload(self, pulse_info):
        payload = dict(IPV4_RESPONSE)
        payload["pulse_info"] = pulse_info
        return payload

    def test_pulses_trimmed_to_cap(self):
        many_pulses = [dict(PULSE_1) for _ in range(50)]
        payload = self._make_payload(
            {"count": 50, "pulses": many_pulses, "references": []}
        )
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(payload)),
        )
        try:
            result = provider.lookup(_indicator())
            pulses = result.data["pulse_info"]["pulses"]
            assert len(pulses) == otx_module._MAX_PULSES == 10
        finally:
            provider.close()

    def test_pulse_tags_trimmed_to_cap(self):
        pulse = dict(PULSE_1)
        pulse["tags"] = [f"tag-{i}" for i in range(50)]
        payload = self._make_payload(
            {"count": 1, "pulses": [pulse], "references": []}
        )
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(payload)),
        )
        try:
            result = provider.lookup(_indicator())
            tags = result.data["pulse_info"]["pulses"][0]["tags"]
            assert len(tags) == otx_module._MAX_PULSE_LIST_ENTRIES == 20
        finally:
            provider.close()

    def test_pulse_references_trimmed_to_cap(self):
        pulse = dict(PULSE_1)
        pulse["references"] = [f"https://ref/{i}" for i in range(50)]
        payload = self._make_payload(
            {"count": 1, "pulses": [pulse], "references": []}
        )
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(payload)),
        )
        try:
            result = provider.lookup(_indicator())
            refs = result.data["pulse_info"]["pulses"][0]["references"]
            assert len(refs) == otx_module._MAX_PULSE_LIST_ENTRIES == 20
        finally:
            provider.close()

    def test_pulse_info_references_trimmed_to_cap(self):
        payload = self._make_payload(
            {
                "count": 1,
                "pulses": [],
                "references": [f"https://otx/{i}" for i in range(40)],
            }
        )
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(payload)),
        )
        try:
            result = provider.lookup(_indicator())
            refs = result.data["pulse_info"]["references"]
            assert len(refs) == otx_module._MAX_PULSE_REFERENCES == 10
        finally:
            provider.close()

    def test_related_trimmed_to_cap(self):
        related = {
            "alienvault": {
                "adversary": [f"adv-{i}" for i in range(40)],
                "malware_families": [],
                "industries": [],
            },
            "other": {"adversary": [], "malware_families": [], "industries": []},
        }
        payload = self._make_payload(
            {"count": 1, "pulses": [], "references": [], "related": related}
        )
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(payload)),
        )
        try:
            result = provider.lookup(_indicator())
            adversaries = result.data["pulse_info"]["related"]["alienvault"][
                "adversary"
            ]
            assert len(adversaries) == otx_module._MAX_RELATED_ENTRIES == 10
        finally:
            provider.close()

    def test_validation_trimmed_to_cap(self):
        payload = dict(IPV4_RESPONSE)
        payload["validation"] = [
            {"source": f"s-{i}", "message": "m", "name": "n"}
            for i in range(30)
        ]
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(payload)),
        )
        try:
            result = provider.lookup(_indicator())
            validation = result.data["validation"]
            assert len(validation) == otx_module._MAX_VALIDATION_ENTRIES == 10
        finally:
            provider.close()


class TestRawResponseSafety:
    def test_raw_response_never_leaks(self):
        leaky = {
            "indicator": IP_VALUE,
            "type": "IPv4",
            "type_title": "IPv4",
            "base_indicator": {"id": 11911, "indicator": IP_VALUE},
            "sections": ["general", "geo", "reputation", "url_list"],
            "secretNote": "classified",
            "fullRawDump": "raw json dump",
            "request": {"headers": {"X-OTX-API-KEY": SECRET_KEY}},
            "validation": [
                {"source": "whitelist", "message": "m", "name": "n"},
            ],
            "pulse_info": {
                "count": 1,
                "pulses": [
                    {
                        "id": "x",
                        "name": "n",
                        "description": "d",
                        "created": "t",
                        "modified": "t",
                        "tags": [],
                        "references": [],
                        "author": {"username": "u", "avatar_url": "x"},
                        "adversary": "a",
                        "TLP": "white",
                        "indicator_count": 1,
                        "export_count": 999,
                        "secretPulseField": "x",
                    },
                ],
                "references": [],
                "related": {
                    "alienvault": {
                        "adversary": ["x"],
                        "malware_families": [],
                        "industries": [],
                    },
                    "other": {
                        "adversary": [],
                        "malware_families": [],
                        "industries": [],
                    },
                },
            },
        }
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(leaky)),
        )
        try:
            result = provider.lookup(_indicator())
            dumped = json.dumps(result.model_dump(mode="json"))
            assert SECRET_KEY not in dumped
            assert "type_title" not in dumped
            assert "base_indicator" not in dumped
            assert "sections" not in dumped
            assert "secretNote" not in dumped
            assert "fullRawDump" not in dumped
            assert "request" not in dumped
            assert '"export_count"' not in dumped
            assert "secretPulseField" not in dumped
            assert "avatar_url" not in dumped
        finally:
            provider.close()

    def test_hash_unselected_fields_never_leak(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(HASH_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator(IndicatorType.HASH, HASH_VALUE))
            dumped = json.dumps(result.model_dump(mode="json"))
            assert "analysis" not in dumped
            assert "secretNote" not in dumped
            assert "fullRawDump" not in dumped
        finally:
            provider.close()

# ===========================================================================
# G. Unsupported types & input validation
# ===========================================================================

class TestUnsupportedTypes:
    def test_unsupported_indicator_type_fails_before_http(self):
        # All four enum members are supported, so to exercise the guard we
        # construct an indicator whose type is not in the enum set
        # (bypassing pydantic validation via model_construct).  The guard
        # raises UnsupportedIndicatorTypeError (or AttributeError for a
        # non-enum string) -- the key contract is that NO HTTP request
        # is attempted.
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
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


class TestInputValidation:
    def test_empty_value_rejected_before_http(self):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            # ThreatIndicator itself rejects blank ``value`` at construction,
            # so bypass construction-time validation to exercise the provider's
            # own defensive guard on an empty value.
            indicator = _indicator(IndicatorType.DOMAIN, "valid.example.com")
            indicator.value = ""
            with pytest.raises(InvalidIndicatorError):
                provider.lookup(indicator)
            assert calls["count"] == 0
        finally:
            provider.close()

    def test_blank_value_rejected_before_http(self):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            indicator = _indicator(IndicatorType.HASH, HASH_VALUE)
            indicator.value = "   "
            with pytest.raises(InvalidIndicatorError):
                provider.lookup(indicator)
            assert calls["count"] == 0
        finally:
            provider.close()

    def test_invalid_ip_fails_before_http(self):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(InvalidIndicatorError) as excinfo:
                provider.lookup(_indicator(IndicatorType.IP, "999.1.1.1"))
            assert "not a valid IPv4 or IPv6 address" in str(excinfo.value)
            assert calls["count"] == 0
        finally:
            provider.close()

    def test_malformed_ipv6_fails_before_http(self):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(InvalidIndicatorError):
                provider.lookup(_indicator(IndicatorType.IP, "2001:::gg"))
            assert calls["count"] == 0
        finally:
            provider.close()

    def test_ip_with_leading_space_fails_before_http(self):
        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(InvalidIndicatorError):
                provider.lookup(_indicator(IndicatorType.IP, " 118.25.6.39"))
            assert calls["count"] == 0
        finally:
            provider.close()

# ===========================================================================
# H. HTTP error handling
# ===========================================================================

class TestHttpErrors:
    def test_bad_request(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(400, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "bad request" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_unauthorized(self):
        provider = AlienVaultOTXProvider(
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
        provider = AlienVaultOTXProvider(
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

    def test_not_found(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(404, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "not found" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_404_message_notes_no_otx_record(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(404, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "no OTX record" in str(excinfo.value)
        finally:
            provider.close()

    def test_429_rate_limit(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(429, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(RateLimitError) as excinfo:
                provider.lookup(_indicator())
            assert "Rate limit exceeded" in str(excinfo.value)
            assert "AlienVault OTX" in str(excinfo.value)
            assert SECRET_KEY not in str(excinfo.value)
        finally:
            provider.close()

    def test_429_rate_limit_with_retry_after(self):
        provider = AlienVaultOTXProvider(
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

    def test_retry_after_non_numeric_ignored(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(
                    429,
                    headers={"Retry-After": "not-a-number"},
                    json={},
                    request=req,
                ),
            ),
        )
        try:
            with pytest.raises(RateLimitError) as excinfo:
                provider.lookup(_indicator())
            assert excinfo.value.retry_after is None
        finally:
            provider.close()

    @pytest.mark.parametrize("status", [500, 502, 503])
    def test_server_errors(self, status, monkeypatch):
        # Avoid slowing the test with retry backoff sleeps.
        monkeypatch.setattr(otx_module, "_MAX_RETRIES", 0)
        monkeypatch.setattr(otx_module, "_RETRY_BASE_DELAY", 0.0)

        provider = AlienVaultOTXProvider(
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

    def test_500_is_retried_but_not_429(self, monkeypatch):
        """5xx retries; 429 raises immediately without retry."""
        monkeypatch.setattr(otx_module, "_MAX_RETRIES", 5)
        monkeypatch.setattr(otx_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(429, json={}, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(RateLimitError):
                provider.lookup(_indicator())
            assert calls["count"] == 1
        finally:
            provider.close()

    def test_malformed_json_body(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=b"not-json{{", request=request,
            )

        provider = AlienVaultOTXProvider(
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
        provider = AlienVaultOTXProvider(
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

    def test_non_dict_json_body(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(200, json=[1, 2, 3], request=req),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "expected JSON object" in str(excinfo.value)
        finally:
            provider.close()

    def test_detail_in_200_body_is_error(self):
        """OTX HTTP-200 bodies with a top-level detail are defensive errors."""
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(
                    200, json={"detail": "Internal error"}, request=req,
                ),
            ),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "API error" in str(excinfo.value)
        finally:
            provider.close()

    def test_client_errors_are_not_retried(self, monkeypatch):
        monkeypatch.setattr(otx_module, "_MAX_RETRIES", 5)
        monkeypatch.setattr(otx_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(400, json={}, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError):
                provider.lookup(_indicator())
            assert calls["count"] == 1
        finally:
            provider.close()

# ===========================================================================
# I. Retry & timeout behaviour
# ===========================================================================

class TestRetryBehaviour:
    def test_transient_errors_are_retried_then_fail(self, monkeypatch):
        monkeypatch.setattr(otx_module, "_MAX_RETRIES", 1)
        monkeypatch.setattr(otx_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(500, json={}, request=request)

        provider = AlienVaultOTXProvider(
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
        monkeypatch.setattr(otx_module, "_MAX_RETRIES", 2)
        monkeypatch.setattr(otx_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(503, json={}, request=request)

        provider = AlienVaultOTXProvider(
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
        monkeypatch.setattr(otx_module, "_MAX_RETRIES", 2)
        monkeypatch.setattr(otx_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            if calls["count"] == 1:
                return httpx.Response(503, json={}, request=request)
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
            assert calls["count"] == 2
        finally:
            provider.close()

    def test_timeout_retried_then_fail(self, monkeypatch):
        monkeypatch.setattr(otx_module, "_MAX_RETRIES", 1)
        monkeypatch.setattr(otx_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            raise httpx.ConnectTimeout("request timed out")

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "request timed out" in str(excinfo.value)
            assert calls["count"] == 2
        finally:
            provider.close()

    def test_timeout_recovers_on_retry(self, monkeypatch):
        monkeypatch.setattr(otx_module, "_MAX_RETRIES", 1)
        monkeypatch.setattr(otx_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            if calls["count"] == 1:
                raise httpx.ConnectTimeout("request timed out")
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
            assert calls["count"] == 2
        finally:
            provider.close()

    def test_transport_error_retried_then_fail(self, monkeypatch):
        monkeypatch.setattr(otx_module, "_MAX_RETRIES", 1)
        monkeypatch.setattr(otx_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            raise httpx.ConnectError("connection reset by peer")

        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(handler),
        )
        try:
            with pytest.raises(ProviderLookupError) as excinfo:
                provider.lookup(_indicator())
            assert "transport error" in str(excinfo.value)
            assert calls["count"] == 2
        finally:
            provider.close()

    def test_transport_error_recovers_on_retry(self, monkeypatch):
        monkeypatch.setattr(otx_module, "_MAX_RETRIES", 1)
        monkeypatch.setattr(otx_module, "_RETRY_BASE_DELAY", 0.0)

        calls = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["count"] += 1
            if calls["count"] == 1:
                raise httpx.ConnectError("connection reset by peer")
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        provider = AlienVaultOTXProvider(
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
# J. Timeout & client configuration
# ===========================================================================

class TestTimeoutAndClient:
    def test_timeout_configuration_override(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            timeout_seconds=7.5,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            assert provider._timeout_seconds == 7.5
            result = provider.lookup(_indicator())
            assert result.found is True
        finally:
            provider.close()

    def test_timeout_from_settings(self, monkeypatch):
        monkeypatch.setattr(settings, "otx_timeout_seconds", 5.0)
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            assert provider._timeout_seconds == 5.0
        finally:
            provider.close()

    def test_explicit_timeout_beats_settings(self, monkeypatch):
        monkeypatch.setattr(settings, "otx_timeout_seconds", 12.0)
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            timeout_seconds=3.5,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            assert provider._timeout_seconds == 3.5
        finally:
            provider.close()

    def test_default_timeout_from_config_constant(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            expected = getattr(settings, "otx_timeout_seconds", 30.0)
            assert provider._timeout_seconds == expected
        finally:
            provider.close()

    def test_injected_httpx_client_used(self):
        """The injected client (and its transport) must be the one used."""
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=IPV4_RESPONSE, request=request)

        injected = httpx.Client(transport=httpx.MockTransport(handler))
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=injected,
        )
        try:
            result = provider.lookup(_indicator())
            assert result.found is True
            assert captured["url"] == IPV4_ENDPOINT
        finally:
            provider.close()

    def test_provider_owns_internal_client_when_none_injected(self):
        provider = AlienVaultOTXProvider(api_key=SECRET_KEY)
        try:
            assert provider._client is not None
        finally:
            provider.close()

    def test_close_does_not_fail_when_injected_client(self):
        injected = httpx.Client(transport=httpx.MockTransport(_ok_json({})))
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY, http_client=injected,
        )
        try:
            assert True
        finally:
            provider.close()

# ===========================================================================
# K. Result contract
# ===========================================================================

class TestResultContract:
    def test_confidence_is_none(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.confidence is None
        finally:
            provider.close()

    def test_metadata_provider(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            # ``provider`` is a top-level result field (not inside metadata).
            assert result.provider == "AlienVault OTX"
            assert result.metadata["resource_type"] == "otx-indicator"
            assert result.metadata["otx_api_version"] == "v1"
        finally:
            provider.close()

    def test_lookup_timestamp_present(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.timestamp is not None
            assert result.timestamp.tzinfo is not None
        finally:
            provider.close()

    def test_no_verdict_fields_in_result(self):
        """The provider must not decide malicious/safe/compromised."""
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            dumped = json.dumps(result.model_dump(mode="json"))
            for verdict_word in ("malicious", "benign", "compromised", "safe"):
                assert verdict_word not in dumped.lower()
        finally:
            provider.close()

    def test_reputation_not_verdict(self):
        """reputation=0 must not be interpreted as a malicious flag."""
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            assert result.data.get("reputation") == 0
            assert result.found is True  # pulses prove intel exists
        finally:
            provider.close()

# ===========================================================================
# L. Deterministic parsing & module constants
# ===========================================================================

class TestDeterministicParsing:
    def test_same_input_same_output(self):
        providers = []
        try:
            for _ in range(3):
                providers.append(
                    AlienVaultOTXProvider(
                        api_key=SECRET_KEY,
                        http_client=_make_client(_ok_json(IPV4_RESPONSE)),
                    )
                )
            results = [
                p.lookup(_indicator(IndicatorType.IP, IP_VALUE))
                for p in providers
            ]
            dumped = [
                json.dumps(r.model_dump(mode="json"), sort_keys=True)
                for r in results
            ]
            # ``timestamp`` necessarily differs per lookup call, so compare
            # everything else (the parsed data) for determinism.
            stripped = []
            for d in dumped:
                payload = json.loads(d)
                payload.pop("timestamp", None)
                stripped.append(json.dumps(payload, sort_keys=True))
            assert stripped[0] == stripped[1] == stripped[2]
        finally:
            for p in providers:
                p.close()

    def test_author_is_reduced_not_dumped(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(_ok_json(IPV4_RESPONSE)),
        )
        try:
            result = provider.lookup(_indicator())
            dumped = json.dumps(result.model_dump(mode="json"))
            assert "avatar_url" not in dumped
            assert '"author": {"username": "analyst007"}' in dumped
        finally:
            provider.close()

    def test_module_constants_are_bounded(self):
        assert otx_module._MAX_RETRIES == 2
        assert isinstance(otx_module._MAX_PULSES, int)
        assert otx_module._MAX_PULSES > 0
        assert otx_module._MAX_PULSES <= 20
        assert otx_module._MAX_VALIDATION_ENTRIES == 10
        assert otx_module._MAX_RELATED_ENTRIES == 10
        assert otx_module._MAX_PULSE_REFERENCES == 10
        assert otx_module._MAX_PULSE_LIST_ENTRIES == 20

    def test_rate_limit_error_retry_after_parsing(self):
        provider = AlienVaultOTXProvider(
            api_key=SECRET_KEY,
            http_client=_make_client(
                lambda req: httpx.Response(429, json={}, request=req),
            ),
        )
        try:
            with pytest.raises(RateLimitError) as excinfo:
                provider.lookup(_indicator())
            assert excinfo.value.provider_name == "AlienVault OTX"
        finally:
            provider.close()