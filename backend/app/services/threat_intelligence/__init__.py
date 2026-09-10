"""Provider-agnostic abstraction for threat intelligence lookups.

This package establishes the contract and infrastructure that future
threat-intelligence providers (VirusTotal, AbuseIPDB, AlienVault OTX)
will implement.  Step 7C introduces the abstraction only.  Step 7D adds
the first concrete provider implementation (VirusTotal).
"""

from app.services.threat_intelligence.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)
from app.services.threat_intelligence.exceptions import (
    DuplicateProviderError,
    InvalidIndicatorError,
    ProviderLookupError,
    ProviderNotFoundError,
    RateLimitError,
    ThreatIntelError,
    UnsupportedIndicatorTypeError,
)
from app.services.threat_intelligence.registry import ProviderRegistry
from app.services.threat_intelligence.types import (
    IndicatorType,
    ThreatIndicator,
)
from app.services.threat_intelligence.virustotal import VirusTotalProvider
from app.services.threat_intelligence.abuseipdb import AbuseIPDBProvider
from app.services.threat_intelligence.alienvault_otx import AlienVaultOTXProvider

__all__ = [
    "ThreatIntelError",
    "UnsupportedIndicatorTypeError",
    "ProviderNotFoundError",
    "DuplicateProviderError",
    "ProviderLookupError",
    "InvalidIndicatorError",
    "RateLimitError",
    "IndicatorType",
    "ThreatIndicator",
    "ThreatIntelResult",
    "ThreatIntelProvider",
    "ProviderRegistry",
    "VirusTotalProvider",
    "AbuseIPDBProvider",
    "AlienVaultOTXProvider",
]
