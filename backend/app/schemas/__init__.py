"""Data-contract schemas for SentinelAI's security event pipeline.

Convenience re-exports for the canonical schemas consumed across the
pipeline (raw security event, normalized event, enriched event, and the
Threat Intelligence Agent contract).  Consumers may import from this
package or from the individual modules; both paths are equivalent.
"""

from app.schemas.detection import (
    DetectionEvidence,
    DetectionMetadata,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    RuleType,
)
from app.schemas.detection_agent import (
    DetectionAnalysis,
    DetectionAnalysisMetadata,
    DetectionFailure,
)
from app.schemas.enriched_event import (
    EnrichedSecurityEvent,
    EnrichmentResult,
)
from app.schemas.normalized_event import (
    Actor,
    Endpoint,
    EventCategory,
    EventOutcome,
    FileInfo,
    NormalizedSecurityEvent,
    ProcessInfo,
)
from app.schemas.security_event import (
    Provenance,
    SecurityEvent,
    SourceType,
)
from app.schemas.threat_intelligence_agent import (
    ExtractedIndicator,
    ProviderAssociation,
    ProviderFailure,
    ThreatIntelMetadata,
    ThreatIntelligenceAnalysis,
    THREAT_INTELLIGENCE_ENRICHMENT_TYPE,
    threat_intel_result_to_enrichment,
)

__all__ = [
    "SecurityEvent",
    "SourceType",
    "Provenance",
    "NormalizedSecurityEvent",
    "EventCategory",
    "EventOutcome",
    "Actor",
    "Endpoint",
    "ProcessInfo",
    "FileInfo",
    "EnrichmentResult",
    "EnrichedSecurityEvent",
    "ExtractedIndicator",
    "ProviderAssociation",
    "ProviderFailure",
    "ThreatIntelMetadata",
    "ThreatIntelligenceAnalysis",
    "THREAT_INTELLIGENCE_ENRICHMENT_TYPE",
    "threat_intel_result_to_enrichment",
    "RuleType",
    "DetectionSeverity",
    "DetectionEvidence",
    "DetectionMetadata",
    "DetectionRule",
    "DetectionResult",
    "DetectionAnalysis",
    "DetectionAnalysisMetadata",
    "DetectionFailure",
]