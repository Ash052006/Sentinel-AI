"""Threat Hunting subsystem (V2.19).

A read-only, analyst-driven hunting capability over SentinelAI's persisted
analytical records (detections, correlations + members, risk assessments,
threat-intel indicators/lookups, incident memory, audit log).  Hunts are
structured, bounded, deterministic and provenance-faithful; a hunt can
never mutate security state or execute a response.
"""

from .service import ThreatHuntService

__all__ = ["ThreatHuntService"]