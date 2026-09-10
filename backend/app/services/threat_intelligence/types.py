"""Indicator types and validated indicator model for threat intelligence.

Defines the standardised representation of an Indicator of Compromise
(IoC) that the provider layer consumes.  Every provider receives a
:class:`ThreatIndicator` rather than raw, unstructured data.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class IndicatorType(str, Enum):
    """Classification of threat-intelligence indicators.

    The set covers the most common IoC categories.  New values can be
    added in later versions without breaking the provider contract.
    """

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class ThreatIndicator(BaseModel):
    """Validated, provider-neutral representation of an Indicator of Compromise.

    Every threat-intelligence provider receives a ``ThreatIndicator``
    rather than a raw dictionary or string.  This guarantees a consistent
    interface regardless of the underlying indicator kind.

    Attributes:
        indicator_type: The category of indicator (IP, domain, URL, hash).
        value: The indicator value itself (e.g. ``"8.8.8.8"``,
            ``"example.com"``).
    """

    indicator_type: IndicatorType = Field(
        ...,
        description="Classification of the indicator (ip, domain, url, hash).",
    )

    value: str = Field(
        ...,
        min_length=1,
        description=(
            "The indicator value (e.g. '8.8.8.8', 'example.com', "
            "'https://evil.com/payload', a SHA-256 hash)."
        ),
    )

    @field_validator("value")
    @classmethod
    def _value_not_blank(cls, v: str) -> str:
        """Reject purely whitespace values."""
        if not v.strip():
            raise ValueError("indicator value must not be blank/whitespace")
        return v
