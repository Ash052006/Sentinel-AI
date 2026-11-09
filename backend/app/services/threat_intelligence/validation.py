"""Centralized indicator validation policy for threat intelligence.

Protects against data leakage, quota exhaustion, and provider errors by
classifying IPv4 and IPv6 indicators using Python's standard library
``ipaddress`` module and preventing non-public addresses from being dispatched
to external threat intelligence providers.
"""

from __future__ import annotations

import ipaddress
import logging

from app.services.threat_intelligence.types import IndicatorType

logger = logging.getLogger(__name__)

# RFC 1918 Private IPv4 address spaces
_RFC1918_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# RFC 4193 Unique Local IPv6 unicast addresses
_RFC4193_NETWORKS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("fc00::/7"),
)

# RFC 5737 IPv4 Address Blocks Reserved for Documentation (TEST-NET-1, TEST-NET-2, TEST-NET-3)
_RFC5737_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
)

# RFC 3849 IPv6 Address Prefix Reserved for Documentation
_RFC3849_NETWORKS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("2001:db8::/32"),
)

# Additional non-globally-routable and reserved address blocks
_RESERVED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),          # RFC 1122 "this network"
    ipaddress.ip_network("100.64.0.0/10"),       # RFC 6598 Shared Address Space / CGNAT
    ipaddress.ip_network("198.18.0.0/15"),       # RFC 2544 Benchmarking
    ipaddress.ip_network("240.0.0.0/4"),         # RFC 1112 Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
)


def classify_non_public_ip(value: str, *, allow_documentation_ips: bool = False) -> str | None:
    """Return a descriptive classification string if *value* is a non-public IP, else None.

    Evaluates specific IP properties in precedence order to classify:
    * Loopback addresses (127.0.0.0/8, ::1)
    * Link-local addresses (169.254.0.0/16, fe80::/10)
    * Multicast addresses (224.0.0.0/4, ff00::/8)
    * Unspecified addresses (0.0.0.0, ::)
    * Private addresses (RFC 1918, RFC 4193 ULA)
    * Documentation addresses (RFC 5737, RFC 3849) unless explicitly allowed by test configuration
    * Reserved and non-globally-routable addresses (240.0.0.0/4, CGNAT 100.64.0.0/10, etc.)

    Returns None for public IP addresses or non-IP strings.
    """
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None

    if ip.is_loopback:
        return f"loopback IPv{ip.version} address"
    if ip.is_link_local:
        return f"link-local IPv{ip.version} address"
    if ip.is_multicast:
        return f"multicast IPv{ip.version} address"
    if ip.is_unspecified:
        return f"unspecified IPv{ip.version} address"
    if ip.version == 4 and any(ip in net for net in _RFC1918_NETWORKS):
        return "private IPv4 address"
    if ip.version == 6 and any(ip in net for net in _RFC4193_NETWORKS):
        return "private IPv6 address"
    if not allow_documentation_ips:
        if ip.version == 4 and any(ip in net for net in _RFC5737_NETWORKS):
            return "documentation IPv4 address"
        if ip.version == 6 and any(ip in net for net in _RFC3849_NETWORKS):
            return "documentation IPv6 address"
    if ip.is_reserved or any(ip in net for net in _RESERVED_NETWORKS):
        return f"reserved IPv{ip.version} address"

    return None


def is_non_public_ip(value: str, *, allow_documentation_ips: bool = False) -> bool:
    """Return True if *value* is an IPv4 or IPv6 address that must not be sent to external TI providers."""
    return classify_non_public_ip(value, allow_documentation_ips=allow_documentation_ips) is not None


def should_skip_external_lookup(
    indicator_type: IndicatorType, value: str, *, allow_documentation_ips: bool = False
) -> tuple[bool, str | None]:
    """Determine whether external lookup for an indicator should be skipped.

    Applies IP-specific protection rules only to ``IndicatorType.IP``.
    Domains, URLs, and file hashes are never blocked by IP validation rules.

    Returns:
        A tuple of ``(should_skip, reason)``.
    """
    if indicator_type != IndicatorType.IP:
        return False, None

    reason = classify_non_public_ip(value, allow_documentation_ips=allow_documentation_ips)
    if reason is not None:
        return True, reason

    return False, None
