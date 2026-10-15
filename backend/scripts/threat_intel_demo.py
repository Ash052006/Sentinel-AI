"""Generate real threat-intelligence records for local verification.

Runs the **real** Step 8A pipeline end to end -- no fixtures, no stubs, no
mocked providers -- so the read surface has genuine rows to serve:

    NormalizedSecurityEvent
        -> ThreatIntelligenceAgent   (indicator extraction)
        -> VirusTotal / AbuseIPDB / AlienVault OTX  (live provider calls)
        -> ThreatIntelligencePersistenceService      (indicators + lookups)

Nothing here is a demo shortcut inserted straight into the database.  The
only thing this script adds over normal operation is which
``NormalizedSecurityEvent`` values are fed in, so the console has something
to display.  Every indicator and lookup row it produces is written by the
same persistence service the production ingest path uses, with the same
provenance (``enriched`` on lookups, enforced by a CHECK constraint).

Indicators used
---------------
``8.8.8.8``, ``google.com``, ``1.1.1.1``, ``github.com`` and a public
sha256.  These are ordinary, globally routable, non-malicious indicators
chosen precisely so the resulting console view demonstrates *provider
coverage and honest status* rather than an alarming fabricated verdict.  A
provider that finds nothing about them is reported as ``NO DATA``; a
provider that errors is reported as the failure it is.

Usage::

    ./scripts/threat_intel_demo.py                # default event set
    ./scripts/threat_intel_demo.py --list         # show events, write nothing
    ./scripts/threat_intel_demo.py --only-ip      # a single indicator
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy.orm import Session  # noqa: E402

from app.agents.threat_intelligence import ThreatIntelligenceAgent  # noqa: E402
from app.database.postgres.session import SessionLocal  # noqa: E402
from app.schemas.enriched_event import EnrichedSecurityEvent  # noqa: E402
from app.schemas.normalized_event import (  # noqa: E402
    Endpoint,
    EventCategory,
    EventOutcome,
    FileInfo,
    NormalizedSecurityEvent,
    SourceType,
)
from app.schemas.security_event import Provenance  # noqa: E402
from app.services.threat_intelligence import (  # noqa: E402
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
    ProviderRegistry,
    VirusTotalProvider,
)
from app.services.threat_intelligence_persistence import (  # noqa: E402
    ThreatIntelligencePersistenceService,
)
from app.services.threat_intelligence_query import (  # noqa: E402
    ThreatIntelQueryService,
)

#: A real, public, non-malicious sample file hash used to demonstrate the
#: ``hash`` indicator type.  This is the published SHA-256 of the
#: "eicar.com" standard anti-malware test file -- a defensive-testing
#: artefact, not live malware.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _utc(hours_ago: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours_ago)


def build_events() -> list[EnrichedSecurityEvent]:
    """Return the demo events fed through the real Step 8A pipeline.

    Each event is a normal :class:`NormalizedSecurityEvent` shaped like the
    output of the NormalizationAgent, carrying indicators only in fields the
    extraction rules actually read: ``source_endpoint.ip``,
    ``destination_endpoint.ip``, ``file.hash``, and the closed
    ``normalized_data`` allowlist for domain/url keys.
    """
    events: list[EnrichedSecurityEvent] = []

    def event(
        *,
        hours_ago: float,
        source: str,
        dest_ip: str,
        normalized_data: dict | None = None,
        file_hash: str | None = None,
        action: str,
    ) -> None:
        stamp = _utc(hours_ago)
        normalized = NormalizedSecurityEvent(
            event_id=uuid.uuid4(),
            timestamp=stamp,
            event_category=EventCategory.NETWORK,
            action=action,
            outcome=EventOutcome.SUCCESS,
            source=source,
            source_type=SourceType.OPERATING_SYSTEM,
            source_endpoint=Endpoint(ip="10.20.30.40", port=54321),
            destination_endpoint=Endpoint(ip=dest_ip, port=443),
            file=FileInfo(hash=file_hash) if file_hash else None,
            normalized_data=normalized_data or {},
            provenance=Provenance.OBSERVED,
        )
        events.append(
            EnrichedSecurityEvent(
                event_id=normalized.event_id,
                timestamp=stamp,
                normalized_event=normalized,
                enrichments=[],
                provenance=Provenance.ENRICHED,
            )
        )

    # DNS resolution plus a TLS session to a public resolver: one event, one
    # IP indicator, one domain indicator.
    event(
        hours_ago=3,
        source="windows-ws07",
        dest_ip="8.8.8.8",
        normalized_data={"domain": "google.com", "url": "https://www.google.com/"},
        action="dns resolution and TLS session",
    )

    # A second event that re-observes the same IP, so first_seen/last_seen
    # and the per-indicator lookup counters have something real to show.
    event(
        hours_ago=1,
        source="windows-ws07",
        dest_ip="8.8.8.8",
        action="tls heartbeat",
    )

    # A different public resolver.
    event(
        hours_ago=6,
        source="linux-app02",
        dest_ip="1.1.1.1",
        normalized_data={"domain": "github.com"},
        action="https request",
    )

    # A file-download event, to exercise the hash indicator type.
    event(
        hours_ago=9,
        source="windows-dc01",
        dest_ip="8.8.8.8",
        file_hash=EICAR_SHA256,
        action="file download",
    )

    return events


def build_registry() -> ProviderRegistry:
    """Register the three real providers, skipping any with no API key.

    A provider without a key is omitted rather than stubbed: the run then
    simply produces fewer lookups, which the console reports honestly as
    "no lookup exists" for that provider instead of inventing a result.
    """
    from app.core.config import settings

    providers = []
    skipped: list[str] = []

    for label, key, factory in (
        ("VirusTotal", settings.virustotal_api_key, VirusTotalProvider),
        ("abuseipdb", settings.abuseipdb_api_key, AbuseIPDBProvider),
        ("AlienVault OTX", settings.otx_api_key, AlienVaultOTXProvider),
    ):
        if not key:
            skipped.append(label)
            continue
        try:
            providers.append(factory())
        except Exception as exc:  # noqa: BLE001 - config problem, not a crash
            skipped.append(f"{label} ({type(exc).__name__})")

    if skipped:
        print(f"providers skipped, no API key configured: {', '.join(skipped)}")

    if not providers:
        raise SystemExit(
            "No provider API keys configured. Set VIRUSTOTAL_API_KEY, "
            "ABUSEIPDB_API_KEY, and/or OTX_API_KEY in backend/.env first."
        )

    return ProviderRegistry(providers)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list",
        action="store_true",
        help="Show the demo events and exit without writing anything.",
    )
    parser.add_argument(
        "--only-ip",
        action="store_true",
        help="Only run the first (8.8.8.8 / google.com) event.",
    )
    args = parser.parse_args()

    events = build_events()
    if args.only_ip:
        events = events[:1]

    print(f"demo events: {len(events)}")
    for item in events:
        print(f"  event {item.event_id}  {item.timestamp:%Y-%m-%d %H:%M:%SZ}")

    if args.list:
        return 0

    registry = build_registry()
    print(f"providers registered: {', '.join(registry.provider_names())}")

    agent = ThreatIntelligenceAgent(registry)
    persistence = ThreatIntelligencePersistenceService()

    totals = {"indicators": 0, "created": 0, "updated": 0, "lookups": 0, "skipped": 0}

    for item in events:
        with SessionLocal() as db:
            analysis = agent.analyze(item)
            result = persistence.persist_analysis(db, analysis)
            db.commit()

        print()
        print(f"event {item.event_id}")
        print(
            f"  indicators extracted {len(analysis.indicators)}  "
            f"results {len(analysis.results)}  failures {len(analysis.failures)}"
        )
        for extracted in analysis.indicators:
            print(f"    - {extracted.canonical_key}  (from {extracted.source_field})")
        for failure in analysis.failures:
            print(f"    ! {failure.provider}: {failure.error_type} -- {failure.message}")
        print(
            f"  persisted: indicators +{result.indicators_created}/"
            f"~{result.indicators_updated}  lookups +{result.lookups_created} "
            f"(skipped {result.lookups_skipped} identical)"
        )
        totals["indicators"] += len(analysis.indicators)
        totals["created"] += result.indicators_created
        totals["updated"] += result.indicators_updated
        totals["lookups"] += result.lookups_created
        totals["skipped"] += result.lookups_skipped

    print()
    print(
        f"totals: {totals['indicators']} indicator extractions, "
        f"{totals['created']} indicators created, {totals['updated']} updated, "
        f"{totals['lookups']} lookups persisted, {totals['skipped']} deduplicated"
    )

    with SessionLocal() as db:
        page = ThreatIntelQueryService(db).list_indicators(page_size=50)

    print(f"read surface now serves {page.total} indicator(s):")
    for record in page.items:
        print(
            f"  {record.indicator_type.value:<6} {record.value:<66} "
            f"lookups={record.lookup_count} status={record.status} "
            f"providers={','.join(record.providers) or '-'}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
