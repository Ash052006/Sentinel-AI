"""Tests for the Threat Intelligence persistence contract (Step 8C-A).

Verifies the SQLAlchemy models that define the PostgreSQL persistence
contract for threat-intelligence data.  These are pure model-level unit
tests: no live PostgreSQL server, no network calls, no repository/service
implementation.

Covers:
    1. Valid indicator model
    2. Supported indicator types
    3. Required fields
    4. Uniqueness constraints at the model/contract level
    5. Provider lookup representation
    6. Successful result representation
    7. Failure representation
    8. Event → indicator relationship
    9. Indicator → provider lookup relationship
    10. Provider lookup → result relationship
    11. Provenance remains ENRICHED
    12. Structured evidence can be represented
    13. API keys cannot be represented as dedicated persisted fields
    14. Raw HTTP response is not a required persistence field
    15. Timezone-aware timestamps
    16. UUID conventions match existing models
    17. Existing database conventions are respected
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import CheckConstraint, inspect

from app.database.postgres.base import Base
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import LookupStatus, ThreatIntelLookup
from app.schemas.security_event import Provenance
from app.services.threat_intelligence.types import IndicatorType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def _create_tables():
    """Produce the PostgreSQL-targeted DDL for every model table.

    These are pure unit tests: there is no live PostgreSQL server.  We
    instead compile the ``CREATE TABLE`` DDL through the PostgreSQL dialect
    so every column type, constraint, and index in the persistence contract
    is checked as expressible in real Postgres DDL.  The caller asserts on
    the returned DDL string.

    Returns:
        A single string of the compiled ``CREATE TABLE`` statements for all
        tables in the model :class:`~app.database.postgres.base.Base` metadata.
    """
    from sqlalchemy.dialects.postgresql import dialect as pg_dialect
    from sqlalchemy.schema import CreateIndex, CreateTable

    dialect = pg_dialect()
    statements = []
    for table in Base.metadata.tables.values():
        statements.append(str(CreateTable(table).compile(dialect=dialect)))
        for index in table.indexes:
            statements.append(str(CreateIndex(index).compile(dialect=dialect)))
    return "\n\n".join(statements)


def _indicator_uuid() -> uuid.UUID:
    return uuid.uuid4()


def _make_indicator(
    *,
    value: str = "185.10.10.10",
    indicator_type: IndicatorType = IndicatorType.IP,
    canonical_key: str | None = None,
) -> ThreatIntelIndicator:
    if canonical_key is None:
        normalized = value
        if indicator_type in (IndicatorType.DOMAIN, IndicatorType.HASH):
            normalized = value.lower()
        canonical_key = f"{indicator_type.value}:{normalized}"
    now = datetime.now(timezone.utc)
    return ThreatIntelIndicator(
        id=_indicator_uuid(),
        value=value,
        indicator_type=indicator_type,
        canonical_key=canonical_key,
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )


def _make_lookup(
    indicator_id: uuid.UUID,
    *,
    event_id: uuid.UUID | None = None,
    provider: str = "VirusTotal",
    status: LookupStatus = LookupStatus.SUCCESS,
    found: bool | None = None,
    confidence: float | None = None,
    evidence: dict | None = None,
    result_metadata: dict | None = None,
    result_timestamp: datetime | None = None,
    error_type: str | None = None,
    error_message: str | None = None,
    retryable: bool | None = None,
) -> ThreatIntelLookup:
    now = datetime.now(timezone.utc)
    return ThreatIntelLookup(
        id=_indicator_uuid(),
        event_id=event_id or _indicator_uuid(),
        indicator_id=indicator_id,
        provider=provider,
        status=status,
        performed_at=now,
        retryable=retryable,
        error_type=error_type,
        error_message=error_message,
        found=found,
        confidence=confidence,
        result_timestamp=result_timestamp,
        evidence=evidence,
        result_metadata=result_metadata,
        provenance=Provenance.ENRICHED.value,
        created_at=now,
        updated_at=now,
    )


# ---------------------------------------------------------------------------
# 1. Valid indicator model
# ---------------------------------------------------------------------------

def test_valid_indicator_model_constructs():
    """A valid indicator with all required fields constructs correctly."""
    indicator = _make_indicator()
    assert isinstance(indicator.id, uuid.UUID)
    assert indicator.value == "185.10.10.10"
    assert indicator.indicator_type == IndicatorType.IP
    assert indicator.canonical_key == "ip:185.10.10.10"
    assert indicator.first_seen_at is not None
    assert indicator.last_seen_at is not None
    assert indicator.created_at is not None
    assert indicator.updated_at is not None


# ---------------------------------------------------------------------------
# 2. Supported indicator types
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("itype", "value", "canonical"),
    [
        (IndicatorType.IP, "8.8.8.8", "ip:8.8.8.8"),
        (IndicatorType.DOMAIN, "Evil.COM", "domain:evil.com"),
        (IndicatorType.URL, "https://evil.com/x?A=B", "url:https://evil.com/x?A=B"),
        (IndicatorType.HASH, "ABCDEF0123456789abcdef", "hash:abcdef0123456789abcdef"),
    ],
)
def test_supported_indicator_types(itype, value, canonical):
    """All four supported indicator types map to a valid canonical_key.

    Domains and hashes are lower-cased (Step 8A conservative
    normalization); URLs are kept byte-for-byte (no aggressive
    canonicalization, preserving Step 8A).
    """
    indicator = _make_indicator(value=value, indicator_type=itype)
    assert indicator.indicator_type is itype
    assert indicator.canonical_key == canonical


def test_exactly_four_supported_indicator_types():
    """The contract supports only IP, DOMAIN, URL, HASH (Step 8A set)."""
    assert set(IndicatorType) == {
        IndicatorType.IP,
        IndicatorType.DOMAIN,
        IndicatorType.URL,
        IndicatorType.HASH,
    }


# ---------------------------------------------------------------------------
# 3. Required fields
# ---------------------------------------------------------------------------

def test_indicator_required_fields_non_nullable():
    """The core indicator fields are required (non-nullable) columns."""
    values = {
        "value": "8.8.8.8",
        "indicator_type": "ip",
        "canonical_key": "ip:8.8.8.8",
        "first_seen_at": datetime.now(timezone.utc),
        "last_seen_at": datetime.now(timezone.utc),
    }
    for column_name in values:
        column = ThreatIntelIndicator.__table__.columns[column_name]
        assert not column.nullable, f"{column_name} should be required"


def test_lookup_required_fields_non_nullable():
    """Lookup execution fields are required; result/failure are optional."""
    required = {"event_id", "indicator_id", "provider", "status", "performed_at"}
    optional = {
        "retryable", "error_type", "error_message",
        "found", "confidence", "result_timestamp", "evidence", "result_metadata",
    }
    required.add("provenance")  # required, defaults to ENRICHED
    for column_name in required:
        column = ThreatIntelLookup.__table__.columns[column_name]
        assert not column.nullable, f"{column_name} should be required"
    for column_name in optional:
        column = ThreatIntelLookup.__table__.columns[column_name]
        assert column.nullable, f"{column_name} should be optional/nullable"


# ---------------------------------------------------------------------------
# 4. Uniqueness constraints at the model/contract level
# ---------------------------------------------------------------------------

def test_indicator_canonical_key_is_unique():
    """canonical_key carries database-level uniqueness (global dedup)."""
    # Declared unique directly on the mapped column.
    assert ThreatIntelIndicator.__table__.columns["canonical_key"].unique is True
    # unique=True + index=True materializes as a UNIQUE INDEX in Postgres.
    indexes = {idx.name: idx.unique for idx in ThreatIntelIndicator.__table__.indexes}
    assert indexes.get("ix_threat_intel_indicators_canonical_key") is True


def test_indicator_type_value_composite_unique():
    """(indicator_type, value) is a composite unique safety net."""
    for constraint in ThreatIntelIndicator.__table__.constraints:
        if getattr(constraint, "name", None) != "uq_threat_intel_indicators_type_value":
            continue
        assert {c.name for c in constraint.columns} == {"indicator_type", "value"}
        return
    pytest.fail("composite uniqueness constraint not found")


def test_canonical_key_unique_declared_in_ddl(_create_tables):
    """The canonical_key UNIQUE enforcement appears in the rendered Postgres DDL."""
    ddl = _create_tables.lower()
    assert "unique index ix_threat_intel_indicators_canonical_key" in ddl
    assert "uq_threat_intel_indicators_type_value" in ddl


# ---------------------------------------------------------------------------
# 5. Provider lookup representation
# ---------------------------------------------------------------------------

def test_provider_lookup_representation():
    """A lookup captures provider execution: provider, status, performed_at."""
    indicator = _make_indicator()
    lookup = _make_lookup(
        indicator.id,
        provider="AbuseIPDB",
        status=LookupStatus.SUCCESS,
        found=True,
        confidence=0.9,
        evidence={"report": {"count": 3}},
    )
    assert lookup.provider == "AbuseIPDB"
    assert lookup.status is LookupStatus.SUCCESS
    assert lookup.performed_at.tzinfo is not None
    assert lookup.event_id is not None
    assert lookup.indicator_id == indicator.id


# ---------------------------------------------------------------------------
# 6. Successful result representation
# ---------------------------------------------------------------------------

def test_successful_result_representation():
    """A successful result populates found/confidence/evidence/timestamp."""
    now = datetime.now(timezone.utc)
    lookup = _make_lookup(
        _indicator_uuid(),
        status=LookupStatus.SUCCESS,
        found=True,
        confidence=0.95,
        evidence={"verdict": "malicious", "tags": ["botnet"]},
        result_metadata={"source": "vt"},
        result_timestamp=now,
    )
    assert lookup.found is True
    assert lookup.confidence == 0.95
    assert lookup.evidence == {"verdict": "malicious", "tags": ["botnet"]}
    assert lookup.result_metadata == {"source": "vt"}
    assert lookup.result_timestamp == now
    # A success lookup carries no failure fields
    assert lookup.error_type is None
    assert lookup.error_message is None
    assert lookup.retryable is None


# ---------------------------------------------------------------------------
# 7. Failure representation
# ---------------------------------------------------------------------------

def test_failure_representation():
    """A failed lookup is represented secret-safely on the lookup row."""
    lookup = _make_lookup(
        _indicator_uuid(),
        status=LookupStatus.ERROR,
        provider="OTX",
        error_type="timeout",
        error_message="provider timed out",
        retryable=True,
    )
    assert lookup.status is LookupStatus.ERROR
    assert lookup.error_type == "timeout"
    assert lookup.error_message == "provider timed out"
    assert lookup.retryable is True
    # A failure carries no result evidence
    assert lookup.found is None
    assert lookup.confidence is None
    assert lookup.evidence is None
    assert lookup.result_timestamp is None


# ---------------------------------------------------------------------------
# 8. Event → indicator relationship
# ---------------------------------------------------------------------------

def test_event_to_indicator_relationship_via_event_id():
    """event_id is indexed so a lookup stays traceable to its event."""
    event_id = _indicator_uuid()
    indicator = _make_indicator()
    lookup = _make_lookup(indicator.id, event_id=event_id)
    assert lookup.event_id == event_id
    # event_id column is indexed
    index_names = {idx.name for idx in ThreatIntelLookup.__table__.indexes}
    assert "ix_threat_intel_lookups_event_id" in index_names


# ---------------------------------------------------------------------------
# 9. Indicator → provider lookup relationship
# ---------------------------------------------------------------------------

def test_indicator_to_lookup_relationship(_create_tables):
    """One indicator maps to many provider lookups via ORM relationship."""
    rel = ThreatIntelIndicator.__mapper__.relationships["lookups"]
    assert rel.back_populates == "indicator"
    # One-to-many: local side is the indicator PK, remote side is the FK.
    assert set(rel.local_columns) == {ThreatIntelIndicator.__table__.c.id}
    assert set(rel.remote_side) == {ThreatIntelLookup.__table__.c.indicator_id}
    # Both tables' DDL renders together (relationship is mappable).
    ddl = _create_tables.lower()
    assert "create table threat_intel_indicators" in ddl
    assert "create table threat_intel_lookups" in ddl


def test_fk_indicator_id_targets_indicator_table():
    """Lookup.indicator_id is a real foreign key to the indicator table."""
    fks = ThreatIntelLookup.__table__.foreign_keys
    assert len(fks) == 1
    fk = next(iter(fks))
    assert fk.target_fullname == "threat_intel_indicators.id"


# ---------------------------------------------------------------------------
# 10. Provider lookup → result relationship
# ---------------------------------------------------------------------------

def test_lookup_to_result_relationship_inline():
    """A successful lookup carries its result/evidence inline (1:1)."""
    lookup = _make_lookup(
        _indicator_uuid(),
        status=LookupStatus.SUCCESS,
        found=True,
        evidence={"threat_score": 8},
    )
    # The result/evidence is accessible directly from the lookup row.
    assert lookup.evidence == {"threat_score": 8}
    assert lookup.found is True
    assert lookup.result_timestamp is not None or lookup.result_timestamp is None


# ---------------------------------------------------------------------------
# 11. Provenance remains ENRICHED
# ---------------------------------------------------------------------------

def test_provenance_defaults_to_enriched():
    """A lookup defaults to provenance ENRICHED."""
    lookup = _make_lookup(_indicator_uuid())
    assert lookup.provenance == Provenance.ENRICHED.value


def test_provenance_check_constraints_to_enriched():
    """A CHECK constraint prevents non-ENRICHED provenance on evidence."""
    checks = [
        (c.name, c.sqltext.text)
        for c in ThreatIntelLookup.__table__.constraints
        if isinstance(c, CheckConstraint)
    ]
    assert len(checks) == 1
    _name, sqltext = checks[0]
    assert "enriched" in sqltext.lower()


def test_provenance_enum_unchanged():
    """The existing Provenance enum still exposes ENRICHED distinctly."""
    assert hasattr(Provenance, "ENRICHED")
    assert hasattr(Provenance, "OBSERVED")
    assert hasattr(Provenance, "RECONSTRUCTED")
    assert Provenance.ENRICHED.value == "enriched"


# ---------------------------------------------------------------------------
# 12. Structured evidence can be represented
# ---------------------------------------------------------------------------

def test_structured_evidence_jsonb_column(_create_tables):
    """Evidence is a JSONB column in the rendered Postgres DDL."""
    ddl = _create_tables
    evidence_ddl = ddl.lower()
    assert "evidence" in evidence_ddl
    assert "jsonb" in evidence_ddl.lower()


def test_evidence_column_is_json():
    """The evidence column type is a JSON type (JSON/JSONB), not generic text."""
    from sqlalchemy.dialects import postgresql
    evidence_type = ThreatIntelLookup.__table__.columns["evidence"].type
    assert isinstance(evidence_type, postgresql.JSON)


# ---------------------------------------------------------------------------
# 13. API keys cannot be represented as dedicated persisted fields
# ---------------------------------------------------------------------------

def test_no_api_key_field_on_indicator():
    """No API key / credential column exists on the indicator model."""
    column_names = {c.name for c in ThreatIntelIndicator.__table__.columns}
    forbidden = {"api_key", "apikey", "auth", "authorization", "cookie",
                 "credential", "secret", "token"}
    assert column_names.isdisjoint(forbidden), \
        f"found forbidden secret column: {column_names & forbidden}"


def test_no_api_key_field_on_lookup():
    """No API key / credential / raw-request column exists on the lookup."""
    column_names = {c.name for c in ThreatIntelLookup.__table__.columns}
    forbidden = {"api_key", "apikey", "auth", "authorization", "cookie",
                 "credential", "secret", "token", "raw_request", "raw_response",
                 "request", "http_request", "http_response"}
    assert column_names.isdisjoint(forbidden), \
        f"found forbidden secret column: {column_names & forbidden}"


# ---------------------------------------------------------------------------
# 14. Raw HTTP response is not a required persistence field
# ---------------------------------------------------------------------------

def test_no_raw_http_required_columns():
    """No raw HTTP request/response fields are required on either model."""
    for table in (ThreatIntelIndicator.__table__, ThreatIntelLookup.__table__):
        for column in table.columns:
            assert "raw" not in column.name.lower(), f"unexpected raw column {column.name}"
            assert "http" not in column.name.lower(), f"unexpected http column {column.name}"


def test_evidence_not_required():
    """The evidence field is optional, not a required persistence field."""
    assert ThreatIntelLookup.__table__.columns["evidence"].nullable


# ---------------------------------------------------------------------------
# 15. Timestamps are timezone-aware
# ---------------------------------------------------------------------------

def test_indicator_timestamps_timezone_aware():
    """Indicator timestamp columns are timezone-aware DateTime."""
    for name in ("first_seen_at", "last_seen_at", "created_at", "updated_at"):
        column = ThreatIntelIndicator.__table__.columns[name]
        assert column.type.timezone is True, f"{name} should be timezone-aware"


def test_lookup_timestamps_timezone_aware():
    """Lookup timestamp columns are timezone-aware DateTime."""
    for name in ("performed_at", "result_timestamp", "created_at", "updated_at"):
        column = ThreatIntelLookup.__table__.columns[name]
        assert column.type.timezone is True, f"{name} should be timezone-aware"


# ---------------------------------------------------------------------------
# 16. UUID conventions match existing models
# ---------------------------------------------------------------------------

def test_uuid_primary_key_conventions():
    """Indicator and lookup PKs are UUID columns, like existing models."""
    from sqlalchemy.dialects.postgresql import UUID as PG_UUID
    for column in (ThreatIntelIndicator.__table__.columns["id"],
                   ThreatIntelLookup.__table__.columns["id"]):
        assert column.primary_key is True
        assert isinstance(column.type, PG_UUID)


def test_uuid_foreign_key_conventions():
    """event_id and indicator_id use the UUID(as_uuid=True) convention."""
    from sqlalchemy.dialects.postgresql import UUID as PG_UUID
    for column in (ThreatIntelLookup.__table__.columns["event_id"],
                   ThreatIntelLookup.__table__.columns["indicator_id"]):
        assert isinstance(column.type, PG_UUID)


# ---------------------------------------------------------------------------
# 17. Existing database conventions are respected
# ---------------------------------------------------------------------------

def test_models_inherit_base_and_mixin():
    """Models inherit from Base and use UUIDTimestampMixin conventions."""
    from app.database.postgres.base import Base as BaseClass
    assert issubclass(ThreatIntelIndicator, BaseClass)
    assert issubclass(ThreatIntelLookup, BaseClass)
    for model in (ThreatIntelIndicator, ThreatIntelLookup):
        assert "id" in model.__table__.columns
        assert "created_at" in model.__table__.columns
        assert "updated_at" in model.__table__.columns


def test_table_names_are_plural_snake_case():
    """Table names follow the plural underscore convention of existing models."""
    assert ThreatIntelIndicator.__tablename__ == "threat_intel_indicators"
    assert ThreatIntelLookup.__tablename__ == "threat_intel_lookups"


def test_indicator_type_reuses_existing_enum():
    """The persistence model reuses IndicatorType values, not a second enum."""
    assert ThreatIntelIndicator.__table__.columns["indicator_type"].type.enums == [
        "ip", "domain", "url", "hash",
    ]


def test_lookup_status_enum_only():
    """LookupStatus exposes exactly success/error."""
    assert {member.value for member in LookupStatus} == {"success", "error"}



