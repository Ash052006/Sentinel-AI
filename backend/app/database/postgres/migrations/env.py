from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings
from app.database.postgres.base import Base

# Import models here so Alembic can detect them.
# Models will be added as the project grows.
from app.models.role import Role
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import ThreatIntelLookup
from app.models.detection_result import DetectionResult
from app.models.detection_rule_failure import DetectionRuleFailure
from app.models.correlation_result import CorrelationResult
from app.models.correlation_member import CorrelationMember
from app.models.risk_assessment import RiskAssessment
from app.models.incident_memory import IncidentMemoryRow
from app.models.detection_rule_version import DetectionRuleVersionRow
from app.models.detection_rule_release import DetectionRuleReleaseRow
from app.models.detection_rule_change import DetectionRuleChangeRow
from app.models.approval_request import ApprovalRequestRow
from app.models.soar_playbook import SoarPlaybookRow
from app.models.soar_playbook_version import SoarPlaybookVersionRow
from app.models.soar_execution import SoarExecutionRow
from app.models.soar_step_execution import SoarStepExecutionRow
# Every model module must be imported here so its table reaches
# ``target_metadata``.  ``threat_hunt`` and ``incident_report`` were only
# present via a transitive import, which means a harmless refactor could drop
# their tables from the metadata entirely and make autogenerate propose
# deleting live tables.  Keep this list exhaustive.
from app.models.threat_hunt import (
    ThreatHuntEvidenceRow,
    ThreatHuntFindingRow,
    ThreatHuntRow,
    ThreatHuntTimelineItemRow,
)
from app.models.incident_report import IncidentReportRow


config = context.config

# Use the database URL from SentinelAI configuration.
config.set_main_option(
    "sqlalchemy.url",
    settings.database_url,
)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in offline mode."""

    url = config.get_main_option("sqlalchemy.url")

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in online mode."""

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()