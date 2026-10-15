import os
import uuid
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Test-database isolation — must happen BEFORE the app package is imported.
#
# ``app.core.config.settings`` reads DATABASE_URL at import time and
# ``app.database.postgres.session`` builds its engine from that singleton, so
# the redirection has to be in place before the first ``app`` import.  Without
# it the entire suite writes to the development database, which is how the dev
# database accumulated thousands of orphaned test users, correlations and audit
# rows.
# ---------------------------------------------------------------------------
_TEST_DB_SUFFIX = "_test"


def _url_from_env_file() -> str | None:
    """Read DATABASE_URL from the backend ``.env`` without importing settings.

    ``.env`` may legitimately repeat a key (``DATABASE_URL=`` as a placeholder
    followed by the real value); pydantic-settings lets the last occurrence
    win, so this mirrors that and keeps the last non-empty value.
    """
    env_path = Path(__file__).resolve().parent.parent / ".env"
    found: str | None = None
    try:
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key.strip().upper() == "DATABASE_URL":
                value = value.strip().strip("'\"")
                if value:
                    found = value
    except OSError:
        return None
    return found


def _isolate_test_database() -> str:
    """Point DATABASE_URL at a dedicated test database and return it.

    ``SENTINEL_TEST_DATABASE_URL`` overrides the derived name.  If it resolves
    to the development database the suite would pollute real data, so refuse to
    start rather than silently doing so.
    """
    explicit = os.environ.get("SENTINEL_TEST_DATABASE_URL")
    base = os.environ.get("DATABASE_URL") or _url_from_env_file()
    if explicit:
        url = explicit
    elif base:
        # Preserve the driver (postgresql+psycopg://) and credentials; only the
        # database name changes.  The suffix is applied idempotently so pointing
        # DATABASE_URL at an already-suffixed name cannot silently produce a
        # doubled ``_test_test`` database — a different, freshly migrated
        # database whose empty state would mask order-dependent failures.
        prefix, _, name = base.rstrip("/").rpartition("/")
        while name.endswith(_TEST_DB_SUFFIX):
            name = name[: -len(_TEST_DB_SUFFIX)]
        url = f"{prefix}/{name}{_TEST_DB_SUFFIX}"
    else:
        pytest.exit(
            "Cannot isolate tests: set SENTINEL_TEST_DATABASE_URL or "
            "DATABASE_URL (or a backend .env) so a test database can be "
            "derived.",
            returncode=4,
        )

    # Never write tests into the development database.  The canonical development
    # name is the base name with any test suffix stripped, so every combination
    # is refused — including an explicit SENTINEL_TEST_DATABASE_URL that names
    # the development database while DATABASE_URL happens to name the test one.
    if base:
        dev_prefix, _, dev_name = base.rstrip("/").rpartition("/")
        while dev_name.endswith(_TEST_DB_SUFFIX):
            dev_name = dev_name[: -len(_TEST_DB_SUFFIX)]
        test_prefix, _, test_name = url.rstrip("/").rpartition("/")
        if (dev_prefix, dev_name) == (test_prefix, test_name):
            pytest.exit(
                "Refusing to run the test suite against the development "
                f"database ({url}). The suite never writes to the database "
                "named in DATABASE_URL; set SENTINEL_TEST_DATABASE_URL to "
                "choose a different one.",
                returncode=4,
            )
    os.environ["DATABASE_URL"] = url
    return url


_isolate_test_database()

# Ensure the app package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.main import app
from app.core.security import create_access_token, hash_password
from app.database.postgres.session import SessionLocal
from app.models.role import Role
from app.models.user import User


@pytest.fixture(scope="session", autouse=True)
def _test_database() -> None:
    """Create the isolated test database and bring it to the current schema.

    Uses the real Alembic migrations so the tests exercise the same schema,
    CHECK constraints and comments as production, rather than a metadata-only
    approximation that could silently diverge.
    """
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    url = make_url(os.environ["DATABASE_URL"])
    target = url.database

    # Connect to the maintenance database to create ours if it is absent.
    maintenance = create_engine(
        url.set(database="postgres").render_as_string(hide_password=False),
        isolation_level="AUTOCOMMIT",
        connect_args={"connect_timeout": 5},
    )
    try:
        with maintenance.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": target},
            ).scalar()
            if not exists:
                # Identifier cannot be bound as a parameter; quote it instead.
                conn.execute(text(f'CREATE DATABASE "{target}"'))
    except Exception as exc:  # noqa: BLE001
        pytest.exit(
            f"Could not reach PostgreSQL to prepare the test database: {exc}",
            returncode=4,
        )
    finally:
        maintenance.dispose()

    from alembic import command
    from alembic.config import Config

    backend_dir = Path(__file__).resolve().parent.parent
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "app/database/postgres/migrations"))
    cfg.set_main_option("sqlalchemy.url", url.render_as_string(hide_password=False))
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session", autouse=True)
def _shipped_detection_rules(_test_database: None) -> None:
    """Deploy the shipped detection rules into the isolated test database.

    Rules are governed *reference data*, not evidence produced by a test run.
    Detection needs a deployed rule set to match anything at all, and the demo
    scenario correlates real detections.  Without this the demo reported one
    detection instead of nine — a failure that was previously masked because
    the development database already held rule rows from earlier demo runs.

    Idempotent: a rule already released and deployed is left untouched, so
    repeated suite runs converge instead of accumulating versions.
    """
    from app.database.postgres.session import SessionLocal
    from app.services.detection_as_code.lifecycle import LifecycleService
    from app.services.detection_as_code.manifest import load_manifest
    from app.services.detection.rule_loader import DEFAULT_RULES_DIR
    from app.services.detection_as_code.repository import all_deployed_releases
    from app.services.detection_as_code.validation import (
        DetectionRuleValidationService,
    )

    manifest = load_manifest(DEFAULT_RULES_DIR)
    validator = DetectionRuleValidationService(rules_root=DEFAULT_RULES_DIR)

    db = SessionLocal()
    try:
        # One query for the whole set, rather than a registry rebuild per rule.
        already = {row.rule_id for row in all_deployed_releases(db)}
        pending = [e for e in manifest.rules if e.rule_id not in already]
        if pending:
            lifecycle = LifecycleService(
                db, validator=validator, actor_user_id=None, actor_role="admin"
            )
            for entry in pending:
                lifecycle.validate_rule(entry.rule_id, version="1.0.0")
                lifecycle.release(entry.rule_id, "1.0.0")
                lifecycle.deploy(entry.rule_id, "1.0.0")
            db.commit()
    finally:
        db.close()


@pytest.fixture(scope="session")
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture(scope="session")
def db_session():
    """Provide a database session for test setup/teardown."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="session")
def _ensure_roles(db_session: Session):
    """Ensure required roles exist in the database. Runs once per test session."""
    for role_name in ("admin", "analyst", "ciso"):
        existing = db_session.execute(
            select(Role).where(Role.name == role_name)
        ).scalar_one_or_none()

        if existing is None:
            role = Role(name=role_name, description=f"{role_name} role")
            db_session.add(role)

    db_session.commit()


@pytest.fixture(scope="session")
def admin_user(db_session: Session, _ensure_roles) -> User:
    """Create or retrieve a test admin user."""
    email = f"test-admin-{uuid.uuid4().hex[:8]}@example.com"
    role = db_session.execute(
        select(Role).where(Role.name == "admin")
    ).scalar_one()

    user = User(
        email=email,
        password_hash=hash_password("TestPassword123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="session")
def analyst_user(db_session: Session, _ensure_roles) -> User:
    """Create or retrieve a test analyst user."""
    email = f"test-analyst-{uuid.uuid4().hex[:8]}@example.com"
    role = db_session.execute(
        select(Role).where(Role.name == "analyst")
    ).scalar_one()

    user = User(
        email=email,
        password_hash=hash_password("TestPassword123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="session")
def ciso_user(db_session: Session, _ensure_roles) -> User:
    """Create or retrieve a test ciso user."""
    email = f"test-ciso-{uuid.uuid4().hex[:8]}@example.com"
    role = db_session.execute(
        select(Role).where(Role.name == "ciso")
    ).scalar_one()

    user = User(
        email=email,
        password_hash=hash_password("TestPassword123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="session")
def admin_token(admin_user: User) -> str:
    """Generate a valid JWT token for the admin user."""
    return create_access_token(str(admin_user.id))


@pytest.fixture(scope="session")
def analyst_token(analyst_user: User) -> str:
    """Generate a valid JWT token for the analyst user."""
    return create_access_token(str(analyst_user.id))


@pytest.fixture(scope="session")
def ciso_token(ciso_user: User) -> str:
    """Generate a valid JWT token for the ciso user."""
    return create_access_token(str(ciso_user.id))


def auth_header(token: str) -> dict[str, str]:
    """Return an Authorization header dict for the given token."""
    return {"Authorization": f"Bearer {token}"}


# V3.23 debate fixtures are defined in their own module but must be visible to
# both the unit and integration debate suites, so they are re-exported here.
# Imported last to keep the V2 fixtures above readable.
from tests.integration.debate_fixtures import (  # noqa: E402,F401
    debate_correlation,
)
