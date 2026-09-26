import uuid
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

# Ensure the app package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import app
from app.core.security import create_access_token, hash_password
from app.database.postgres.session import SessionLocal
from app.models.role import Role
from app.models.user import User


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
