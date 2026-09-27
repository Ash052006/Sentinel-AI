"""Bearer-token subject hardening for ``get_current_user``.

A signature-valid token is not sufficient for authentication: the ``sub``
claim is used verbatim as a ``users.id`` (native PostgreSQL ``uuid``)
comparison.  A token minted with a non-UUID subject used to reach the
database and surface a driver-level ``DataError`` as **HTTP 500** on every
protected route, so any principal able to mint a token could turn a
malformed claim into a server error (and pollute logs with a traceback).

These tests pin the corrected contract:

* a well-formed UUID ``sub`` resolves normally;
* a non-string or non-UUID ``sub`` is rejected as **401**, never 500;
* a genuine database fault is **not** laundered into a 401 — an outage is a
  server problem and must stay one.

The suite is hermetic: an in-memory SQLite session backs the dependency
override, so no shared/development database is touched.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731
SQLiteTypeCompiler.visit_UUID = lambda self, type_, **kw: "CHAR(32)"  # noqa: E731
SQLiteTypeCompiler.visit_uuid = lambda self, type_, **kw: "CHAR(32)"  # noqa: E731

from app.api.dependencies import get_current_user, get_db  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.security import create_access_token, hash_password  # noqa: E402
from app.database.postgres.base import Base  # noqa: E402
from app.models.role import Role  # noqa: E402
from app.models.user import User  # noqa: E402
from tests.conftest import auth_header  # noqa: E402


def _mint(sub: object) -> str:
    """Mint a *signature-valid* token carrying an arbitrary ``sub``."""
    payload = {
        "sub": sub,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    return jwt.encode(
        payload, settings.jwt_secret, algorithm=settings.jwt_algorithm
    )


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def client(db: Session) -> TestClient:
    app = FastAPI()

    @app.get("/protected")
    def _protected(user: User = Depends(get_current_user)) -> dict[str, str]:
        return {"user_id": str(user.id)}

    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture()
def a_user(db: Session) -> User:
    role = Role(name="analyst")
    user = User(
        email=f"token-probe-{uuid.uuid4().hex[:12]}@example.com",
        password_hash=hash_password("Sup3rSecret!"),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


class TestSubjectValidation:
    def test_valid_uuid_subject_is_accepted(self, client, a_user) -> None:
        response = client.get("/protected", headers=auth_header(create_access_token(str(a_user.id))))
        assert response.status_code == 200
        assert response.json() == {"user_id": str(a_user.id)}

    def test_non_uuid_string_subject_is_401_not_500(self, client, a_user) -> None:
        for bad in ("not-a-uuid", "", "12345", "../../etc/passwd", "null"):
            response = client.get("/protected", headers=auth_header(_mint(bad)))
            assert response.status_code == 401, bad

    def test_non_string_subject_is_401(self, client, a_user) -> None:
        for bad in (12345, 1.5, True, ["a"], {"sub": "x"}, None):
            response = client.get("/protected", headers=auth_header(_mint(bad)))
            assert response.status_code == 401, bad

    def test_brace_and_hex_forms_resolve_to_the_same_user(self, client, a_user) -> None:
        """``uuid.UUID`` accepts several textual spellings; they must all
        authenticate as the same principal rather than 500 or 401."""
        raw = str(a_user.id)
        hyphenless = raw.replace("-", "")
        response = client.get(
            "/protected", headers=auth_header(_mint(hyphenless.upper()))
        )
        assert response.status_code == 200
        assert response.json() == {"user_id": str(a_user.id)}


class TestFailureSemantics:
    def test_unknown_but_wellformed_subject_is_401(self, client, a_user) -> None:
        ghost = uuid.uuid4()
        response = client.get("/protected", headers=auth_header(create_access_token(str(ghost))))
        assert response.status_code == 401

    def test_database_fault_is_not_reported_as_auth_failure(
        self, db: Session, a_user, client
    ) -> None:
        """A DB outage must stay a 5xx.  Conflating it with 401 would send
        every client into a re-login loop during an incident and would hide
        the real fault from monitoring."""

        def _explode(*args, **kwargs):
            raise OperationalError("SELECT 1", {}, Exception("connection refused"))

        db.execute = _explode  # type: ignore[method-assign]
        try:
            response = client.get(
                "/protected", headers=auth_header(create_access_token(str(a_user.id)))
            )
        finally:
            del db.execute
        assert response.status_code >= 500
