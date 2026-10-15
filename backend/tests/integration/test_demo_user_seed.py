"""Regression tests for the local demo accounts created by the CLI seed.

These cover ``python -m app.cli seed-demo-users``: the two deterministic local
identities used for manual V2 RBAC verification.

What is deliberately *not* tested here: the passwords themselves.  The seed
stores only the platform's own Argon2id hash, and every authentication
assertion below goes through the real ``/api/auth/login`` -> JWT ->
``/api/users/me`` -> role-check path.  No test injects a user into a request
context, so a bypass would fail these tests rather than hide behind them.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import delete, func, select

from app.cli import _DEMO_USERS, _seed_demo_users, main
from app.core.security import hash_password, verify_password
from app.models.audit_log import AuditLog
from app.models.role import Role
from app.models.user import User
from tests.conftest import auth_header


ADMIN_EMAIL = "admin@sentinel.dev"
ANALYST_EMAIL = "analyst@sentinel.dev"

#: Resolved the same way the CLI resolves them: environment override first,
#: local-only default otherwise.  Reading them from ``_DEMO_USERS`` keeps this
#: test honest if the documented local default ever changes.
_ADMIN_PASSWORD = _DEMO_USERS[0][3]
_ANALYST_PASSWORD = _DEMO_USERS[1][3]


@pytest.fixture
def clean_demo_accounts(db_session):
    """Remove the demo accounts so each test starts from a known state.

    Scoped to exactly these two emails: the test database is wiped per test
    run, and nothing outside these addresses is ever touched.  Audit rows are
    cleared first because logging in writes ``audit_logs`` rows that reference
    the user, and the foreign key would otherwise refuse the delete.
    """
    def _purge() -> None:
        db_session.execute(
            delete(AuditLog).where(
                AuditLog.user_id.in_(
                    select(User.id).where(
                        User.email.in_([ADMIN_EMAIL, ANALYST_EMAIL])
                    )
                )
            )
        )
        db_session.execute(
            delete(User).where(User.email.in_([ADMIN_EMAIL, ANALYST_EMAIL]))
        )
        db_session.commit()

    _purge()
    yield
    db_session.rollback()
    _purge()


def _seed() -> dict:
    """Invoke the real CLI seed function and return its payload."""
    import argparse

    return _seed_demo_users(argparse.Namespace(json=True))


def _emails(db_session) -> list[str]:
    return sorted(
        db_session.execute(
            select(User.email).where(
                User.email.in_([ADMIN_EMAIL, ANALYST_EMAIL])
            )
        ).scalars().all()
    )


def _user(db_session, email: str) -> User:
    return db_session.execute(
        select(User).where(User.email == email)
    ).scalar_one()


class TestDemoUserSeed:
    """The seed creates the two accounts and assigns the right roles."""

    def test_creates_both_demo_accounts(self, db_session, clean_demo_accounts):
        payload = _seed()

        assert payload["status"] == "PASS"
        assert payload["summary"]["created"] == 2
        assert payload["summary"]["reused"] == 0
        assert _emails(db_session) == [ADMIN_EMAIL, ANALYST_EMAIL]

    def test_assigns_the_seeded_admin_and_analyst_roles(self, db_session, clean_demo_accounts):
        _seed()

        assert _user(db_session, ADMIN_EMAIL).role.name == "admin"
        assert _user(db_session, ANALYST_EMAIL).role.name == "analyst"

    def test_creates_no_duplicate_users_on_a_second_seed(self, db_session, clean_demo_accounts):
        _seed()
        second = _seed()

        assert second["summary"]["created"] == 0
        assert second["summary"]["reused"] == 2
        for email in (ADMIN_EMAIL, ANALYST_EMAIL):
            count = db_session.execute(
                select(func.count()).select_from(User).where(User.email == email)
            ).scalar_one()
            assert count == 1, f"{email} must exist exactly once"

    def test_second_seed_returns_the_same_identities(self, db_session, clean_demo_accounts):
        first = {a["email"]: a["user_id"] for a in _seed()["accounts"]}
        second = {a["email"]: a["user_id"] for a in _seed()["accounts"]}

        # Real persisted UUIDs, stable across runs -- never invented.
        assert first == second
        for user_id in first.values():
            assert str(_user(db_session, next(e for e in first if first[e] == user_id)).id) == user_id

    def test_reuses_an_existing_account_without_overwriting_its_password(
        self, db_session, clean_demo_accounts
    ):
        """An existing account is preserved, not silently re-credentialed."""
        role = db_session.execute(
            select(Role).where(Role.name == "analyst")
        ).scalar_one()
        pre_existing_hash = hash_password("SomeOtherLocalPassword!9")
        db_session.add(User(
            email=ANALYST_EMAIL,
            password_hash=pre_existing_hash,
            is_active=True,
            role_id=role.id,
        ))
        db_session.commit()

        payload = _seed()

        assert payload["summary"]["created"] == 1
        assert payload["summary"]["reused"] == 1
        stored = _user(db_session, ANALYST_EMAIL).password_hash
        assert verify_password("SomeOtherLocalPassword!9", stored)
        assert not verify_password(_ANALYST_PASSWORD, stored)

    def test_corrects_only_the_role_of_an_existing_account(self, db_session, clean_demo_accounts):
        role = db_session.execute(
            select(Role).where(Role.name == "analyst")
        ).scalar_one()
        db_session.add(User(
            email=ADMIN_EMAIL,
            password_hash=hash_password(_ADMIN_PASSWORD),
            is_active=True,
            role_id=role.id,  # wrong role for the admin demo identity
        ))
        db_session.commit()

        payload = _seed()

        assert payload["summary"]["roles_corrected"] == 1
        assert _user(db_session, ADMIN_EMAIL).role.name == "admin"
        assert _user(db_session, ANALYST_EMAIL).role.name == "analyst"

    def test_never_reports_credential_material(self, db_session, clean_demo_accounts):
        payload = _seed()
        rendered = json.dumps(payload)

        # Prose may mention passwords; actual secret material may not appear.
        assert _ADMIN_PASSWORD not in rendered
        assert _ANALYST_PASSWORD not in rendered
        assert "$argon2" not in rendered
        assert not any(
            "password_hash" in account for account in payload["accounts"]
        )

    def test_persists_only_a_hash_never_plaintext(self, db_session, clean_demo_accounts):
        _seed()

        for email, plaintext in (
            (ADMIN_EMAIL, _ADMIN_PASSWORD),
            (ANALYST_EMAIL, _ANALYST_PASSWORD),
        ):
            stored = _user(db_session, email).password_hash
            assert plaintext not in stored
            assert verify_password(plaintext, stored), "the real hash must verify"


class TestDemoUserAuthentication:
    """The seeded accounts authenticate through the real login endpoint."""

    def test_admin_login_issues_a_token_identifying_the_admin(
        self, client, db_session, clean_demo_accounts
    ):
        _seed()
        response = client.post(
            "/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": _ADMIN_PASSWORD},
        )

        assert response.status_code == 200
        token = response.json()["access_token"]
        assert token.count(".") == 2, "expected a three-segment JWT"

        me = client.get("/api/users/me", headers=auth_header(token))
        assert me.status_code == 200
        assert me.json()["role"] == "admin"
        assert me.json()["id"] == str(_user(db_session, ADMIN_EMAIL).id)

    def test_analyst_login_issues_a_token_identifying_the_analyst(
        self, client, db_session, clean_demo_accounts
    ):
        _seed()
        response = client.post(
            "/api/auth/login",
            json={"email": ANALYST_EMAIL, "password": _ANALYST_PASSWORD},
        )

        assert response.status_code == 200
        token = response.json()["access_token"]

        me = client.get("/api/users/me", headers=auth_header(token))
        assert me.status_code == 200
        assert me.json()["role"] == "analyst"
        assert me.json()["id"] == str(_user(db_session, ANALYST_EMAIL).id)

    @pytest.mark.parametrize("email", [ADMIN_EMAIL, ANALYST_EMAIL])
    def test_wrong_password_is_rejected(self, client, db_session, clean_demo_accounts, email):
        """Proves the seed did not install a bypass or universal credential."""
        _seed()

        response = client.post(
            "/api/auth/login",
            json={"email": email, "password": "definitely-not-the-password"},
        )

        assert response.status_code == 401


class TestDemoUserRBAC:
    """Existing RBAC semantics, exercised through the seeded accounts."""

    def test_admin_reaches_the_admin_only_audit_log(self, client, db_session, clean_demo_accounts):
        _seed()
        token = client.post(
            "/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": _ADMIN_PASSWORD},
        ).json()["access_token"]

        response = client.get("/api/audit/logs", headers=auth_header(token))

        assert response.status_code == 200, "admin must reach the admin-only Audit API"

    def test_analyst_is_denied_the_admin_only_audit_log(self, client, db_session, clean_demo_accounts):
        _seed()
        token = client.post(
            "/api/auth/login",
            json={"email": ANALYST_EMAIL, "password": _ANALYST_PASSWORD},
        ).json()["access_token"]

        response = client.get("/api/audit/logs", headers=auth_header(token))

        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    def test_analyst_reaches_the_shared_security_endpoint(self, client, db_session, clean_demo_accounts):
        _seed()
        token = client.post(
            "/api/auth/login",
            json={"email": ANALYST_EMAIL, "password": _ANALYST_PASSWORD},
        ).json()["access_token"]

        assert client.get(
            "/api/users/security-test", headers=auth_header(token)
        ).status_code == 200
        assert client.get(
            "/api/users/admin-test", headers=auth_header(token)
        ).status_code == 403


class TestDemoUserApiDoesNotLeakSecrets:
    """No user-facing endpoint may expose a password or its hash."""

    def _token_for(self, client, email, password) -> str:
        return client.post(
            "/api/auth/login", json={"email": email, "password": password}
        ).json()["access_token"]

    @pytest.mark.parametrize(
        "email,password",
        [(ADMIN_EMAIL, _ADMIN_PASSWORD), (ANALYST_EMAIL, _ANALYST_PASSWORD)],
    )
    def test_current_user_response_carries_no_credential_material(
        self, client, db_session, clean_demo_accounts, email, password
    ):
        _seed()
        body = client.get(
            "/api/users/me", headers=auth_header(self._token_for(client, email, password))
        ).text

        assert "password" not in body.lower()
        assert password not in body
        assert "$argon2" not in body

    @pytest.mark.parametrize(
        "email,password",
        [(ADMIN_EMAIL, _ADMIN_PASSWORD), (ANALYST_EMAIL, _ANALYST_PASSWORD)],
    )
    def test_login_response_carries_no_credential_material(
        self, client, db_session, clean_demo_accounts, email, password
    ):
        _seed()
        body = client.post(
            "/api/auth/login", json={"email": email, "password": password}
        ).text

        assert "password" not in body.lower()
        assert "$argon2" not in body


class TestDemoUserCliSurface:
    """The seed is reachable through the project's own CLI conventions."""

    def test_cli_subcommand_exists_and_reports_no_secret_material(self, capsys, db_session, clean_demo_accounts):
        exit_code = main(["seed-demo-users", "--json"])

        assert exit_code == 0
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload["status"] == "PASS"
        assert {a["email"] for a in payload["accounts"]} == {ADMIN_EMAIL, ANALYST_EMAIL}
        assert _ADMIN_PASSWORD not in out
        assert _ANALYST_PASSWORD not in out

    def test_cli_help_lists_the_seed_command(self, capsys):
        with pytest.raises(SystemExit):
            main(["--help"])
        assert "seed-demo-users" in capsys.readouterr().out