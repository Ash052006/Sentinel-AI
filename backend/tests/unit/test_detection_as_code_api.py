"""Detection-as-Code API + RBAC tests (V2.17).

Exercises the FastAPI surface for the governed lifecycle: authentication,
the role surface (ciso = read-only, analyst = read + validate, admin = full
lifecycle), HTTP semantics, and idempotent transitions against shipped
rules that the baseline onboarding already released/deployed.
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.models.role import Role
from app.models.user import User
from tests.conftest import (
    auth_header as _auth,
    admin_token,
    analyst_token,
    ciso_token,
)

RULE_ID = "11111111-1111-4111-8111-111111111111"

LIST_URL = "/api/detection-as-code"
DETAIL_URL = f"/api/detection-as-code/{RULE_ID}"
UNKNOWN_URL = "/api/detection-as-code/00000000-0000-0000-0000-000000000000"

POST_URLS = {
    "validate": "/api/detection-as-code/validate",
    "release": "/api/detection-as-code/release",
    "deploy": "/api/detection-as-code/deploy",
    "rollback": "/api/detection-as-code/rollback",
    "enabled": "/api/detection-as-code/enabled",
}


@pytest.fixture(scope="session")
def outsider_analyst_token(db_session: Session, _ensure_roles) -> str:
    """A non-SOC role token: read is denied, and so are all mutations."""
    role = db_session.execute(
        select(Role).where(Role.name == "viewer")
    ).scalar_one_or_none()
    if role is None:
        role = Role(name="viewer", description="read-only non-SOC role")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)
    email = f"test-viewer-{uuid.uuid4().hex[:8]}@example.com"
    user = User(
        email=email,
        password_hash=hash_password("TestPassword123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return create_access_token(str(user.id))


class TestAuthentication:
    def test_list_requires_token(self, client: TestClient):
        assert client.get(LIST_URL).status_code == 401

    def test_detail_requires_token(self, client: TestClient):
        assert client.get(DETAIL_URL).status_code == 401

    def test_mutations_require_token(self, client: TestClient):
        for url in POST_URLS.values():
            assert client.post(url, json={"rule_id": RULE_ID}).status_code == 401

    def test_invalid_token_rejected(self, client: TestClient):
        bogus = {"Authorization": "Bearer not-a-jwt"}
        assert client.get(LIST_URL, headers=bogus).status_code == 401
        assert client.post(POST_URLS["validate"], headers=bogus, json={"rule_id": RULE_ID}).status_code == 401


class TestReadAccess:
    def test_list_by_role(self, client: TestClient, admin_token, analyst_token, ciso_token):
        for token in (admin_token, analyst_token, ciso_token):
            response = client.get(LIST_URL, headers=_auth(token))
            assert response.status_code == 200, token
            body = response.json()
            assert body["total"] >= 53
            assert len(body["items"]) >= 1

    def test_detail_by_role(
        self, client: TestClient, admin_token, analyst_token, ciso_token
    ):
        for token in (admin_token, analyst_token, ciso_token):
            response = client.get(DETAIL_URL, headers=_auth(token))
            assert response.status_code == 200, token
            body = response.json()
            assert body["current"]["rule_id"] == RULE_ID
            assert body["current"]["version"] in ("1.0.0", "1.1.0")

    def test_detail_unknown_rule_404(self, client: TestClient, admin_token):
        response = client.get(UNKNOWN_URL, headers=_auth(admin_token))
        assert response.status_code == 404

    def test_viewer_denied_read(self, client: TestClient, outsider_analyst_token):
        assert client.get(LIST_URL, headers=_auth(outsider_analyst_token)).status_code == 403
        assert client.get(DETAIL_URL, headers=_auth(outsider_analyst_token)).status_code == 403


class TestValidateRbac:
    def test_validate_allowed_for_admin_and_analyst(
        self, client: TestClient, admin_token, analyst_token
    ):
        for token in (admin_token, analyst_token):
            response = client.post(
                POST_URLS["validate"], json={"rule_id": RULE_ID}, headers=_auth(token)
            )
            assert response.status_code == 200, response.text
            assert response.json()["rule_id"] == RULE_ID

    def test_validate_denied_for_ciso(self, client: TestClient, ciso_token):
        response = client.post(
            POST_URLS["validate"], json={"rule_id": RULE_ID}, headers=_auth(ciso_token)
        )
        assert response.status_code == 403

    def test_validate_unknown_rule_404(self, client: TestClient, admin_token):
        response = client.post(
            POST_URLS["validate"], json={"rule_id": "nope"}, headers=_auth(admin_token)
        )
        assert response.status_code == 404

    def test_validate_bump_without_reason_422(self, client: TestClient, admin_token):
        response = client.post(
            POST_URLS["validate"],
            json={"rule_id": RULE_ID, "version": "1.2.0", "bump_class": "minor"},
            headers=_auth(admin_token),
        )
        assert response.status_code == 422


class TestLifecycleRbac:
    def test_release_deploy_rollback_enabled_admin_only(
        self,
        client: TestClient,
        admin_token,
        analyst_token,
        ciso_token,
    ):
        # analyst + ciso are denied every mutation except validate.
        for token in (analyst_token, ciso_token):
            for name in ("release", "deploy", "rollback", "enabled"):
                response = client.post(
                    POST_URLS[name],
                    json={"rule_id": RULE_ID, "version": "1.0.0"},
                    headers=_auth(token),
                )
                assert response.status_code == 403, f"{name}: {response.text}"

        # Admin transitions are idempotent against the onboarded rule.
        enabled_body = {
            "rule_id": RULE_ID,
            "version": "1.0.0",
            "enabled": True,
        }
        for name, body in (
            ("release", {"rule_id": RULE_ID, "version": "1.0.0"}),
            ("deploy", {"rule_id": RULE_ID, "version": "1.0.0"}),
            ("enabled", enabled_body),
            ("rollback", {"rule_id": RULE_ID, "version": "1.0.0"}),
        ):
            response = client.post(
                POST_URLS[name], json=body, headers=_auth(admin_token)
            )
            assert response.status_code == 200, f"{name}: {response.text}"
            assert response.json()["rule_id"] == RULE_ID

    def test_rollback_unknown_version_admin_404(
        self, client: TestClient, admin_token
    ):
        response = client.post(
            POST_URLS["rollback"],
            json={"rule_id": RULE_ID, "version": "9.9.9"},
            headers=_auth(admin_token),
        )
        assert response.status_code == 404