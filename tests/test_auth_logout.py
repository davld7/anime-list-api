import os

import pytest
from bson import ObjectId

os.environ["JWT_SECRET_KEY"] = "test_secret_key_for_testing_only"

from fastapi.testclient import TestClient

from app.core.security import get_password_hash, hash_refresh_token
from app.db.database import get_refresh_tokens_collection, get_users_collection
from app.repositories.refresh_token_repository import get_refresh_token_by_hash
from app.repositories.user_repository import create_user, get_user_by_username
from main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def _create_user(username, password="password123", active=True, auth_version=1):
    return create_user({
        "username": username,
        "password_hash": get_password_hash(password),
        "permissions": ["read"],
        "active": active,
        "auth_version": auth_version,
    })


def _login(client, username, password="password123"):
    response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200
    return response.json()


def _cleanup_user(user_id):
    get_users_collection().delete_one({"_id": ObjectId(user_id)})
    get_refresh_tokens_collection().delete_many({"user_id": ObjectId(user_id)})


def test_logout_success(client):
    user = _create_user("logout_success_user")
    try:
        tokens = _login(client, "logout_success_user")
        token_hash = hash_refresh_token(tokens["refresh_token"])

        response = client.post(
            "/auth/logout",
            json={"refresh_token": tokens["refresh_token"]},
        )

        assert response.status_code == 204

        stored = get_refresh_token_by_hash(token_hash)
        assert stored is not None
        assert stored["revoked"] is True
    finally:
        _cleanup_user(user["_id"])


def test_logout_repeated(client):
    user = _create_user("logout_repeated_user")
    try:
        tokens = _login(client, "logout_repeated_user")

        first = client.post(
            "/auth/logout",
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert first.status_code == 204

        second = client.post(
            "/auth/logout",
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert second.status_code == 204
    finally:
        _cleanup_user(user["_id"])


def test_logout_unknown_token(client):
    response = client.post(
        "/auth/logout",
        json={"refresh_token": "unknown_random_refresh_token"},
    )
    assert response.status_code == 204


def test_logout_does_not_affect_other_sessions(client):
    user = _create_user("logout_multi_session_user")
    try:
        tokens_a = _login(client, "logout_multi_session_user")
        tokens_b = _login(client, "logout_multi_session_user")

        assert tokens_a["refresh_token"] != tokens_b["refresh_token"]

        logout_a = client.post(
            "/auth/logout",
            json={"refresh_token": tokens_a["refresh_token"]},
        )
        assert logout_a.status_code == 204

        assert (
            get_refresh_token_by_hash(hash_refresh_token(tokens_a["refresh_token"]))["revoked"]
            is True
        )

        use_b = client.post(
            "/auth/refresh",
            json={"refresh_token": tokens_b["refresh_token"]},
        )
        assert use_b.status_code == 200
    finally:
        _cleanup_user(user["_id"])


def test_logout_does_not_modify_auth_version(client):
    user = _create_user("logout_version_user", auth_version=4)
    try:
        tokens = _login(client, "logout_version_user")

        response = client.post(
            "/auth/logout",
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert response.status_code == 204

        stored_user = get_user_by_username("logout_version_user")
        assert stored_user is not None
        assert stored_user["auth_version"] == 4
    finally:
        _cleanup_user(user["_id"])
