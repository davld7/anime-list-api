import os
from datetime import datetime, timedelta, timezone

import pytest
from bson import ObjectId

os.environ["JWT_SECRET_KEY"] = "test_secret_key_for_testing_only"

from fastapi.testclient import TestClient

from app.core.security import (
    create_refresh_token,
    get_password_hash,
    hash_refresh_token,
)
from app.db.database import get_refresh_tokens_collection, get_users_collection
from app.repositories.refresh_token_repository import (
    create_refresh_token as persist_refresh_token,
)
from app.repositories.refresh_token_repository import (
    get_refresh_token_by_hash,
    revoke_refresh_token,
)
from app.repositories.user_repository import create_user
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


def test_refresh_success(client):
    user = _create_user("refresh_success_user")
    try:
        tokens = _login(client, "refresh_success_user")

        response = client.post(
            "/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["token_type"] == "bearer"
        assert data["access_token"]
        assert data["refresh_token"]
    finally:
        _cleanup_user(user["_id"])


def test_refresh_rotation(client):
    user = _create_user("refresh_rotation_user", auth_version=3)
    try:
        tokens = _login(client, "refresh_rotation_user")
        old_refresh = tokens["refresh_token"]
        old_hash = hash_refresh_token(old_refresh)

        response = client.post(
            "/auth/refresh",
            json={"refresh_token": old_refresh},
        )

        assert response.status_code == 200
        new_refresh = response.json()["refresh_token"]
        assert new_refresh != old_refresh
        new_hash = hash_refresh_token(new_refresh)

        old_doc = get_refresh_token_by_hash(old_hash)
        new_doc = get_refresh_token_by_hash(new_hash)

        assert old_doc is not None
        assert old_doc["revoked"] is True
        assert old_doc["user_id"] == ObjectId(user["_id"])
        assert old_doc["auth_version"] == 3

        assert new_doc is not None
        assert new_doc["revoked"] is False
        assert new_doc["user_id"] == ObjectId(user["_id"])
        assert new_doc["auth_version"] == 3
    finally:
        _cleanup_user(user["_id"])


def test_refresh_previous_token_cannot_be_reused(client):
    user = _create_user("refresh_reuse_user")
    try:
        tokens = _login(client, "refresh_reuse_user")
        old_refresh = tokens["refresh_token"]

        first = client.post(
            "/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        assert first.status_code == 200

        count_before = get_refresh_tokens_collection().count_documents(
            {"user_id": ObjectId(user["_id"])}
        )

        second = client.post(
            "/auth/refresh",
            json={"refresh_token": old_refresh},
        )

        assert second.status_code == 401
        count_after = get_refresh_tokens_collection().count_documents(
            {"user_id": ObjectId(user["_id"])}
        )
        assert count_after == count_before
    finally:
        _cleanup_user(user["_id"])


def test_refresh_unknown_token(client):
    response = client.post(
        "/auth/refresh",
        json={"refresh_token": create_refresh_token()},
    )
    assert response.status_code == 401


def test_refresh_expired_token(client):
    user = _create_user("refresh_expired_user")
    try:
        plain = create_refresh_token()
        token_hash = hash_refresh_token(plain)
        past = datetime.now(timezone.utc) - timedelta(days=1)

        persist_refresh_token(
            user_id=ObjectId(user["_id"]),
            token_hash=token_hash,
            auth_version=1,
            expires_at=past,
        )

        # Record exists (TTL has not run yet): the 401 must come from the
        # explicit expiry check, not from a missing document.
        assert get_refresh_token_by_hash(token_hash) is not None

        response = client.post(
            "/auth/refresh",
            json={"refresh_token": plain},
        )

        assert response.status_code == 401
    finally:
        _cleanup_user(user["_id"])


def test_refresh_inactive_user(client):
    user = _create_user("refresh_inactive_user")
    try:
        tokens = _login(client, "refresh_inactive_user")

        get_users_collection().update_one(
            {"_id": ObjectId(user["_id"])},
            {"$set": {"active": False}},
        )

        response = client.post(
            "/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )

        assert response.status_code == 401
    finally:
        _cleanup_user(user["_id"])


def test_refresh_stale_auth_version(client):
    from app.repositories.user_repository import update_user_by_id_atomic

    user = _create_user("refresh_version_user", auth_version=1)
    try:
        tokens = _login(client, "refresh_version_user")

        update_user_by_id_atomic(ObjectId(user["_id"]), {}, {"auth_version": 1})

        response = client.post(
            "/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )

        assert response.status_code == 401
    finally:
        _cleanup_user(user["_id"])


def test_multiple_sessions_refresh_only_rotated_one(client):
    user = _create_user("refresh_multi_session_user")
    try:
        tokens_a = _login(client, "refresh_multi_session_user")
        tokens_b = _login(client, "refresh_multi_session_user")

        assert tokens_a["refresh_token"] != tokens_b["refresh_token"]

        rotate_a = client.post(
            "/auth/refresh",
            json={"refresh_token": tokens_a["refresh_token"]},
        )
        assert rotate_a.status_code == 200

        use_b = client.post(
            "/auth/refresh",
            json={"refresh_token": tokens_b["refresh_token"]},
        )
        assert use_b.status_code == 200

        assert (
            get_refresh_token_by_hash(hash_refresh_token(tokens_a["refresh_token"]))["revoked"]
            is True
        )
    finally:
        _cleanup_user(user["_id"])


def test_revoke_refresh_token_is_atomic_single_success(client):
    user = _create_user("refresh_atomic_user")
    try:
        plain = create_refresh_token()
        token_hash = hash_refresh_token(plain)
        future = datetime.now(timezone.utc) + timedelta(days=1)

        persist_refresh_token(
            user_id=ObjectId(user["_id"]),
            token_hash=token_hash,
            auth_version=1,
            expires_at=future,
        )

        first = revoke_refresh_token(token_hash)
        assert first is not None
        assert first["revoked"] is True

        second = revoke_refresh_token(token_hash)
        assert second is None
    finally:
        _cleanup_user(user["_id"])
