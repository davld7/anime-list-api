import os
import sys
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest
from bson import ObjectId

os.environ["JWT_SECRET_KEY"] = "test_secret_key_for_testing_only"

from app.db.database import get_refresh_tokens_collection, init_database
from app.repositories.refresh_token_repository import (
    create_refresh_token,
    delete_refresh_tokens_by_user_id,
    get_refresh_token_by_hash,
    revoke_refresh_token,
)

_test_module = sys.modules[__name__]


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_database()
    yield


@pytest.fixture(autouse=True)
def clean_created_tokens(monkeypatch):
    original_create = create_refresh_token
    created_ids: set[ObjectId] = set()

    def recording_create(*args, **kwargs):
        document = original_create(*args, **kwargs)
        created_ids.add(document["_id"])
        return document

    monkeypatch.setattr(_test_module, "create_refresh_token", recording_create)

    yield

    collection = get_refresh_tokens_collection()
    if created_ids:
        collection.delete_many({"_id": {"$in": list(created_ids)}})


def hash_token(token: str) -> str:
    return sha256(token.encode()).hexdigest()


class TestRefreshTokenRepository:
    def test_create_refresh_token(self):
        user_id = ObjectId()
        token_hash = hash_token("test_refresh_token")
        auth_version = 1
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        result = create_refresh_token(user_id, token_hash, auth_version, expires_at)

        assert result is not None
        assert result["_id"] is not None
        assert result["user_id"] == user_id
        assert result["token_hash"] == token_hash
        assert result["auth_version"] == auth_version
        assert result["expires_at"] == expires_at
        assert result["revoked"] is False
        assert result["created_at"] is not None

    def test_get_refresh_token_by_hash(self):
        user_id = ObjectId()
        token = "test_refresh_token_2"
        token_hash = hash_token(token)
        auth_version = 1
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        create_refresh_token(user_id, token_hash, auth_version, expires_at)

        result = get_refresh_token_by_hash(token_hash)

        assert result is not None
        assert result["token_hash"] == token_hash
        assert result["user_id"] == user_id
        assert result["auth_version"] == auth_version
        assert result["revoked"] is False

    def test_get_refresh_token_by_hash_not_found(self):
        result = get_refresh_token_by_hash("nonexistent_hash")
        assert result is None

    def test_revoke_refresh_token_success(self):
        user_id = ObjectId()
        token = "test_refresh_token_3"
        token_hash = hash_token(token)
        auth_version = 1
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        create_refresh_token(user_id, token_hash, auth_version, expires_at)

        result = revoke_refresh_token(token_hash)

        assert result is not None
        assert result["revoked"] is True
        assert result["token_hash"] == token_hash

        # Verify it's actually revoked in the database
        found = get_refresh_token_by_hash(token_hash)
        assert found["revoked"] is True

    def test_revoke_refresh_token_already_revoked(self):
        user_id = ObjectId()
        token = "test_refresh_token_4"
        token_hash = hash_token(token)
        auth_version = 1
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        create_refresh_token(user_id, token_hash, auth_version, expires_at)

        # First revocation should succeed
        result1 = revoke_refresh_token(token_hash)
        assert result1 is not None
        assert result1["revoked"] is True

        # Second revocation should return None (not found with revoked=False)
        result2 = revoke_refresh_token(token_hash)
        assert result2 is None

    def test_revoke_refresh_token_not_found(self):
        result = revoke_refresh_token("nonexistent_hash")
        assert result is None

    def test_delete_refresh_tokens_by_user_id(self):
        user_id = ObjectId()
        other_user_id = ObjectId()
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        # Create multiple tokens for user_id
        for i in range(3):
            token = f"test_refresh_token_user_{i}"
            token_hash = hash_token(token)
            create_refresh_token(user_id, token_hash, 1, expires_at)

        # Create token for another user
        token_hash = hash_token("other_user_token")
        create_refresh_token(other_user_id, token_hash, 1, expires_at)

        # Delete tokens for user_id
        deleted_count = delete_refresh_tokens_by_user_id(user_id)

        assert deleted_count == 3

        # Verify tokens are deleted
        collection = get_refresh_tokens_collection()
        remaining = list(collection.find({"user_id": user_id}))
        assert len(remaining) == 0

        # Verify other user's token still exists
        other_tokens = list(collection.find({"user_id": other_user_id}))
        assert len(other_tokens) == 1

    def test_delete_refresh_tokens_by_user_id_none(self):
        user_id = ObjectId()
        deleted_count = delete_refresh_tokens_by_user_id(user_id)
        assert deleted_count == 0

    def test_multiple_refresh_tokens_per_user(self):
        user_id = ObjectId()
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        token1_hash = hash_token("token_1")
        token2_hash = hash_token("token_2")
        token3_hash = hash_token("token_3")

        create_refresh_token(user_id, token1_hash, 1, expires_at)
        create_refresh_token(user_id, token2_hash, 1, expires_at)
        create_refresh_token(user_id, token3_hash, 2, expires_at)

        collection = get_refresh_tokens_collection()
        tokens = list(collection.find({"user_id": user_id}))
        assert len(tokens) == 3

        # Each token should have its own auth_version
        auth_versions = [t["auth_version"] for t in tokens]
        assert 1 in auth_versions
        assert 2 in auth_versions

    def test_refresh_token_stores_auth_version(self):
        user_id = ObjectId()
        token_hash = hash_token("test_token_auth_version")
        auth_version = 5
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        result = create_refresh_token(user_id, token_hash, auth_version, expires_at)

        assert result["auth_version"] == auth_version

        found = get_refresh_token_by_hash(token_hash)
        assert found["auth_version"] == auth_version
