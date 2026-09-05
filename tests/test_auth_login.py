from unittest.mock import patch

from app.core.security import get_password_hash


def test_login_success(client):
    from datetime import datetime, timedelta, timezone

    from bson import ObjectId

    from app.core.config import settings
    from app.core.security import hash_refresh_token
    from app.db.database import get_refresh_tokens_collection
    from app.repositories.user_repository import create_user, get_users_collection

    collection = get_users_collection()
    refresh_collection = get_refresh_tokens_collection()

    username = "testuser_login_success"
    collection.delete_one({"username": username})

    created_user = create_user({
        "username": username,
        "password_hash": get_password_hash("correct_password"),
        "permissions": ["read", "write"],
        "active": True,
        "auth_version": 2,
    })

    try:
        response = client.post(
            "/auth/login",
            json={"username": username, "password": "correct_password"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["token_type"] == "bearer"
        assert data["access_token"]
        assert data["refresh_token"]
        # Refresh token is opaque, not a JWT (JWT segments are dot-separated).
        assert "." not in data["refresh_token"]

        # Stored as SHA-256 hash, never plaintext.
        token_hash = hash_refresh_token(data["refresh_token"])
        stored = refresh_collection.find_one({"token_hash": token_hash})
        assert stored is not None
        assert stored["token_hash"] == token_hash
        assert data["refresh_token"] not in str(stored)
        assert stored["user_id"] == ObjectId(created_user["_id"])
        assert stored["auth_version"] == 2
        assert stored["revoked"] is False

        # `stored["expires_at"]` comes back from MongoDB as naive UTC datetime.
        expected = datetime.now(timezone.utc) + timedelta(
            days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
        )
        assert abs((stored["expires_at"] - expected.replace(tzinfo=None)).total_seconds()) < 300
    finally:
        refresh_collection.delete_many({"user_id": ObjectId(created_user["_id"])})
        collection.delete_one({"_id": ObjectId(created_user["_id"])})




def test_login_user_not_found(client):
    from app.db.database import get_refresh_tokens_collection

    refresh_collection = get_refresh_tokens_collection()

    with patch('app.routers.auth.get_user_by_username') as mock_get_user:
        mock_get_user.return_value = None

        before = refresh_collection.count_documents({})
        response = client.post(
            "/auth/login",
            json={"username": "nonexistent", "password": "password"}
        )
        after = refresh_collection.count_documents({})

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"
        assert after == before




def test_login_incorrect_password(client):
    from bson import ObjectId

    from app.db.database import get_refresh_tokens_collection
    from app.repositories.user_repository import create_user, get_users_collection

    collection = get_users_collection()
    refresh_collection = get_refresh_tokens_collection()

    username = "testuser_login_wrong_password"
    collection.delete_one({"username": username})

    created_user = create_user({
        "username": username,
        "password_hash": get_password_hash("correct_password"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    })

    try:
        response = client.post(
            "/auth/login",
            json={"username": username, "password": "wrong_password"}
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"
        assert (
            refresh_collection.count_documents({"user_id": ObjectId(created_user["_id"])}) == 0
        )
    finally:
        collection.delete_one({"_id": ObjectId(created_user["_id"])})




def test_login_inactive_user(client):
    from bson import ObjectId

    from app.db.database import get_refresh_tokens_collection
    from app.repositories.user_repository import create_user, get_users_collection

    collection = get_users_collection()
    refresh_collection = get_refresh_tokens_collection()

    username = "testuser_login_inactive"
    collection.delete_one({"username": username})

    created_user = create_user({
        "username": username,
        "password_hash": get_password_hash("correct_password"),
        "permissions": ["read"],
        "active": False,
        "auth_version": 1,
    })

    try:
        response = client.post(
            "/auth/login",
            json={"username": username, "password": "correct_password"}
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"
        assert (
            refresh_collection.count_documents({"user_id": ObjectId(created_user["_id"])}) == 0
        )
    finally:
        collection.delete_one({"_id": ObjectId(created_user["_id"])})


# =========================
# GET /auth/me TESTS
# =========================

# =========================
# DUMMY HASH TIMING TESTS
# =========================


def test_login_user_not_found_still_verifies_dummy_password(client):
    from app.routers.auth import DUMMY_PASSWORD_HASH

    with patch('app.routers.auth.get_user_by_username') as mock_get_user, \
         patch('app.routers.auth.verify_password') as mock_verify:

        mock_get_user.return_value = None
        mock_verify.return_value = False

        response = client.post(
            "/auth/login",
            json={"username": "ghost_user", "password": "password"}
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"
        mock_verify.assert_called_once_with("password", DUMMY_PASSWORD_HASH)
