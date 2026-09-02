import os
from datetime import timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

os.environ["JWT_SECRET_KEY"] = "test_secret_key_for_testing_only"

from app.core.security import (
    create_access_token,
    decode_access_token,
    get_password_hash,
    verify_password,
)
from main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


# =========================
# PASSWORD HASHING TESTS
# =========================
def test_password_hashing():
    plain_password = "test_password_123"
    hashed = get_password_hash(plain_password)

    assert hashed != plain_password
    assert verify_password(plain_password, hashed)
    assert not verify_password("wrong_password", hashed)


def test_password_hash_is_not_plain_text():
    plain_password = "test_password_123"
    hashed = get_password_hash(plain_password)

    assert plain_password not in hashed
    assert len(hashed) > 20


# =========================
# JWT TOKEN TESTS
# =========================
def test_create_and_decode_valid_token():
    username = "testuser"
    token = create_access_token(data={"sub": username, "auth_version": 1})

    assert token is not None
    assert isinstance(token, str)

    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == username
    assert payload["auth_version"] == 1


def test_decode_invalid_token():
    invalid_token = "invalid.token.here"
    payload = decode_access_token(invalid_token)
    assert payload is None


def test_token_expiration():
    username = "testuser"
    short_expire = timedelta(seconds=1)
    token = create_access_token(
        data={"sub": username, "auth_version": 1},
        expires_delta=short_expire,
    )

    import time
    time.sleep(2)

    payload = decode_access_token(token)
    assert payload is None


# =========================
# LOGIN TESTS
# =========================
def test_login_success(client):
    with patch('app.routers.auth.get_user_by_username') as mock_get_user:
        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "testuser",
            "password_hash": get_password_hash("correct_password"),
            "permissions": ["read", "write"],
            "active": True,
        }
        mock_get_user.return_value = mock_user

        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "correct_password"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"


def test_login_user_not_found(client):
    with patch('app.routers.auth.get_user_by_username') as mock_get_user:
        mock_get_user.return_value = None

        response = client.post(
            "/auth/login",
            json={"username": "nonexistent", "password": "password"}
        )

        assert response.status_code == 401


def test_login_incorrect_password(client):
    with patch('app.routers.auth.get_user_by_username') as mock_get_user:
        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "testuser",
            "password_hash": get_password_hash("correct_password"),
            "permissions": ["read"],
            "active": True,
        }
        mock_get_user.return_value = mock_user

        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "wrong_password"}
        )

        assert response.status_code == 401


def test_login_inactive_user(client):
    with patch('app.routers.auth.get_user_by_username') as mock_get_user:
        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "testuser",
            "password_hash": get_password_hash("correct_password"),
            "permissions": ["read"],
            "active": False,
        }
        mock_get_user.return_value = mock_user

        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "correct_password"}
        )

        assert response.status_code == 401


# =========================
# PUBLIC ENDPOINT TESTS
# =========================
def test_public_endpoint_without_authentication(client):
    response = client.get("/animes/")
    assert response.status_code == 200


# =========================
# PROTECTED ENDPOINT TESTS
# =========================
def test_protected_endpoint_without_authentication(client):
    response = client.post(
        "/animes/",
        json={
            "name": "Test Anime",
            "description": "Test Description",
            "episodes": 12,
            "season": "Summer 2024",
            "genres": ["Action"],
            "image_url": "https://example.com/image.jpg",
        },
    )

    assert response.status_code == 401


def test_protected_endpoint_with_invalid_token(client):
    response = client.post(
        "/animes/",
        json={
            "name": "Test Anime",
            "description": "Test Description",
            "episodes": 12,
            "season": "Summer 2024",
            "genres": ["Action"],
            "image_url": "https://example.com/image.jpg",
        },
        headers={"Authorization": "Bearer invalid_token"},
    )

    assert response.status_code == 401


def test_protected_endpoint_with_valid_token_sufficient_permission(client):
    token = create_access_token(data={"sub": "testuser", "auth_version": 1})

    with patch("app.core.dependencies.get_user_by_username") as mock_get_user, \
         patch("app.routers.animes.get_anime_by_name") as mock_get_by_name, \
         patch("app.routers.animes.create_anime") as mock_create_anime:

        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "testuser",
            "password_hash": get_password_hash("password"),
            "permissions": ["write"],
            "active": True,
            "auth_version": 1,
        }

        mock_get_user.return_value = mock_user
        mock_get_by_name.return_value = None

        mock_create_anime.return_value = {
            "_id": "507f1f77bcf86cd799439011",
            "name": "Test Anime",
            "description": "Test Description",
            "episodes": 12,
            "season": "Summer 2024",
            "genres": ["Action"],
            "image_url": "https://example.com/image.jpg",
        }

        response = client.post(
            "/animes/",
            json={
                "name": "Test Anime",
                "description": "Test Description",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/image.jpg",
            },
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 201


def test_protected_endpoint_with_valid_token_insufficient_permission(client):
    token = create_access_token(data={"sub": "testuser", "auth_version": 1})

    with patch("app.core.dependencies.get_user_by_username") as mock_get_user:
        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "testuser",
            "password_hash": get_password_hash("password"),
            "permissions": ["read"],
            "active": True,
            "auth_version": 1,
        }
        mock_get_user.return_value = mock_user

        response = client.post(
            "/animes/",
            json={
                "name": "Test Anime",
                "description": "Test Description",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/image.jpg",
            },
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403


def test_protected_endpoint_with_expired_token(client):
    token = create_access_token(
        data={"sub": "testuser", "auth_version": 1},
        expires_delta=timedelta(seconds=1),
    )

    import time
    time.sleep(2)

    response = client.post(
        "/animes/",
        json={
            "name": "Test Anime",
            "description": "Test Description",
            "episodes": 12,
            "season": "Summer 2024",
            "genres": ["Action"],
            "image_url": "https://example.com/image.jpg",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_protected_endpoint_with_invalid_sub(client):
    token = create_access_token(data={"sub": 123})

    response = client.post(
        "/animes/",
        json={
            "name": "Test Anime",
            "description": "Test Description",
            "episodes": 12,
            "season": "Summer 2024",
            "genres": ["Action"],
            "image_url": "https://example.com/image.jpg",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_protected_endpoint_with_empty_sub(client):
    token = create_access_token(data={"sub": ""})

    response = client.post(
        "/animes/",
        json={
            "name": "Test Anime",
            "description": "Test Description",
            "episodes": 12,
            "season": "Summer 2024",
            "genres": ["Action"],
            "image_url": "https://example.com/image.jpg",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_protected_endpoint_with_nonexistent_user(client):
    token = create_access_token(data={"sub": "nonexistent_user", "auth_version": 1})

    with patch("app.core.dependencies.get_user_by_username") as mock_get_user:
        mock_get_user.return_value = None

        response = client.post(
            "/animes/",
            json={
                "name": "Test Anime",
                "description": "Test Description",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/image.jpg",
            },
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 401


def test_protected_endpoint_with_inactive_user(client):
    token = create_access_token(data={"sub": "inactive_user", "auth_version": 1})

    with patch("app.core.dependencies.get_user_by_username") as mock_get_user:
        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "inactive_user",
            "password_hash": get_password_hash("password"),
            "permissions": ["write"],
            "active": False,
            "auth_version": 1,
        }
        mock_get_user.return_value = mock_user

        response = client.post(
            "/animes/",
            json={
                "name": "Test Anime",
                "description": "Test Description",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/image.jpg",
            },
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 401


# =========================
# CHANGE USERNAME TESTS
# =========================
def test_change_username_success(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user, get_user_by_username

    user_data = {
        "username": "testuser_change",
        "password_hash": get_password_hash("test_password"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    token = create_access_token(data={"sub": "testuser_change", "auth_version": 1})

    response = client.put(
        "/auth/username",
        json={"new_username": "testuser_changed"},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["new_username"] == "testuser_changed"
    assert "message" in data

    # Verify username was actually updated in database
    updated_user = get_user_by_username("testuser_changed")
    assert updated_user is not None
    assert updated_user["username"] == "testuser_changed"

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


def test_change_username_without_authentication(client):
    response = client.put(
        "/auth/username",
        json={"new_username": "new_username"}
    )

    assert response.status_code == 401


def test_change_username_to_existing_username(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    # Create two users
    user1_data = {
        "username": "user1",
        "password_hash": get_password_hash("password1"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    }
    user2_data = {
        "username": "user2",
        "password_hash": get_password_hash("password2"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    }
    created_user1 = create_user(user1_data)
    created_user2 = create_user(user2_data)

    token = create_access_token(data={"sub": "user1", "auth_version": 1})

    response = client.put(
        "/auth/username",
        json={"new_username": "user2"},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 409

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user1["_id"])})
    collection.delete_one({"_id": ObjectId(created_user2["_id"])})


def test_change_username_to_same_username(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_same",
        "password_hash": get_password_hash("test_password"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    token = create_access_token(data={"sub": "testuser_same", "auth_version": 1})

    response = client.put(
        "/auth/username",
        json={"new_username": "testuser_same"},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 400

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


def test_old_jwt_invalid_after_username_change(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_jwt",
        "password_hash": get_password_hash("test_password"),
        "permissions": ["write"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    # Get initial JWT
    old_token = create_access_token(data={"sub": "testuser_jwt", "auth_version": 1})

    # Change username
    response = client.put(
        "/auth/username",
        json={"new_username": "testuser_jwt_new"},
        headers={"Authorization": f"Bearer {old_token}"}
    )
    assert response.status_code == 200

    # Try to use old JWT on protected endpoint
    with patch("app.core.dependencies.get_user_by_username") as mock_get_user:
        mock_get_user.return_value = None  # Old username no longer exists

        response = client.post(
            "/animes/",
            json={
                "name": "Test Anime",
                "description": "Test Description",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/image.jpg",
            },
            headers={"Authorization": f"Bearer {old_token}"}
        )

        assert response.status_code == 401

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


def test_login_with_new_username_after_change(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_login",
        "password_hash": get_password_hash("test_password"),
        "permissions": ["write"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    # Change username
    old_token = create_access_token(data={"sub": "testuser_login", "auth_version": 1})
    response = client.put(
        "/auth/username",
        json={"new_username": "testuser_login_new"},
        headers={"Authorization": f"Bearer {old_token}"}
    )
    assert response.status_code == 200

    # Login with new username
    with patch('app.routers.auth.get_user_by_username') as mock_get_user:
        mock_user = {
            "_id": created_user["_id"],
            "username": "testuser_login_new",
            "password_hash": get_password_hash("test_password"),
            "permissions": ["write"],
            "active": True,
            "auth_version": 1,
        }
        mock_get_user.return_value = mock_user

        response = client.post(
            "/auth/login",
            json={"username": "testuser_login_new", "password": "test_password"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        new_token = data["access_token"]

    # Verify new JWT works on protected endpoint
    with patch("app.core.dependencies.get_user_by_username") as mock_get_user, \
         patch("app.routers.animes.get_anime_by_name") as mock_get_by_name, \
         patch("app.routers.animes.create_anime") as mock_create_anime:

        mock_user = {
            "_id": created_user["_id"],
            "username": "testuser_login_new",
            "password_hash": get_password_hash("test_password"),
            "permissions": ["write"],
            "active": True,
            "auth_version": 1,
        }
        mock_get_user.return_value = mock_user
        mock_get_by_name.return_value = None

        mock_create_anime.return_value = {
            "_id": "507f1f77bcf86cd799439011",
            "name": "Test Anime",
            "description": "Test Description",
            "episodes": 12,
            "season": "Summer 2024",
            "genres": ["Action"],
            "image_url": "https://example.com/image.jpg",
        }

        response = client.post(
            "/animes/",
            json={
                "name": "Test Anime",
                "description": "Test Description",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/image.jpg",
            },
            headers={"Authorization": f"Bearer {new_token}"}
        )

        assert response.status_code == 201

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


# =========================
# CHANGE PASSWORD TESTS
# =========================
def test_change_password_success(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_password",
        "password_hash": get_password_hash("old_password"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    token = create_access_token(data={"sub": "testuser_password", "auth_version": 1})

    response = client.put(
        "/auth/password",
        json={"current_password": "old_password", "new_password": "new_password"},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    data = response.json()
    assert "message" in data

    # Verify password was actually updated in database
    from app.repositories.user_repository import get_user_by_username
    updated_user = get_user_by_username("testuser_password")
    assert updated_user is not None
    assert updated_user["auth_version"] == 2
    assert verify_password("new_password", updated_user["password_hash"])
    assert not verify_password("old_password", updated_user["password_hash"])

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


def test_change_password_incorrect_current_password(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_password_wrong",
        "password_hash": get_password_hash("correct_password"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    token = create_access_token(data={"sub": "testuser_password_wrong", "auth_version": 1})

    response = client.put(
        "/auth/password",
        json={"current_password": "wrong_password", "new_password": "new_password"},
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 401

    # Verify password was NOT updated in database
    from app.repositories.user_repository import get_user_by_username
    updated_user = get_user_by_username("testuser_password_wrong")
    assert updated_user is not None
    assert updated_user["auth_version"] == 1
    assert verify_password("correct_password", updated_user["password_hash"])
    assert not verify_password("new_password", updated_user["password_hash"])

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


def test_change_password_without_authentication(client):
    response = client.put(
        "/auth/password",
        json={"current_password": "old_password", "new_password": "new_password"}
    )

    assert response.status_code == 401


def test_old_jwt_invalid_after_password_change(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_jwt_password",
        "password_hash": get_password_hash("old_password"),
        "permissions": ["write"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    # Get initial JWT
    old_token = create_access_token(data={"sub": "testuser_jwt_password", "auth_version": 1})

    # Change password
    response = client.put(
        "/auth/password",
        json={"current_password": "old_password", "new_password": "new_password"},
        headers={"Authorization": f"Bearer {old_token}"}
    )
    assert response.status_code == 200

    # Try to use old JWT on protected endpoint
    with patch("app.core.dependencies.get_user_by_username") as mock_get_user:
        mock_user = {
            "_id": created_user["_id"],
            "username": "testuser_jwt_password",
            "password_hash": get_password_hash("new_password"),
            "permissions": ["write"],
            "active": True,
            "auth_version": 2,
        }
        mock_get_user.return_value = mock_user

        response = client.post(
            "/animes/",
            json={
                "name": "Test Anime",
                "description": "Test Description",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/image.jpg",
            },
            headers={"Authorization": f"Bearer {old_token}"}
        )

        assert response.status_code == 401

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


def test_login_with_old_password_fails_after_change(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_login_password",
        "password_hash": get_password_hash("old_password"),
        "permissions": ["write"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    # Change password
    token = create_access_token(data={"sub": "testuser_login_password", "auth_version": 1})
    response = client.put(
        "/auth/password",
        json={"current_password": "old_password", "new_password": "new_password"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

    # Try to login with old password
    with patch('app.routers.auth.get_user_by_username') as mock_get_user:
        mock_user = {
            "_id": created_user["_id"],
            "username": "testuser_login_password",
            "password_hash": get_password_hash("new_password"),
            "permissions": ["write"],
            "active": True,
            "auth_version": 2,
        }
        mock_get_user.return_value = mock_user

        response = client.post(
            "/auth/login",
            json={"username": "testuser_login_password", "password": "old_password"}
        )

        assert response.status_code == 401

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


def test_login_with_new_password_works_after_change(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_login_new_password",
        "password_hash": get_password_hash("old_password"),
        "permissions": ["write"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    # Change password
    token = create_access_token(data={"sub": "testuser_login_new_password", "auth_version": 1})
    response = client.put(
        "/auth/password",
        json={"current_password": "old_password", "new_password": "new_password"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

    # Login with new password
    with patch('app.routers.auth.get_user_by_username') as mock_get_user:
        mock_user = {
            "_id": created_user["_id"],
            "username": "testuser_login_new_password",
            "password_hash": get_password_hash("new_password"),
            "permissions": ["write"],
            "active": True,
            "auth_version": 2,
        }
        mock_get_user.return_value = mock_user

        response = client.post(
            "/auth/login",
            json={"username": "testuser_login_new_password", "password": "new_password"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        new_token = data["access_token"]

    # Verify new JWT works on protected endpoint
    with patch("app.core.dependencies.get_user_by_username") as mock_get_user, \
         patch("app.routers.animes.get_anime_by_name") as mock_get_by_name, \
         patch("app.routers.animes.create_anime") as mock_create_anime:

        mock_user = {
            "_id": created_user["_id"],
            "username": "testuser_login_new_password",
            "password_hash": get_password_hash("new_password"),
            "permissions": ["write"],
            "active": True,
            "auth_version": 2,
        }
        mock_get_user.return_value = mock_user
        mock_get_by_name.return_value = None

        mock_create_anime.return_value = {
            "_id": "507f1f77bcf86cd799439011",
            "name": "Test Anime",
            "description": "Test Description",
            "episodes": 12,
            "season": "Summer 2024",
            "genres": ["Action"],
            "image_url": "https://example.com/image.jpg",
        }

        response = client.post(
            "/animes/",
            json={
                "name": "Test Anime",
                "description": "Test Description",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/image.jpg",
            },
            headers={"Authorization": f"Bearer {new_token}"}
        )

        assert response.status_code == 201

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


def test_auth_version_increments_correctly(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_version",
        "password_hash": get_password_hash("password1"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    token = create_access_token(data={"sub": "testuser_version", "auth_version": 1})

    # First password change
    response = client.put(
        "/auth/password",
        json={"current_password": "password1", "new_password": "password2"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

    from app.repositories.user_repository import get_user_by_username
    updated_user = get_user_by_username("testuser_version")
    assert updated_user["auth_version"] == 2

    # Second password change
    token2 = create_access_token(data={"sub": "testuser_version", "auth_version": 2})
    response = client.put(
        "/auth/password",
        json={"current_password": "password2", "new_password": "password3"},
        headers={"Authorization": f"Bearer {token2}"}
    )
    assert response.status_code == 200

    updated_user = get_user_by_username("testuser_version")
    assert updated_user["auth_version"] == 3

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


def test_user_without_auth_version_uses_fallback(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_no_version",
        "password_hash": get_password_hash("password"),
        "permissions": ["read"],
        "active": True,
    }
    created_user = create_user(user_data)

    # Create JWT with auth_version=1 (matching the fallback)
    token = create_access_token(data={"sub": "testuser_no_version", "auth_version": 1})

    # Should work because user.get("auth_version", 1) returns 1
    with patch("app.core.dependencies.get_user_by_username") as mock_get_user:
        mock_user = {
            "_id": created_user["_id"],
            "username": "testuser_no_version",
            "password_hash": get_password_hash("password"),
            "permissions": ["read"],
            "active": True,
        }
        mock_get_user.return_value = mock_user

        response = client.get("/animes/", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


def test_multiple_password_changes_increment_auth_version(client):
    from bson import ObjectId

    from app.repositories.user_repository import create_user

    user_data = {
        "username": "testuser_multi",
        "password_hash": get_password_hash("password1"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    }
    created_user = create_user(user_data)

    from app.repositories.user_repository import get_user_by_username

    # First change
    token1 = create_access_token(data={"sub": "testuser_multi", "auth_version": 1})
    response = client.put(
        "/auth/password",
        json={"current_password": "password1", "new_password": "password2"},
        headers={"Authorization": f"Bearer {token1}"}
    )
    assert response.status_code == 200
    user = get_user_by_username("testuser_multi")
    assert user["auth_version"] == 2

    # Second change
    token2 = create_access_token(data={"sub": "testuser_multi", "auth_version": 2})
    response = client.put(
        "/auth/password",
        json={"current_password": "password2", "new_password": "password3"},
        headers={"Authorization": f"Bearer {token2}"}
    )
    assert response.status_code == 200
    user = get_user_by_username("testuser_multi")
    assert user["auth_version"] == 3

    # Third change
    token3 = create_access_token(data={"sub": "testuser_multi", "auth_version": 3})
    response = client.put(
        "/auth/password",
        json={"current_password": "password3", "new_password": "password4"},
        headers={"Authorization": f"Bearer {token3}"}
    )
    assert response.status_code == 200
    user = get_user_by_username("testuser_multi")
    assert user["auth_version"] == 4

    # Clean up
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    collection.delete_one({"_id": ObjectId(created_user["_id"])})


# =========================
# UPDATE USER PERMISSIONS TESTS
# =========================

TARGET_USER_ID = "507f1f77bcf86cd799439044"


def _admin_mock_headers():
    token = create_access_token(data={"sub": "admin_user", "auth_version": 1})
    return {"Authorization": f"Bearer {token}"}


def _admin_mock_user(permissions=None):
    return {
        "_id": "507f1f77bcf86cd799439011",
        "username": "admin_user",
        "password_hash": get_password_hash("password"),
        "permissions": permissions if permissions is not None else ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    }


def _target_mock_user(active=True, permissions=("read",)):
    return {
        "_id": TARGET_USER_ID,
        "username": "target_user",
        "password_hash": get_password_hash("password"),
        "permissions": list(permissions),
        "active": active,
        "auth_version": 1,
    }


def test_admin_can_update_other_user_permissions(client):
    from bson import ObjectId

    admin = _admin_mock_user()
    target = _target_mock_user(permissions=["read"])
    new_permissions = ["read", "write"]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.update_user_by_id") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_update.return_value = {**target, "permissions": new_permissions}

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": new_permissions},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["permissions"] == new_permissions

        mock_update.assert_called_once_with(
            ObjectId(TARGET_USER_ID),
            {"permissions": new_permissions},
        )


def test_update_permissions_without_admin_permission(client):
    non_admin = _admin_mock_user(permissions=["read", "write"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = non_admin

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": ["read"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 403


def test_update_permissions_without_authentication(client):
    response = client.put(
        f"/auth/users/{TARGET_USER_ID}/permissions",
        json={"permissions": ["read"]},
    )

    assert response.status_code == 401


def test_update_permissions_user_not_found(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id:
        mock_current.return_value = admin
        mock_get_by_id.return_value = None

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": ["read"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 404


def test_update_permissions_invalid_object_id(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            "/auth/users/zzzzzzzzzzzzzzzzzzzzzzzz/permissions",
            json={"permissions": ["read"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 400


def test_update_permissions_short_object_id(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            "/auth/users/abc/permissions",
            json={"permissions": ["read"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422


def test_update_permissions_unknown_permission_rejected(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": ["read", "unknown"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422


def test_update_permissions_duplicate_permission_rejected(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": ["read", "read"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422


def test_update_permissions_empty_list_valid(client):
    from bson import ObjectId

    admin = _admin_mock_user()
    target = _target_mock_user(permissions=["read", "write", "admin"])
    new_permissions = []

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.count_active_admins") as mock_count, \
         patch("app.routers.auth.update_user_by_id") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_count.return_value = 2
        mock_update.return_value = {**target, "permissions": new_permissions}

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": new_permissions},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["permissions"] == []
        mock_update.assert_called_once_with(
            ObjectId(TARGET_USER_ID),
            {"permissions": new_permissions},
        )


def test_admin_can_grant_admin_to_other_user(client):
    admin = _admin_mock_user()
    target = _target_mock_user(permissions=["read"])
    new_permissions = ["read", "admin"]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.update_user_by_id") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_update.return_value = {**target, "permissions": new_permissions}

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": new_permissions},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["permissions"] == new_permissions


def test_admin_can_remove_admin_when_another_active_admin_exists(client):
    admin = _admin_mock_user()
    target = _target_mock_user(permissions=["read", "write", "admin"])
    new_permissions = ["read", "write"]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.count_active_admins") as mock_count, \
         patch("app.routers.auth.update_user_by_id") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_count.return_value = 2
        mock_update.return_value = {**target, "permissions": new_permissions}

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": new_permissions},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["permissions"] == new_permissions


def test_admin_cannot_remove_admin_from_last_active_admin(client):
    admin = _admin_mock_user()
    target = _target_mock_user(permissions=["read", "write", "admin"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.count_active_admins") as mock_count:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_count.return_value = 1

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": ["read", "write"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 409


def test_admin_can_modify_own_permissions_keeping_admin(client):
    admin = _admin_mock_user(permissions=["read", "write", "admin"])
    new_permissions = ["read", "admin"]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.update_user_by_id") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = admin
        mock_update.return_value = {**admin, "permissions": new_permissions}

        response = client.put(
            f"/auth/users/{admin['_id']}/permissions",
            json={"permissions": new_permissions},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["permissions"] == new_permissions


def test_admin_can_remove_own_admin_when_another_active_admin_exists(client):
    admin = _admin_mock_user(permissions=["read", "write", "admin"])
    new_permissions = ["read", "write"]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.count_active_admins") as mock_count, \
         patch("app.routers.auth.update_user_by_id") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = admin
        mock_count.return_value = 2
        mock_update.return_value = {**admin, "permissions": new_permissions}

        response = client.put(
            f"/auth/users/{admin['_id']}/permissions",
            json={"permissions": new_permissions},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["permissions"] == new_permissions


def test_admin_cannot_remove_own_admin_when_last_active_admin(client):
    admin = _admin_mock_user(permissions=["read", "write", "admin"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.count_active_admins") as mock_count:

        mock_current.return_value = admin
        mock_get_by_id.return_value = admin
        mock_count.return_value = 1

        response = client.put(
            f"/auth/users/{admin['_id']}/permissions",
            json={"permissions": ["read", "write"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 409


def test_inactive_admin_does_not_count_for_last_admin_protection(client):
    admin = _admin_mock_user()
    inactive_admin = _target_mock_user(active=False, permissions=["read", "admin"])
    new_permissions = ["read"]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.update_user_by_id") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = inactive_admin
        mock_update.return_value = {**inactive_admin, "permissions": new_permissions}

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": new_permissions},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["permissions"] == new_permissions


def test_update_permissions_does_not_change_auth_version(client):
    from bson import ObjectId

    admin = _admin_mock_user()
    target = _target_mock_user(permissions=["read"])
    new_permissions = ["read", "write"]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.update_user_by_id") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_update.return_value = {**target, "permissions": new_permissions}

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/permissions",
            json={"permissions": new_permissions},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200

        mock_update.assert_called_once_with(
            ObjectId(TARGET_USER_ID),
            {"permissions": new_permissions},
        )
        assert "auth_version" not in mock_update.call_args.args[1]
        assert "auth_version" not in mock_update.call_args.kwargs


def test_updated_permissions_take_effect_immediately(client):
    from bson import ObjectId

    from app.repositories.user_repository import (
        create_user,
        get_user_by_username,
        get_users_collection,
    )

    admin = create_user({
        "username": "admin_immediate",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    })
    target = create_user({
        "username": "target_immediate",
        "password_hash": get_password_hash("password"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    })

    try:
        admin_token = create_access_token(
            data={"sub": "admin_immediate", "auth_version": 1}
        )
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        with patch("app.routers.auth.count_active_admins") as mock_count:
            mock_count.return_value = 1

            response = client.put(
                f"/auth/users/{target['_id']}/permissions",
                json={"permissions": ["read", "write"]},
                headers=admin_headers,
            )
        assert response.status_code == 200

        updated = get_user_by_username("target_immediate")
        assert updated["permissions"] == ["read", "write"]
        assert updated["auth_version"] == 1

        target_token = create_access_token(
            data={"sub": "target_immediate", "auth_version": 1}
        )
        target_headers = {"Authorization": f"Bearer {target_token}"}

        with patch("app.routers.animes.get_anime_by_name") as mock_by_name, \
             patch("app.routers.animes.create_anime") as mock_create:

            mock_by_name.return_value = None
            mock_create.return_value = {
                "_id": "507f1f77bcf86cd799439044",
                "name": "Test Anime Immediate",
                "description": "Test Description",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/image.jpg",
            }

            response = client.post(
                "/animes/",
                json={
                    "name": "Test Anime Immediate",
                    "description": "Test Description",
                    "episodes": 12,
                    "season": "Summer 2024",
                    "genres": ["Action"],
                    "image_url": "https://example.com/image.jpg",
                },
                headers=target_headers,
            )
            assert response.status_code == 201
    finally:
        collection = get_users_collection()
        collection.delete_one({"_id": ObjectId(admin["_id"])})
        collection.delete_one({"_id": ObjectId(target["_id"])})


# =========================
# ADMIN UPDATE USER PASSWORD TESTS
# =========================


def test_admin_can_update_other_user_password(client):
    from bson import ObjectId

    admin = _admin_mock_user()
    target = _target_mock_user()
    new_password_hash = get_password_hash("new_password")

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.update_user_by_id_atomic") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_update.return_value = {**target, "password_hash": new_password_hash}

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/password",
            json={"new_password": "new_password"},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert "message" in response.json()

        mock_update.assert_called_once()
        args, kwargs = mock_update.call_args
        assert args[0] == ObjectId(TARGET_USER_ID)
        assert "password_hash" in args[1]
        assert args[1]["password_hash"] != "new_password"
        assert args[2] == {"auth_version": 1}


def test_update_user_password_without_admin_permission(client):
    non_admin = _admin_mock_user(permissions=["read", "write"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = non_admin

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/password",
            json={"new_password": "new_password"},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 403


def test_update_user_password_without_authentication(client):
    response = client.put(
        f"/auth/users/{TARGET_USER_ID}/password",
        json={"new_password": "new_password"},
    )

    assert response.status_code == 401


def test_update_user_password_user_not_found(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id:
        mock_current.return_value = admin
        mock_get_by_id.return_value = None

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/password",
            json={"new_password": "new_password"},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 404


def test_update_user_password_invalid_object_id(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            "/auth/users/zzzzzzzzzzzzzzzzzzzzzzzz/password",
            json={"new_password": "new_password"},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 400


def test_update_user_password_short_object_id(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            "/auth/users/abc/password",
            json={"new_password": "new_password"},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422


def test_update_user_password_missing_new_password(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/password",
            json={},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422


def test_update_user_password_empty_new_password(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/password",
            json={"new_password": ""},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422


def test_admin_update_password_increments_auth_version(client):
    from bson import ObjectId

    from app.repositories.user_repository import (
        create_user,
        get_user_by_username,
        get_users_collection,
    )

    admin = create_user({
        "username": "admin_pw",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    })
    target = create_user({
        "username": "target_pw",
        "password_hash": get_password_hash("old_password"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    })

    try:
        admin_token = create_access_token(
            data={"sub": "admin_pw", "auth_version": 1}
        )
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        response = client.put(
            f"/auth/users/{target['_id']}/password",
            json={"new_password": "new_password"},
            headers=admin_headers,
        )
        assert response.status_code == 200

        updated = get_user_by_username("target_pw")
        assert updated["auth_version"] == 2
        assert verify_password("new_password", updated["password_hash"])
        assert not verify_password("old_password", updated["password_hash"])

        # Other fields are untouched
        assert updated["username"] == "target_pw"
        assert updated["permissions"] == ["read"]
        assert updated["active"] is True
    finally:
        collection = get_users_collection()
        collection.delete_one({"_id": ObjectId(admin["_id"])})
        collection.delete_one({"_id": ObjectId(target["_id"])})
