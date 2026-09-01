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
    token = create_access_token(data={"sub": username})

    assert token is not None
    assert isinstance(token, str)

    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == username


def test_decode_invalid_token():
    invalid_token = "invalid.token.here"
    payload = decode_access_token(invalid_token)
    assert payload is None


def test_token_expiration():
    username = "testuser"
    short_expire = timedelta(seconds=1)
    token = create_access_token(data={"sub": username}, expires_delta=short_expire)

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
# PROTECTED ENDPOINT TESTS
# =========================

def test_public_endpoint_without_authentication(client):
    response = client.get("/animes/")
    assert response.status_code == 200


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
    token = create_access_token(data={"sub": "testuser"})

    with patch("app.core.dependencies.get_user_by_username") as mock_get_user, \
         patch("app.routers.animes.get_anime_by_name") as mock_get_by_name, \
         patch("app.routers.animes.create_anime") as mock_create_anime:

        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "testuser",
            "password_hash": get_password_hash("password"),
            "permissions": ["write"],
            "active": True,
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
    token = create_access_token(data={"sub": "testuser"})

    with patch("app.core.dependencies.get_user_by_username") as mock_get_user:
        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "testuser",
            "password_hash": get_password_hash("password"),
            "permissions": ["read"],
            "active": True,
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
        data={"sub": "testuser"},
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
    token = create_access_token(data={"sub": "nonexistent_user"})

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
    token = create_access_token(data={"sub": "inactive_user"})

    with patch("app.core.dependencies.get_user_by_username") as mock_get_user:
        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "inactive_user",
            "password_hash": get_password_hash("password"),
            "permissions": ["write"],
            "active": False,
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
# ADMIN CREATION TESTS
# =========================
def test_admin_creation_when_no_users_exist():
    import main
    original_settings = main.settings

    with patch.object(main, 'settings') as mock_settings, \
         patch('main.count_users') as mock_count, \
         patch('main.create_user') as mock_create:

        mock_settings.INITIAL_ADMIN_USERNAME = "admin"
        mock_settings.INITIAL_ADMIN_PASSWORD = "admin_password"
        mock_count.return_value = 0

        main.init_admin_user()

        mock_create.assert_called_once()
        call_args = mock_create.call_args[0][0]
        assert call_args["username"] == "admin"
        assert call_args["permissions"] == ["read", "write", "admin"]
        assert call_args["active"] is True
        assert "password_hash" in call_args
        assert call_args["password_hash"] != "admin_password"
        assert verify_password("admin_password", call_args["password_hash"])

    main.settings = original_settings


def test_admin_creation_skipped_when_users_exist():
    import main
    original_settings = main.settings

    with patch.object(main, 'settings') as mock_settings, \
         patch('main.count_users') as mock_count, \
         patch('main.create_user') as mock_create:

        mock_settings.INITIAL_ADMIN_USERNAME = "admin"
        mock_settings.INITIAL_ADMIN_PASSWORD = "admin_password"
        mock_count.return_value = 5  # Users already exist

        main.init_admin_user()

        mock_create.assert_not_called()

    main.settings = original_settings


def test_admin_creation_skipped_when_no_credentials():
    import main
    original_settings = main.settings

    with patch.object(main, 'settings') as mock_settings, \
         patch('main.create_user') as mock_create:

        mock_settings.INITIAL_ADMIN_USERNAME = ""
        mock_settings.INITIAL_ADMIN_PASSWORD = ""

        main.init_admin_user()

        mock_create.assert_not_called()

    main.settings = original_settings
