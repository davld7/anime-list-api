import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pymongo.errors import DuplicateKeyError

os.environ["JWT_SECRET_KEY"] = "test_secret_key_for_testing_only"

from app.core.security import create_access_token, get_password_hash
from main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def auth_headers():
    token = create_access_token(data={"sub": "testuser", "auth_version": 1})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def mock_authenticated_user():
    return {
        "_id": "507f1f77bcf86cd799439011",
        "username": "testuser",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    }


# =========================
# HEALTH CHECK TEST
# =========================
def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] == "ok"
    assert "database" in data


# =========================
# GET ANIMES PAGINATED TEST
# =========================
def test_get_paginated_animes(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.get_paginated_animes') as mock_get_paginated:

        mock_get_user.return_value = mock_authenticated_user
        mock_get_paginated.return_value = []

        response = client.get("/animes/page?page=1", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


# =========================
# GET TOTAL PAGES TEST
# =========================
def test_get_total_pages(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.count_animes') as mock_count:

        mock_get_user.return_value = mock_authenticated_user
        mock_count.return_value = 10

        response = client.get("/animes/pages", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_animes" in data
        assert "total_pages" in data
        assert isinstance(data["total_animes"], int)
        assert isinstance(data["total_pages"], int)


# =========================
# GET BY ID TEST
# =========================
def test_get_anime_by_id_success(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.get_anime_by_id') as mock_get_by_id:

        mock_get_user.return_value = mock_authenticated_user
        mock_get_by_id.return_value = {
            "_id": "642a63402537c1f25e5f20fd",
            "name": "Test Anime",
            "description": "Test",
            "episodes": 12,
            "season": "Summer 2024",
            "genres": ["Action"],
            "image_url": "https://example.com/image.jpg"
        }

        response = client.get("/animes/by-id/642a63402537c1f25e5f20fd", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["_id"] == "642a63402537c1f25e5f20fd"
        assert "name" in data


def test_get_anime_by_id_not_found(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.get_anime_by_id') as mock_get_by_id:

        mock_get_user.return_value = mock_authenticated_user
        mock_get_by_id.return_value = None

        response = client.get("/animes/by-id/123456789012345678901234", headers=auth_headers)
        assert response.status_code == 404


def test_get_anime_by_id_invalid_format(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user:
        mock_get_user.return_value = mock_authenticated_user

        response = client.get("/animes/by-id/invalid-id", headers=auth_headers)
        assert response.status_code == 422


# =========================
# GET BY NAME TEST
# =========================
def test_get_anime_by_name_success(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.get_anime_by_name') as mock_get_by_name:

        mock_get_user.return_value = mock_authenticated_user
        mock_get_by_name.return_value = {
            "_id": "642a63402537c1f25e5f20fd",
            "name": "86 EIGHTY-SIX",
            "description": "Test",
            "episodes": 12,
            "season": "Spring 2021",
            "genres": ["Action"],
            "image_url": "https://example.com/image.jpg"
        }

        response = client.get("/animes/by-name/86 EIGHTY-SIX", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "86 EIGHTY-SIX"


def test_get_anime_by_name_not_found(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.get_anime_by_name') as mock_get_by_name:

        mock_get_user.return_value = mock_authenticated_user
        mock_get_by_name.return_value = None

        response = client.get("/animes/by-name/nonexistent_anime", headers=auth_headers)
        assert response.status_code == 404


# =========================
# JSON BODY REPAIR INTEGRATION TEST
# =========================
def test_create_anime_with_real_newlines_in_description(
    client, auth_headers, mock_authenticated_user
):
    """Test that real newlines in JSON strings are repaired and accepted."""
    # Mock the repository to avoid database operations
    with patch('app.routers.animes.get_anime_by_name') as mock_get_by_name, \
         patch('app.routers.animes.create_anime') as mock_create, \
         patch('app.core.dependencies.get_user_by_username') as mock_get_user:

        # Mock: user is authenticated
        mock_get_user.return_value = mock_authenticated_user

        # Mock: anime doesn't exist yet
        mock_get_by_name.return_value = None

        # Mock: return the created anime with an ID
        mock_create.return_value = {
            "_id": "507f1f77bcf86cd799439011",
            "name": "Test Normalization",
            "description": "Parrafo uno.\n\nParrafo dos.",
            "episodes": 1,
            "season": "Invierno 2026",
            "genres": ["Drama"],
            "image_url": "https://example.com/a.jpg"
        }

        # Construct the body manually with REAL newlines (not escaped)
        # This simulates what Reqable might send
        invalid_json_body = b'''{
  "name": "Test Normalization",
  "description": "Parrafo uno.

Parrafo dos.",
  "episodes": 1,
  "season": "Invierno 2026",
  "genres": [
    "Drama"
  ],
  "image_url": "https://example.com/a.jpg"
}'''

        # Send the request with the manually constructed body
        response = client.post(
            "/animes/",
            content=invalid_json_body,
            headers={"Content-Type": "application/json", **auth_headers}
        )

        # The request should succeed (not fail with JSON parse error)
        assert response.status_code == 201

        # Verify the repository was called with the repaired data
        mock_create.assert_called_once()
        call_args = mock_create.call_args[0][0]

        # The description should contain actual newlines (after JSON deserialization)
        assert call_args["description"] == "Parrafo uno.\n\nParrafo dos."
        assert call_args["name"] == "Test Normalization"
        assert call_args["episodes"] == 1


# =========================
# DUPLICATE KEY CONFLICT TESTS
# =========================
def test_create_anime_duplicate_key_returns_409(
    client, auth_headers, mock_authenticated_user
):
    """Test that a DuplicateKeyError during insert returns 409 Conflict."""
    with patch('app.routers.animes.get_anime_by_name') as mock_get_by_name, \
         patch('app.routers.animes.create_anime') as mock_create, \
         patch('app.core.dependencies.get_user_by_username') as mock_get_user:

        mock_get_user.return_value = mock_authenticated_user
        mock_get_by_name.return_value = None
        mock_create.side_effect = DuplicateKeyError("duplicate key error")

        response = client.post(
            "/animes/",
            json={
                "name": "Race Condition Anime",
                "description": "Test",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/anime.jpg",
            },
            headers=auth_headers,
        )

        assert response.status_code == 409
        assert response.json()["detail"] == "Anime already exists."


def test_update_anime_duplicate_key_returns_409(
    client, auth_headers, mock_authenticated_user
):
    """Test that a DuplicateKeyError during update returns 409 Conflict."""
    with patch('app.routers.animes.update_anime') as mock_update, \
         patch('app.core.dependencies.get_user_by_username') as mock_get_user:

        mock_get_user.return_value = mock_authenticated_user
        mock_update.side_effect = DuplicateKeyError("duplicate key error")

        response = client.put(
            "/animes/642a63402537c1f25e5f20fd",
            json={
                "name": "Already Existing Name",
                "description": "Test",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/anime.jpg",
            },
            headers=auth_headers,
        )

        assert response.status_code == 409
        assert response.json()["detail"] == "Anime already exists."


# =========================
# UPDATE ANIME TESTS
# =========================


def test_update_anime_success(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.update_anime') as mock_update:

        mock_get_user.return_value = mock_authenticated_user
        mock_update.return_value = {
            "_id": "642a63402537c1f25e5f20fd",
            "name": "Updated Anime",
            "description": "Updated description",
            "episodes": 24,
            "season": "Winter 2025",
            "genres": ["Action", "Drama"],
            "image_url": "https://example.com/updated.jpg",
        }

        response = client.put(
            "/animes/642a63402537c1f25e5f20fd",
            json={
                "name": "Updated Anime",
                "description": "Updated description",
                "episodes": 24,
                "season": "Winter 2025",
                "genres": ["Action", "Drama"],
                "image_url": "https://example.com/updated.jpg",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["_id"] == "642a63402537c1f25e5f20fd"
        assert data["name"] == "Updated Anime"
        assert data["episodes"] == 24
        assert data["genres"] == ["Action", "Drama"]

        from bson import ObjectId
        mock_update.assert_called_once_with(
            ObjectId("642a63402537c1f25e5f20fd"),
            {
                "name": "Updated Anime",
                "description": "Updated description",
                "episodes": 24,
                "season": "Winter 2025",
                "genres": ["Action", "Drama"],
                "image_url": "https://example.com/updated.jpg",
            },
        )


def test_update_anime_not_found(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.update_anime') as mock_update:

        mock_get_user.return_value = mock_authenticated_user
        mock_update.return_value = None

        response = client.put(
            "/animes/642a63402537c1f25e5f20fd",
            json={
                "name": "Ghost Anime",
                "description": "Test",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/anime.jpg",
            },
            headers=auth_headers,
        )

        assert response.status_code == 404
        assert response.json()["detail"] == "Anime not found."


def test_update_anime_without_write_permission(client, auth_headers):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.update_anime') as mock_update:

        mock_get_user.return_value = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "testuser",
            "password_hash": get_password_hash("password"),
            "permissions": ["read"],
            "active": True,
            "auth_version": 1,
        }

        response = client.put(
            "/animes/642a63402537c1f25e5f20fd",
            json={
                "name": "No Permission Anime",
                "description": "Test",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/anime.jpg",
            },
            headers=auth_headers,
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "Permission 'write' required"
        mock_update.assert_not_called()


def test_update_anime_validation_error_returns_422(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.update_anime') as mock_update:

        mock_get_user.return_value = mock_authenticated_user

        response = client.put(
            "/animes/642a63402537c1f25e5f20fd",
            json={
                "name": "",
                "description": "Test",
                "episodes": 12,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/anime.jpg",
            },
            headers=auth_headers,
        )

        assert response.status_code == 422
        mock_update.assert_not_called()


# =========================
# DELETE ANIME TESTS
# =========================


def test_delete_anime_success(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.delete_anime') as mock_delete:

        mock_get_user.return_value = mock_authenticated_user
        mock_delete.return_value = {
            "_id": "642a63402537c1f25e5f20fd",
            "name": "To Be Deleted",
            "description": "Test",
            "episodes": 12,
            "season": "Summer 2024",
            "genres": ["Action"],
            "image_url": "https://example.com/anime.jpg",
        }

        response = client.delete("/animes/642a63402537c1f25e5f20fd", headers=auth_headers)

        assert response.status_code == 204
        assert response.text == ""

        from bson import ObjectId
        mock_delete.assert_called_once_with(ObjectId("642a63402537c1f25e5f20fd"))


def test_delete_anime_without_admin_permission(client, auth_headers):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.delete_anime') as mock_delete:

        mock_get_user.return_value = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "testuser",
            "password_hash": get_password_hash("password"),
            "permissions": ["read", "write"],
            "active": True,
            "auth_version": 1,
        }

        response = client.delete("/animes/642a63402537c1f25e5f20fd", headers=auth_headers)

        assert response.status_code == 403
        assert response.json()["detail"] == "Permission 'admin' required"
        mock_delete.assert_not_called()


def test_delete_anime_not_found(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.delete_anime') as mock_delete:

        mock_get_user.return_value = mock_authenticated_user
        mock_delete.return_value = None

        response = client.delete("/animes/642a63402537c1f25e5f20fd", headers=auth_headers)

        assert response.status_code == 404
        assert response.json()["detail"] == "Anime not found."


# =========================
# OBJECT ID VALIDATION TESTS
# =========================


def test_get_anime_by_id_invalid_object_id_returns_400(
    client, auth_headers, mock_authenticated_user
):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user:
        mock_get_user.return_value = mock_authenticated_user

        response = client.get("/animes/by-id/zzzzzzzzzzzzzzzzzzzzzzzz", headers=auth_headers)
        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid ObjectId"


# =========================
# CREATE ANIME VALIDATION TESTS
# =========================


def test_create_anime_validation_error_returns_422(client, auth_headers, mock_authenticated_user):
    with patch('app.core.dependencies.get_user_by_username') as mock_get_user, \
         patch('app.routers.animes.get_anime_by_name') as mock_get_by_name, \
         patch('app.routers.animes.create_anime') as mock_create:

        mock_get_user.return_value = mock_authenticated_user
        mock_get_by_name.return_value = None

        response = client.post(
            "/animes/",
            json={
                "name": "Invalid Anime",
                "description": "Test",
                "episodes": -1,
                "season": "Summer 2024",
                "genres": ["Action"],
                "image_url": "https://example.com/anime.jpg",
            },
            headers=auth_headers,
        )

        assert response.status_code == 422
        mock_get_by_name.assert_not_called()
        mock_create.assert_not_called()
