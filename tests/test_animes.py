from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


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
def test_get_paginated_animes(client):
    response = client.get("/animes/page?page=1")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


# =========================
# GET TOTAL PAGES TEST
# =========================
def test_get_total_pages(client):
    response = client.get("/animes/pages")
    assert response.status_code == 200
    data = response.json()
    assert "total_animes" in data
    assert "total_pages" in data
    assert isinstance(data["total_animes"], int)
    assert isinstance(data["total_pages"], int)


# =========================
# GET BY ID TEST
# =========================
def test_get_anime_by_id_success(client):
    response = client.get("/animes/by-id/642a63402537c1f25e5f20fd")
    assert response.status_code == 200
    data = response.json()
    assert data["_id"] == "642a63402537c1f25e5f20fd"
    assert "name" in data


def test_get_anime_by_id_not_found(client):
    response = client.get("/animes/by-id/123456789012345678901234")
    assert response.status_code == 404


def test_get_anime_by_id_invalid_format(client):
    response = client.get("/animes/by-id/invalid-id")
    assert response.status_code == 422


# =========================
# GET BY NAME TEST
# =========================
def test_get_anime_by_name_success(client):
    response = client.get("/animes/by-name/86 EIGHTY-SIX")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "86 EIGHTY-SIX"


def test_get_anime_by_name_not_found(client):
    response = client.get("/animes/by-name/nonexistent_anime")
    assert response.status_code == 404


# =========================
# JSON BODY REPAIR INTEGRATION TEST
# =========================
def test_create_anime_with_real_newlines_in_description(client):
    """Test that real newlines in JSON strings are repaired and accepted."""
    # Mock the repository to avoid database operations
    with patch('app.routers.animes.get_anime_by_name') as mock_get_by_name, \
         patch('app.routers.animes.create_anime') as mock_create:

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
            headers={"Content-Type": "application/json"}
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
