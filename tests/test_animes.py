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
