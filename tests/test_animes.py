from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


# =========================
# HEALTH CHECK TEST
# =========================
def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] == "ok"
    assert "database" in data


# =========================
# GET ANIMES PAGINATED TEST
# =========================
def test_get_paginated_animes():
    response = client.get("/animes/page?page=1")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


# =========================
# GET TOTAL PAGES TEST
# =========================
def test_get_total_pages():
    response = client.get("/animes/pages")
    assert response.status_code == 200
    data = response.json()
    assert "total_animes" in data
    assert "total_pages" in data
    assert isinstance(data["total_animes"], int)
    assert isinstance(data["total_pages"], int)


# =========================
# GET BY NAME TEST
# =========================
def test_get_anime_by_name():
    response = client.get("/animes/by-name/nonexistent_anime")
    assert response.status_code in [200, 404]
