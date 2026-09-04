from unittest.mock import patch

from app.core.security import create_access_token, get_password_hash, verify_password


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
    from app.db.database import get_refresh_tokens_collection
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    get_refresh_tokens_collection().delete_many({"user_id": ObjectId(created_user["_id"])})
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
    from app.db.database import get_refresh_tokens_collection
    from app.repositories.user_repository import get_users_collection
    collection = get_users_collection()
    get_refresh_tokens_collection().delete_many({"user_id": ObjectId(created_user["_id"])})
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


