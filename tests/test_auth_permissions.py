from unittest.mock import patch

from app.core.security import create_access_token, get_password_hash, verify_password
from tests.conftest import (
    TARGET_USER_ID,
    _admin_mock_headers,
    _admin_mock_user,
    _target_mock_user,
)


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


# =========================
# TOGGLE USER ACTIVE TESTS
# =========================


