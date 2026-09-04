from unittest.mock import patch

from pymongo.errors import DuplicateKeyError

from app.core.security import (
    create_access_token,
    get_password_hash,
    verify_password,
)
from tests.conftest import (
    TARGET_USER_ID,
    _admin_mock_headers,
    _admin_mock_user,
    _target_mock_user,
)


def test_admin_can_create_user(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_username") as mock_get_by_name, \
         patch("app.routers.auth.create_user") as mock_create:

        mock_current.return_value = admin
        mock_get_by_name.return_value = None
        mock_create.return_value = {
            "_id": "507f1f77bcf86cd799439099",
            "username": "new_user",
            "permissions": ["read"],
            "active": True,
            "auth_version": 1,
        }

        response = client.post(
            "/auth/users",
            json={
                "username": "new_user",
                "password": "password123",
                "permissions": ["read"],
                "active": True,
            },
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "new_user"
        assert data["permissions"] == ["read"]
        assert data["active"] is True
        assert "password" not in data
        assert "password_hash" not in data

        mock_create.assert_called_once()
        call_args = mock_create.call_args[0][0]
        assert call_args["username"] == "new_user"
        assert call_args["password_hash"] != "password123"
        assert call_args["permissions"] == ["read"]
        assert call_args["active"] is True




def test_create_user_with_admin_permissions(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_username") as mock_get_by_name, \
         patch("app.routers.auth.create_user") as mock_create:

        mock_current.return_value = admin
        mock_get_by_name.return_value = None
        mock_create.return_value = {
            "_id": "507f1f77bcf86cd799439099",
            "username": "new_admin",
            "permissions": ["read", "write", "admin"],
            "active": True,
            "auth_version": 1,
        }

        response = client.post(
            "/auth/users",
            json={
                "username": "new_admin",
                "password": "password123",
                "permissions": ["read", "write", "admin"],
                "active": True,
            },
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 201
        data = response.json()
        assert data["permissions"] == ["read", "write", "admin"]




def test_create_user_inactive(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_username") as mock_get_by_name, \
         patch("app.routers.auth.create_user") as mock_create:

        mock_current.return_value = admin
        mock_get_by_name.return_value = None
        mock_create.return_value = {
            "_id": "507f1f77bcf86cd799439099",
            "username": "inactive_user",
            "permissions": ["read"],
            "active": False,
            "auth_version": 1,
        }

        response = client.post(
            "/auth/users",
            json={
                "username": "inactive_user",
                "password": "password123",
                "permissions": ["read"],
                "active": False,
            },
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 201
        data = response.json()
        assert data["active"] is False




def test_create_user_without_authentication(client):
    response = client.post(
        "/auth/users",
        json={
            "username": "new_user",
            "password": "password123",
            "permissions": ["read"],
        },
    )

    assert response.status_code == 401




def test_create_user_without_admin_permission(client):
    non_admin = _admin_mock_user(permissions=["read", "write"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = non_admin

        response = client.post(
            "/auth/users",
            json={
                "username": "new_user",
                "password": "password123",
                "permissions": ["read"],
            },
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 403




def test_create_user_username_already_taken(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_username") as mock_get_by_name:

        mock_current.return_value = admin
        mock_get_by_name.return_value = {"username": "existing_user"}

        response = client.post(
            "/auth/users",
            json={
                "username": "existing_user",
                "password": "password123",
                "permissions": ["read"],
            },
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 409




def test_create_user_duplicate_key_error(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_username") as mock_get_by_name, \
         patch("app.routers.auth.create_user") as mock_create:

        mock_current.return_value = admin
        mock_get_by_name.return_value = None
        mock_create.side_effect = DuplicateKeyError("duplicate key error")

        response = client.post(
            "/auth/users",
            json={
                "username": "new_user",
                "password": "password123",
                "permissions": ["read"],
            },
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 409




def test_create_user_missing_username(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = admin

        response = client.post(
            "/auth/users",
            json={"password": "password123", "permissions": ["read"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422




def test_create_user_missing_password(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = admin

        response = client.post(
            "/auth/users",
            json={"username": "new_user", "permissions": ["read"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422




def test_create_user_empty_username(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = admin

        response = client.post(
            "/auth/users",
            json={"username": "", "password": "password123", "permissions": ["read"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422




def test_create_user_empty_password(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = admin

        response = client.post(
            "/auth/users",
            json={"username": "new_user", "password": "", "permissions": ["read"]},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422




def test_create_user_invalid_permission(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = admin

        response = client.post(
            "/auth/users",
            json={
                "username": "new_user",
                "password": "password123",
                "permissions": ["read", "superadmin"],
            },
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422




def test_create_user_duplicate_permission_rejected(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = admin

        response = client.post(
            "/auth/users",
            json={
                "username": "new_user",
                "password": "password123",
                "permissions": ["read", "read"],
            },
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422




def test_create_user_defaults_active_true(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_username") as mock_get_by_name, \
         patch("app.routers.auth.create_user") as mock_create:

        mock_current.return_value = admin
        mock_get_by_name.return_value = None
        mock_create.return_value = {
            "_id": "507f1f77bcf86cd799439099",
            "username": "new_user",
            "permissions": ["read"],
            "active": True,
            "auth_version": 1,
        }

        response = client.post(
            "/auth/users",
            json={
                "username": "new_user",
                "password": "password123",
                "permissions": ["read"],
            },
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 201
        data = response.json()
        assert data["active"] is True




def test_create_user_creates_in_database(client):
    from bson import ObjectId

    from app.repositories.user_repository import (
        create_user as repo_create_user,
    )
    from app.repositories.user_repository import (
        get_users_collection,
    )

    collection = get_users_collection()
    collection.delete_one({"username": "admin_create"})
    collection.delete_one({"username": "created_via_endpoint"})

    admin = repo_create_user({
        "username": "admin_create",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    })

    try:
        admin_token = create_access_token(
            data={"sub": "admin_create", "auth_version": 1}
        )
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        response = client.post(
            "/auth/users",
            json={
                "username": "created_via_endpoint",
                "password": "password123",
                "permissions": ["read", "write"],
                "active": True,
            },
            headers=admin_headers,
        )
        assert response.status_code == 201

        data = response.json()
        assert data["username"] == "created_via_endpoint"
        assert data["permissions"] == ["read", "write"]
        assert data["active"] is True
        assert "password" not in data
        assert "password_hash" not in data

        from app.repositories.user_repository import get_user_by_username
        db_user = get_user_by_username("created_via_endpoint")
        assert db_user is not None
        assert db_user["username"] == "created_via_endpoint"
        assert db_user["permissions"] == ["read", "write"]
        assert db_user["active"] is True
        assert db_user["auth_version"] == 1
        assert verify_password("password123", db_user["password_hash"])

        collection = get_users_collection()
        created = get_user_by_username("created_via_endpoint")
        collection.delete_one({"_id": created["_id"]})
    finally:
        collection = get_users_collection()
        collection.delete_one({"_id": ObjectId(admin["_id"])})




def test_create_user_auth_version_starts_at_one(client):
    from bson import ObjectId

    from app.repositories.user_repository import (
        create_user as repo_create_user,
    )
    from app.repositories.user_repository import (
        get_users_collection,
    )

    collection = get_users_collection()
    collection.delete_one({"username": "admin_version"})
    collection.delete_one({"username": "version_check_user"})

    admin = repo_create_user({
        "username": "admin_version",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    })

    try:
        admin_token = create_access_token(
            data={"sub": "admin_version", "auth_version": 1}
        )
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        response = client.post(
            "/auth/users",
            json={
                "username": "version_check_user",
                "password": "password123",
                "permissions": ["read"],
            },
            headers=admin_headers,
        )
        assert response.status_code == 201

        from app.repositories.user_repository import get_user_by_username
        db_user = get_user_by_username("version_check_user")
        assert db_user["auth_version"] == 1

        collection = get_users_collection()
        collection.delete_one({"_id": db_user["_id"]})
    finally:
        collection = get_users_collection()
        collection.delete_one({"_id": ObjectId(admin["_id"])})




def test_create_user_response_never_exposes_password_hash(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_username") as mock_get_by_name, \
         patch("app.routers.auth.create_user") as mock_create:

        mock_current.return_value = admin
        mock_get_by_name.return_value = None
        mock_create.return_value = {
            "_id": "507f1f77bcf86cd799439099",
            "username": "new_user",
            "password_hash": "should_not_appear",
            "permissions": ["read"],
            "active": True,
            "auth_version": 1,
        }

        response = client.post(
            "/auth/users",
            json={
                "username": "new_user",
                "password": "password123",
                "permissions": ["read"],
            },
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 201
        response_text = response.text
        assert "password_hash" not in response_text
        assert "should_not_appear" not in response_text


# =========================
# LIST USERS TESTS
# =========================



def test_admin_can_deactivate_user(client):
    from bson import ObjectId

    admin = _admin_mock_user()
    target = _target_mock_user(active=True)

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.update_user_by_id_atomic") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_update.return_value = {**target, "active": False}

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/active",
            json={"active": False},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["active"] is False

        mock_update.assert_called_once_with(
            ObjectId(TARGET_USER_ID),
            {"active": False},
            {"auth_version": 1},
        )




def test_admin_can_activate_user(client):
    from bson import ObjectId

    admin = _admin_mock_user()
    target = _target_mock_user(active=False)

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.update_user_by_id_atomic") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_update.return_value = {**target, "active": True}

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/active",
            json={"active": True},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["active"] is True

        mock_update.assert_called_once_with(
            ObjectId(TARGET_USER_ID),
            {"active": True},
            {"auth_version": 1},
        )




def test_toggle_active_without_authentication(client):
    response = client.put(
        f"/auth/users/{TARGET_USER_ID}/active",
        json={"active": False},
    )

    assert response.status_code == 401




def test_toggle_active_without_admin_permission(client):
    non_admin = _admin_mock_user(permissions=["read", "write"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = non_admin

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/active",
            json={"active": False},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 403




def test_toggle_active_user_not_found(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id:

        mock_current.return_value = admin
        mock_get_by_id.return_value = None

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/active",
            json={"active": False},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 404




def test_toggle_active_invalid_object_id(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            "/auth/users/zzzzzzzzzzzzzzzzzzzzzzzz/active",
            json={"active": False},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 400




def test_toggle_active_short_object_id(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            "/auth/users/abc/active",
            json={"active": False},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422




def test_toggle_active_missing_field(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/active",
            json={},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422




def test_toggle_active_invalid_value(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/active",
            json={"active": "maybe"},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422




def test_toggle_active_idempotent_when_state_already_matches(client):
    admin = _admin_mock_user()
    target = _target_mock_user(active=True)

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.update_user_by_id_atomic") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/active",
            json={"active": True},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["active"] is True
        mock_update.assert_not_called()




def test_toggle_active_last_active_admin_returns_409(client):
    admin = _admin_mock_user()
    target = _target_mock_user(active=True, permissions=["read", "admin"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.count_active_admins") as mock_count:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_count.return_value = 1

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/active",
            json={"active": False},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 409




def test_admin_can_deactivate_self_when_another_active_admin_exists(client):
    admin = _admin_mock_user()
    target = _target_mock_user(active=True, permissions=["read", "admin"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.count_active_admins") as mock_count, \
         patch("app.routers.auth.update_user_by_id_atomic") as mock_update:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_count.return_value = 2
        mock_update.return_value = {**target, "active": False}

        response = client.put(
            f"/auth/users/{TARGET_USER_ID}/active",
            json={"active": False},
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json()["active"] is False




def test_toggle_active_increments_auth_version(client):
    from bson import ObjectId

    from app.repositories.user_repository import (
        create_user,
        get_user_by_username,
        get_users_collection,
    )

    collection = get_users_collection()
    collection.delete_many({"username": {"$in": ["admin_toggle", "target_toggle"]}})

    admin = create_user({
        "username": "admin_toggle",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    })
    target = create_user({
        "username": "target_toggle",
        "password_hash": get_password_hash("password"),
        "permissions": ["read"],
        "active": True,
        "auth_version": 1,
    })

    try:
        admin_token = create_access_token(
            data={"sub": "admin_toggle", "auth_version": 1}
        )
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        response = client.put(
            f"/auth/users/{target['_id']}/active",
            json={"active": False},
            headers=admin_headers,
        )
        assert response.status_code == 200

        updated = get_user_by_username("target_toggle")
        assert updated["auth_version"] == 2
        assert updated["active"] is False
        assert updated["username"] == "target_toggle"
        assert updated["permissions"] == ["read"]

        response = client.put(
            f"/auth/users/{target['_id']}/active",
            json={"active": True},
            headers=admin_headers,
        )
        assert response.status_code == 200

        updated = get_user_by_username("target_toggle")
        assert updated["auth_version"] == 3
        assert updated["active"] is True
        assert updated["username"] == "target_toggle"
        assert updated["permissions"] == ["read"]
    finally:
        collection = get_users_collection()
        collection.delete_one({"_id": ObjectId(admin["_id"])})
        collection.delete_one({"_id": ObjectId(target["_id"])})




def test_toggle_active_preserves_other_fields(client):
    from bson import ObjectId

    from app.repositories.user_repository import (
        create_user,
        get_user_by_username,
        get_users_collection,
    )

    collection = get_users_collection()
    collection.delete_many({"username": {"$in": ["admin_preserve", "target_preserve"]}})

    admin = create_user({
        "username": "admin_preserve",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    })
    target = create_user({
        "username": "target_preserve",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write"],
        "active": True,
        "auth_version": 1,
    })

    try:
        admin_token = create_access_token(
            data={"sub": "admin_preserve", "auth_version": 1}
        )
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        response = client.put(
            f"/auth/users/{target['_id']}/active",
            json={"active": False},
            headers=admin_headers,
        )
        assert response.status_code == 200

        updated = get_user_by_username("target_preserve")
        assert updated["username"] == "target_preserve"
        assert updated["permissions"] == ["read", "write"]
        assert verify_password("password", updated["password_hash"])
        assert updated["active"] is False
        assert updated["auth_version"] == 2
    finally:
        collection = get_users_collection()
        collection.delete_one({"_id": ObjectId(admin["_id"])})
        collection.delete_one({"_id": ObjectId(target["_id"])})


# =========================
# ADMIN CREATE USER TESTS
# =========================




def test_list_users_requires_admin_permission(client):
    non_admin = _admin_mock_user(permissions=["read", "write"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = non_admin

        response = client.get(
            "/auth/users",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 403




def test_list_users_requires_authentication(client):
    response = client.get("/auth/users")
    assert response.status_code == 401




def test_list_users_returns_paginated_results(client):
    admin = _admin_mock_user()
    mock_users = [
        {
            "_id": f"507f1f77bcf86cd7994390{i:02d}",
            "username": f"user_{i}",
            "permissions": ["read"],
            "active": True,
            "auth_version": 1,
        }
        for i in range(3)
    ]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_paginated_users") as mock_get_users:

        mock_current.return_value = admin
        mock_get_users.return_value = mock_users

        response = client.get(
            "/auth/users?page=1",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3
        assert data[0]["username"] == "user_0"
        assert data[1]["username"] == "user_1"
        assert data[2]["username"] == "user_2"




def test_list_users_page_2(client):
    admin = _admin_mock_user()
    mock_users = [
        {
            "_id": "507f1f77bcf86cd799439010",
            "username": "page2_user",
            "permissions": ["read"],
            "active": True,
            "auth_version": 1,
        }
    ]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_paginated_users") as mock_get_users:

        mock_current.return_value = admin
        mock_get_users.return_value = mock_users

        response = client.get(
            "/auth/users?page=2",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        mock_get_users.assert_called_once_with(2, 10, {})




def test_list_users_empty_results(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_paginated_users") as mock_get_users:

        mock_current.return_value = admin
        mock_get_users.return_value = []

        response = client.get(
            "/auth/users?page=1",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert response.json() == []




def test_list_users_active_filter_true(client):
    admin = _admin_mock_user()
    mock_users = [
        {
            "_id": "507f1f77bcf86cd799439010",
            "username": "active_user",
            "permissions": ["read"],
            "active": True,
            "auth_version": 1,
        }
    ]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_paginated_users") as mock_get_users:

        mock_current.return_value = admin
        mock_get_users.return_value = mock_users

        response = client.get(
            "/auth/users?active=true",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert len(response.json()) == 1
        mock_get_users.assert_called_once_with(1, 10, {"active": True})




def test_list_users_active_filter_false(client):
    admin = _admin_mock_user()
    mock_users = [
        {
            "_id": "507f1f77bcf86cd799439010",
            "username": "inactive_user",
            "permissions": ["read"],
            "active": False,
            "auth_version": 1,
        }
    ]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_paginated_users") as mock_get_users:

        mock_current.return_value = admin
        mock_get_users.return_value = mock_users

        response = client.get(
            "/auth/users?active=false",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        assert len(response.json()) == 1
        mock_get_users.assert_called_once_with(1, 10, {"active": False})




def test_list_users_never_exposes_password_hash(client):
    admin = _admin_mock_user()
    mock_users = [
        {
            "_id": "507f1f77bcf86cd799439010",
            "username": "user_with_hash",
            "password_hash": "super_secret_hash_value",
            "permissions": ["read"],
            "active": True,
            "auth_version": 1,
        }
    ]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_paginated_users") as mock_get_users:

        mock_current.return_value = admin
        mock_get_users.return_value = mock_users

        response = client.get(
            "/auth/users",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        response_text = response.text
        assert "password_hash" not in response_text
        assert "super_secret_hash_value" not in response_text




def test_list_users_response_contains_expected_fields(client):
    admin = _admin_mock_user()
    mock_users = [
        {
            "_id": "507f1f77bcf86cd799439010",
            "username": "test_user",
            "permissions": ["read", "write", "admin"],
            "active": True,
            "auth_version": 3,
        }
    ]

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_paginated_users") as mock_get_users:

        mock_current.return_value = admin
        mock_get_users.return_value = mock_users

        response = client.get(
            "/auth/users",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        data = response.json()[0]
        assert data["_id"] == "507f1f77bcf86cd799439010"
        assert data["username"] == "test_user"
        assert data["permissions"] == ["read", "write", "admin"]
        assert data["active"] is True
        assert "password" not in data


# =========================
# GET USER PAGES TESTS
# =========================



def test_get_user_pages_requires_admin_permission(client):
    non_admin = _admin_mock_user(permissions=["read", "write"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = non_admin

        response = client.get(
            "/auth/users/pages",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 403




def test_get_user_pages_requires_authentication(client):
    response = client.get("/auth/users/pages")
    assert response.status_code == 401




def test_get_user_pages_returns_totals(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.count_users") as mock_count:

        mock_current.return_value = admin
        mock_count.return_value = 25

        response = client.get(
            "/auth/users/pages",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total_users"] == 25
        assert data["total_pages"] == 3




def test_get_user_pages_zero_users(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.count_users") as mock_count:

        mock_current.return_value = admin
        mock_count.return_value = 0

        response = client.get(
            "/auth/users/pages",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total_users"] == 0
        assert data["total_pages"] == 0




def test_get_user_pages_active_filter(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.count_users") as mock_count:

        mock_current.return_value = admin
        mock_count.return_value = 10

        response = client.get(
            "/auth/users/pages?active=true",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        mock_count.assert_called_once_with({"active": True})


# =========================
# GET USER BY ID TESTS
# =========================




def test_get_user_by_id_returns_user(client):
    admin = _admin_mock_user()
    target = _target_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target

        response = client.get(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["_id"] == TARGET_USER_ID
        assert data["username"] == "target_user"
        assert data["permissions"] == ["read"]
        assert data["active"] is True




def test_get_user_by_id_not_found(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id:

        mock_current.return_value = admin
        mock_get_by_id.return_value = None

        response = client.get(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 404




def test_get_user_by_id_invalid_object_id(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.get(
            "/auth/users/zzzzzzzzzzzzzzzzzzzzzzzz",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 400




def test_get_user_by_id_requires_authentication(client):
    response = client.get(
        f"/auth/users/{TARGET_USER_ID}",
    )

    assert response.status_code == 401




def test_get_user_by_id_requires_admin_permission(client):
    non_admin = _admin_mock_user(permissions=["read", "write"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = non_admin

        response = client.get(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 403




def test_get_user_by_id_never_exposes_sensitive_fields(client):
    admin = _admin_mock_user()
    target = {
        "_id": TARGET_USER_ID,
        "username": "target_user",
        "password_hash": "super_secret_hash_value",
        "permissions": ["read"],
        "active": True,
        "auth_version": 5,
    }

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target

        response = client.get(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 200
        response_text = response.text
        assert "password_hash" not in response_text
        assert "super_secret_hash_value" not in response_text
        assert "auth_version" not in response_text


# =========================
# DELETE USER TESTS
# =========================




def test_admin_can_delete_other_user(client):
    from bson import ObjectId

    admin = _admin_mock_user()
    target = _target_mock_user(permissions=["read"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.delete_user_by_id") as mock_delete:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_delete.return_value = True

        response = client.delete(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 204
        mock_delete.assert_called_once_with(ObjectId(TARGET_USER_ID))




def test_delete_user_without_authentication(client):
    response = client.delete(
        f"/auth/users/{TARGET_USER_ID}",
    )

    assert response.status_code == 401




def test_delete_user_without_admin_permission(client):
    non_admin = _admin_mock_user(permissions=["read", "write"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = non_admin

        response = client.delete(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 403




def test_delete_user_not_found(client):
    admin = _admin_mock_user()

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id:

        mock_current.return_value = admin
        mock_get_by_id.return_value = None

        response = client.delete(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 404




def test_delete_user_invalid_object_id(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.delete(
            "/auth/users/zzzzzzzzzzzzzzzzzzzzzzzz",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 400




def test_delete_user_short_object_id(client):
    with patch("app.core.dependencies.get_user_by_username") as mock_current:
        mock_current.return_value = _admin_mock_user()

        response = client.delete(
            "/auth/users/abc",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 422




def test_delete_non_admin_user_allowed(client):
    admin = _admin_mock_user()
    target = _target_mock_user(permissions=["read"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.delete_user_by_id") as mock_delete:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_delete.return_value = True

        response = client.delete(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 204




def test_delete_inactive_admin_allowed_when_other_active_admins_exist(client):
    admin = _admin_mock_user()
    target = _target_mock_user(active=False, permissions=["read", "admin"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.count_active_admins") as mock_count, \
         patch("app.routers.auth.delete_user_by_id") as mock_delete:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_count.return_value = 2
        mock_delete.return_value = True

        response = client.delete(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 204




def test_delete_last_active_admin_returns_409(client):
    admin = _admin_mock_user()
    target = _target_mock_user(active=True, permissions=["read", "admin"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.count_active_admins") as mock_count:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_count.return_value = 1

        response = client.delete(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 409




def test_delete_active_admin_allowed_when_another_active_admin_exists(client):
    admin = _admin_mock_user()
    target = _target_mock_user(active=True, permissions=["read", "admin"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.count_active_admins") as mock_count, \
         patch("app.routers.auth.delete_user_by_id") as mock_delete:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_count.return_value = 2
        mock_delete.return_value = True

        response = client.delete(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 204




def test_admin_can_delete_self_when_another_active_admin_exists(client):
    from bson import ObjectId

    from app.repositories.user_repository import (
        create_user,
        get_user_by_username,
        get_users_collection,
    )

    collection = get_users_collection()
    collection.delete_many({"username": {"$in": ["admin_self_del", "admin_other_del"]}})

    admin = create_user({
        "username": "admin_self_del",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    })
    other_admin = create_user({
        "username": "admin_other_del",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    })

    try:
        admin_token = create_access_token(
            data={"sub": "admin_self_del", "auth_version": 1}
        )
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        response = client.delete(
            f"/auth/users/{admin['_id']}",
            headers=admin_headers,
        )
        assert response.status_code == 204

        from app.repositories.user_repository import get_user_by_id
        deleted_user = get_user_by_id(ObjectId(admin["_id"]))
        assert deleted_user is None

        remaining_admin = get_user_by_username("admin_other_del")
        assert remaining_admin is not None
    finally:
        collection = get_users_collection()
        collection.delete_one({"_id": ObjectId(admin["_id"])})
        collection.delete_one({"_id": ObjectId(other_admin["_id"])})




def test_admin_cannot_delete_self_when_last_active_admin(client):
    from bson import ObjectId

    from app.repositories.user_repository import (
        create_user,
        get_user_by_id,
        get_users_collection,
    )

    collection = get_users_collection()

    # Controlled, test-specific data preparation. Only the documents created
    # by this test are ever removed; nothing that pre-exists is deleted.
    created_ids = []

    admin = create_user({
        "username": "admin_last_self",
        "password_hash": get_password_hash("password"),
        "permissions": ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    })
    created_ids.append(admin["_id"])

    try:
        admin_token = create_access_token(
            data={"sub": "admin_last_self", "auth_version": 1}
        )
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        response = client.delete(
            f"/auth/users/{admin['_id']}",
            headers=admin_headers,
        )
        assert response.status_code == 409

        still_exists = get_user_by_id(ObjectId(admin["_id"]))
        assert still_exists is not None
    finally:
        for user_id in created_ids:
            collection.delete_one({"_id": ObjectId(user_id)})



def test_delete_user_returns_no_content(client):
    admin = _admin_mock_user()
    target = _target_mock_user(permissions=["read"])

    with patch("app.core.dependencies.get_user_by_username") as mock_current, \
         patch("app.routers.auth.get_user_by_id") as mock_get_by_id, \
         patch("app.routers.auth.delete_user_by_id") as mock_delete:

        mock_current.return_value = admin
        mock_get_by_id.return_value = target
        mock_delete.return_value = True

        response = client.delete(
            f"/auth/users/{TARGET_USER_ID}",
            headers=_admin_mock_headers(),
        )

        assert response.status_code == 204
        assert response.text == ""
