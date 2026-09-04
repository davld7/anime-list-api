"""Pytest configuration for the anime-list-api test suite.

IMPORTANT: Everything here that touches environment/configuration runs at
module import time, BEFORE any ``app``/``main``/``database``/``settings``
module is imported by the test files. This guarantees that by the time the
application builds its ``Settings`` object, ``DATABASE_NAME`` is already the
test database ``anime_list_test`` and never the production database
``anime_list``.
"""

import os

import pytest

# ---------------------------------------------------------------------------
# ENVIRONMENT OVERRIDES (must happen before importing app modules)
# ---------------------------------------------------------------------------

# The single database that tests are allowed to touch. Never change this to
# a production name.
TEST_DATABASE_NAME = "anime_list_test"

# Hard-override the database name for the whole test process. Real MongoDB
# credentials stay in MONGO_URI (loaded from .env), so the same cluster is
# reused but pointed exclusively at the test database.
os.environ["DATABASE_NAME"] = TEST_DATABASE_NAME

# Deterministic JWT secret for the test environment.
os.environ.setdefault("JWT_SECRET_KEY", "test_secret_key_for_testing_only")

# ---------------------------------------------------------------------------
# SAFETY GUARD
# ---------------------------------------------------------------------------

# Import the application Settings only now that the environment is correct.
from app.core.config import settings  # noqa: E402


def _assert_test_database():
    if settings.DATABASE_NAME != TEST_DATABASE_NAME:
        raise RuntimeError(
            "Refusing to run tests: DATABASE_NAME must be exactly "
            f"{TEST_DATABASE_NAME!r}, got {settings.DATABASE_NAME!r}. "
            "Tests must never run against a non-test database."
        )


# Abort the test session before any destructive operation if the guard fails.
_assert_test_database()


# ---------------------------------------------------------------------------
# SHARED CLIENT FIXTURE
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    # Re-check the guard right before the application connects to MongoDB so
    # that a misconfigured environment aborts before any write/deletion.
    _assert_test_database()
    from fastapi.testclient import TestClient

    from main import app

    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# SHARED HELPERS (used by the permissions and users test modules)
# ---------------------------------------------------------------------------

TARGET_USER_ID = "507f1f77bcf86cd799439044"


def _admin_mock_headers():
    from app.core.security import create_access_token

    token = create_access_token(data={"sub": "admin_user", "auth_version": 1})
    return {"Authorization": f"Bearer {token}"}


def _admin_mock_user(permissions=None):
    from app.core.security import get_password_hash

    return {
        "_id": "507f1f77bcf86cd799439011",
        "username": "admin_user",
        "password_hash": get_password_hash("password"),
        "permissions": permissions if permissions is not None else ["read", "write", "admin"],
        "active": True,
        "auth_version": 1,
    }


def _target_mock_user(active=True, permissions=("read",)):
    from app.core.security import get_password_hash

    return {
        "_id": TARGET_USER_ID,
        "username": "target_user",
        "password_hash": get_password_hash("password"),
        "permissions": list(permissions),
        "active": active,
        "auth_version": 1,
    }
