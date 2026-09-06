import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.schemas.auth import AuthTokenResponse, RefreshTokenRequest


@pytest.mark.parametrize("days", [30, 45])
def test_refresh_token_expire_days_reads_from_environment(monkeypatch, days):
    """JWT_REFRESH_TOKEN_EXPIRE_DAYS is loaded from the environment.

    The value is set explicitly here so the test never depends on a
    developer's .env file. The second case also exercises overriding it.
    """
    monkeypatch.setenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", str(days))
    assert Settings().JWT_REFRESH_TOKEN_EXPIRE_DAYS == days


def test_auth_token_response_fields():
    token = AuthTokenResponse(
        access_token="access.example",
        refresh_token="opaque_refresh_token",
    )
    assert token.access_token == "access.example"
    assert token.refresh_token == "opaque_refresh_token"
    assert token.token_type == "bearer"


def test_auth_token_response_accepts_explicit_token_type():
    token = AuthTokenResponse(
        access_token="access",
        refresh_token="refresh",
        token_type="bearer",
    )
    assert token.token_type == "bearer"


def test_refresh_token_request_accepts_valid_token():
    request = RefreshTokenRequest(refresh_token="some_opaque_token")
    assert request.refresh_token == "some_opaque_token"


def test_refresh_token_request_rejects_empty_string():
    with pytest.raises(ValidationError):
        RefreshTokenRequest(refresh_token="")
