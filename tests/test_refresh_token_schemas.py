import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.schemas.auth import AuthTokenResponse, RefreshTokenRequest


def test_refresh_token_expire_days_default_is_30():
    assert Settings().JWT_REFRESH_TOKEN_EXPIRE_DAYS == 30


def test_refresh_token_expire_days_can_be_overridden(monkeypatch):
    monkeypatch.setenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "45")
    assert Settings().JWT_REFRESH_TOKEN_EXPIRE_DAYS == 45


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
