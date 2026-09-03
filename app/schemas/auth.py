from pydantic import BaseModel, Field


class AuthTokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="Opaque refresh token")
    token_type: str = Field(default="bearer", description="Token type")


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1, description="Opaque refresh token")
