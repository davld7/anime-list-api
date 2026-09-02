from typing import Annotated

from pydantic import BaseModel, BeforeValidator, Field, field_validator

ALLOWED_PERMISSIONS = {"read", "write", "admin"}


def convert_object_id(v):
    if isinstance(v, dict):
        return str(v.get("_id") or v.get("id"))
    return str(v)


class UserBase(BaseModel):
    username: str = Field(..., min_length=1, description="Username", examples=["david"])
    permissions: list[str] = Field(
        default_factory=list, description="User permissions", examples=[["read", "write", "admin"]]
    )
    active: bool = Field(default=True, description="Whether the user is active")


class UserCreate(UserBase):
    password: str = Field(..., min_length=1, description="Plain text password")


class UserResponse(UserBase):
    id: Annotated[str | None, BeforeValidator(convert_object_id)] = Field(
        default=None, alias="_id", description="MongoDB ObjectId"
    )


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, description="Username")
    password: str = Field(..., min_length=1, description="Password")


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")


class ChangeUsernameRequest(BaseModel):
    new_username: str = Field(..., min_length=1, description="New username", examples=["david2"])


class ChangeUsernameResponse(BaseModel):
    new_username: str = Field(..., description="Updated username")
    message: str = Field(..., description="Information message")


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, description="Current password")
    new_password: str = Field(..., min_length=1, description="New password")


class ChangePasswordResponse(BaseModel):
    message: str = Field(..., description="Information message")


class UpdatePermissionsRequest(BaseModel):
    permissions: list[str] = Field(
        default_factory=list, description="Replacement permissions", examples=[["read", "write"]]
    )

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: list[str]) -> list[str]:
        seen: set[str] = set()
        for perm in v:
            if perm not in ALLOWED_PERMISSIONS:
                raise ValueError(
                    f"Invalid permission: '{perm}'. Allowed: {sorted(ALLOWED_PERMISSIONS)}"
                )
            if perm in seen:
                raise ValueError(f"Duplicate permission: '{perm}'")
            seen.add(perm)
        return v
