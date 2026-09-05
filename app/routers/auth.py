import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Annotated

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, status
from pymongo.errors import DuplicateKeyError

from app.core.config import settings
from app.core.dependencies import get_current_user, require_permission
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    hash_refresh_token,
    verify_password,
)
from app.repositories.refresh_token_repository import (
    create_refresh_token as persist_refresh_token,
)
from app.repositories.refresh_token_repository import (
    get_refresh_token_by_hash,
    revoke_refresh_token,
)
from app.repositories.user_repository import (
    PAGE_SIZE,
    count_active_admins,
    count_users,
    create_user,
    delete_user_by_id,
    get_paginated_users,
    get_user_by_id,
    get_user_by_username,
    update_user_by_id,
    update_user_by_id_atomic,
)
from app.schemas.auth import AuthTokenResponse, RefreshTokenRequest
from app.schemas.user import (
    AdminUpdatePasswordRequest,
    ChangePasswordRequest,
    ChangePasswordResponse,
    ChangeUsernameRequest,
    ChangeUsernameResponse,
    LoginRequest,
    ToggleActiveRequest,
    TotalUsersPages,
    UpdatePermissionsRequest,
    UserCreate,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

logger = logging.getLogger("anime-api.auth")

DUMMY_PASSWORD_HASH = get_password_hash("dummy_password_for_login_timing_equalization")


def parse_user_object_id(user_id: str = Path(..., min_length=24, max_length=24)) -> ObjectId:
    try:
        return ObjectId(user_id)
    except InvalidId:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid ObjectId")


@router.post("/login", response_model=AuthTokenResponse)
def login(login_data: LoginRequest):
    user = get_user_by_username(login_data.username)

    if user is None:
        verify_password(login_data.password, DUMMY_PASSWORD_HASH)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.get("active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    access_token = create_access_token(data={
        "sub": user["username"],
        "auth_version": user.get("auth_version", 1)
    })

    refresh_token = create_refresh_token()
    token_hash = hash_refresh_token(refresh_token)
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )

    persist_refresh_token(
        user_id=user["_id"],
        token_hash=token_hash,
        auth_version=user.get("auth_version", 1),
        expires_at=expires_at,
    )

    logger.info(f"User {user['username']} logged in successfully")

    return AuthTokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post("/refresh", response_model=AuthTokenResponse)
def refresh_token(request: RefreshTokenRequest):
    token_hash = hash_refresh_token(request.refresh_token)
    record = get_refresh_token_by_hash(token_hash)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if record["revoked"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    now = datetime.now(timezone.utc)
    expires_at = record["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user = get_user_by_id(record["user_id"])
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if not user.get("active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if record["auth_version"] != user.get("auth_version", 1):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # Atomic rotation: only one concurrent request can revoke a token
    # (revoke filter requires revoked=False). If it returns None, the token
    # was already used/revoked concurrently.
    revoked = revoke_refresh_token(token_hash)
    if revoked is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    access_token = create_access_token(data={
        "sub": user["username"],
        "auth_version": user.get("auth_version", 1)
    })

    new_refresh_token = create_refresh_token()
    new_token_hash = hash_refresh_token(new_refresh_token)
    new_expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )

    persist_refresh_token(
        user_id=user["_id"],
        token_hash=new_token_hash,
        auth_version=user.get("auth_version", 1),
        expires_at=new_expires_at,
    )

    logger.info(f"Refresh token rotated for user: {user['username']}")

    return AuthTokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: RefreshTokenRequest):
    token_hash = hash_refresh_token(request.refresh_token)
    revoke_refresh_token(token_hash)
    logger.info("Refresh token revoked during logout")
    return None


@router.get("/me", response_model=UserResponse)
def get_me(current_user: Annotated[dict, Depends(get_current_user)]):
    return current_user


@router.put("/username", response_model=ChangeUsernameResponse)
def change_username(
    request: ChangeUsernameRequest,
    current_user: Annotated[dict, Depends(get_current_user)]
):
    current_username = current_user["username"]

    if request.new_username == current_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New username must be different from current username"
        )

    existing_user = get_user_by_username(request.new_username)
    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken"
        )

    user_id = ObjectId(current_user["_id"])

    try:
        updated_user = update_user_by_id_atomic(
            user_id,
            {"username": request.new_username},
            {"auth_version": 1},
        )

        if updated_user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        logger.info(f"User {current_username} changed username to {request.new_username}")

        return ChangeUsernameResponse(
            new_username=request.new_username,
            message="Username updated successfully. Please log in again with your new username."
        )

    except DuplicateKeyError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken"
        )


@router.put("/password", response_model=ChangePasswordResponse)
def change_password(
    request: ChangePasswordRequest,
    current_user: Annotated[dict, Depends(get_current_user)]
):
    if not verify_password(request.current_password, current_user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )

    user_id = ObjectId(current_user["_id"])
    new_password_hash = get_password_hash(request.new_password)

    updated_user = update_user_by_id_atomic(
        user_id,
        {"password_hash": new_password_hash},
        {"auth_version": 1}
    )

    if updated_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    logger.info(f"User {current_user['username']} changed password successfully")

    return ChangePasswordResponse(
        message="Password updated successfully. Please log in again with your new password."
    )


@router.put("/users/{user_id}/permissions", response_model=UserResponse)
def replace_user_permissions(
    user_id: ObjectId = Depends(parse_user_object_id),
    request: UpdatePermissionsRequest = Body(...),
    current_user: dict = Depends(require_permission("admin")),
):
    target_user = get_user_by_id(user_id)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    new_permissions = request.permissions
    target_is_active_admin = target_user.get("active", True) and "admin" in target_user.get(
        "permissions", []
    )

    if target_is_active_admin and "admin" not in new_permissions:
        if count_active_admins() == 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot remove 'admin' from the last active administrator",
            )

    updated_user = update_user_by_id(user_id, {"permissions": new_permissions})
    if updated_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    logger.info(
        f"User {current_user['username']} updated permissions of "
        f"{target_user['username']} to {new_permissions}"
    )

    return updated_user


@router.put("/users/{user_id}/password", response_model=ChangePasswordResponse)
def update_user_password(
    user_id: ObjectId = Depends(parse_user_object_id),
    request: AdminUpdatePasswordRequest = Body(...),
    current_user: dict = Depends(require_permission("admin")),
):
    target_user = get_user_by_id(user_id)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    new_password_hash = get_password_hash(request.new_password)

    updated_user = update_user_by_id_atomic(
        user_id,
        {"password_hash": new_password_hash},
        {"auth_version": 1}
    )

    if updated_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    logger.info(
        f"User {current_user['username']} changed password of user {target_user['username']}"
    )

    return ChangePasswordResponse(
        message="Password updated successfully. Please log in again with your new password."
    )


@router.put("/users/{user_id}/active", response_model=UserResponse)
def toggle_user_active(
    user_id: ObjectId = Depends(parse_user_object_id),
    request: ToggleActiveRequest = Body(...),
    current_user: dict = Depends(require_permission("admin")),
):
    target_user = get_user_by_id(user_id)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    current_active = target_user.get("active", True)
    requested_active = request.active

    if current_active == requested_active:
        return target_user

    if not requested_active:
        target_is_active_admin = current_active and "admin" in target_user.get("permissions", [])
        if target_is_active_admin and count_active_admins() == 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot deactivate the last active administrator",
            )

    updated_user = update_user_by_id_atomic(
        user_id,
        {"active": requested_active},
        {"auth_version": 1},
    )

    if updated_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    action = "activated" if requested_active else "deactivated"
    logger.info(
        f"User {current_user['username']} {action} user {target_user['username']}"
    )

    return updated_user


@router.get("/users", response_model=list[UserResponse])
def list_users(
    page: int = Query(1, ge=1),
    active: bool | None = Query(None),
    _current_user: dict = Depends(require_permission("admin")),
):
    filter_query: dict = {}
    if active is not None:
        filter_query["active"] = active

    return get_paginated_users(page, PAGE_SIZE, filter_query)


@router.get("/users/pages", response_model=TotalUsersPages)
def get_total_user_pages(
    active: bool | None = Query(None),
    _current_user: dict = Depends(require_permission("admin")),
):
    filter_query: dict = {}
    if active is not None:
        filter_query["active"] = active

    total = count_users(filter_query)
    return {
        "total_users": total,
        "total_pages": math.ceil(total / PAGE_SIZE) if total > 0 else 0,
    }


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: ObjectId = Depends(parse_user_object_id),
    _current_user: dict = Depends(require_permission("admin")),
):
    user = get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_new_user(
    user_data: UserCreate,
    current_user: dict = Depends(require_permission("admin")),
):
    existing_user = get_user_by_username(user_data.username)
    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    user_dict = user_data.model_dump()
    user_dict["password_hash"] = get_password_hash(user_dict.pop("password"))

    try:
        created_user = create_user(user_dict)
    except DuplicateKeyError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        ) from None

    logger.info(
        f"User {current_user['username']} created user {created_user['username']}"
    )

    return created_user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: ObjectId = Depends(parse_user_object_id),
    current_user: dict = Depends(require_permission("admin")),
):
    target_user = get_user_by_id(user_id)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    target_is_active_admin = target_user.get("active", True) and "admin" in target_user.get(
        "permissions", []
    )

    if target_is_active_admin and count_active_admins() == 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete the last active administrator",
        )

    deleted = delete_user_by_id(user_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    logger.info(
        f"User {current_user['username']} deleted user {target_user['username']}"
    )

    return None
