import logging
from typing import Annotated

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.errors import DuplicateKeyError

from app.core.dependencies import get_current_user
from app.core.security import create_access_token, get_password_hash, verify_password
from app.repositories.user_repository import (
    get_user_by_username,
    update_user_by_id,
    update_user_by_id_atomic,
)
from app.schemas.user import (
    ChangePasswordRequest,
    ChangePasswordResponse,
    ChangeUsernameRequest,
    ChangeUsernameResponse,
    LoginRequest,
    TokenResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

logger = logging.getLogger("anime-api.auth")


@router.post("/login", response_model=TokenResponse)
def login(login_data: LoginRequest):
    user = get_user_by_username(login_data.username)

    if user is None:
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
            detail="User is inactive",
        )

    access_token = create_access_token(data={
        "sub": user["username"],
        "auth_version": user.get("auth_version", 1)
    })

    logger.info(f"User {user['username']} logged in successfully")

    return TokenResponse(access_token=access_token)


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
        updated_user = update_user_by_id(user_id, {"username": request.new_username})

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
