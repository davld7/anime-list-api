import logging

from fastapi import APIRouter, HTTPException, status

from app.core.security import create_access_token, verify_password
from app.repositories.user_repository import get_user_by_username
from app.schemas.user import LoginRequest, TokenResponse

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

    access_token = create_access_token(data={"sub": user["username"]})

    logger.info(f"User {user['username']} logged in successfully")

    return TokenResponse(access_token=access_token)
