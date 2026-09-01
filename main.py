import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse

from app.core.config import settings
from app.core.security import get_password_hash
from app.db.database import check_database_connection, init_database
from app.repositories.user_repository import count_users, create_user
from app.routers import animes, auth

# =========================
# LOGGER CONFIGURATION
# =========================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger("anime-api")

# =========================
# INIT ADMIN USER
# =========================


def init_admin_user():
    if not settings.INITIAL_ADMIN_USERNAME or not settings.INITIAL_ADMIN_PASSWORD:
        logger.info("Initial admin credentials not provided, skipping admin creation")
        return

    if count_users() > 0:
        logger.info("Users already exist, skipping admin creation")
        return

    admin_data = {
        "username": settings.INITIAL_ADMIN_USERNAME,
        "password_hash": get_password_hash(settings.INITIAL_ADMIN_PASSWORD),
        "permissions": ["read", "write", "admin"],
        "active": True,
    }

    try:
        create_user(admin_data)
        logger.info(f"Initial admin user '{settings.INITIAL_ADMIN_USERNAME}' created successfully")
    except Exception as e:
        logger.error(f"Failed to create initial admin user: {e}")
        raise


# =========================
# LIFESPAN
# =========================


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting API lifecycle...")

    try:
        init_database()
        logger.info("MongoDB initialized successfully.")
    except Exception as e:
        logger.critical(f"MongoDB initialization FAILED: {e}")

    try:
        init_admin_user()
    except Exception as e:
        logger.warning(f"Admin user initialization failed: {e}")

    yield

    logger.info("Shutting down API...")


# =========================
# APP
# =========================

app = FastAPI(
    title="Anime List API",
    description="REST API for anime catalog management.",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(animes.router)
app.include_router(auth.router)

# =========================
# ROOT REDIRECT
# =========================


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/docs")


# =========================
# HEALTH CHECK
# =========================


@app.get("/health")
def health_check():
    db_connected = check_database_connection()

    if not db_connected:
        logger.error("Health check failed: Database not connected")
        raise HTTPException(
            status_code=503, detail="Service unavailable - database connection failed"
        )

    logger.debug("Health check passed")
    return JSONResponse(status_code=200, content={"status": "ok", "database": "connected"})
