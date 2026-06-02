import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

from app.routers import animes
from app.db.database import check_database_connection


# =========================
# LOGGER CONFIGURATION
# =========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("anime-api")


# =========================
# LIFESPAN
# =========================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting API lifecycle...")

    if check_database_connection():
        logger.info("MongoDB connection successful.")
    else:
        logger.critical("MongoDB connection FAILED.")

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
            status_code=503,
            detail="Service unavailable - database connection failed"
        )
    
    logger.debug("Health check passed")
    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "database": "connected"
        }
    )
