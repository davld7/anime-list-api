import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from app.routers import animes
from app.db.database import check_database_connection


# =========================
# LOGGER
# =========================
logger = logging.getLogger("uvicorn.error")


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
