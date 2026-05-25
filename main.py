import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from app.routers import animes
from app.db.database import check_database_connection

# Retrieve the standard Uvicorn error logger to output unified system logs
logger = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages the application lifecycle events, executing startup checks 
    and resource cleanup procedures upon shutdown sequence.
    """
    logger.info("Initializing the API Server lifecycle...")

    if check_database_connection():
        logger.info("Successfully established active stream connection to MongoDB Atlas!")
    else:
        logger.critical(
            "Critical Failure: Unable to establish an authenticated connection to the MongoDB Atlas cluster."
        )

    yield

    logger.info("Deactivating API Server and flushing connections...")

app = FastAPI(
    title="Anime List API",
    description="A modular, high-performance REST API optimized for catalog management and mobile application consumption.",
    version="1.0.0",
    lifespan=lifespan
)

# Include core functional feature routers
app.include_router(animes.router)


@app.get("/", include_in_schema=False)
def root_redirect() -> RedirectResponse:
    """
    Redirects incoming root traffic automatically toward the interactive OpenAPI Swagger UI documentation endpoint.
    """
    return RedirectResponse(url="/docs")