import logging

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.server_api import ServerApi

from app.core.config import settings

logger = logging.getLogger("anime-api.database")


# =========================
# DATABASE CLIENT
# =========================
try:
    client = MongoClient(
        settings.MONGO_URI,
        server_api=ServerApi("1")
    )
    logger.info("MongoDB client initialized successfully")
except Exception as e:
    logger.critical(f"Failed to initialize MongoDB client: {e}")
    raise


db: Database = client.get_database(settings.DATABASE_NAME)
animes_collection: Collection = db.get_collection("animes")

logger.info(f"Connected to database: {settings.DATABASE_NAME}")


# =========================
# INDEX CREATION
# =========================
def create_indexes():
    try:
        animes_collection.create_index([("name", 1)], unique=True)
        logger.info("Created index on 'name' field")
    except Exception as e:
        logger.warning(f"Index creation warning (may already exist): {e}")


# Create indexes on module load
create_indexes()


# =========================
# HEALTH CHECK
# =========================
def check_database_connection() -> bool:
    try:
        client.admin.command("ping")
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False
