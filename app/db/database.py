import logging

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.server_api import ServerApi

from app.core.config import settings

logger = logging.getLogger("anime-api.database")

# =========================
# GLOBALS
# =========================

client = None
db = None
animes_collection = None
users_collection = None


# =========================
# INIT DATABASE
# =========================


def init_database():
    global client, db, animes_collection, users_collection

    try:
        client = MongoClient(
            settings.MONGO_URI, server_api=ServerApi("1"), serverSelectionTimeoutMS=5000
        )

        db = client.get_database(settings.DATABASE_NAME)
        animes_collection = db.get_collection("animes")
        users_collection = db.get_collection("users")

        logger.info("MongoDB connection initialized.")

        create_indexes()

    except Exception as e:
        logger.critical(f"MongoDB connection failed: {e}.")
        raise


# =========================
# SAFE ACCESS
# =========================


def get_animes_collection() -> Collection:
    if animes_collection is None:
        raise RuntimeError("Database not initialized. Check lifespan/init_database.")
    return animes_collection


def get_users_collection() -> Collection:
    if users_collection is None:
        raise RuntimeError("Database not initialized. Check lifespan/init_database.")
    return users_collection


# =========================
# INDEXES
# =========================


def create_indexes():
    try:
        animes_collection = get_animes_collection()
        animes_collection.create_index([("name", 1)], unique=True)
        logger.info("Animes index ensured: name.")

        users_collection = get_users_collection()
        users_collection.create_index([("username", 1)], unique=True)
        logger.info("Users index ensured: username.")

    except Exception as e:
        logger.warning(f"Index warning: {e}")


# =========================
# HEALTH CHECK
# =========================


def check_database_connection() -> bool:
    try:
        if client is None:
            return False

        client.admin.command("ping")
        return True

    except Exception as e:
        logger.error(f"DB check failed: {e}")
        return False
