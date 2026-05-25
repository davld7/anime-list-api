from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.server_api import ServerApi

from pydantic_settings import BaseSettings, SettingsConfigDict


# =========================
# SETTINGS
# =========================
class Settings(BaseSettings):
    MONGO_URI: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()  # type: ignore[call-arg]


# =========================
# DATABASE CLIENT
# =========================
client = MongoClient(
    settings.MONGO_URI,
    server_api=ServerApi("1")
)


db: Database = client.get_database("fastapi")
animes_collection: Collection = db.get_collection("animes")


# =========================
# HEALTH CHECK
# =========================
def check_database_connection() -> bool:
    try:
        client.admin.command("ping")
        return True
    except Exception:
        return False
