from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.server_api import ServerApi
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings manager utilizing Pydantic BaseSettings.
    Automatically loads environment variables from a local `.env` file.
    """
    MONGO_URI: str | None = Field(default=None)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


# Instantiate settings to load configuration
settings = Settings()

# Initialize MongoDB Client with Server API version 1
client: MongoClient = MongoClient(settings.MONGO_URI, server_api=ServerApi('1'))

# Database and Collection instances
db: Database = client.get_database("fastapi")
animes_collection: Collection = db.get_collection("animes")


def check_database_connection() -> bool:
    """
    Pings the MongoDB Atlas administration database to verify if the 
    connection stream is active and properly authenticated.

    Returns:
        bool: True if the database responds successfully, False otherwise.
    """
    try:
        client.admin.command('ping')
        return True
    except Exception:
        return False