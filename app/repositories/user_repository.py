import logging
from typing import Any

from bson import ObjectId

from app.db.database import get_users_collection

logger = logging.getLogger("anime-api.repository")


def get_user_by_username(username: str) -> dict[str, Any] | None:
    collection = get_users_collection()
    return collection.find_one({"username": username})


def get_user_by_id(id: ObjectId) -> dict[str, Any] | None:
    collection = get_users_collection()
    return collection.find_one({"_id": id})


def create_user(data: dict[str, Any]) -> dict[str, Any]:
    collection = get_users_collection()

    result = collection.insert_one(data)
    data["_id"] = result.inserted_id

    logger.info(f"Created user with id: {result.inserted_id}")
    return data


def count_users() -> int:
    collection = get_users_collection()
    return collection.count_documents({})


def update_user_by_id(id: ObjectId, update_data: dict[str, Any]) -> dict[str, Any] | None:
    collection = get_users_collection()

    result = collection.update_one(
        {"_id": id},
        {"$set": update_data}
    )

    if result.matched_count == 0:
        return None

    updated_user = collection.find_one({"_id": id})
    logger.info(f"Updated user with id: {id}")
    return updated_user
