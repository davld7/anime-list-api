import logging
from typing import Any

from bson import ObjectId

from app.db.database import get_users_collection

PAGE_SIZE = 10

logger = logging.getLogger("anime-api.repository")


def get_user_by_username(username: str) -> dict[str, Any] | None:
    collection = get_users_collection()
    return collection.find_one({"username": username})


def get_user_by_id(id: ObjectId) -> dict[str, Any] | None:
    collection = get_users_collection()
    return collection.find_one({"_id": id})


def create_user(data: dict[str, Any]) -> dict[str, Any]:
    collection = get_users_collection()

    if "auth_version" not in data:
        data["auth_version"] = 1

    result = collection.insert_one(data)
    data["_id"] = result.inserted_id

    logger.info(f"Created user with id: {result.inserted_id}")
    return data


def count_users(filter_query: dict[str, Any] | None = None) -> int:
    collection = get_users_collection()
    return collection.count_documents(filter_query or {})


def count_active_admins() -> int:
    collection = get_users_collection()
    return collection.count_documents({"active": True, "permissions": "admin"})


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


def update_user_by_id_atomic(
    id: ObjectId,
    set_data: dict[str, Any],
    inc_data: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    collection = get_users_collection()

    update_operations = {"$set": set_data}
    if inc_data:
        update_operations["$inc"] = inc_data

    result = collection.update_one(
        {"_id": id},
        update_operations
    )

    if result.matched_count == 0:
        return None

    updated_user = collection.find_one({"_id": id})
    logger.info(f"Updated user with id: {id} (atomic)")
    return updated_user


def delete_user_by_id(id: ObjectId) -> bool:
    collection = get_users_collection()
    result = collection.delete_one({"_id": id})
    if result.deleted_count > 0:
        logger.info(f"Deleted user with id: {id}")
    return result.deleted_count > 0


def get_paginated_users(
    page: int,
    page_size: int = PAGE_SIZE,
    filter_query: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    collection = get_users_collection()
    skip = (page - 1) * page_size
    return list(
        collection.find(filter_query or {}).sort("username", 1).skip(skip).limit(page_size)
    )
