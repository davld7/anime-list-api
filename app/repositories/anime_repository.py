import logging
from typing import Any, Optional

from bson import ObjectId
from pymongo import ReturnDocument

from app.db.database import animes_collection

logger = logging.getLogger("anime-api.repository")


COLLATION: dict[str, Any] = {"locale": "en", "strength": 2}
SORT_BY_NAME = [("name", 1)]
PAGE_SIZE = 10


def get_all_animes() -> list[dict[str, Any]]:
    return list(
        animes_collection.find()
        .collation(COLLATION)
        .sort(SORT_BY_NAME)
    )


def get_anime_by_id(id: ObjectId) -> Optional[dict[str, Any]]:
    return animes_collection.find_one({"_id": id})


def get_anime_by_name(name: str) -> Optional[dict[str, Any]]:
    return animes_collection.find_one({"name": name})


def get_paginated_animes(page: int, page_size: int = PAGE_SIZE) -> list[dict[str, Any]]:
    skip = (page - 1) * page_size
    return list(
        animes_collection.find()
        .collation(COLLATION)
        .sort(SORT_BY_NAME)
        .skip(skip)
        .limit(page_size)
    )


def count_animes() -> int:
    return animes_collection.count_documents({})


def create_anime(data: dict[str, Any]) -> dict[str, Any]:
    result = animes_collection.insert_one(data)
    data["_id"] = result.inserted_id
    logger.info(f"Created anime with id: {result.inserted_id}")
    return data


def update_anime(id: ObjectId, data: dict[str, Any]) -> Optional[dict[str, Any]]:
    updated = animes_collection.find_one_and_update(
        {"_id": id},
        {"$set": data},
        return_document=ReturnDocument.AFTER
    )
    if updated:
        logger.info(f"Updated anime with id: {id}")
    return updated


def delete_anime(id: ObjectId) -> Optional[dict[str, Any]]:
    deleted = animes_collection.find_one_and_delete({"_id": id})
    if deleted:
        logger.info(f"Deleted anime with id: {id}")
    return deleted
