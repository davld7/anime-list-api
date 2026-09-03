import logging
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from pymongo import ReturnDocument

from app.db.database import get_refresh_tokens_collection

logger = logging.getLogger("anime-api.repository")


def create_refresh_token(
    user_id: ObjectId,
    token_hash: str,
    auth_version: int,
    expires_at: datetime,
) -> dict[str, Any]:
    collection = get_refresh_tokens_collection()

    now = datetime.now(timezone.utc)
    document = {
        "user_id": user_id,
        "token_hash": token_hash,
        "auth_version": auth_version,
        "expires_at": expires_at,
        "revoked": False,
        "created_at": now,
    }

    result = collection.insert_one(document)
    document["_id"] = result.inserted_id

    logger.info(f"Created refresh token for user_id: {user_id}")
    return document


def get_refresh_token_by_hash(token_hash: str) -> dict[str, Any] | None:
    collection = get_refresh_tokens_collection()
    return collection.find_one({"token_hash": token_hash})


def revoke_refresh_token(token_hash: str) -> dict[str, Any] | None:
    collection = get_refresh_tokens_collection()

    updated = collection.find_one_and_update(
        {"token_hash": token_hash, "revoked": False},
        {"$set": {"revoked": True}},
        return_document=ReturnDocument.AFTER,
    )

    if updated:
        logger.info(f"Revoked refresh token with hash: {token_hash[:8]}...")

    return updated


def delete_refresh_tokens_by_user_id(user_id: ObjectId) -> int:
    collection = get_refresh_tokens_collection()
    result = collection.delete_many({"user_id": user_id})
    if result.deleted_count > 0:
        logger.info(f"Deleted {result.deleted_count} refresh tokens for user_id: {user_id}")
    return result.deleted_count
