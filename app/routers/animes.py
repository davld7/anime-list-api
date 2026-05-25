import math
from typing import Any

from fastapi import (
    APIRouter,
    HTTPException,
    Path,
    Query,
    Depends,
    Body,
    status,
)
from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ReturnDocument

from app.db.database import animes_collection
from app.schemas.anime import Anime, AnimeBase, TotalAnimesPages


router = APIRouter(
    prefix="/animes",
    tags=["Animes"],
)


COLLATION: dict[str, Any] = {"locale": "en", "strength": 2}
SORT_BY_NAME = [("name", 1)]
PAGE_SIZE = 10


# =========================
# VALIDATE OBJECT ID
# =========================
def parse_object_id(id: str = Path(..., min_length=24, max_length=24)) -> ObjectId:
    try:
        return ObjectId(id)
    except InvalidId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid ObjectId"
        )


# =========================
# GET ALL
# =========================
@router.get("/", response_model=list[Anime])
def get_animes():
    return list(
        animes_collection.find()
        .collation(COLLATION)
        .sort(SORT_BY_NAME)
    )


# =========================
# PAGINATION
# =========================
@router.get("/page", response_model=list[Anime])
def get_paginated_animes(page: int = Query(1, ge=1)):

    skip = (page - 1) * PAGE_SIZE

    return list(
        animes_collection.find()
        .collation(COLLATION)
        .sort(SORT_BY_NAME)
        .skip(skip)
        .limit(PAGE_SIZE)
    )


# =========================
# TOTAL PAGES
# =========================
@router.get("/pages", response_model=TotalAnimesPages)
def get_total_pages():

    total = animes_collection.count_documents({})

    return {
        "total_animes": total,
        "total_pages": math.ceil(total / PAGE_SIZE),
    }


# =========================
# GET BY ID
# =========================
@router.get("/{id}", response_model=Anime)
def get_anime_by_id(obj_id: ObjectId = Depends(parse_object_id)):

    anime = animes_collection.find_one({"_id": obj_id})

    if not anime:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anime not found."
        )

    return anime


# =========================
# GET BY NAME
# =========================
@router.get("/by-name/{name}", response_model=Anime)
def get_anime_by_name(name: str):

    anime = animes_collection.find_one({"name": name})

    if not anime:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anime not found."
        )

    return anime


# =========================
# CREATE
# =========================
@router.post("/", response_model=Anime, status_code=status.HTTP_201_CREATED)
def create_anime(anime: AnimeBase):

    if animes_collection.find_one({"name": anime.name}):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Anime already exists."
        )

    data = anime.model_dump()
    result = animes_collection.insert_one(data)

    data["_id"] = result.inserted_id

    return data


# =========================
# UPDATE
# =========================
@router.put("/{id}", response_model=Anime)
def update_anime(
    obj_id: ObjectId = Depends(parse_object_id),
    anime: AnimeBase = Body(...)
):

    data = anime.model_dump()

    updated = animes_collection.find_one_and_update(
        {"_id": obj_id},
        {"$set": data},
        return_document=ReturnDocument.AFTER
    )

    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anime not found."
        )

    return updated


# =========================
# DELETE
# =========================
@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_anime(obj_id: ObjectId = Depends(parse_object_id)):

    deleted = animes_collection.find_one_and_delete(
        {"_id": obj_id}
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anime not found."
        )

    return None
