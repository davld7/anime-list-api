import math
from typing import Annotated, Any
from fastapi import APIRouter, HTTPException, status, Path, Query, Depends
from bson import ObjectId
from bson.errors import InvalidId
from pymongo.errors import PyMongoError

from app.schemas.anime import Anime, AnimeToCreate, TotalAnimesPages
from app.db.database import animes_collection

router = APIRouter(
    prefix="/animes",
    tags=["Animes"],
    responses={status.HTTP_404_NOT_FOUND: {"description": "Anime not found."}}
)

COLLATION: dict[str, Any] = {'locale': 'en', 'strength': 2}
SORT_BY_NAME = [("name", 1)]
PAGE_SIZE = 10


def get_valid_object_id(
    id: str = Path(
        ...,
        min_length=24,
        max_length=24,
        pattern="^[0-9a-fA-F]{24}$",
        description="Unique 24-character hexadecimal identifier for the anime resource."
    )
) -> ObjectId:
    """
    Validates if a given string matches the MongoDB ObjectId format.
    """
    try:
        return ObjectId(id)
    except InvalidId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The provided identifier is not a valid 24-character hexadecimal format."
        )


def helper_find_anime(key: str, value: Any) -> dict[str, Any]:
    """
    Internal helper to locate a document in the database or raise a 404 error if not found.
    """
    anime_raw = animes_collection.find_one({key: value})
    if not anime_raw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anime not found."
        )
    return anime_raw


@router.get("/", response_model=list[Anime], status_code=status.HTTP_200_OK)
def get_animes() -> list[dict[str, Any]]:
    """
    Retrieve the full catalog of anime titles, sorted alphabetically by name.
    """
    return list(animes_collection.find().collation(COLLATION).sort(SORT_BY_NAME))


@router.get("/page", response_model=list[Anime], status_code=status.HTTP_200_OK)
def get_paginated_animes(
    number: int = Query(
        1, ge=1, description="The target page number to retrieve. Defaults to 1."
    )
) -> list[dict[str, Any]]:
    """
    Retrieve a chunked slice of the anime catalog based on the active pagination page context.
    """
    skip_count = (number - 1) * PAGE_SIZE
    return list(
        animes_collection.find()
        .collation(COLLATION)
        .sort(SORT_BY_NAME)
        .skip(skip_count)
        .limit(PAGE_SIZE)
    )


@router.get("/total-animes-pages/", response_model=TotalAnimesPages, status_code=status.HTTP_200_OK)
def get_total_animes_pages() -> dict[str, int]:
    """
    Calculate and return the total count of anime elements and aggregate available pages.
    """
    total_animes = animes_collection.count_documents({})
    return {
        "total_animes": total_animes,
        "total_pages": math.ceil(total_animes / PAGE_SIZE)
    }


@router.get("/id/{id}", response_model=Anime, status_code=status.HTTP_200_OK)
def get_anime_by_id(obj_id: Annotated[ObjectId, Depends(get_valid_object_id)]) -> dict[str, Any]:
    """
    Locate and return a single anime resource utilizing its validated unique ObjectId string.
    """
    return helper_find_anime("_id", obj_id)


@router.get("/name/{name}", response_model=Anime, status_code=status.HTTP_200_OK)
def get_anime_by_name(
    name: str = Path(..., description="The exact name match of the anime title to find.")
) -> dict[str, Any]:
    """
    Locate and return a single anime resource utilizing its exact title string parameter.
    """
    return helper_find_anime("name", name)


@router.post("/", response_model=Anime, status_code=status.HTTP_201_CREATED)
def create_anime(anime: AnimeToCreate) -> dict[str, Any]:
    """
    Register and persist a new anime record into the catalog after enforcing uniqueness constraints.
    """
    anime_existente = animes_collection.find_one({"name": anime.name})
    if anime_existente:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Anime record already exists within the catalog."
        )

    anime_dict = anime.model_dump()
    resultado = animes_collection.insert_one(anime_dict)

    anime_dict["_id"] = resultado.inserted_id
    return anime_dict


@router.put("/", response_model=Anime, status_code=status.HTTP_200_OK)
def update_anime(anime: Anime) -> dict[str, Any]:
    """
    Modify an existing anime record by replacing its data fields fully through its embedded payload ID.
    """
    anime_dict = anime.model_dump()
    del anime_dict["id"]

    try:
        obj_id = ObjectId(anime.id)
    except InvalidId:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The provided schema payload string ID is not a valid ObjectId."
        )

    found = animes_collection.find_one_and_replace({"_id": obj_id}, anime_dict)
    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target anime record not found for modification."
        )

    return helper_find_anime("_id", obj_id)


@router.delete("/{id}", status_code=status.HTTP_200_OK)
def delete_anime(obj_id: Annotated[ObjectId, Depends(get_valid_object_id)]) -> dict[str, str]:
    """
    Permanently purge an anime record out of the database collections via its path identifier.
    """
    try:
        found = animes_collection.find_one_and_delete({"_id": obj_id})
    except PyMongoError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A critical database driver error occurred while attempting resource eviction."
        )

    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target anime record requested for eviction was not found."
        )

    return {"message": "Anime record successfully evicted from the database."}