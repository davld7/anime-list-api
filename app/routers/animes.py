import math

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Path,
    Query,
    status,
)

from app.repositories.anime_repository import (
    PAGE_SIZE,
    count_animes,
    create_anime,
    delete_anime,
    get_all_animes,
    get_anime_by_id,
    get_anime_by_name,
    get_paginated_animes,
    update_anime,
)
from app.schemas.anime import Anime, AnimeBase, TotalAnimesPages

router = APIRouter(
    prefix="/animes",
    tags=["Animes"],
)


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
    return get_all_animes()


# =========================
# PAGINATION
# =========================
@router.get("/page", response_model=list[Anime])
def get_paginated_animes_endpoint(page: int = Query(1, ge=1)):
    return get_paginated_animes(page)


# =========================
# TOTAL PAGES
# =========================
@router.get("/pages", response_model=TotalAnimesPages)
def get_total_pages():
    total = count_animes()
    return {
        "total_animes": total,
        "total_pages": math.ceil(total / PAGE_SIZE),
    }


# =========================
# GET BY ID
# =========================
@router.get("/{id}", response_model=Anime)
def get_anime_by_id_endpoint(obj_id: ObjectId = Depends(parse_object_id)):
    anime = get_anime_by_id(obj_id)
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
def get_anime_by_name_endpoint(name: str):
    anime = get_anime_by_name(name)
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
def create_anime_endpoint(anime: AnimeBase):
    if get_anime_by_name(anime.name):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Anime already exists."
    )
    data = anime.model_dump()
    return create_anime(data)


# =========================
# UPDATE
# =========================
@router.put("/{id}", response_model=Anime)
def update_anime_endpoint(
    obj_id: ObjectId = Depends(parse_object_id),
    anime: AnimeBase = Body(...)
):
    data = anime.model_dump()
    updated = update_anime(obj_id, data)
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
def delete_anime_endpoint(obj_id: ObjectId = Depends(parse_object_id)):
    deleted = delete_anime(obj_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anime not found."
        )
    return None
