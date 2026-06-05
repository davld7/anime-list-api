from typing import Annotated

from pydantic import BaseModel, BeforeValidator, Field


# =========================
# VALIDATORS
# =========================
def convert_object_id(v):
    if isinstance(v, dict):
        return str(v.get("_id") or v.get("id"))
    return str(v)


def convert_genres_list(v):
    if isinstance(v, str):
        return [g.strip() for g in v.split(",") if g.strip()]
    if isinstance(v, list):
        return [str(g).strip() for g in v if str(g).strip()]
    return []


# =========================
# BASE SCHEMA
# =========================
class AnimeBase(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        description="Official anime title.",
        examples=["Frieren: Beyond Journey’s End"]
    )

    description: str = Field(
        ...,
        description="Anime synopsis or plot overview.",
        examples=["The adventure is over but life continues..."]
    )

    episodes: int = Field(
        ...,
        ge=0,
        description="Total number of episodes.",
        examples=[28]
    )

    season: str = Field(
        ...,
        min_length=1,
        description="Release season and year.",
        examples=["Fall 2023"]
    )

    genres: Annotated[list[str], BeforeValidator(convert_genres_list)] = Field(
        default_factory=list,
        description="List of genres.",
        examples=[["Adventure", "Drama", "Fantasy"]]
    )

    image_url: str = Field(
        ...,
        description="Cover image URL.",
        examples=["https://s4.anilist.co/file/anilistcdn/media/anime/cover.jpg"]
    )


# =========================
# RESPONSE MODEL
# =========================
class Anime(AnimeBase):
    id: Annotated[str | None, BeforeValidator(convert_object_id)] = Field(
        default=None,
        alias="_id",
        description="MongoDB ObjectId."
    )


# =========================
# PAGINATION RESPONSE
# =========================
class TotalAnimesPages(BaseModel):
    total_animes: int = Field(
        ...,
        ge=0,
        description="Total anime count.",
        examples=[120]
    )

    total_pages: int = Field(
        ...,
        ge=0,
        description="Total pages available.",
        examples=[12]
    )
