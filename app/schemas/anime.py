from pydantic import BaseModel, Field, HttpUrl, BeforeValidator
from typing import Annotated, Any


def convert_object_id(v: Any) -> str:
    """
    Safely stringifies a MongoDB ObjectId or a dictionary representation 
    containing an ID field into a standard hex string.
    """
    if isinstance(v, dict):
        if "_id" in v:
            return str(v["_id"])
        if "id" in v:
            return str(v["id"])
    return str(v)


def convert_genres_list(v: Any) -> list[str]:
    """
    Sanitizes alternative input formats into a clean list of string genres.
    Supports splitting comma-separated strings and filtering blank elements.
    """
    if isinstance(v, str):
        return [genre.strip() for genre in v.split(",") if genre.strip()]
    if isinstance(v, list):
        return [str(genre).strip() for genre in v if str(genre).strip()]
    return []


class AnimeBase(BaseModel):
    """
    Core schema payload representing shared data fields across anime entities.
    """
    name: str = Field(..., min_length=1,
                      description="The official primary title or name of the anime.")
    description: str = Field(...,
                             description="A comprehensive synopsis or plot overview of the title.")
    episodes: int = Field(..., ge=0,
                          description="Total number of episodes aired or announced for the series.")
    season: str = Field(..., min_length=1,
                        description="The release season context and year of premiere (e.g., 'Fall 2023').")

    genres: Annotated[list[str], BeforeValidator(convert_genres_list)] = Field(
        default_factory=list,
        description="A collection of genre tags associated with this anime title."
    )

    image_url: HttpUrl = Field(...,
                               description="Absolute HTTP URL endpoint pointing to the cover artwork file.")


class AnimeToCreate(AnimeBase):
    """
    Validation schema explicitly optimized for new anime resource creation workflows.
    """
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "name": "Frieren: Beyond Journey’s End",
                    "description": "The adventure is over but life goes on for an elf mage just beginning to learn what living is all about. Elf mage Frieren and her courageous fellow adventurers have defeated the Demon King and brought peace to the land. But Frieren will long outlive the rest of her former party. How will she come to understand what life means to the people around her? Decades after their victory, the funeral of one her friends confronts Frieren with her own near immortality. Frieren sets out to fulfill the last wishes of her comrades and finds herself beginning a new adventure…",
                    "episodes": 28,
                    "season": "Fall 2023",
                    "genres": ["Adventure", "Drama", "Fantasy"],
                    "image_url": "https://s4.anilist.co/file/anilistcdn/media/anime/cover/large/bx154587-qQTzQnEJJ3oB.jpg"
                }
            ]
        }
    }


class Anime(AnimeBase):
    """
    Complete database-mapped entity schema including unique identifier properties.
    """
    id: Annotated[str | None, BeforeValidator(convert_object_id)] = Field(
        default=None,
        alias="_id",
        description="The unique 24-character hexadecimal object identifier initialized by MongoDB."
    )

    model_config = {
        "from_attributes": True,
        "populate_by_name": True
    }


class TotalAnimesPages(BaseModel):
    """
    Data envelope detailing data density and calculated boundaries for pagination systems.
    """
    total_animes: int = Field(..., ge=0,
                              description="The structural aggregate total count of documents inside the collection.")
    total_pages: int = Field(..., ge=0,
                             description="Calculated volume of maximum available pages relative to the configured slice limit size.")