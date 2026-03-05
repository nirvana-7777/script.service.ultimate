# streaming_providers/base/models/vod.py
"""
VOD (Video on Demand) models.

Two types:
  VodCategory  — a browsable node (directory, collection, series, season, …).
                 Never directly playable.
  VodItem      — a playable leaf (movie, episode, documentary, …).
                 Inherits full Content machinery; manifest/DRM resolved via
                 get_manifest(content_id) / get_drm(content_id) like channels
                 and events.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .content import Content
from ..utils.logger import logger


# ---------------------------------------------------------------------------
# Slug utilities
# ---------------------------------------------------------------------------

def slugify(text: str) -> str:
    """
    Convert an arbitrary string to a URL-safe slug.

    Steps:
      1. Unicode normalise (NFKD) and drop combining characters
      2. Lowercase
      3. Replace whitespace and common separators with underscores
      4. Strip everything that is not alphanumeric or underscore/hyphen
      5. Collapse consecutive underscores/hyphens
      6. Strip leading/trailing underscores and hyphens
    """
    # 1. Normalise unicode
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    # 2. Lowercase
    text = text.lower()
    # 3. Whitespace / separators → underscore
    text = re.sub(r"[\s\-–—/\\|]+", "_", text)
    # 4. Keep only safe characters
    text = re.sub(r"\W", "", text)
    # 5. Collapse runs
    text = re.sub(r"_+", "_", text)
    # 6. Strip edges
    return text.strip("_-")


def build_slug_map(entries: list) -> Dict[str, str]:
    """
    Build a slug → content_id mapping for a list of VodCategory / VodItem
    entries, falling back to the content_id itself as the slug when two
    siblings would produce the same slug.

    Returns:
        {slug: content_id}
    """
    # First pass: compute preferred slug for every entry
    preferred: List[tuple] = []
    for entry in entries:
        preferred.append((slugify(entry.name), entry.content_id))

    # Detect collisions
    seen_slugs: Dict[str, int] = {}
    for slug, _ in preferred:
        seen_slugs[slug] = seen_slugs.get(slug, 0) + 1

    slug_map: Dict[str, str] = {}
    for slug, content_id in preferred:
        if seen_slugs[slug] > 1:
            # Fall back to the raw ID as the slug
            final_slug = slugify(content_id) or content_id
            logger.debug(
                f"VOD slug collision for '{slug}' — using id '{final_slug}' instead"
            )
        else:
            final_slug = slug
        slug_map[final_slug] = content_id

    return slug_map


# ---------------------------------------------------------------------------
# VodCategory
# ---------------------------------------------------------------------------

@dataclass
class VodCategory:
    """
    A browsable VOD node — category, collection, series, season, etc.

    Not playable. Resolved by calling provider.get_vod_category(path_ids).
    content_id is used as the path segment ID when navigating deeper.
    """

    # Required
    name: str
    content_id: str
    provider: str

    # Optional metadata
    logo_url: Optional[str] = None
    description: Optional[str] = None

    # Hint about how many children this node has (may be None if unknown)
    child_count: Optional[int] = None

    # Cached slug (computed lazily if not set)
    _slug: Optional[str] = field(default=None, repr=False)

    @property
    def slug(self) -> str:
        if not self._slug:
            self._slug = slugify(self.name)
        return self._slug

    @property
    def node_type(self) -> str:
        return "vod_category"

    def to_dict(self) -> Dict:
        return {
            "type": self.node_type,
            "id": self.content_id,
            "name": self.name,
            "slug": self.slug,
            "provider": self.provider,
            "logo_url": self.logo_url,
            "description": self.description,
            "child_count": self.child_count,
        }


# ---------------------------------------------------------------------------
# VodItem
# ---------------------------------------------------------------------------

@dataclass
class VodItem(Content):
    """
    A playable VOD leaf — movie, episode, documentary, past sports event, etc.

    Inherits all streaming/DRM fields from Content.
    Manifest and DRM are resolved identically to channels and events:
        provider.get_manifest(content_id)
        provider.get_drm(content_id)
    """

    # Timing
    duration_seconds: Optional[int] = None
    release_year: Optional[int] = None

    # Classification
    rating: Optional[str] = None          # e.g. "FSK 12", "PG-13", "TV-MA"
    genre: Optional[str] = None           # already on Content but repeated for clarity

    # People
    cast: Optional[List[str]] = None
    director: Optional[str] = None

    # Series / episode context (None for standalone movies / documentaries)
    season_number: Optional[int] = None
    episode_number: Optional[int] = None

    # Promotional
    trailer_url: Optional[str] = None

    # Content classification
    # True  → short highlight/clip reel (videoType == "CLIP")
    # False → full broadcast recording  (videoType == "STANDALONE_EVENT" etc.)
    is_highlight: bool = False

    # Cached slug
    _slug: Optional[str] = field(default=None, repr=False)

    def __post_init__(self):
        # Ensure mode and content_type are set correctly for on-demand content
        if self.mode == "live":
            self.mode = "vod"
        if self.content_type == "LIVE":
            self.content_type = "VOD"

    @property
    def slug(self) -> str:
        if not self._slug:
            self._slug = slugify(self.name)
        return self._slug

    @property
    def node_type(self) -> str:
        return "vod"

    @property
    def is_episode(self) -> bool:
        return self.season_number is not None or self.episode_number is not None

    @property
    def duration_minutes(self) -> Optional[int]:
        if self.duration_seconds is not None:
            return self.duration_seconds // 60
        return None

    def to_dict(self) -> Dict:
        result = super().to_dict()
        result.update({
            "type": self.node_type,
            "slug": self.slug,
            "is_highlight": self.is_highlight,
            "duration_seconds": self.duration_seconds,
            "duration_minutes": self.duration_minutes,
            "release_year": self.release_year,
            "rating": self.rating,
            "cast": self.cast,
            "director": self.director,
            "season_number": self.season_number,
            "episode_number": self.episode_number,
            "trailer_url": self.trailer_url,
        })
        return result

    def validate(self) -> List[str]:
        warnings = []
        if not self.manifest and not self.manifest_script:
            warnings.append("No manifest URL or manifest script provided")
        if self.license_url and not self.drm_config:
            warnings.append("License URL provided but no DRM configuration")
        if self.duration_seconds is not None and self.duration_seconds <= 0:
            warnings.append("duration_seconds must be positive")
        if self.release_year is not None and not (1888 <= self.release_year <= 2100):
            warnings.append(f"Unusual release_year: {self.release_year}")
        return warnings

    # Factory methods
    @classmethod
    def create_movie(
        cls, name: str, content_id: str, provider: str, **kwargs
    ) -> "VodItem":
        return cls(
            name=name,
            content_id=content_id,
            provider=provider,
            mode="vod",
            content_type="MOVIE",
            **kwargs,
        )

    @classmethod
    def create_episode(
        cls,
        name: str,
        content_id: str,
        provider: str,
        season_number: int,
        episode_number: int,
        **kwargs,
    ) -> "VodItem":
        return cls(
            name=name,
            content_id=content_id,
            provider=provider,
            mode="vod",
            content_type="SERIES",
            season_number=season_number,
            episode_number=episode_number,
            **kwargs,
        )