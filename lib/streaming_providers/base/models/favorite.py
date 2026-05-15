# streaming_providers/base/models/favorite.py

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Optional


class FavoriteType(str, Enum):
    """Type of content that can be favorited."""
    PROGRAM = "PROGRAM"  # TV show, series, or movie
    CLIP = "CLIP"  # Individual episode or video
    LIVE = "LIVE"  # Live channel
    EVENT = "EVENT"  # One-time event


@dataclass
class Favorite:
    """
    A user-saved content reference for "Watch Later" or "My Bookmarks".

    Unlike Bookmark (which tracks playback position), Favorite is just
    a pointer to content the user wants to remember. No progress tracking.
    """

    favorite_id: str  # Composite "provider:content_id"
    provider: str
    content_id: str
    favorite_type: FavoriteType

    # When it was saved
    created_at: datetime = field(default_factory=datetime.now)

    # Optional cached metadata for UI (reduces API calls)
    title: Optional[str] = None
    thumbnail_url: Optional[str] = None

    # Series context (if applicable)
    series_title: Optional[str] = None

    @classmethod
    def create(
            cls,
            provider: str,
            content_id: str,
            favorite_type: FavoriteType,
            title: Optional[str] = None,
            **kwargs,
    ) -> "Favorite":
        """Create a new favorite."""
        return cls(
            favorite_id=f"{provider}:{content_id}",
            provider=provider,
            content_id=content_id,
            favorite_type=favorite_type,
            title=title,
            created_at=datetime.now(),
            **kwargs,
        )

    def to_dict(self) -> Dict:
        """Convert to API-friendly dictionary."""
        return {
            "FavoriteId": self.favorite_id,
            "Provider": self.provider,
            "ContentId": self.content_id,
            "FavoriteType": self.favorite_type.value,
            "CreatedAt": self.created_at.isoformat(),
            "Title": self.title,
            "ThumbnailUrl": self.thumbnail_url,
            "SeriesTitle": self.series_title,
        }