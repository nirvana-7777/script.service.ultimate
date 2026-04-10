# streaming_providers/base/models/bookmark.py
"""
Bookmark model.

A Bookmark represents a saved playback position for any playable content
(live channels, VOD items, events, recordings). It acts as a pointer to
content rather than containing the content itself.

Bookmarks are automatically updated when playback stops or pauses, and
can be used to implement "Continue Watching" features across all content
types and providers.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple


class ContentType(str, Enum):
    """Enum for content types that can be bookmarked."""
    LIVE = "LIVE"             # Live channel (bookmark may represent last watched channel)
    VOD = "VOD"               # Video-on-demand movie or show
    EVENT = "EVENT"           # One-time event (sports, concert, etc.)
    RECORDING = "RECORDING"   # Captured broadcast recording
    SERIES = "SERIES"         # Series container (bookmark may represent last watched episode)
    RADIO = "RADIO"           # Radio stream


class ValidationLevel(str, Enum):
    """Severity levels for validation messages."""
    ERROR = "ERROR"     # Fatal: bookmark is unusable without fixing this
    WARNING = "WARNING" # Non-fatal: bookmark works but behaviour may be unexpected


@dataclass(eq=False)
class Bookmark:
    """
    A saved playback position pointing to playable content.

    Bookmarks are lightweight pointers that store where the user left off.
    The actual content (manifest, DRM, metadata) is fetched separately
    using the provider and content_id.

    This separation allows:
    - Bookmark storage without duplicating content data
    - Same bookmark structure across all content types
    - Provider-independent bookmark management
    - Client-side resolution of content details

    Serialization notes:
    - ``to_dict()``         → PascalCase keys, suitable for API responses.
    - ``to_storage_dict()`` → snake_case keys, suitable for storage backends.
                              Metadata fields (thumbnail, series info, channel
                              info) are intentionally omitted; they are expected
                              to be fetched fresh from the provider on restore.
    - ``from_api_dict()``   → inverse of ``to_dict()``   (PascalCase input).
    - ``from_storage_dict()``→ inverse of ``to_storage_dict()`` (snake_case input).
    """

    # ==========================================================================
    # Core identification (what content this bookmark points to)
    # ==========================================================================

    bookmark_id: str
    """Unique identifier for this bookmark (composite 'provider:content_id')."""

    provider: str
    """Provider name (e.g., 'rtl_de', 'joyn_at', 'zdf')."""

    content_id: str
    """Provider-specific content identifier (channel ID, VOD ID, event ID, etc.)."""

    content_type: ContentType
    """Type of content being bookmarked (see ContentType enum)."""

    # ==========================================================================
    # Playback position (where the user stopped)
    # ==========================================================================

    position_seconds: int = 0
    """
    Playback position in seconds from the start.
    0 = not started or start of content.
    Negative values = completed (e.g., -1 indicates finished).
    """

    duration_seconds: Optional[int] = None
    """Total duration of the content in seconds. Used for UI progress bars."""

    # Threshold at which content is considered effectively complete (0.0–1.0).
    COMPLETION_THRESHOLD: float = field(default=0.95, init=False, repr=False)

    # ==========================================================================
    # Timestamps (when the bookmark was created/updated)
    # ==========================================================================

    last_updated: datetime = field(default_factory=datetime.now)
    """When this bookmark was last saved/updated."""

    created_at: datetime = field(default_factory=datetime.now)
    """When this bookmark was first created."""

    # ==========================================================================
    # Optional cached metadata for UI display (reduces API calls)
    # ==========================================================================

    title: Optional[str] = None
    """Title of the bookmarked content (cached for UI display)."""

    thumbnail_url: Optional[str] = None
    """URL to thumbnail image (could be from the saved position or default)."""

    # Series/episode context (for VOD and RECORDING content types)
    series_title: Optional[str] = None
    season_number: Optional[int] = None
    episode_number: Optional[int] = None
    episode_name: Optional[str] = None

    # Channel context (for LIVE and RECORDING content types)
    channel_name: Optional[str] = None
    channel_logo: Optional[str] = None

    # ==========================================================================
    # Properties
    # ==========================================================================

    @property
    def is_completed(self) -> bool:
        """
        True if the user has finished watching this content.

        Content is considered complete when:
        - position_seconds is negative (explicitly marked done), OR
        - position has reached or exceeded the completion threshold (≥ 95 % by
          default), avoiding a "perpetual 99.9 %" state for content that was
          watched to the end without an explicit completion event.
        """
        if self.position_seconds < 0:
            return True
        if (
            self.duration_seconds
            and self.duration_seconds > 0
            and self.position_seconds >= self.duration_seconds * self.COMPLETION_THRESHOLD
        ):
            return True
        return False

    @property
    def progress_percent(self) -> Optional[float]:
        """
        Calculate watch progress as a percentage.

        Returns:
            100.0 if completed; a value in [0, 100] if duration is known;
            None if duration is unknown.
        """
        if self.is_completed:
            return 100.0
        if self.duration_seconds and self.duration_seconds > 0 and self.position_seconds >= 0:
            return min((self.position_seconds / self.duration_seconds) * 100, 100.0)
        return None

    @property
    def remaining_seconds(self) -> Optional[int]:
        """
        Calculate remaining watch time in seconds.

        Returns:
            0 if completed; remaining seconds if duration is known; None otherwise.
        """
        if self.is_completed:
            return 0
        if self.duration_seconds and self.duration_seconds > 0 and self.position_seconds >= 0:
            return max(0, self.duration_seconds - self.position_seconds)
        return None

    def is_stale(self, max_age_hours: int = 720) -> bool:
        """
        Check if bookmark is stale (older than max_age_hours).

        Args:
            max_age_hours: Maximum age in hours before bookmark is considered
                           stale. Default 720 hours = 30 days.

        Returns:
            True if bookmark hasn't been updated in the specified period.
        """
        age = datetime.now() - self.last_updated
        return age.total_seconds() > (max_age_hours * 3600)

    @property
    def composite_id(self) -> str:
        """Return a composite identifier combining provider and content_id."""
        return f"{self.provider}:{self.content_id}"

    # ==========================================================================
    # Factory methods
    # ==========================================================================

    @classmethod
    def create(
        cls,
        provider: str,
        content_id: str,
        content_type: ContentType,
        position_seconds: int = 0,
        duration_seconds: Optional[int] = None,
        title: Optional[str] = None,
        **kwargs,
    ) -> "Bookmark":
        """
        Create a new bookmark with automatic ID generation.

        Args:
            provider: Provider name.
            content_id: Content identifier.
            content_type: Type of content (see ContentType).
            position_seconds: Playback position in seconds.
            duration_seconds: Total duration in seconds.
            title: Content title (cached for UI).
            **kwargs: Additional metadata (thumbnail_url, series_title, etc.).

        Returns:
            New Bookmark instance.
        """
        now = datetime.now()
        bookmark_id = f"{provider}:{content_id}"
        return cls(
            bookmark_id=bookmark_id,
            provider=provider,
            content_id=content_id,
            content_type=content_type,
            position_seconds=position_seconds,
            duration_seconds=duration_seconds,
            title=title,
            last_updated=now,
            created_at=now,
            **kwargs,
        )

    @classmethod
    def create_completed(
        cls,
        provider: str,
        content_id: str,
        content_type: ContentType,
        duration_seconds: Optional[int] = None,
        title: Optional[str] = None,
        **kwargs,
    ) -> "Bookmark":
        """
        Create a bookmark marking content as completed.

        Args:
            provider: Provider name.
            content_id: Content identifier.
            content_type: Type of content.
            duration_seconds: Total duration in seconds.
            title: Content title.
            **kwargs: Additional metadata.

        Returns:
            Bookmark with position set to -1 (completed).
        """
        return cls.create(
            provider=provider,
            content_id=content_id,
            content_type=content_type,
            position_seconds=-1,
            duration_seconds=duration_seconds,
            title=title,
            **kwargs,
        )

    @classmethod
    def from_api_dict(cls, data: Dict) -> "Bookmark":
        """
        Create a Bookmark from a PascalCase API dictionary (inverse of ``to_dict``).

        Args:
            data: Dictionary with PascalCase keys as returned by ``to_dict()``.

        Returns:
            Bookmark instance.
        """
        def _parse_dt(value) -> Optional[datetime]:
            if value is None:
                return None
            if isinstance(value, datetime):
                return value
            return datetime.fromisoformat(value)

        return cls(
            bookmark_id=data["BookmarkId"],
            provider=data["Provider"],
            content_id=data["ContentId"],
            content_type=ContentType(data["ContentType"]),
            position_seconds=data.get("PositionSeconds", 0),
            duration_seconds=data.get("DurationSeconds"),
            last_updated=_parse_dt(data.get("LastUpdated")) or datetime.now(),
            created_at=_parse_dt(data.get("CreatedAt")) or datetime.now(),
            title=data.get("Title"),
            thumbnail_url=data.get("ThumbnailUrl"),
            series_title=data.get("SeriesTitle"),
            season_number=data.get("SeasonNumber"),
            episode_number=data.get("EpisodeNumber"),
            episode_name=data.get("EpisodeName"),
            channel_name=data.get("ChannelName"),
            channel_logo=data.get("ChannelLogo"),
        )

    @classmethod
    def from_storage_dict(cls, data: Dict) -> "Bookmark":
        """
        Create a Bookmark from a snake_case storage dictionary
        (inverse of ``to_storage_dict``).

        Args:
            data: Dictionary with snake_case keys as written by
                  ``to_storage_dict()``.

        Returns:
            Bookmark instance.
        """
        def _parse_dt(value) -> Optional[datetime]:
            if value is None:
                return None
            if isinstance(value, datetime):
                return value
            return datetime.fromisoformat(value)

        return cls(
            bookmark_id=data["bookmark_id"],
            provider=data["provider"],
            content_id=data["content_id"],
            content_type=ContentType(data["content_type"]),
            position_seconds=data.get("position_seconds", 0),
            duration_seconds=data.get("duration_seconds"),
            last_updated=_parse_dt(data.get("last_updated")) or datetime.now(),
            created_at=_parse_dt(data.get("created_at")) or datetime.now(),
            title=data.get("title"),
        )

    # ==========================================================================
    # Serialization
    # ==========================================================================

    def to_dict(self, include_none: bool = True) -> Dict:
        """
        Convert bookmark to a PascalCase dictionary for API responses.

        Args:
            include_none: When True (default) all fields are present so callers
                          can distinguish "field is absent" from "field is None".
                          Pass False for a compact payload that omits None values.

        Returns:
            Dictionary with PascalCase keys.
        """
        result = {
            # Core identification
            "BookmarkId": self.bookmark_id,
            "Provider": self.provider,
            "ContentId": self.content_id,
            "ContentType": self.content_type.value,

            # Playback position
            "PositionSeconds": self.position_seconds,
            "DurationSeconds": self.duration_seconds,
            "ProgressPercent": self.progress_percent,
            "RemainingSeconds": self.remaining_seconds,
            "IsCompleted": self.is_completed,

            # Timestamps
            "LastUpdated": self.last_updated.isoformat(),
            "CreatedAt": self.created_at.isoformat(),

            # Cached metadata
            "Title": self.title,
            "ThumbnailUrl": self.thumbnail_url,

            # Series context
            "SeriesTitle": self.series_title,
            "SeasonNumber": self.season_number,
            "EpisodeNumber": self.episode_number,
            "EpisodeName": self.episode_name,

            # Channel context
            "ChannelName": self.channel_name,
            "ChannelLogo": self.channel_logo,
        }

        if not include_none:
            return {k: v for k, v in result.items() if v is not None}
        return result

    def to_storage_dict(self) -> Dict:
        """
        Convert to a snake_case dictionary for storage backends (minimal fields).

        Metadata fields (thumbnail, series info, channel info) are intentionally
        omitted — they are expected to be re-fetched from the provider on restore
        so that cached data does not become stale across storage roundtrips.

        Returns:
            Dictionary with only essential fields.
        """
        return {
            "bookmark_id": self.bookmark_id,
            "provider": self.provider,
            "content_id": self.content_id,
            "content_type": self.content_type.value,
            "position_seconds": self.position_seconds,
            "duration_seconds": self.duration_seconds,
            "last_updated": self.last_updated.isoformat(),
            "created_at": self.created_at.isoformat(),
            "title": self.title,
        }

    # ==========================================================================
    # Validation
    # ==========================================================================

    def validate(self) -> List[Tuple[ValidationLevel, str]]:
        """
        Validate bookmark data integrity.

        Returns:
            List of (ValidationLevel, message) tuples. Empty list means valid.
            ERROR entries indicate the bookmark is unusable without a fix.
            WARNING entries indicate unexpected but non-fatal conditions.
        """
        issues: List[Tuple[ValidationLevel, str]] = []

        if not self.provider:
            issues.append((ValidationLevel.ERROR, "Provider name is required"))

        if not self.content_id:
            issues.append((ValidationLevel.ERROR, "Content ID is required"))

        if self.position_seconds < -1:
            issues.append((
                ValidationLevel.ERROR,
                f"Invalid position_seconds: {self.position_seconds} (must be >= -1)",
            ))

        if self.duration_seconds is not None and self.duration_seconds <= 0:
            issues.append((
                ValidationLevel.ERROR,
                f"duration_seconds must be positive, got {self.duration_seconds}",
            ))

        if (
            self.position_seconds > 0
            and self.duration_seconds
            and self.position_seconds > self.duration_seconds
        ):
            issues.append((
                ValidationLevel.WARNING,
                f"Position ({self.position_seconds}s) exceeds duration ({self.duration_seconds}s)",
            ))

        if self.season_number is not None and self.season_number < 0:
            issues.append((
                ValidationLevel.WARNING,
                f"season_number must be >= 0, got {self.season_number}",
            ))

        if self.episode_number is not None and self.episode_number < 0:
            issues.append((
                ValidationLevel.WARNING,
                f"episode_number must be >= 0, got {self.episode_number}",
            ))

        return issues

    def is_valid(self) -> bool:
        """Return True if the bookmark has no ERROR-level validation issues."""
        return not any(level == ValidationLevel.ERROR for level, _ in self.validate())

    # ==========================================================================
    # Comparison
    # ==========================================================================

    def __eq__(self, other) -> bool:
        """Two bookmarks are equal if they point to the same content."""
        if not isinstance(other, Bookmark):
            return False
        return self.provider == other.provider and self.content_id == other.content_id

    def __hash__(self) -> int:
        """Hash based on provider and content_id."""
        return hash((self.provider, self.content_id))