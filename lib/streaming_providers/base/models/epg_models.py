#!/usr/bin/env python3
# streaming_providers/base/models/epg_models.py
"""
EPG Models - Data classes for Electronic Program Guide entries
Based on Kodi PVR EPG Tag specification (ETSI EN 300 468 DVB-SI standard)
"""

from dataclasses import dataclass, fields, replace
from datetime import datetime
from enum import IntEnum
from typing import List, Optional, Union, Dict, Any

# EPG Constants from Kodi PVR specification
EPG_TAG_INVALID_UID = 0
"""Special broadcast ID value to indicate invalid/unset EPG event UID."""

EPG_TAG_INVALID_SERIES_EPISODE = -1
"""Special value for series/episode/part numbers to indicate not applicable."""

EPG_TIMEFRAME_UNLIMITED = -1
"""Special timeframe value to indicate no time restrictions."""

EPG_STRING_TOKEN_SEPARATOR = ","
"""Separator for multiple values in string fields (cast, directors, writers)."""


def _coerce_timestamp(value: Union[int, str, None], field_name: str) -> Optional[int]:
    """
    Coerce a raw timestamp value (int, numeric string, or ISO-8601 string)
    into a Unix timestamp (int seconds).

    This is the single source of truth for timestamp parsing used by
    EPGEntry.__post_init__. Upstream providers are inconsistent about
    whether they send epoch ints, epoch strings, or ISO-8601 datetimes,
    so all three forms are accepted here.

    Args:
        value: Raw timestamp value to coerce.
        field_name: Name of the field being coerced, used only for error
            messages (e.g. "start", "end").

    Returns:
        Unix timestamp as int, or None if value was None.

    Raises:
        ValueError: If value is a non-empty string/other type that cannot
            be parsed as either a numeric epoch or an ISO-8601 datetime.
    """
    if value is None:
        return None

    # Already an int (bools are ints too, but that's not a realistic
    # input here so no special-casing).
    if isinstance(value, int):
        return value

    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None

        # Numeric epoch string, e.g. "1750000000" or "-1"
        if stripped.lstrip("-").isdigit():
            return int(stripped)

        # ISO-8601 datetime string, e.g. "2026-06-17T16:28:00Z"
        try:
            dt = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
            return int(dt.timestamp())
        except (ValueError, AttributeError) as e:
            raise ValueError(
                f"{field_name} could not be parsed as a timestamp: "
                f"{value!r} ({e})"
            ) from e

    raise ValueError(
        f"{field_name} must be an int, numeric string, or ISO-8601 string, "
        f"got {type(value)}: {value!r}"
    )


class EPGEventState(IntEnum):
    """
    EPG event states for event lifecycle callbacks.
    Used with EpgEventStateChange() callback in C++ PVR client.
    """

    CREATED = 0  # Event created
    UPDATED = 1  # Event updated
    DELETED = 2  # Event deleted


@dataclass
class EPGEntry:
    """
    EPG Entry model for Kodi PVR Backend.

    Represents a single program/event in the Electronic Program Guide.
    Based on Kodi's PVREPGTag C++ class specification.

    This class matches the dictionary format used by epg_parser.py and
    expected by the C++ PVR frontend.

    BROADCAST ID ENCODING:
    ----------------------
    The broadcast_id field uses a special encoding scheme that embeds provider
    information for catchup functionality:

    - Bits 0-15 (lower 16 bits): Provider hash
    - Bits 16-31 (upper 16 bits): Event hash (channel + start time)

    This allows identifying the provider from just the broadcast_id, which is
    critical for catchup operations where only the broadcast_id is available.

    Usage:
        # Creating entries (done by parser)
        broadcast_id = EPGEntry.encode_broadcast_id("rtlplus", "rtl", start_time)

        # In catchup handler (only broadcast_id available)
        provider_hash = EPGEntry.get_provider_hash(broadcast_id)
        # Look up provider from hash in registry

        # Or verify provider
        if EPGEntry.verify_provider(broadcast_id, "rtlplus"):
            # Get catchup stream from rtlplus
    """

    # Required fields
    broadcast_id: int
    """Unique identifier for this broadcast event. Must be unique per channel."""

    title: str
    """Program title."""

    start: int
    """Start time as Unix timestamp (seconds since epoch)."""

    end: int
    """End time as Unix timestamp (seconds since epoch)."""

    program_id: Optional[str] = None

    epg_event_id: Optional[str] = None
    """
    Provider-native LISTING guid (e.g. "das_erste_hd_031eace5" for Magenta2) —
    distinct from program_id, which holds the PROGRAM guid (e.g.
    "telekom.de-031eace5"). These are two different identifiers on the
    upstream API: the listing guid identifies a specific broadcast slot on a
    specific channel/time, while the program guid identifies the underlying
    content regardless of when/where it airs.

    This is the identifier required to schedule an nPVR recording (passed to
    the client as part of the EPG entry, cached client-side against
    broadcast_id, and sent back as "epg_event_id" when the user creates a
    timer for this broadcast). Populate it whenever the upstream provider
    exposes a listing-level guid separate from the program guid; leave as
    None for providers where no such distinction exists.
    """

    # Optional fields - Program Information
    description: Optional[str] = None
    """Full program description/plot. C++ expects 'description' key."""

    plot_outline: Optional[str] = None
    """Short plot outline (first sentence or ~100 chars of description)."""

    episode_name: Optional[str] = None
    """Episode title/name (XMLTV sub-title)."""

    original_title: Optional[str] = None
    """Original title if different from main title."""

    # Optional fields - Media Metadata
    year: Optional[int] = None
    """Production year."""

    icon: Optional[str] = None
    """URL to program icon/poster image. C++ expects 'icon' key."""

    # Optional fields - People (C++ expects arrays)
    cast: Optional[List[str]] = None
    """List of actor names. C++ expects array format."""

    directors: Optional[List[str]] = None
    """List of director names. C++ expects 'directors' array."""

    writers: Optional[List[str]] = None
    """List of writer names. C++ expects 'writers' array."""

    producers: Optional[List[str]] = None
    """
    List of producer names. Note: unlike cast/directors/writers, Kodi's
    PVREPGTag C++ interface has no dedicated producer slot, so this field
    is not rendered by the Kodi frontend today. It is still captured here
    for JSON/API consumers and providers (e.g. MoveTV's channel-based EPG
    endpoint) that return producer data as part of a single one-shot
    fetch with no separate enrichment pass to fall back on.
    """

    # Optional fields - Genre/Category
    genre: Optional[int] = None
    """
    Numeric genre type based on DVB-SI standard (ETSI EN 300 468).
    Use EPGGenre constants (e.g., EPGGenre.MOVIEDRAMA = 0x10).
    Set to EPGGenre.USE_STRING (0xF0) to use genre_description instead.
    """

    genre_sub_type: Optional[int] = None
    """
    Numeric genre subtype based on DVB-SI standard.
    Use EPGGenreSubtype nested classes (e.g., EPGGenreSubtype.Sports.FOOTBALL_SOCCER).
    Must be used in combination with appropriate genre type.
    """

    genre_description: Optional[str] = None
    """
    Text description of genre.
    Used when genre=EPGGenre.USE_STRING or for custom genres not in DVB-SI standard.
    """

    genres: Optional[List[str]] = None
    """
    List of text genre/category labels (e.g. ["Komedija", "Drama", "Romansa"]),
    distinct from the single numeric DVB-SI `genre` field and from the single
    `genre_description` string above. Named to match EPGProgramDetails.genres
    so the two line up if this ever gets pulled into a shared merge field.
    """

    # Optional fields - Episode Information
    season_number: Optional[int] = None
    """Season/series number (1-based). C++ expects 'season_number' key."""

    episode_number: Optional[int] = None
    """Episode number within season (1-based)."""

    episode_part_number: Optional[int] = None
    """Part number for multi-part episodes (1-based)."""

    # Optional fields - Ratings
    star_rating: Optional[int] = None
    """Star rating on 0-10 scale."""

    parental_rating: Optional[int] = None
    """Parental rating code/age restriction."""

    parental_rating_code: Optional[str] = None
    """Text parental rating code (e.g., 'TV-PG', 'FSK 12')."""

    # Optional fields - Additional Metadata
    first_aired: Optional[int] = None
    """Original air date as Unix timestamp."""

    imdb_number: Optional[str] = None
    """
    IMDB identifier (e.g. 'tt1234567').
    May be unset on grid-import entries and only populated later once a
    provider detail fetch (EPGProgramDetails.imdb_number) is merged in —
    it is not guaranteed to be present in the initial schedule import.
    """

    series_link: Optional[str] = None
    """Link to series information."""

    flags: Optional[int] = None
    """
    Bit field flags for EPG entry properties.
    Combine flags using bitwise OR: EPGFlags.IS_SERIES | EPGFlags.IS_NEW

    Available flags:
    - EPGFlags.UNDEFINED (0x00): Nothing special
    - EPGFlags.IS_SERIES (0x01): Part of a series
    - EPGFlags.IS_NEW (0x02): New episode/content
    - EPGFlags.IS_PREMIERE (0x04): Premiere episode
    - EPGFlags.IS_FINALE (0x08): Finale episode
    - EPGFlags.IS_LIVE (0x10): Live broadcast

    Example:
        flags = EPGFlags.IS_SERIES | EPGFlags.IS_NEW
    """

    def to_dict(self) -> dict:
        """
        Convert EPGEntry to dictionary format for frontend consumption.

        This format is used by:
        - Kodi PVR frontend (C++)
        - Web UI / API endpoints
        - Other frontend clients

        Note: The dict includes both broadcast_id (for Kodi) and program_id
        (for provider-specific operations). Frontends that only need the
        integer ID can ignore program_id.
        """
        result = {
            "broadcast_id": self.broadcast_id,
            "title": self.title,
            "start": self.start,
            "end": self.end,
        }

        # Include program_id if available (multi-platform support)
        if self.program_id is not None:
            result["program_id"] = self.program_id

        # Add all optional fields
        optional_fields = [
            "description",
            "plot_outline",
            "episode_name",
            "original_title",
            "year",
            "icon",
            "cast",
            "directors",
            "writers",
            "producers",
            "genre",
            "genre_description",
            "genres",
            "season_number",
            "episode_number",
            "episode_part_number",
            "star_rating",
            "parental_rating",
            "parental_rating_code",
            "first_aired",
            "imdb_number",
            "series_link",
            "flags",
        ]

        for field_name in optional_fields:
            value = getattr(self, field_name)
            if value is not None:
                result[field_name] = value

        return result

    @classmethod
    def from_dict(cls, data: dict) -> "EPGEntry":
        """
        Create EPGEntry from dictionary (e.g., from epg_parser output).

        Args:
            data: Dictionary with EPG data

        Returns:
            EPGEntry instance
        """
        # Extract only fields that exist in EPGEntry
        valid_fields = {f.name for f in fields(cls)}

        filtered_data = {k: v for k, v in data.items() if k in valid_fields}

        return cls(**filtered_data)

    def merge_details(self, details: "EPGProgramDetails") -> "EPGEntry":
        """
        Overlay shared EPGContent fields from a fetched EPGProgramDetails
        onto this entry. Convenience wrapper around the module-level
        merge_content() function - see its docstring for exact semantics
        (non-None overlay only, returns a new EPGEntry).

        Example:
            entry = entry.merge_details(details)
        """
        return merge_content(self, details)

    @property
    def duration_seconds(self) -> int:
        """Calculate program duration in seconds."""
        return self.end - self.start

    @property
    def start_datetime(self) -> datetime:
        """Get start time as datetime object."""
        return datetime.fromtimestamp(self.start)

    @property
    def end_datetime(self) -> datetime:
        """Get end time as datetime object."""
        return datetime.fromtimestamp(self.end)

    def is_currently_airing(self, reference_time: Optional[int] = None) -> bool:
        """
        Check if program is currently airing.

        Args:
            reference_time: Unix timestamp to check against (None = now)

        Returns:
            True if program is airing at reference_time
        """
        if reference_time is None:
            reference_time = int(datetime.now().timestamp())

        return self.start <= reference_time < self.end

    def overlaps_with(self, start_time: int, end_time: int) -> bool:
        """
        Check if this program overlaps with a given time range.

        Args:
            start_time: Start of time range (Unix timestamp)
            end_time: End of time range (Unix timestamp)

        Returns:
            True if there is any overlap
        """
        # Program overlaps if it doesn't end before range starts
        # and doesn't start after range ends
        return self.end > start_time and self.start < end_time

    def has_flag(self, flag: int) -> bool:
        """
        Check if a specific flag is set.

        Args:
            flag: Flag to check (use EPGFlags constants)

        Returns:
            True if flag is set

        Example:
            if entry.has_flag(EPGFlags.IS_LIVE):
                print("Live broadcast")
        """
        if self.flags is None:
            return False
        return EPGFlags.has_flag(self.flags, flag)

    def set_flag(self, flag: int) -> None:
        """
        Set a specific flag (adds to existing flags).

        Args:
            flag: Flag to set (use EPGFlags constants)

        Example:
            entry.set_flag(EPGFlags.IS_NEW)
        """
        if self.flags is None:
            self.flags = flag
        else:
            self.flags |= flag

    def clear_flag(self, flag: int) -> None:
        """
        Clear a specific flag (removes from existing flags).

        Args:
            flag: Flag to clear (use EPGFlags constants)

        Example:
            entry.clear_flag(EPGFlags.IS_NEW)
        """
        if self.flags is not None:
            self.flags &= ~flag

    @property
    def is_series(self) -> bool:
        """Check if this entry is part of a series."""
        return self.has_flag(EPGFlags.IS_SERIES)

    @property
    def is_new(self) -> bool:
        """Check if this entry is flagged as new."""
        return self.has_flag(EPGFlags.IS_NEW)

    @property
    def is_premiere(self) -> bool:
        """Check if this entry is a premiere."""
        return self.has_flag(EPGFlags.IS_PREMIERE)

    @property
    def is_finale(self) -> bool:
        """Check if this entry is a finale."""
        return self.has_flag(EPGFlags.IS_FINALE)

    @property
    def is_live(self) -> bool:
        """Check if this entry is a live broadcast."""
        return self.has_flag(EPGFlags.IS_LIVE)

    @staticmethod
    def join_string_list(items: List[str]) -> str:
        """
        Join list of strings using EPG_STRING_TOKEN_SEPARATOR.
        Useful for cast, directors, writers fields when converting from lists.

        Args:
            items: List of strings to join

        Returns:
            Joined string using EPG separator

        Example:
            cast_str = EPGEntry.join_string_list(["Actor 1", "Actor 2", "Actor 3"])
            # Returns: "Actor 1,Actor 2,Actor 3"
        """
        return EPG_STRING_TOKEN_SEPARATOR.join(items)

    @staticmethod
    def split_string_list(text: str) -> List[str]:
        """
        Split string using EPG_STRING_TOKEN_SEPARATOR.
        Useful for parsing cast, directors, writers fields.

        Args:
            text: String to split

        Returns:
            List of strings

        Example:
            cast = EPGEntry.split_string_list("Actor 1,Actor 2,Actor 3")
            # Returns: ["Actor 1", "Actor 2", "Actor 3"]
        """
        if not text:
            return []
        return [
            item.strip()
            for item in text.split(EPG_STRING_TOKEN_SEPARATOR)
            if item.strip()
        ]

    @staticmethod
    def encode_broadcast_id(
        provider_name: str, channel_id: str, start_time: int
    ) -> int:
        """
        Generate deterministic broadcast ID with encoded provider information.

        The ID structure allows extraction of provider hash for catchup operations:
        - Bits 0-15 (lower 16 bits): Provider hash (65536 possible values)
        - Bits 16-31 (upper 16 bits): Event hash (channel + start time)

        This ensures:
        1. Unique IDs across different providers
        2. Provider can be identified from broadcast_id alone
        3. Same event on same provider always gets same ID

        Args:
            provider_name: Provider name (e.g., "rtlplus", "joyn_de")
            channel_id: Channel ID (e.g., "rtl", "prosieben")
            start_time: Unix timestamp of programme start

        Returns:
            Unique 32-bit broadcast ID with encoded provider info

        Example:
            broadcast_id = EPGEntry.encode_broadcast_id("rtlplus", "rtl", 1234567890)
            provider_hash = EPGEntry.get_provider_hash(broadcast_id)
        """
        import hashlib

        # Generate provider hash (16 bits)
        provider_hash_obj = hashlib.sha256(provider_name.encode("utf-8"))
        provider_hash = int(provider_hash_obj.hexdigest()[:4], 16)  # 16 bits

        # Generate event hash from channel + start time (16 bits)
        event_input = f"{channel_id}_{start_time}".encode("utf-8")
        event_hash_obj = hashlib.sha256(event_input)
        event_hash = int(event_hash_obj.hexdigest()[:4], 16)  # 16 bits

        # Combine: upper 16 bits = event hash, lower 16 bits = provider hash
        broadcast_id = (event_hash << 16) | provider_hash

        # Ensure positive and non-zero
        return broadcast_id if broadcast_id > 0 else 1

    @staticmethod
    def get_provider_hash(broadcast_id: int) -> int:
        """
        Extract provider hash from encoded broadcast ID.

        Args:
            broadcast_id: Encoded broadcast ID from encode_broadcast_id()

        Returns:
            16-bit provider hash (lower 16 bits of broadcast_id)

        Example:
            broadcast_id = EPGEntry.encode_broadcast_id("rtlplus", "rtl", 1234567890)
            provider_hash = EPGEntry.get_provider_hash(broadcast_id)
            # Use provider_hash to look up provider from registry
        """
        return broadcast_id & 0xFFFF

    @staticmethod
    def get_event_hash(broadcast_id: int) -> int:
        """
        Extract event hash from encoded broadcast ID.

        Args:
            broadcast_id: Encoded broadcast ID from encode_broadcast_id()

        Returns:
            16-bit event hash (upper 16 bits of broadcast_id)
        """
        return (broadcast_id >> 16) & 0xFFFF

    @staticmethod
    def verify_provider(broadcast_id: int, provider_name: str) -> bool:
        """
        Verify if a broadcast ID matches a given provider.

        Args:
            broadcast_id: Encoded broadcast ID
            provider_name: Provider name to verify against

        Returns:
            True if broadcast_id was generated for this provider

        Example:
            if EPGEntry.verify_provider(broadcast_id, "rtlplus"):
                print("This EPG entry is from rtlplus")
        """
        import hashlib

        # Get provider hash from broadcast_id
        stored_hash = EPGEntry.get_provider_hash(broadcast_id)

        # Calculate hash for given provider name
        provider_hash_obj = hashlib.sha256(provider_name.encode("utf-8"))
        calculated_hash = int(provider_hash_obj.hexdigest()[:4], 16)

        return stored_hash == calculated_hash

    def __post_init__(self):
        """Validate required fields after initialization."""
        # --- COERCE TIMESTAMPS FIRST ---
        start_coerced = _coerce_timestamp(self.start, "start")
        end_coerced = _coerce_timestamp(self.end, "end")

        if start_coerced is None:
            raise ValueError("start is required and cannot be None")
        if end_coerced is None:
            raise ValueError("end is required and cannot be None")

        self.start = start_coerced
        self.end = end_coerced
        # --- END COERCION ---

        # Now validate
        if self.broadcast_id <= EPG_TAG_INVALID_UID:
            raise ValueError(
                f"broadcast_id must be greater than EPG_TAG_INVALID_UID ({EPG_TAG_INVALID_UID})"
            )

        if not self.title or not self.title.strip():
            raise ValueError("title is required and cannot be empty")

        if self.start <= 0:
            raise ValueError("start time must be a valid Unix timestamp")

        if self.end <= self.start:
            raise ValueError("end time must be after start time")

        # Validate episode numbers if set
        if (
            self.season_number is not None
            and self.season_number < EPG_TAG_INVALID_SERIES_EPISODE
        ):
            raise ValueError(
                f"season_number must be >= EPG_TAG_INVALID_SERIES_EPISODE ({EPG_TAG_INVALID_SERIES_EPISODE})"
            )

        if (
            self.episode_number is not None
            and self.episode_number < EPG_TAG_INVALID_SERIES_EPISODE
        ):
            raise ValueError(
                f"episode_number must be >= EPG_TAG_INVALID_SERIES_EPISODE ({EPG_TAG_INVALID_SERIES_EPISODE})"
            )

        if (
            self.episode_part_number is not None
            and self.episode_part_number < EPG_TAG_INVALID_SERIES_EPISODE
        ):
            raise ValueError(
                f"episode_part_number must be >= EPG_TAG_INVALID_SERIES_EPISODE ({EPG_TAG_INVALID_SERIES_EPISODE})"
            )


@dataclass(frozen=True)
class PersonData:
    """Enriched person data with image and roles."""
    id: str
    name: str
    image: Optional[str] = None
    roles: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"id": self.id, "name": self.name}
        if self.image:
            result["image"] = self.image
        if self.roles:
            result["roles"] = self.roles
        return result


@dataclass(frozen=True)
class EPGProgramDetails:
    """
    Enrichment metadata for a single programme fetched from a provider's
    program-detail endpoint.
    """
    program_id: str
    description: Optional[str] = None
    episode_name: Optional[str] = None
    year: Optional[int] = None
    icon: Optional[str] = None

    # String-based credits (backwards compatible for Kodi/PVR)
    cast: Optional[List[str]] = None
    directors: Optional[List[str]] = None
    writers: Optional[List[str]] = None
    producers: Optional[List[str]] = None
    presenter: Optional[List[str]] = None
    composers: Optional[List[str]] = None
    contributors: Optional[List[str]] = None

    # Enriched person data (for modern web UIs)
    cast_details: Optional[List[PersonData]] = None
    directors_details: Optional[List[PersonData]] = None
    writers_details: Optional[List[PersonData]] = None
    producers_details: Optional[List[PersonData]] = None
    presenter_details: Optional[List[PersonData]] = None

    # Extended media metadata
    backdrop: Optional[str] = None
    poster: Optional[str] = None

    # External identifiers
    imdb_number: Optional[str] = None
    """
    IMDB identifier (e.g. 'tt1234567'), when returned by the provider's
    detail endpoint. Named to match EPGEntry.imdb_number so the two can be
    merged directly without a field-name translation step.
    """

    provider_vod_id: Optional[str] = None
    """
    Provider-specific identifier valid for that provider's own VOD/catchup
    service (distinct from imdb_number and from the general-purpose
    program_id). Not a shared/EPGEntry concept — this is provider playback
    plumbing, only meaningful in combination with the provider it came from.
    """

    series_id: Optional[str] = None
    """
    Provider-specific series identifier (e.g. 'HRT1-SH4506209'), distinct
    from program_id which is episode-scoped (e.g.
    'HRT1-SH4506209-S4E236'). Not part of EPGContent — EPGEntry has no
    matching field. Useful as a grouping key if detail fetches are ever
    batched/cached per-series or per-season rather than per-episode.
    """

    # Additional metadata
    genres: Optional[List[str]] = None
    parental_rating: Optional[int] = None
    release_date: Optional[int] = None
    duration: Optional[int] = None

    season_number: Optional[int] = None
    episode_number: Optional[int] = None

    country_of_origin: Optional[List[str]] = None
    """
    Country/countries of origin as returned by the provider's detail
    endpoint (e.g. ["Österreich"], ["USA"]). Not part of EPGContent —
    EPGEntry has no matching field, same treatment as presenter/composers.
    """

    trailer: Optional[List[str]] = None
    """
    Trailer URL(s), when the provider's detail endpoint returns them.
    Not part of EPGContent — no matching EPGEntry field.
    """

    def to_dict(self) -> dict:
        """Serialise to a plain dict, omitting None values."""
        result: dict = {"program_id": self.program_id}

        simple_fields = (
            "description", "episode_name", "year", "icon",
            "cast", "directors", "writers", "producers",
            "presenter", "composers", "contributors",
            "backdrop", "poster", "imdb_number", "provider_vod_id",
            "series_id",
            "genres", "parental_rating",
            "release_date", "duration",
            "season_number", "episode_number",
            "country_of_origin", "trailer",
        )

        for field in simple_fields:
            value = getattr(self, field)
            if value is not None:
                result[field] = value

        detail_fields = (
            "cast_details", "directors_details", "writers_details",
            "producers_details", "presenter_details"
        )

        for field in detail_fields:
            value = getattr(self, field)
            if value is not None:
                result[field] = [person.to_dict() for person in value]

        return result


@dataclass(frozen=True)
class EPGContent:
    """
    Single source of truth for the fields that are shared in meaning
    between EPGEntry (schedule/grid data) and EPGProgramDetails
    (enrichment data fetched from a provider's detail endpoint).

    This is deliberately NOT used via class inheritance. EPGEntry is
    mutable (it mutates `flags` via set_flag/clear_flag) while
    EPGProgramDetails is frozen, and dataclasses do not allow mixing
    frozen and non-frozen classes across an inheritance chain in either
    direction. EPGEntry also has required positional fields
    (broadcast_id, title, start, end) which, combined with a base
    class's defaulted fields, would hit dataclasses' "non-default
    argument follows default argument" ordering error.

    Instead, EPGContent is used as:
      1. A single declared list of "shared" field names, walked by
         merge_content() below - adding a new shared field means adding
         it here AND to whichever of EPGEntry/EPGProgramDetails don't
         already have it, rather than hand-copying merge logic in three
         separate places.
      2. A documentation anchor: a same-named field on EPGEntry and
         EPGProgramDetails is expected to carry the same meaning and be
         safe to overlay via merge_content().

    Field types/defaults here must stay in sync with the matching
    fields on EPGEntry and EPGProgramDetails.
    """
    description: Optional[str] = None
    episode_name: Optional[str] = None
    year: Optional[int] = None
    icon: Optional[str] = None
    cast: Optional[List[str]] = None
    directors: Optional[List[str]] = None
    writers: Optional[List[str]] = None
    season_number: Optional[int] = None
    episode_number: Optional[int] = None
    parental_rating: Optional[int] = None
    imdb_number: Optional[str] = None


def merge_content(entry: "EPGEntry", details: "EPGProgramDetails") -> "EPGEntry":
    """
    Overlay the shared EPGContent fields from a fetched EPGProgramDetails
    onto an existing EPGEntry, returning a NEW EPGEntry.

    Only non-None values from `details` are applied, so a detail fetch
    that didn't return a given field (e.g. no imdb_number available for
    this title) will not clobber a value already present on `entry`.

    Fields that exist on EPGProgramDetails but NOT in EPGContent (e.g.
    provider_vod_id, genres, backdrop/poster, presenter/composers/
    contributors, the *_details enriched-person fields) are intentionally
    NOT copied here - EPGEntry has no matching field for them. Callers
    that need that richer data should keep the EPGProgramDetails instance
    itself rather than expecting it to appear on the merged EPGEntry.

    Note: EPGEntry.producers is the one exception - it exists directly on
    EPGEntry (not via EPGContent/merge) for providers like MoveTV that
    return producer data in a single one-shot grid fetch with no separate
    detail-fetch step to enrich later. It is set at parse time, not
    merged in here.

    A new EPGEntry is returned (rather than mutating in place) because
    EPGEntry is not frozen, but merge_content should behave predictably
    even if a caller holds another reference to the original entry.

    Args:
        entry: The existing schedule entry (e.g. from a grid import).
        details: Freshly-fetched detail-endpoint enrichment data.

    Returns:
        A new EPGEntry with EPGContent-shared fields overlaid from
        details wherever details provided a non-None value.

    Example:
        # Two-step: grid import now, detail fetch later
        entry = merge_content(entry, details)

        # Or via the EPGEntry convenience method:
        entry = entry.merge_details(details)

    Raises:
        ValueError: If both entry.program_id and details.program_id are
            set but differ, since applying details for a different
            programme onto this entry would silently mix data - the
            same class of bug as the Magenta2/ThePlatform field-mapping
            issue, just at the merge step instead of the parse step.
    """
    if (
        entry.program_id is not None
        and details.program_id is not None
        and entry.program_id != details.program_id
    ):
        raise ValueError(
            f"program_id mismatch: entry has {entry.program_id!r}, "
            f"details has {details.program_id!r} - refusing to merge "
            f"details for a different programme onto this entry"
        )

    updates = {
        f.name: getattr(details, f.name)
        for f in fields(EPGContent)
        if getattr(details, f.name) is not None
    }
    return replace(entry, **updates)


# Constants matching C++ EPG_TAG_FLAG values
class EPGFlags:
    """
    Bit field flags for EPG entry properties.
    Based on Kodi's EPG_TAG_FLAG enum.

    These can be combined using bitwise OR operator:
    flags = EPGFlags.IS_SERIES | EPGFlags.IS_NEW

    Example:
        entry = EPGEntry(
            ...,
            flags=EPGFlags.IS_SERIES | EPGFlags.IS_PREMIERE
        )
    """

    UNDEFINED = 0x00  # 0000 0000 : Nothing special to say about this entry
    IS_SERIES = 0x01  # 0000 0001 : This EPG entry is part of a series
    IS_NEW = 0x02  # 0000 0010 : This EPG entry will be flagged as new
    IS_PREMIERE = 0x04  # 0000 0100 : This EPG entry will be flagged as a premiere
    IS_FINALE = 0x08  # 0000 1000 : This EPG entry will be flagged as a finale
    IS_LIVE = 0x10  # 0001 0000 : This EPG entry will be flagged as live

    @staticmethod
    def has_flag(flags: int, flag: int) -> bool:
        """
        Check if a specific flag is set.

        Args:
            flags: Combined flags value
            flag: Flag to check for

        Returns:
            True if flag is set

        Example:
            if EPGFlags.has_flag(entry.flags, EPGFlags.IS_LIVE):
                print("This is a live broadcast")
        """
        return (flags & flag) == flag

    @staticmethod
    def combine(*flags: int) -> int:
        """
        Combine multiple flags using bitwise OR.

        Args:
            *flags: Variable number of flag values

        Returns:
            Combined flags value

        Example:
            combined = EPGFlags.combine(
                EPGFlags.IS_SERIES,
                EPGFlags.IS_NEW,
                EPGFlags.IS_PREMIERE
            )
        """
        result = 0
        for flag in flags:
            result |= flag
        return result

    @staticmethod
    def get_flag_names(flags: int) -> List[str]:
        """
        Get list of flag names that are set.

        Args:
            flags: Combined flags value

        Returns:
            List of flag names

        Example:
            flags = EPGFlags.IS_SERIES | EPGFlags.IS_NEW
            names = EPGFlags.get_flag_names(flags)
            # Returns: ["IS_SERIES", "IS_NEW"]
        """
        flag_map = {
            EPGFlags.IS_SERIES: "IS_SERIES",
            EPGFlags.IS_NEW: "IS_NEW",
            EPGFlags.IS_PREMIERE: "IS_PREMIERE",
            EPGFlags.IS_FINALE: "IS_FINALE",
            EPGFlags.IS_LIVE: "IS_LIVE",
        }

        result = []
        for flag_value, flag_name in flag_map.items():
            if flags & flag_value:
                result.append(flag_name)

        return result if result else ["UNDEFINED"]


# Genre type constants based on ETSI EN 300 468 V1.14.1 (DVB-SI EIT content descriptor)
# These match Kodi's EPG_EVENT_CONTENTMASK values
class EPGGenre:
    """
    EPG genre type codes based on DVB-SI standard (ETSI EN 300 468).
    These are the main content masks - use with genre_type field.
    """

    # Main genre types (content masks)
    UNDEFINED = 0x00
    MOVIEDRAMA = 0x10
    NEWSCURRENTAFFAIRS = 0x20
    SHOW = 0x30
    SPORTS = 0x40
    CHILDRENYOUTH = 0x50
    MUSICBALLETDANCE = 0x60
    ARTSCULTURE = 0x70
    SOCIALPOLITICALECONOMICS = 0x80
    EDUCATIONALSCIENCE = 0x90
    LEISUREHOBBIES = 0xA0
    SPECIAL = 0xB0
    USERDEFINED = 0xF0

    # Special Kodi value to indicate genre is provided as string
    USE_STRING = 0xF0  # Same as USERDEFINED, signals use of genre_description


class EPGGenreSubtype:
    """
    EPG genre subtype codes based on DVB-SI standard (ETSI EN 300 468).
    These are used with genre_sub_type field in combination with main genre_type.
    """

    # Movie/Drama subtypes (use with EPGGenre.MOVIEDRAMA)
    class MovieDrama:
        GENERAL = 0x00
        DETECTIVE_THRILLER = 0x01
        ADVENTURE_WESTERN_WAR = 0x02
        SCIENCEFICTION_FANTASY_HORROR = 0x03
        COMEDY = 0x04
        SOAP_MELODRAMA_FOLKLORIC = 0x05
        ROMANCE = 0x06
        SERIOUS_CLASSICAL_RELIGIOUS_HISTORICAL = 0x07
        ADULT = 0x08
        USERDEFINED = 0x0F

    # News/Current Affairs subtypes (use with EPGGenre.NEWSCURRENTAFFAIRS)
    class NewsCurrentAffairs:
        GENERAL = 0x00
        WEATHER = 0x01
        MAGAZINE = 0x02
        DOCUMENTARY = 0x03
        DISCUSSION_INTERVIEW_DEBATE = 0x04
        USERDEFINED = 0x0F

    # Show/Game Show subtypes (use with EPGGenre.SHOW)
    class Show:
        GENERAL = 0x00
        GAMESHOW_QUIZ_CONTEST = 0x01
        VARIETY_SHOW = 0x02
        TALK_SHOW = 0x03
        USERDEFINED = 0x0F

    # Sports subtypes (use with EPGGenre.SPORTS)
    class Sports:
        GENERAL = 0x00
        OLYMPICGAMES_WORLDCUP = 0x01
        SPORTS_MAGAZINES = 0x02
        FOOTBALL_SOCCER = 0x03
        TENNIS_SQUASH = 0x04
        TEAMSPORTS = 0x05
        ATHLETICS = 0x06
        MOTORSPORT = 0x07
        WATERSPORT = 0x08
        WINTERSPORTS = 0x09
        EQUESTRIAN = 0x0A
        MARTIALSPORTS = 0x0B
        USERDEFINED = 0x0F

    # Children/Youth subtypes (use with EPGGenre.CHILDRENYOUTH)
    class ChildrenYouth:
        GENERAL = 0x00
        PRESCHOOL_CHILDREN = 0x01
        ENTERTAIN_6TO14 = 0x02
        ENTERTAIN_10TO16 = 0x03
        INFORMATIONAL_EDUCATIONAL_SCHOOL = 0x04
        CARTOONS_PUPPETS = 0x05
        USERDEFINED = 0x0F

    # Music/Ballet/Dance subtypes (use with EPGGenre.MUSICBALLETDANCE)
    class MusicBalletDance:
        GENERAL = 0x00
        ROCKPOP = 0x01
        SERIOUSMUSIC_CLASSICALMUSIC = 0x02
        FOLK_TRADITIONAL_MUSIC = 0x03
        JAZZ = 0x04
        MUSICAL_OPERA = 0x05
        BALLET = 0x06
        USERDEFINED = 0x0F

    # Arts/Culture subtypes (use with EPGGenre.ARTSCULTURE)
    class ArtsCulture:
        GENERAL = 0x00
        PERFORMINGARTS = 0x01
        FINEARTS = 0x02
        RELIGION = 0x03
        POPULARCULTURE_TRADITIONALARTS = 0x04
        LITERATURE = 0x05
        FILM_CINEMA = 0x06
        EXPERIMENTALFILM_VIDEO = 0x07
        BROADCASTING_PRESS = 0x08
        NEWMEDIA = 0x09
        ARTS_CULTUREMAGAZINES = 0x0A
        FASHION = 0x0B
        USERDEFINED = 0x0F

    # Social/Political/Economics subtypes (use with EPGGenre.SOCIALPOLITICALECONOMICS)
    class SocialPoliticalEconomics:
        GENERAL = 0x00
        MAGAZINES_REPORTS_DOCUMENTARY = 0x01
        ECONOMICS_SOCIALADVISORY = 0x02
        REMARKABLEPEOPLE = 0x03
        USERDEFINED = 0x0F

    # Educational/Science subtypes (use with EPGGenre.EDUCATIONALSCIENCE)
    class EducationalScience:
        GENERAL = 0x00
        NATURE_ANIMALS_ENVIRONMENT = 0x01
        TECHNOLOGY_NATURALSCIENCES = 0x02
        MEDICINE_PHYSIOLOGY_PSYCHOLOGY = 0x03
        FOREIGNCOUNTRIES_EXPEDITIONS = 0x04
        SOCIAL_SPIRITUALSCIENCES = 0x05
        FURTHEREDUCATION = 0x06
        LANGUAGES = 0x07
        USERDEFINED = 0x0F

    # Leisure/Hobbies subtypes (use with EPGGenre.LEISUREHOBBIES)
    class LeisureHobbies:
        GENERAL = 0x00
        TOURISM_TRAVEL = 0x01
        HANDICRAFT = 0x02
        MOTORING = 0x03
        FITNESSANDHEALTH = 0x04
        COOKING = 0x05
        ADVERTISEMENT_SHOPPING = 0x06
        GARDENING = 0x07
        USERDEFINED = 0x0F

    # Special Characteristics subtypes (use with EPGGenre.SPECIAL)
    class Special:
        GENERAL = 0x00
        BLACKANDWHITE = 0x01
        UNPUBLISHED = 0x02
        LIVEBROADCAST = 0x03
        PLANOSTEREOSCOPIC = 0x04
        LOCALORREGIONAL = 0x05
        USERDEFINED = 0x0F


# Legacy alias for backwards compatibility with existing code
PVREPGTag = EPGEntry

# Export all public symbols
__all__ = [
    # Main classes
    "EPGEntry",
    "EPGProgramDetails",
    "EPGContent",
    "PersonData",
    "PVREPGTag",  # Legacy alias
    # Functions
    "merge_content",
    # Constants
    "EPG_TAG_INVALID_UID",
    "EPG_TAG_INVALID_SERIES_EPISODE",
    "EPG_TIMEFRAME_UNLIMITED",
    "EPG_STRING_TOKEN_SEPARATOR",
    # Enums and flags
    "EPGEventState",
    "EPGFlags",
    "EPGGenre",
    "EPGGenreSubtype",
]