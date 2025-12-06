#!/usr/bin/env python3
# streaming_providers/base/models/epg_models.py
"""
EPG Models - Data classes for Electronic Program Guide entries
Based on Kodi PVR EPG Tag specification
"""

from dataclasses import dataclass
from typing import Optional, List
from datetime import datetime


@dataclass
class EPGEntry:
    """
    EPG Entry model for Kodi PVR Backend.

    Represents a single program/event in the Electronic Program Guide.
    Based on Kodi's PVREPGTag C++ class specification.

    This class matches the dictionary format used by epg_parser.py and
    expected by the C++ PVR frontend.
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
    """IMDB identifier."""

    series_link: Optional[str] = None
    """Link to series information."""

    flags: Optional[int] = None
    """
    Bit field flags for EPG entry properties.
    Common flags: IS_SERIES=0x01, IS_NEW=0x02, IS_PREMIERE=0x04,
                  IS_FINALE=0x08, IS_LIVE=0x10
    """

    def to_dict(self) -> dict:
        """
        Convert EPGEntry to dictionary format expected by C++ frontend.
        Only includes non-None values to minimize data transfer.

        Returns:
            Dictionary with EPG data
        """
        result = {
            'broadcast_id': self.broadcast_id,
            'title': self.title,
            'start': self.start,
            'end': self.end,
        }

        # Add optional fields only if they have values
        optional_fields = [
            'description', 'plot_outline', 'episode_name', 'original_title',
            'year', 'icon', 'cast', 'directors', 'writers', 'genre',
            'genre_description', 'season_number', 'episode_number',
            'episode_part_number', 'star_rating', 'parental_rating',
            'parental_rating_code', 'first_aired', 'imdb_number',
            'series_link', 'flags'
        ]

        for field_name in optional_fields:
            value = getattr(self, field_name)
            if value is not None:
                result[field_name] = value

        return result

    @classmethod
    def from_dict(cls, data: dict) -> 'EPGEntry':
        """
        Create EPGEntry from dictionary (e.g., from epg_parser output).

        Args:
            data: Dictionary with EPG data

        Returns:
            EPGEntry instance
        """
        from dataclasses import fields

        # Extract only fields that exist in EPGEntry
        valid_fields = {f.name for f in fields(cls)}

        filtered_data = {
            k: v for k, v in data.items()
            if k in valid_fields
        }

        return cls(**filtered_data)

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

    def __post_init__(self):
        """Validate required fields after initialization."""
        if self.broadcast_id <= 0:
            raise ValueError("broadcast_id must be positive")

        if not self.title or not self.title.strip():
            raise ValueError("title is required and cannot be empty")

        if self.start <= 0:
            raise ValueError("start time must be a valid Unix timestamp")

        if self.end <= self.start:
            raise ValueError("end time must be after start time")


# Constants matching C++ EPG_TAG_FLAG values
class EPGFlags:
    """Bit flags for EPG entry properties."""
    IS_SERIES = 0x01
    IS_NEW = 0x02
    IS_PREMIERE = 0x04
    IS_FINALE = 0x08
    IS_LIVE = 0x10


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