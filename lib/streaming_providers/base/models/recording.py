# streaming_providers/base/models/recording.py
"""
Recording model.

A Recording represents a captured broadcast — it was recorded from a live
channel (like an Event) but is consumed as on-demand content (like a VodItem).
Because it straddles both concerns without cleanly fitting either, it inherits
directly from Content and adds recording-specific fields.

Mapping to PVR API fields is noted in inline comments where names diverge.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from .content import Content


class RecordingStatus(Enum):
    """Lifecycle state of the recording itself (not the broadcast)."""
    PENDING     = "PENDING"      # scheduled to be recorded
    RECORDING   = "RECORDING"    # currently being captured
    COMPLETED   = "COMPLETED"    # fully captured and available
    FAILED      = "FAILED"       # capture failed or was interrupted
    DELETED     = "DELETED"      # marked deleted; may still be recoverable


class ChannelType(Enum):
    """Maps to PVR_RECORDING_CHANNEL_TYPE."""
    UNKNOWN  = "UNKNOWN"
    TV       = "TV"
    RADIO    = "RADIO"


@dataclass
class Recording(Content):
    """
    A captured broadcast recording.

    Inherits all streaming/DRM/manifest fields from Content so that playback
    is resolved the same way as channels, events, and VOD items:
        provider.get_manifest(content_id)   # content_id == recording_id
        provider.get_drm(content_id)

    Fields are a union of:
      - PVR recording API fields (see table; PVR name noted in comments)
      - Fields shared with Event (timing, channel provenance)
      - Fields shared with VodItem (episode/series context, playback state)
      - Storage / management fields unique to recordings
    """

    # ------------------------------------------------------------------
    # Identity / provenance
    # ------------------------------------------------------------------
    # content_id (inherited) == recording_id  →  SetRecordingId / GetRecordingId

    # The title is already `name` on Content, but PVR distinguishes a top-level
    # title from an episode name within a series.
    episode_name: Optional[str] = None          # SetEpisodeName / GetEpisodeName

    # Channel the recording was captured from
    channel_name: Optional[str] = None          # SetChannelName / GetChannelName
    channel_uid: Optional[int] = None           # SetChannelUid / GetChannelUid
    channel_type: ChannelType = ChannelType.TV  # SetChannelType / GetChannelType

    # EPG linkage — lets the UI look up the original broadcast metadata
    epg_event_id: Optional[int] = None          # SetEPGEventId / GetEPGEventId (unsigned int)

    # ------------------------------------------------------------------
    # Timing  (mirrors Event.start_time / end_time)
    # ------------------------------------------------------------------
    recording_time: Optional[datetime] = None   # SetRecordingTime / GetRecordingTime
    duration_seconds: Optional[int] = None      # SetDuration / GetDuration  (seconds)
    first_aired: Optional[str] = None           # SetFirstAired / GetFirstAired (ISO date string)

    # ------------------------------------------------------------------
    # Series / episode context  (mirrors VodItem)
    # ------------------------------------------------------------------
    season_number: Optional[int] = None         # SetSeriesNumber / GetSeriesNumber
    episode_number: Optional[int] = None        # SetEpisodeNumber / GetEpisodeNumber
    series_title: Optional[str] = None          # not in PVR table; added for UI grouping
    series_id: Optional[str] = None             # not in PVR table; added for back-navigation
    release_year: Optional[int] = None          # SetYear / GetYear

    # ------------------------------------------------------------------
    # Descriptions / metadata
    # ------------------------------------------------------------------
    # description (short) is inherited from Content
    plot: Optional[str] = None                  # SetPlot / GetPlot  (long description)
    plot_outline: Optional[str] = None          # SetPlotOutline / GetPlotOutline  (short summary)
    genre_description: Optional[str] = None     # SetGenreDescription / GetGenreDescription
    genre_type: Optional[int] = None            # SetGenreType / GetGenreType  (DVB genre code)
    genre_sub_type: Optional[int] = None        # SetGenreSubType / GetGenreSubType

    # ------------------------------------------------------------------
    # Visual assets
    # ------------------------------------------------------------------
    # logo_url (inherited from Content) ≈ icon_path
    icon_path: Optional[str] = None             # SetIconPath / GetIconPath
    thumbnail_url: Optional[str] = None         # SetThumbnailPath / GetThumbnailPath
    fanart_url: Optional[str] = None            # SetFanartPath / GetFanartPath

    # ------------------------------------------------------------------
    # Playback state  (unique to recordings; events and VOD don't track this)
    # ------------------------------------------------------------------
    play_count: int = 0                         # SetPlayCount / GetPlayCount
    last_played_position: int = 0               # SetLastPlayedPosition / GetLastPlayedPosition (seconds)

    # ------------------------------------------------------------------
    # Storage / management
    # ------------------------------------------------------------------
    directory: Optional[str] = None             # SetDirectory / GetDirectory
    size_in_bytes: Optional[int] = None         # SetSizeInBytes / GetSizeInBytes
    priority: Optional[int] = None              # SetPriority / GetPriority
    lifetime: Optional[int] = None              # SetLifetime / GetLifetime  (days; 0 = keep forever)
    flags: Optional[str] = None                 # SetFlags / GetFlags

    # Provider identification (separate from the streaming provider on Content)
    client_provider_uid: Optional[int] = None   # SetClientProviderUid / GetClientProviderUid
    provider_name: Optional[str] = None         # SetProviderName / GetProviderName

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    status: RecordingStatus = RecordingStatus.COMPLETED
    # is_deleted is derived from status but exposed as a convenience flag to
    # match the PVR API; setting it syncs the status enum.
    _is_deleted: bool = field(default=False, repr=False)

    # ------------------------------------------------------------------
    # Post-init
    # ------------------------------------------------------------------
    def __post_init__(self):
        # Recordings are always played on-demand
        self.mode = "vod"
        self.on_demand = True

        # Sync is_deleted → status
        if self._is_deleted and self.status != RecordingStatus.DELETED:
            self.status = RecordingStatus.DELETED

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def recording_id(self) -> str:
        """Semantic alias for content_id — maps to PVR GetRecordingId."""
        return self.content_id

    @recording_id.setter
    def recording_id(self, value: str):
        self.content_id = value

    @property
    def is_deleted(self) -> bool:
        """SetIsDeleted / GetIsDeleted — synced with RecordingStatus.DELETED."""
        return self.status == RecordingStatus.DELETED

    @is_deleted.setter
    def is_deleted(self, value: bool):
        if value:
            self.status = RecordingStatus.DELETED
        elif self.status == RecordingStatus.DELETED:
            self.status = RecordingStatus.COMPLETED

    @property
    def is_episode(self) -> bool:
        return self.season_number is not None or self.episode_number is not None

    @property
    def duration_minutes(self) -> Optional[int]:
        if self.duration_seconds is not None:
            return self.duration_seconds // 60
        return None

    @property
    def is_watched(self) -> bool:
        """True if the recording has been played at least once."""
        return self.play_count > 0

    @property
    def is_in_progress(self) -> bool:
        """True if the recording is currently being captured."""
        return self.status == RecordingStatus.RECORDING

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        result = super().to_dict()
        result.update({
            # Identity
            "EpisodeName": self.episode_name,
            "ChannelName": self.channel_name,
            "ChannelUid": self.channel_uid,
            "ChannelType": self.channel_type.value,
            "EpgEventId": self.epg_event_id,
            # Timing
            "RecordingTime": self.recording_time.isoformat() if self.recording_time else None,
            "DurationSeconds": self.duration_seconds,
            "DurationMinutes": self.duration_minutes,
            "FirstAired": self.first_aired,
            # Series / episode
            "SeasonNumber": self.season_number,
            "EpisodeNumber": self.episode_number,
            "SeriesTitle": self.series_title,
            "SeriesId": self.series_id,
            "ReleaseYear": self.release_year,
            # Descriptions
            "Plot": self.plot,
            "PlotOutline": self.plot_outline,
            "GenreDescription": self.genre_description,
            "GenreType": self.genre_type,
            "GenreSubType": self.genre_sub_type,
            # Visual
            "IconPath": self.icon_path,
            "ThumbnailUrl": self.thumbnail_url,
            "FanartUrl": self.fanart_url,
            # Playback state
            "PlayCount": self.play_count,
            "LastPlayedPosition": self.last_played_position,
            # Storage
            "Directory": self.directory,
            "SizeInBytes": self.size_in_bytes,
            "Priority": self.priority,
            "Lifetime": self.lifetime,
            "Flags": self.flags,
            "ClientProviderUid": self.client_provider_uid,
            "ProviderName": self.provider_name,
            # Status
            "Status": self.status.value,
            "IsDeleted": self.is_deleted,
        })
        return result

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> List[str]:
        warnings = []
        if not self.manifest and not self.manifest_script:
            warnings.append("No manifest URL or manifest script provided")
        if self.license_url and not self.drm_config:
            warnings.append("License URL provided but no DRM configuration")
        if self.duration_seconds is not None and self.duration_seconds <= 0:
            warnings.append("duration_seconds must be positive")
        if self.size_in_bytes is not None and self.size_in_bytes < 0:
            warnings.append("size_in_bytes must not be negative")
        if self.lifetime is not None and self.lifetime < 0:
            warnings.append("lifetime must be 0 (keep forever) or a positive number of days")
        if self.release_year is not None and not (1888 <= self.release_year <= 2100):
            warnings.append(f"Unusual release_year: {self.release_year}")
        return warnings

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def create_completed(
        cls,
        name: str,
        recording_id: str,
        provider: str,
        recording_time: Optional[datetime] = None,
        duration_seconds: Optional[int] = None,
        **kwargs,
    ) -> "Recording":
        """Create a fully captured recording ready for playback."""
        return cls(
            name=name,
            content_id=recording_id,
            provider=provider,
            status=RecordingStatus.COMPLETED,
            recording_time=recording_time,
            duration_seconds=duration_seconds,
            **kwargs,
        )

    @classmethod
    def create_in_progress(
        cls,
        name: str,
        recording_id: str,
        provider: str,
        recording_time: Optional[datetime] = None,
        **kwargs,
    ) -> "Recording":
        """Create a recording that is currently being captured (live recording)."""
        return cls(
            name=name,
            content_id=recording_id,
            provider=provider,
            status=RecordingStatus.RECORDING,
            recording_time=recording_time,
            **kwargs,
        )

    @classmethod
    def create_episode_recording(
        cls,
        name: str,
        recording_id: str,
        provider: str,
        season_number: int,
        episode_number: int,
        series_title: Optional[str] = None,
        **kwargs,
    ) -> "Recording":
        """Create a recording of a specific series episode."""
        return cls(
            name=name,
            content_id=recording_id,
            provider=provider,
            status=RecordingStatus.COMPLETED,
            season_number=season_number,
            episode_number=episode_number,
            series_title=series_title,
            **kwargs,
        )