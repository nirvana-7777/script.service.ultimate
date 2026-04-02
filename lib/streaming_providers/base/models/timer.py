# streaming_providers/base/models/timer.py
"""
Timer model.

A Timer represents a scheduled recording instruction — it tells the backend
*when* and *what* to record.  Unlike a Recording (which is captured content
that can be played back), a Timer is purely a management object: it has no
manifest and no DRM.  It therefore does NOT inherit from Content.

Mapping to the PVR Timer API is noted in inline comments where names diverge.

Two companion enumerations are provided:
  - TimerState   — lifecycle state of the timer itself
  - TimerWeekday — bitmask constants for recurring-timer day selection
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum, IntFlag
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class TimerState(Enum):
    """
    Lifecycle state of the timer.
    Maps to PVR_TIMER_STATE_* constants.
    """
    NEW        = "NEW"         # just created, not yet saved to provider
    SCHEDULED  = "SCHEDULED"  # saved, waiting for start time
    RECORDING  = "RECORDING"  # capture is currently in progress
    COMPLETED  = "COMPLETED"  # recording finished successfully
    ABORTED    = "ABORTED"    # recording was manually stopped
    CANCELLED  = "CANCELLED"  # timer was deleted before it fired
    CONFLICT   = "CONFLICT"   # overlaps with another timer / resource issue
    ERROR      = "ERROR"      # provider reported an error


class TimerWeekday(IntFlag):
    """
    Bitmask for recurring timer weekday selection.
    Maps to PVR_WEEKDAY_* constants.
    Combine with bitwise OR:  TimerWeekday.MONDAY | TimerWeekday.WEDNESDAY
    """
    NONE      = 0
    MONDAY    = 1
    TUESDAY   = 2
    WEDNESDAY = 4
    THURSDAY  = 8
    FRIDAY    = 16
    SATURDAY  = 32
    SUNDAY    = 64
    ALL_DAYS  = MONDAY | TUESDAY | WEDNESDAY | THURSDAY | FRIDAY | SATURDAY | SUNDAY
    WEEKDAYS  = MONDAY | TUESDAY | WEDNESDAY | THURSDAY | FRIDAY
    WEEKEND   = SATURDAY | SUNDAY


class DuplicateHandling(Enum):
    """
    Strategy for preventing duplicate episode recordings.
    Maps to PVR_TIMER_DUPLICATE_PREVENTION_* values.
    """
    NONE             = 0   # record all, even duplicates
    SAME_EPG_ID      = 1   # skip if same EPG event ID already recorded
    SAME_TITLE       = 2   # skip if title matches an existing recording
    SAME_SUBTITLE    = 3   # skip if subtitle/episode name matches
    SAME_DESCRIPTION = 4   # skip if description matches


# ---------------------------------------------------------------------------
# Timer dataclass
# ---------------------------------------------------------------------------

@dataclass
class Timer:
    """
    A scheduled recording instruction.

    Required fields (must be set for every timer):
        client_index  — unique identifier assigned by the provider
        state         — current lifecycle state
        timer_type_id — references a TimerType.type_id
        title         — display name / series title

    All other fields are optional and mirror PVR API capabilities.
    """

    # ------------------------------------------------------------------
    # Identity  (required)
    # ------------------------------------------------------------------
    # PVR: SetClientIndex / GetClientIndex  (unsigned int)
    client_index: int = 0

    # PVR: SetState / GetState
    state: TimerState = TimerState.NEW

    # PVR: SetTimerType / GetTimerType  (unsigned int — references TimerType.type_id)
    timer_type_id: int = 1

    # PVR: SetTitle / GetTitle
    title: str = ""

    # Provider this timer belongs to (not a PVR field; used for routing)
    provider: str = ""

    # ------------------------------------------------------------------
    # Hierarchy — series / parent timers
    # ------------------------------------------------------------------
    # PVR: SetParentClientIndex / GetParentClientIndex
    # 0 = top-level timer (no parent)
    parent_client_index: int = 0

    # ------------------------------------------------------------------
    # Channel
    # ------------------------------------------------------------------
    # PVR: SetClientChannelUid / GetClientChannelUid
    # -1 = "any channel" (used by EPG-search timers)
    client_channel_uid: int = -1

    # Human-readable channel name for display (not in PVR table)
    channel_name: Optional[str] = None

    # ------------------------------------------------------------------
    # Timing
    # ------------------------------------------------------------------
    # PVR: SetStartTime / GetStartTime  (Unix timestamp; 0 = ASAP)
    start_time: Optional[datetime] = None

    # PVR: SetEndTime / GetEndTime  (Unix timestamp; 0 = open-ended)
    end_time: Optional[datetime] = None

    # PVR: SetStartAnyTime / GetStartAnyTime
    # True = ignore start_time; begin whenever the event is detected
    start_any_time: bool = False

    # PVR: SetEndAnyTime / GetEndAnyTime
    # True = ignore end_time; record until the event ends naturally
    end_any_time: bool = False

    # PVR: SetFirstDay / GetFirstDay  (Unix timestamp)
    # For recurring timers: do not fire before this date
    first_day: Optional[datetime] = None

    # ------------------------------------------------------------------
    # Pre/post padding
    # ------------------------------------------------------------------
    # PVR: SetMarginStart / GetMarginStart  (minutes)
    margin_start: int = 0

    # PVR: SetMarginEnd / GetMarginEnd  (minutes)
    margin_end: int = 0

    # ------------------------------------------------------------------
    # EPG search / linkage
    # ------------------------------------------------------------------
    # PVR: SetEPGSearchString / GetEPGSearchString
    # Used by search-based recurring timers (e.g. "record anything matching 'Tatort'")
    epg_search_string: Optional[str] = None

    # PVR: SetFullTextEpgSearch / GetFullTextEpgSearch
    # True = match anywhere in title/description; False = title-only
    full_text_epg_search: bool = False

    # PVR: SetEPGUid / GetEPGUid  (unsigned int)
    # EPG event ID this timer was created from (0 = not linked to an EPG event)
    epg_uid: int = 0

    # Convenience: the full EPG event ID including provider prefix (not in PVR table)
    epg_event_id: Optional[str] = None

    # ------------------------------------------------------------------
    # Recurring schedule
    # ------------------------------------------------------------------
    # PVR: SetWeekdays / GetWeekdays  (bitmask of TimerWeekday)
    weekdays: TimerWeekday = TimerWeekday.NONE

    # PVR: SetPreventDuplicateEpisodes / GetPreventDuplicateEpisodes
    prevent_duplicate_episodes: DuplicateHandling = DuplicateHandling.NONE

    # Series link — used by some providers to group related timers
    # PVR: SetSeriesLink / GetSeriesLink
    series_link: Optional[str] = None

    # ------------------------------------------------------------------
    # Recording management
    # ------------------------------------------------------------------
    # PVR: SetDirectory / GetDirectory
    directory: Optional[str] = None

    # PVR: SetPriority / GetPriority
    # Higher value = higher priority when resources are scarce
    priority: int = 50

    # PVR: SetLifetime / GetLifetime  (days; 0 = keep forever)
    lifetime: int = 0

    # PVR: SetMaxRecordings / GetMaxRecordings
    # 0 = unlimited; positive integer = keep only this many recordings
    max_recordings: int = 0

    # PVR: SetRecordingGroup / GetRecordingGroup  (unsigned int)
    recording_group: int = 0

    # ------------------------------------------------------------------
    # Genre metadata
    # ------------------------------------------------------------------
    # PVR: SetGenreType / GetGenreType  (DVB genre code)
    genre_type: Optional[int] = None

    # PVR: SetGenreSubType / GetGenreSubType
    genre_sub_type: Optional[int] = None

    # ------------------------------------------------------------------
    # Internal / bookkeeping (not in PVR table)
    # ------------------------------------------------------------------
    # When this timer record was last fetched or updated locally
    last_updated: Optional[datetime] = None

    # Free-form summary from the provider (maps to description in UI)
    description: Optional[str] = None

    # ------------------------------------------------------------------
    # Post-init
    # ------------------------------------------------------------------
    def __post_init__(self):
        # Normalise: a recurring timer with explicit weekdays but NONE set
        # should fall back to the provider's default — we do not force it here
        # but we expose a helper property for convenience.
        pass

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_recurring(self) -> bool:
        """True if this timer fires on multiple days (weekday mask is set)."""
        return self.weekdays != TimerWeekday.NONE

    @property
    def is_epg_based(self) -> bool:
        """True if this timer was created from or linked to an EPG event."""
        return bool(self.epg_uid) or bool(self.epg_event_id)

    @property
    def is_search_based(self) -> bool:
        """True if this timer uses an EPG keyword search."""
        return bool(self.epg_search_string)

    @property
    def is_active(self) -> bool:
        """True if the timer is still expected to produce a recording."""
        return self.state in (TimerState.NEW, TimerState.SCHEDULED, TimerState.RECORDING)

    @property
    def duration_minutes(self) -> Optional[int]:
        """Planned recording duration in minutes (None if open-ended)."""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            return int(delta.total_seconds() // 60)
        return None

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        return {
            # Identity
            "ClientIndex": self.client_index,
            "State": self.state.value,
            "TimerTypeId": self.timer_type_id,
            "Title": self.title,
            "Provider": self.provider,
            # Hierarchy
            "ParentClientIndex": self.parent_client_index,
            # Channel
            "ClientChannelUid": self.client_channel_uid,
            "ChannelName": self.channel_name,
            # Timing
            "StartTime": self.start_time.isoformat() if self.start_time else None,
            "EndTime": self.end_time.isoformat() if self.end_time else None,
            "StartAnyTime": self.start_any_time,
            "EndAnyTime": self.end_any_time,
            "FirstDay": self.first_day.isoformat() if self.first_day else None,
            "DurationMinutes": self.duration_minutes,
            # Padding
            "MarginStart": self.margin_start,
            "MarginEnd": self.margin_end,
            # EPG
            "EpgSearchString": self.epg_search_string,
            "FullTextEpgSearch": self.full_text_epg_search,
            "EpgUid": self.epg_uid,
            "EpgEventId": self.epg_event_id,
            # Recurring
            "Weekdays": self.weekdays.value,
            "PreventDuplicateEpisodes": self.prevent_duplicate_episodes.value,
            "SeriesLink": self.series_link,
            # Management
            "Directory": self.directory,
            "Priority": self.priority,
            "Lifetime": self.lifetime,
            "MaxRecordings": self.max_recordings,
            "RecordingGroup": self.recording_group,
            # Genre
            "GenreType": self.genre_type,
            "GenreSubType": self.genre_sub_type,
            # Convenience flags
            "IsRecurring": self.is_recurring,
            "IsEpgBased": self.is_epg_based,
            "IsSearchBased": self.is_search_based,
            "IsActive": self.is_active,
            # Metadata
            "Description": self.description,
            "LastUpdated": self.last_updated.isoformat() if self.last_updated else None,
        }

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> List[str]:
        warnings = []
        if not self.title:
            warnings.append("title must not be empty")
        if self.timer_type_id <= 0:
            warnings.append("timer_type_id must be a positive integer")
        if self.start_time and self.end_time and self.start_time >= self.end_time:
            warnings.append("start_time must be before end_time")
        if self.margin_start < 0:
            warnings.append("margin_start must not be negative")
        if self.margin_end < 0:
            warnings.append("margin_end must not be negative")
        if self.priority < 0 or self.priority > 100:
            warnings.append("priority should be between 0 and 100")
        if self.lifetime < 0:
            warnings.append("lifetime must be 0 (keep forever) or a positive number of days")
        if self.max_recordings < 0:
            warnings.append("max_recordings must not be negative")
        if self.is_recurring and self.epg_uid:
            warnings.append(
                "timer has both weekdays and epg_uid set; "
                "recurring EPG-based timers should use series_link instead"
            )
        return warnings

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def create_one_shot(
        cls,
        title: str,
        provider: str,
        client_channel_uid: int,
        start_time: datetime,
        end_time: datetime,
        timer_type_id: int = 1,
        **kwargs,
    ) -> "Timer":
        """Create a single-event timer for a specific channel and time window."""
        return cls(
            title=title,
            provider=provider,
            client_channel_uid=client_channel_uid,
            start_time=start_time,
            end_time=end_time,
            timer_type_id=timer_type_id,
            state=TimerState.SCHEDULED,
            **kwargs,
        )

    @classmethod
    def create_recurring(
        cls,
        title: str,
        provider: str,
        client_channel_uid: int,
        weekdays: TimerWeekday,
        start_time: datetime,
        end_time: datetime,
        timer_type_id: int = 1,
        prevent_duplicate_episodes: DuplicateHandling = DuplicateHandling.SAME_EPG_ID,
        **kwargs,
    ) -> "Timer":
        """Create a recurring weekly timer (e.g. record every Monday at 20:15)."""
        return cls(
            title=title,
            provider=provider,
            client_channel_uid=client_channel_uid,
            weekdays=weekdays,
            start_time=start_time,
            end_time=end_time,
            timer_type_id=timer_type_id,
            prevent_duplicate_episodes=prevent_duplicate_episodes,
            state=TimerState.SCHEDULED,
            **kwargs,
        )

    @classmethod
    def create_epg_based(
        cls,
        title: str,
        provider: str,
        client_channel_uid: int,
        epg_uid: int,
        start_time: datetime,
        end_time: datetime,
        timer_type_id: int = 1,
        **kwargs,
    ) -> "Timer":
        """Create a timer tied to a specific EPG event."""
        return cls(
            title=title,
            provider=provider,
            client_channel_uid=client_channel_uid,
            epg_uid=epg_uid,
            start_time=start_time,
            end_time=end_time,
            timer_type_id=timer_type_id,
            state=TimerState.SCHEDULED,
            **kwargs,
        )

    @classmethod
    def create_search_based(
        cls,
        title: str,
        provider: str,
        epg_search_string: str,
        timer_type_id: int = 1,
        client_channel_uid: int = -1,
        full_text_epg_search: bool = False,
        prevent_duplicate_episodes: DuplicateHandling = DuplicateHandling.SAME_SUBTITLE,
        **kwargs,
    ) -> "Timer":
        """Create a keyword-search timer that records any matching EPG event."""
        return cls(
            title=title,
            provider=provider,
            client_channel_uid=client_channel_uid,
            epg_search_string=epg_search_string,
            full_text_epg_search=full_text_epg_search,
            prevent_duplicate_episodes=prevent_duplicate_episodes,
            timer_type_id=timer_type_id,
            state=TimerState.SCHEDULED,
            **kwargs,
        )