# streaming_providers/base/models/timer_type.py
"""
Timer type model.

A TimerType describes a *category* of timer a provider supports — not a
single scheduled recording, but the template that governs what options are
available when creating one.  Providers expose their supported timer types via
get_timer_types(); clients use this information to build a creation UI and to
know which timer_type_id to pass when calling add_timer().

Mapping to PVRTimerType is noted in inline comments.
"""

from dataclasses import dataclass, field
from typing import Dict, List


# ---------------------------------------------------------------------------
# Attribute bitmask constants
# (mirrors PVR_TIMER_TYPE_ATTRIBUTE_* from the Kodi PVR API)
# ---------------------------------------------------------------------------

class TimerTypeAttribute:
    """
    Bitmask constants describing the capabilities of a TimerType.
    Combine with bitwise OR to build the `attributes` field.
    """
    NONE                       = 0x00000000
    IS_MANUAL                  = 0x00000001  # timer is set manually (not EPG-based)
    IS_REPEATING               = 0x00000002  # fires on multiple days / events
    IS_EPG_BASED               = 0x00000004  # linked to a specific EPG event
    SUPPORTS_ENABLE_DISABLE    = 0x00000008  # timer can be enabled/disabled without deleting
    SUPPORTS_CHANNELS          = 0x00000010  # channel selection is meaningful
    SUPPORTS_START_TIME        = 0x00000020  # start time can be specified
    SUPPORTS_START_ANY_TIME    = 0x00000040  # "start any time" flag is supported
    SUPPORTS_END_TIME          = 0x00000080  # end time can be specified
    SUPPORTS_END_ANY_TIME      = 0x00000100  # "end any time" flag is supported
    SUPPORTS_FIRST_DAY         = 0x00000200  # first-day constraint is supported
    SUPPORTS_WEEKDAYS          = 0x00000400  # weekday mask is supported
    SUPPORTS_EPG_SEARCH        = 0x00000800  # keyword EPG search is supported
    SUPPORTS_FULL_TEXT_SEARCH  = 0x00001000  # full-text EPG search is supported
    SUPPORTS_RECORDING_FOLDERS = 0x00002000  # directory selection is supported
    SUPPORTS_PRIORITIES        = 0x00004000  # priority selection is supported
    SUPPORTS_LIFETIMES         = 0x00008000  # lifetime selection is supported
    SUPPORTS_PADDING           = 0x00010000  # pre/post margin padding is supported
    SUPPORTS_RECORDING_GROUP   = 0x00020000  # recording group assignment is supported
    SUPPORTS_MAX_RECORDINGS    = 0x00040000  # max-recordings limit is supported
    SUPPORTS_DUPLICATE_CHECK   = 0x00080000  # duplicate-episode prevention is supported
    REQUIRES_EPG_TAG_ON_CREATE = 0x00100000  # an EPG tag must be provided at creation time
    FORBIDS_EPG_TAG_ON_CREATE  = 0x00200000  # EPG tag must NOT be provided at creation time


# ---------------------------------------------------------------------------
# Helper: labelled integer option (used for dropdown selections)
# ---------------------------------------------------------------------------

@dataclass
class TimerTypeIntOption:
    """
    A single labelled option in a numeric selection list.
    Mirrors PVRTypeIntValue used for priority, lifetime, etc.
    """
    value: int
    description: str

    def to_dict(self) -> Dict:
        return {"Value": self.value, "Description": self.description}


# ---------------------------------------------------------------------------
# TimerType dataclass
# ---------------------------------------------------------------------------

@dataclass
class TimerType:
    """
    Describes a category of timer supported by a provider.

    Required fields:
        type_id     — unique identifier within the provider (PVR: SetId / GetId)
        attributes  — bitmask of TimerTypeAttribute constants

    Optional fields control which UI elements appear when the type is selected
    and what default values are pre-filled.
    """

    # ------------------------------------------------------------------
    # Identity  (required)
    # ------------------------------------------------------------------
    # PVR: SetId / GetId  (unsigned int; must be > 0)
    type_id: int = 1

    # PVR: SetAttributes / GetAttributes  (bitmask of TimerTypeAttribute)
    attributes: int = TimerTypeAttribute.NONE

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------
    # PVR: SetDescription / GetDescription
    description: str = ""

    # ------------------------------------------------------------------
    # Priority selection
    # ------------------------------------------------------------------
    # PVR: SetPriorities / GetPriorities
    # List of (value, label) options presented in the priority dropdown.
    # Empty list = free-text integer input.
    priority_options: List[TimerTypeIntOption] = field(default_factory=list)

    # PVR: SetPrioritiesDefault / GetPrioritiesDefault
    priority_default: int = 50

    # ------------------------------------------------------------------
    # Lifetime selection
    # ------------------------------------------------------------------
    # PVR: SetLifetimes / GetLifetimes
    lifetime_options: List[TimerTypeIntOption] = field(default_factory=list)

    # PVR: SetLifetimesDefault / GetLifetimesDefault  (days; 0 = keep forever)
    lifetime_default: int = 0

    # ------------------------------------------------------------------
    # Duplicate-episode prevention selection
    # ------------------------------------------------------------------
    # PVR: SetPreventDuplicateEpisodes / GetPreventDuplicateEpisodes
    prevent_duplicate_options: List[TimerTypeIntOption] = field(default_factory=list)

    # PVR: SetPreventDuplicateEpisodesDefault / GetPreventDuplicateEpisodesDefault
    prevent_duplicate_default: int = 0

    # ------------------------------------------------------------------
    # Recording group selection
    # ------------------------------------------------------------------
    # PVR: SetRecordingGroups / GetRecordingGroups
    recording_group_options: List[TimerTypeIntOption] = field(default_factory=list)

    # PVR: SetRecordingGroupDefault / GetRecordingGroupDefault
    recording_group_default: int = 0

    # ------------------------------------------------------------------
    # Max recordings selection
    # ------------------------------------------------------------------
    # PVR: SetMaxRecordings / GetMaxRecordings
    max_recordings_options: List[TimerTypeIntOption] = field(default_factory=list)

    # PVR: SetMaxRecordingsDefault / GetMaxRecordingsDefault  (0 = unlimited)
    max_recordings_default: int = 0

    # ------------------------------------------------------------------
    # Convenience attribute helpers
    # ------------------------------------------------------------------

    def supports(self, attribute: int) -> bool:
        """Check whether a specific attribute flag is set."""
        return bool(self.attributes & attribute)

    @property
    def is_manual(self) -> bool:
        return self.supports(TimerTypeAttribute.IS_MANUAL)

    @property
    def is_repeating(self) -> bool:
        return self.supports(TimerTypeAttribute.IS_REPEATING)

    @property
    def is_epg_based(self) -> bool:
        return self.supports(TimerTypeAttribute.IS_EPG_BASED)

    @property
    def supports_channels(self) -> bool:
        return self.supports(TimerTypeAttribute.SUPPORTS_CHANNELS)

    @property
    def supports_weekdays(self) -> bool:
        return self.supports(TimerTypeAttribute.SUPPORTS_WEEKDAYS)

    @property
    def supports_epg_search(self) -> bool:
        return self.supports(TimerTypeAttribute.SUPPORTS_EPG_SEARCH)

    @property
    def supports_padding(self) -> bool:
        return self.supports(TimerTypeAttribute.SUPPORTS_PADDING)

    @property
    def supports_priorities(self) -> bool:
        return self.supports(TimerTypeAttribute.SUPPORTS_PRIORITIES)

    @property
    def supports_lifetimes(self) -> bool:
        return self.supports(TimerTypeAttribute.SUPPORTS_LIFETIMES)

    @property
    def supports_duplicate_check(self) -> bool:
        return self.supports(TimerTypeAttribute.SUPPORTS_DUPLICATE_CHECK)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        return {
            "TypeId": self.type_id,
            "Attributes": self.attributes,
            "Description": self.description,
            # Priority
            "PriorityOptions": [o.to_dict() for o in self.priority_options],
            "PriorityDefault": self.priority_default,
            # Lifetime
            "LifetimeOptions": [o.to_dict() for o in self.lifetime_options],
            "LifetimeDefault": self.lifetime_default,
            # Duplicate handling
            "PreventDuplicateOptions": [o.to_dict() for o in self.prevent_duplicate_options],
            "PreventDuplicateDefault": self.prevent_duplicate_default,
            # Recording group
            "RecordingGroupOptions": [o.to_dict() for o in self.recording_group_options],
            "RecordingGroupDefault": self.recording_group_default,
            # Max recordings
            "MaxRecordingsOptions": [o.to_dict() for o in self.max_recordings_options],
            "MaxRecordingsDefault": self.max_recordings_default,
            # Derived flags (convenience for clients that don't parse bitmasks)
            "IsManual": self.is_manual,
            "IsRepeating": self.is_repeating,
            "IsEpgBased": self.is_epg_based,
            "SupportsChannels": self.supports_channels,
            "SupportsWeekdays": self.supports_weekdays,
            "SupportsEpgSearch": self.supports_epg_search,
            "SupportsPadding": self.supports_padding,
            "SupportsPriorities": self.supports_priorities,
            "SupportsLifetimes": self.supports_lifetimes,
            "SupportsDuplicateCheck": self.supports_duplicate_check,
        }

    # ------------------------------------------------------------------
    # Factory helpers for the most common timer type patterns
    # ------------------------------------------------------------------

    @classmethod
    def make_manual_one_shot(
        cls,
        type_id: int = 1,
        description: str = "Manual one-time recording",
        **kwargs,
    ) -> "TimerType":
        """Record a specific channel between two explicit timestamps."""
        return cls(
            type_id=type_id,
            description=description,
            attributes=(
                TimerTypeAttribute.IS_MANUAL
                | TimerTypeAttribute.SUPPORTS_CHANNELS
                | TimerTypeAttribute.SUPPORTS_START_TIME
                | TimerTypeAttribute.SUPPORTS_END_TIME
                | TimerTypeAttribute.SUPPORTS_PRIORITIES
                | TimerTypeAttribute.SUPPORTS_LIFETIMES
                | TimerTypeAttribute.SUPPORTS_PADDING
                | TimerTypeAttribute.FORBIDS_EPG_TAG_ON_CREATE
            ),
            **kwargs,
        )

    @classmethod
    def make_epg_one_shot(
        cls,
        type_id: int = 2,
        description: str = "EPG-based one-time recording",
        **kwargs,
    ) -> "TimerType":
        """Record a single EPG event."""
        return cls(
            type_id=type_id,
            description=description,
            attributes=(
                TimerTypeAttribute.IS_EPG_BASED
                | TimerTypeAttribute.SUPPORTS_CHANNELS
                | TimerTypeAttribute.SUPPORTS_START_TIME
                | TimerTypeAttribute.SUPPORTS_END_TIME
                | TimerTypeAttribute.SUPPORTS_PRIORITIES
                | TimerTypeAttribute.SUPPORTS_LIFETIMES
                | TimerTypeAttribute.SUPPORTS_PADDING
                | TimerTypeAttribute.REQUIRES_EPG_TAG_ON_CREATE
            ),
            **kwargs,
        )

    @classmethod
    def make_manual_recurring(
        cls,
        type_id: int = 3,
        description: str = "Manual recurring recording",
        **kwargs,
    ) -> "TimerType":
        """Record the same time slot on selected weekdays."""
        return cls(
            type_id=type_id,
            description=description,
            attributes=(
                TimerTypeAttribute.IS_MANUAL
                | TimerTypeAttribute.IS_REPEATING
                | TimerTypeAttribute.SUPPORTS_CHANNELS
                | TimerTypeAttribute.SUPPORTS_START_TIME
                | TimerTypeAttribute.SUPPORTS_END_TIME
                | TimerTypeAttribute.SUPPORTS_WEEKDAYS
                | TimerTypeAttribute.SUPPORTS_FIRST_DAY
                | TimerTypeAttribute.SUPPORTS_PRIORITIES
                | TimerTypeAttribute.SUPPORTS_LIFETIMES
                | TimerTypeAttribute.SUPPORTS_PADDING
                | TimerTypeAttribute.SUPPORTS_MAX_RECORDINGS
                | TimerTypeAttribute.FORBIDS_EPG_TAG_ON_CREATE
            ),
            **kwargs,
        )

    @classmethod
    def make_epg_search(
        cls,
        type_id: int = 4,
        description: str = "EPG keyword search recording",
        **kwargs,
    ) -> "TimerType":
        """Record every EPG event whose title/description matches a keyword."""
        return cls(
            type_id=type_id,
            description=description,
            attributes=(
                TimerTypeAttribute.IS_EPG_BASED
                | TimerTypeAttribute.IS_REPEATING
                | TimerTypeAttribute.SUPPORTS_CHANNELS
                | TimerTypeAttribute.SUPPORTS_EPG_SEARCH
                | TimerTypeAttribute.SUPPORTS_FULL_TEXT_SEARCH
                | TimerTypeAttribute.SUPPORTS_PRIORITIES
                | TimerTypeAttribute.SUPPORTS_LIFETIMES
                | TimerTypeAttribute.SUPPORTS_DUPLICATE_CHECK
                | TimerTypeAttribute.SUPPORTS_MAX_RECORDINGS
                | TimerTypeAttribute.FORBIDS_EPG_TAG_ON_CREATE
            ),
            **kwargs,
        )