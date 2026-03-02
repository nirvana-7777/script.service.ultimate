# streaming_providers/base/models/event.py
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from .content import Content


class EventStatus(Enum):
    SCHEDULED = "SCHEDULED"
    LIVE = "LIVE"
    ENDED = "ENDED"
    CANCELLED = "CANCELLED"


@dataclass
class Event(Content):
    """
    Represents a one-time live or scheduled event (concert, sports match, etc.)
    """

    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    status: EventStatus = EventStatus.SCHEDULED
    subtitle: Optional[str] = None           # secondaryTitle
    original_name: Optional[str] = None      # originalName
    competition: Optional[str] = None        # txCompetition
    venue: Optional[str] = None              # txEvent
    gender: Optional[str] = None             # txGender
    discipline: Optional[str] = None         # txDiscipline
    age_category: Optional[str] = None       # txAge
    master_event: Optional[str] = None       # txMaster-sporting-event
    channel: Optional[str] = None            # primaryChannel

    def __post_init__(self):
        if self.status == EventStatus.SCHEDULED and self.start_time and self.end_time:
            now = datetime.now(timezone.utc)
            if self.start_time <= now <= self.end_time:
                self.status = EventStatus.LIVE
            elif now > self.end_time:
                self.status = EventStatus.ENDED

    # Semantic alias
    @property
    def event_id(self) -> str:
        return self.content_id

    @event_id.setter
    def event_id(self, value: str):
        self.content_id = value

    @property
    def is_live(self) -> bool:
        return self.status == EventStatus.LIVE

    @property
    def is_upcoming(self) -> bool:
        return self.status == EventStatus.SCHEDULED

    @property
    def duration_minutes(self) -> Optional[int]:
        if self.start_time and self.end_time:
            return int((self.end_time - self.start_time).total_seconds() / 60)
        return None

    def to_dict(self) -> Dict:
        result = super().to_dict()
        result.update({
            "StartTime": self.start_time.isoformat() if self.start_time else None,
            "EndTime": self.end_time.isoformat() if self.end_time else None,
            "Status": self.status.value,
            "DurationMinutes": self.duration_minutes,
        })
        return result

    def validate(self) -> List[str]:
        warnings = []
        if not self.manifest and not self.manifest_script:
            warnings.append("No manifest URL or manifest script provided")
        if self.license_url and not self.drm_config:
            warnings.append("License URL provided but no DRM configuration")
        if self.start_time and self.end_time and self.start_time >= self.end_time:
            warnings.append("start_time must be before end_time")
        return warnings

    # Factory methods
    @classmethod
    def create_live_event(
        cls, name: str, event_id: str, provider: str, **kwargs
    ) -> "Event":
        return cls(
            name=name,
            content_id=event_id,
            provider=provider,
            status=EventStatus.LIVE,
            **kwargs,
        )

    @classmethod
    def create_scheduled_event(
        cls,
        name: str,
        event_id: str,
        provider: str,
        start_time: datetime,
        end_time: datetime,
        **kwargs,
    ) -> "Event":
        return cls(
            name=name,
            content_id=event_id,
            provider=provider,
            start_time=start_time,
            end_time=end_time,
            **kwargs,
        )