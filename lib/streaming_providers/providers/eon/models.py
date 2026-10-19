# streaming_providers/providers/eon/models.py
"""
Provider-local data models: plain dataclasses + from_api_response parsers.
No business logic, no network calls.

Parsing is STRICT on required fields (KeyError); the channel manager parses
entry by entry and skips malformed entries, so one bad channel cannot take
the whole list down. Optional fields tolerate null (the v4 payloads carry
`ageRating: null` and duplicate category ids).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ...base.models import Channel
from ...base.models.epg_models import EPGEntry, EPGFlags
from .constants import EonDefaults


def _int_or_zero(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# ----------------------------------------------------------------------
# Channels (v4/channels)
# ----------------------------------------------------------------------
@dataclass
class EonPublishingPoint:
    name: str
    profile_ids: List[int]
    sigs: Dict[str, str] = field(default_factory=dict)   # playerCfg type -> sig

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "EonPublishingPoint":
        sigs: Dict[str, str] = {}
        for cfg in data.get("playerCfgs") or []:
            if isinstance(cfg, dict) and cfg.get("type") and cfg.get("sig"):
                sigs[str(cfg["type"])] = str(cfg["sig"])
        return cls(
            name=data["publishingPoint"],
            profile_ids=[_int_or_zero(i) for i in data.get("profileIds") or []],
            sigs=sigs,
        )

    def sig_for(self, kind: str) -> Optional[str]:
        return self.sigs.get(kind)


@dataclass
class EonChannel:
    id: str
    name: str
    short_name: str
    subscribed: bool
    cutv_enabled: bool
    cutv_delay_ms: int
    aa_enabled: bool
    is_radio: bool
    publishing_points: List[EonPublishingPoint]
    logo_path: Optional[str] = None

    @classmethod
    def from_api_response(cls, data: Dict[str, Any], *, is_radio: bool = False) -> "EonChannel":
        return cls(
            id=str(data["id"]),
            name=data["name"],
            short_name=data.get("shortName") or data["name"],
            subscribed=bool(data.get("subscribed")),
            cutv_enabled=bool(data.get("cutvEnabled")),
            cutv_delay_ms=_int_or_zero(data.get("cutvDelay")),
            aa_enabled=bool(data.get("aaEnabled")),
            is_radio=is_radio,
            publishing_points=[
                EonPublishingPoint.from_api_response(p)
                for p in data.get("publishingPoint") or []
            ],
            logo_path=_pick_logo(data.get("images")),
        )

    @property
    def catchup_hours(self) -> int:
        if not self.cutv_enabled or self.cutv_delay_ms <= 0:
            return 0
        return self.cutv_delay_ms // 3_600_000

    def to_channel(
        self, provider_name: str, *, country: str, language: str,
        number: int, logo_url: Optional[str], short_names: bool,
    ) -> Channel:
        name = self.short_name if short_names else self.name
        # NOTE the factory parameter names: create_live_channel and
        # create_radio_channel take `channel_id`.
        factory = Channel.create_radio_channel if self.is_radio else Channel.create_live_channel
        channel = factory(name=name, channel_id=self.id, provider=provider_name)
        channel.logo_url = logo_url or ""
        channel.channel_number = number
        channel.catchup_hours = self.catchup_hours
        channel.country = country.upper()
        channel.language = language
        channel.streaming_format = "hls"
        return channel


def _pick_logo(images: Any) -> Optional[str]:
    """Largest LOGO_16_9_DARK, else the largest of any logo type."""
    if not isinstance(images, dict):
        return None
    for key in ("LOGO_16_9_DARK", *sorted(images)):
        variants = images.get(key)
        if isinstance(variants, list) and variants:
            best = max(
                (v for v in variants if isinstance(v, dict) and v.get("path")),
                key=lambda v: _int_or_zero(v.get("height")),
                default=None,
            )
            if best:
                return best["path"]
    return None


# ----------------------------------------------------------------------
# Catalog (v1/rndprofiles, v1/servers, v1/sp)
# ----------------------------------------------------------------------
@dataclass
class EonRenderingProfile:
    id: int
    name: str
    core_stream_id: str
    audio_bitrate: int
    video_bitrate: int

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "EonRenderingProfile":
        return cls(
            id=int(data["id"]),
            name=data.get("name") or "",
            core_stream_id=data["coreStreamId"],
            audio_bitrate=_int_or_zero(data.get("audioBitrate")),
            video_bitrate=_int_or_zero(data.get("videoBitrate")),
        )


@dataclass
class EonServer:
    id: str
    ip: str
    hostname: str

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "EonServer":
        server = cls(
            id=str(data.get("id") or ""),
            ip=data.get("ip") or "",
            hostname=data["hostname"],
        )
        return server


# ----------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------
@dataclass
class EonTokenResponse:
    """Response of oauth/token (any grant)."""

    access_token: str
    refresh_token: str = ""
    stream_key: str = ""
    stream_user: str = ""
    device_number: str = ""
    expires_in: Optional[float] = None

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "EonTokenResponse":
        if not isinstance(data, dict) or not data.get("access_token"):
            raise ValueError("token response is missing access_token")
        expires = data.get("expires_in")
        return cls(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token") or "",
            stream_key=data.get("stream_key") or "",
            stream_user=data.get("stream_un") or "",
            device_number=data.get("device_number") or "",
            expires_in=float(expires) if isinstance(expires, (int, float)) else None,
        )


@dataclass
class EonDeviceRegistration:
    device_id: str
    device_number: str

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "EonDeviceRegistration":
        if not isinstance(data, dict):
            raise ValueError("device response is not an object")
        device_id = _int_or_zero(data.get("deviceId"))
        number = data.get("deviceNumber") or ""
        if not device_id or not number:
            raise ValueError("device response is missing deviceId / deviceNumber")
        return cls(device_id=str(device_id), device_number=number)


# ----------------------------------------------------------------------
# EPG (v2/events/epg)
# ----------------------------------------------------------------------
@dataclass
class EonEpgEvent:
    id: str
    channel_id: Optional[str]
    title: str
    original_title: Optional[str]
    description: Optional[str]
    start: int                    # Unix seconds (the API sends ms)
    end: int
    age_rating: int
    live: bool
    season_number: int
    episode_number: int
    icon_path: Optional[str]

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "EonEpgEvent":
        icon = None
        for image in data.get("images") or []:
            if isinstance(image, dict) and image.get("size") == EonDefaults.EPG_ICON_SIZE and image.get("path"):
                icon = image["path"]
                break
        channel_id = data.get("channelId")
        return cls(
            id=str(data["id"]),
            channel_id=str(channel_id) if channel_id is not None else None,
            title=data["title"],
            original_title=data.get("originalTitle"),
            description=data.get("shortDescription"),
            start=int(data["startTime"]) // 1000,
            end=int(data["endTime"]) // 1000,
            age_rating=_int_or_zero(data.get("ageRating")),   # "6" (string) or null
            live=bool(data.get("liveBroadcast")),
            season_number=_int_or_zero(data.get("seasonNumber")),
            episode_number=_int_or_zero(data.get("episodeNumber")),
            icon_path=icon,
        )

    def to_entry(self, provider_name: str, channel_id: str, icon_url: Optional[str]) -> EPGEntry:
        flags = EPGFlags.UNDEFINED
        if self.live:
            flags |= EPGFlags.IS_LIVE
        if self.episode_number:
            flags |= EPGFlags.IS_SERIES
        return EPGEntry(
            broadcast_id=EPGEntry.encode_broadcast_id(provider_name, channel_id, self.start),
            title=self.title,
            start=self.start,
            end=self.end,
            # One id per broadcast -> program_id; epg_event_id stays None.
            program_id=self.id,
            description=self.description or None,
            original_title=self.original_title if self.original_title and self.original_title != self.title else None,
            icon=icon_url,
            season_number=self.season_number or None,
            episode_number=self.episode_number or None,
            parental_rating=self.age_rating or None,
            flags=flags,
        )