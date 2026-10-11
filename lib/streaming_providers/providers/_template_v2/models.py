# streaming_providers/providers/example/models.py
"""
Provider-local data models: plain dataclasses + from_api_response parsers.
No business logic, no network calls.

Parsing is STRICT on purpose (KeyError on missing required fields); the
manager parses entry-by-entry and skips malformed entries, so one bad
channel cannot take the whole list down.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ...base.models import Channel


@dataclass
class ExampleChannel:
    id: str
    name: str
    logo_url: Optional[str] = None

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "ExampleChannel":
        return cls(id=data["id"], name=data["name"], logo_url=data.get("logoUrl"))

    def to_channel(self, provider_name: str) -> Channel:
        # NOTE the factory parameter names: create_live_channel and
        # create_radio_channel take `channel_id`, create_vod_channel takes
        # `content_id`.
        channel = Channel.create_live_channel(
            name=self.name, channel_id=self.id, provider=provider_name
        )
        channel.logo_url = self.logo_url or ""
        channel.catchup_hours = 0   # set only when catchup is really offered
        return channel


@dataclass
class ExamplePlayout:
    """Response of the playout endpoint (manifest + optional DRM)."""

    stream_url: str
    stream_id: str
    license_url: Optional[str] = None      # None = clear stream

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "ExamplePlayout":
        stream = data.get("stream") if isinstance(data, dict) else None
        if not isinstance(stream, dict) or not stream.get("url") or not stream.get("id"):
            raise ValueError("playout response is missing stream.url / stream.id")
        return cls(
            stream_url=stream["url"],
            stream_id=stream["id"],
            license_url=stream.get("licenseUrl"),
        )
