# streaming_providers/base/models/channel.py
from dataclasses import dataclass
from typing import Dict, List, Optional

from .content import Content, Quality
from ..utils.logger import logger


@dataclass
class Channel(Content):
    """
    Represents a continuously available live channel or VOD stream.
    """

    channel_number: Optional[int] = None
    is_radio: bool = False

    def __post_init__(self):
        self._validate_fields()
        if self.is_radio and self.content_type == "LIVE":
            self.content_type = "RADIO"
            self.quality = "AUDIO"

    def _validate_fields(self):
        if self.mode == "vod" and self.content_type == "LIVE":
            logger.warning(
                f"Channel {self.name} ({self.content_id}): "
                f"VOD mode with LIVE content_type - consider changing to VOD"
            )
        if self.session_manifest and self.manifest:
            logger.warning(
                f"Channel {self.name} ({self.content_id}): "
                f"session_manifest=True but manifest URL is set - manifest will be ignored"
            )

    # Backward compatibility alias
    @property
    def channel_id(self) -> str:
        return self.content_id

    @channel_id.setter
    def channel_id(self, value: str):
        self.content_id = value

    def to_dict(self) -> Dict:
        result = super().to_dict()
        result["ChannelNumber"] = self.channel_number
        result["IsRadio"] = self.is_radio
        return result

    def is_audio_content(self) -> bool:
        return self.is_radio

    def detect_and_set_radio(self) -> None:
        if self.is_radio:
            return
        radio_indicators = [
            self.name.lower().startswith("radio"),
            "radio" in self.name.lower(),
            self.quality in ["audio", "aac", "mp3", "AUDIO"],
            self.description and "radio" in self.description.lower(),
            self.genre and "radio" in self.genre.lower(),
        ]
        if any(radio_indicators):
            self.is_radio = True
            if not self.quality or self.quality.upper() not in [q for q in vars(Quality).values() if isinstance(q, str)]:
                self.quality = "AUDIO"
            if self.content_type == "LIVE":
                self.content_type = "RADIO"

    def validate(self) -> List[str]:
        warnings = []
        if not self.manifest and not self.manifest_script:
            warnings.append("No manifest URL or manifest script provided")
        if self.license_url and not self.drm_config:
            warnings.append("License URL provided but no DRM configuration")
        if self.mode == "vod" and self.content_type == "LIVE":
            warnings.append("VOD mode should not have LIVE content_type")
        if self.is_radio and self.quality not in ["AUDIO", "audio", None]:
            warnings.append(f"Radio channel has video quality setting: {self.quality}")
        return warnings

    # Factory methods
    @classmethod
    def create_live_channel(
        cls, name: str, channel_id: str, provider: str, **kwargs
    ) -> "Channel":
        return cls(
            name=name,
            content_id=channel_id,
            provider=provider,
            mode="live",
            content_type="LIVE",
            **kwargs,
        )

    @classmethod
    def create_vod_channel(
        cls, name: str, content_id: str, provider: str, **kwargs
    ) -> "Channel":
        return cls(
            name=name,
            content_id=content_id,
            provider=provider,
            mode="vod",
            content_type="VOD",
            **kwargs,
        )

    @classmethod
    def create_radio_channel(
        cls, name: str, channel_id: str, provider: str, **kwargs
    ) -> "Channel":
        return cls(
            name=name,
            content_id=channel_id,
            provider=provider,
            is_radio=True,
            content_type="RADIO",
            quality="AUDIO",
            **kwargs,
        )


# Backward compatibility alias — all existing code using StreamingChannel continues to work
StreamingChannel = Channel