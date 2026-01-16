# streaming_providers/providers/joyn/models.py
import json
from dataclasses import dataclass, field
from typing import Dict, Optional

from ...base.models import StreamingChannel


class PlaybackRestrictedException(Exception):
    """
    Exception raised when content playback is restricted
    """

    pass


@dataclass
class JoynChannel:
    """
    Represents a Joyn channel with all necessary streaming data
    """

    # Core identification
    name: str
    channel_id: str

    # Visual elements
    logo_url: Optional[str] = None

    # Streaming configuration
    mode: str = "live"  # "live" or "vod"
    session_manifest: bool = False
    manifest: Optional[str] = None
    manifest_script: Optional[str] = None

    # CDM (Content Decryption Module) settings
    cdm_type: Optional[str] = None
    use_cdm: bool = True
    cdm: Optional[str] = None  # Usually "pid={pid}"
    cdm_mode: str = "external"

    # Video settings
    video: str = "best"
    on_demand: bool = True
    speed_up: bool = True

    # Additional metadata
    content_type: str = "LIVE"  # 'LIVE' or 'VOD'
    description: Optional[str] = None
    genre: Optional[str] = None
    language: str = "de"
    country: str = "DE"

    # Streaming data
    license_url: Optional[str] = None
    certificate_url: Optional[str] = None
    streaming_format: Optional[str] = None

    # Internal tracking
    raw_data: Dict = field(default_factory=dict)

    @classmethod
    def from_api_data(cls, api_data: Dict, **kwargs) -> "JoynChannel":
        """
        Create JoynChannel from API response data

        Args:
            api_data: Raw API response data
            **kwargs: Additional parameters to override defaults

        Returns:
            JoynChannel instance
        """
        channel = cls(
            name=api_data.get("title", "Unknown Channel"),
            channel_id=api_data.get("id", ""),
            content_type=api_data.get("type", "LIVE"),
            raw_data=api_data.copy(),
        )

        # Apply any additional parameters
        for key, value in kwargs.items():
            if hasattr(channel, key):
                setattr(channel, key, value)

        return channel

    def set_streaming_data(
        self,
        manifest: str,
        cdm_type: str = None,
        pid: str = None,
        license_url: str = None,
        certificate_url: str = None,
        streaming_format: str = None,
    ) -> None:
        """
        Configure streaming-specific data

        Args:
            manifest: Manifest URL for streaming
            cdm_type: Content decryption module type
            pid: Program ID for CDM
            license_url: License URL for DRM
            certificate_url: Certificate URL for DRM
            streaming_format: Streaming format (e.g., 'dash')
        """
        self.manifest = manifest

        if cdm_type:
            self.cdm_type = cdm_type

        if pid:
            self.cdm = f"pid={pid}"

        if license_url:
            self.license_url = license_url

        if certificate_url:
            self.certificate_url = certificate_url

        if streaming_format:
            self.streaming_format = streaming_format

    def set_logo(self, logo_url: str) -> None:
        """Set channel logo URL"""
        self.logo_url = logo_url

    def set_metadata(self, description: str = None, genre: str = None) -> None:
        """Set additional metadata"""
        if description:
            self.description = description
        if genre:
            self.genre = genre

    def is_live(self) -> bool:
        """Check if channel is live TV"""
        return self.content_type == "LIVE" and self.mode == "live"

    def is_vod(self) -> bool:
        """Check if channel is video on demand"""
        return self.content_type == "VOD" or self.mode == "vod"

    def to_streaming_channel(self, provider_name: str = "joyn") -> StreamingChannel:
        """
        Convert to generic StreamingChannel object

        Args:
            provider_name: Provider name to set

        Returns:
            StreamingChannel instance
        """
        return StreamingChannel(
            name=self.name,
            channel_id=self.channel_id,
            provider=provider_name,
            logo_url=self.logo_url,
            mode=self.mode,
            session_manifest=self.session_manifest,
            manifest=self.manifest,
            manifest_script=self.manifest_script,
            cdm_type=self.cdm_type,
            use_cdm=self.use_cdm,
            cdm=self.cdm,
            cdm_mode=self.cdm_mode,
            video=self.video,
            on_demand=self.on_demand,
            speed_up=self.speed_up,
            content_type=self.content_type,
            description=self.description,
            genre=self.genre,
            language=self.language,
            country=self.country,
            license_url=self.license_url,
            certificate_url=self.certificate_url,
            streaming_format=self.streaming_format,
        )

    def to_dict(self) -> Dict:
        """
        Convert to dictionary format matching your output specification

        Returns:
            Dictionary in the format expected by your application
        """
        return {
            "Name": self.name,
            "LogoUrl": self.logo_url,
            "Mode": self.mode,
            "SessionManifest": self.session_manifest,
            "Manifest": self.manifest,
            "ManifestScript": self.manifest_script,
            "CdmType": self.cdm_type,
            "UseCdm": self.use_cdm,
            "Cdm": self.cdm,
            "CdmMode": self.cdm_mode,
            "Video": self.video,
            "OnDemand": self.on_demand,
            "SpeedUp": self.speed_up,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def __str__(self) -> str:
        return (
            f"JoynChannel(name='{self.name}', id='{self.channel_id}', type='{self.content_type}')"
        )

    def __repr__(self) -> str:
        return self.__str__()
