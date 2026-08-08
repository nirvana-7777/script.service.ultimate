# streaming_providers/base/models/content.py
from dataclasses import dataclass
from typing import Dict, List, Optional

from .drm import DRMConfig


class StreamingMode:
    """Enum for streaming modes"""
    LIVE = "live"
    VOD = "vod"


class ContentType:
    """Enum for content types"""
    LIVE = "LIVE"
    VOD = "VOD"
    SERIES = "SERIES"
    MOVIE = "MOVIE"
    RADIO = "RADIO"


class Quality:
    """Enum for stream quality"""
    SD = "SD"
    HD = "HD"
    UHD = "UHD"
    FOUR_K = "4K"
    AUDIO = "AUDIO"


@dataclass
class Content:
    """
    Base dataclass for all provider content (channels, events, etc.)
    Contains all fields shared between content types.
    """

    # Core identification
    name: str
    content_id: str
    provider: str

    # Visual
    logo_url: Optional[str] = None

    # Streaming configuration
    mode: str = "live"
    session_manifest: bool = False
    manifest: Optional[str] = None
    manifest_script: Optional[str] = None

    # DRM/CDM settings
    cdm_type: Optional[str] = None
    use_cdm: bool = True
    cdm: Optional[str] = None
    cdm_mode: str = "external"
    drm_config: Optional[DRMConfig] = None

    # Video settings
    video: str = "best"
    on_demand: bool = True
    speed_up: bool = True

    # Metadata
    quality: Optional[str] = None
    content_type: str = "LIVE"
    description: Optional[str] = None
    genre: Optional[str] = None
    language: str = "de"
    country: str = "DE"

    # Streaming URLs
    license_url: Optional[str] = None
    certificate_url: Optional[str] = None
    streaming_format: Optional[str] = None

    def set_static_manifest(self, manifest_url: str) -> None:
        """Set a static manifest URL."""
        self.manifest = manifest_url
        self.session_manifest = False
        self.manifest_script = None

    def set_dynamic_manifest(self, manifest_script_params: str) -> None:
        """Set dynamic manifest parameters fetched at request time."""
        self.manifest = None
        self.session_manifest = True
        self.manifest_script = manifest_script_params

    def get_streaming_urls(self) -> List[str]:
        """Return all relevant URLs."""
        urls = []
        if self.manifest:
            urls.append(self.manifest)
        if self.license_url:
            urls.append(self.license_url)
        if self.certificate_url:
            urls.append(self.certificate_url)
        return urls

    def requires_drm(self) -> bool:
        return bool(self.drm_config) or bool(self.license_url)

    @property
    def dynamic_manifest(self) -> bool:
        return self.session_manifest

    @dynamic_manifest.setter
    def dynamic_manifest(self, value: bool):
        self.session_manifest = value

    @property
    def requires_session_manifest(self) -> bool:
        return self.session_manifest

    def to_dict(self) -> Dict:
        result = {
            "Name": self.name,
            "Id": self.content_id,
            "Provider": self.provider,
            "LogoUrl": self.logo_url,
            "Quality": self.quality,
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
            "ContentType": self.content_type,
            "Country": self.country,
            "Language": self.language,
            "StreamingFormat": self.streaming_format,
            "LicenseUrl": self.license_url,
            "CertificateUrl": self.certificate_url,
        }
        if self.drm_config:
            result["DrmConfig"] = self.drm_config.to_dict()
        return result