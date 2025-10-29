# streaming_providers/base/models.py
from dataclasses import dataclass
from typing import Dict, Optional
from .drm_models import DRMConfig

@dataclass
class StreamingChannel:
    """
    Universal channel representation for all providers
    """
    # Core identification
    name: str
    channel_id: str
    provider: str  # 'joyn', 'zdf', 'ard', etc.

    # Visual elements
    logo_url: Optional[str] = None

    # Streaming configuration
    mode: str = "live"  # "live" or "vod"
    session_manifest: bool = False
    manifest: Optional[str] = None
    manifest_script: Optional[str] = None

    # DRM/CDM settings
    cdm_type: Optional[str] = None
    use_cdm: bool = True
    cdm: Optional[str] = None
    cdm_mode: str = 'external'

    # DRM Configuration
    drm_config: Optional[DRMConfig] = None

    # Video settings
    video: str = 'best'
    on_demand: bool = True
    speed_up: bool = True

    # Additional metadata
    content_type: str = 'LIVE'
    description: Optional[str] = None
    genre: Optional[str] = None
    language: str = 'de'
    country: str = 'DE'

    # Streaming URLs
    license_url: Optional[str] = None
    certificate_url: Optional[str] = None
    streaming_format: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary format"""
        result = {
            'Name': self.name,
            'Id': self.channel_id,
            'Provider': self.provider,
            'LogoUrl': self.logo_url,
            'Mode': self.mode,
            'SessionManifest': self.session_manifest,
            'Manifest': self.manifest,
            'ManifestScript': self.manifest_script,
            'CdmType': self.cdm_type,
            'UseCdm': self.use_cdm,
            'Cdm': self.cdm,
            'CdmMode': self.cdm_mode,
            'Video': self.video,
            'OnDemand': self.on_demand,
            'SpeedUp': self.speed_up,
            'ContentType': self.content_type,
            'Country': self.country,
            'Language': self.language,
            'StreamingFormat': self.streaming_format
        }

        # Add DRM config if present
        if self.drm_config:
            result['DrmConfig'] = self.drm_config.to_dict()

        return result

    def set_static_manifest(self, manifest_url: str) -> None:
        """
        Set a static manifest URL (scenario 1: provider gives manifest directly)
        """
        self.manifest = manifest_url
        self.session_manifest = False
        self.manifest_script = None

    def set_dynamic_manifest(self, manifest_script_params: str) -> None:
        """
        Set dynamic manifest parameters (scenario 3: manifest needs to be fetched at request time)

        Args:
            manifest_script_params: Parameters needed to fetch manifest (e.g., channel_id, api_endpoint)
        """
        self.manifest = None
        self.session_manifest = True
        self.manifest_script = manifest_script_params
