# streaming_providers/base/models.py
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, List
import logging
from .drm_models import DRMConfig

# Setup logging for validation warnings
logger = logging.getLogger(__name__)


class StreamingMode(Enum):
    """Enum for streaming modes"""
    LIVE = "live"
    VOD = "vod"


class ContentType(Enum):
    """Enum for content types"""
    LIVE = "LIVE"
    VOD = "VOD"
    SERIES = "SERIES"
    MOVIE = "MOVIE"
    RADIO = "RADIO"


class Quality(Enum):
    """Enum for stream quality"""
    SD = "SD"
    HD = "HD"
    UHD = "UHD"
    FOUR_K = "4K"
    AUDIO = "AUDIO"


@dataclass
class StreamingChannel:
    """
    Universal channel representation for all providers

    Backward Compatibility Note:
    - All existing fields remain unchanged
    - New fields have default values
    - All existing methods remain functional
    """
    # Core identification
    name: str
    channel_id: str
    provider: str  # 'joyn', 'zdf', 'ard', etc.

    # Visual elements
    logo_url: Optional[str] = None

    # Channel metadata
    channel_number: Optional[int] = None  # Display channel number (e.g., 1, 3, 99)
    quality: Optional[str] = None  # 'SD', 'HD', 'UHD', '4K'

    # Streaming configuration
    mode: str = "live"  # "live" or "vod" - kept as string for compatibility
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

    # NEW: Radio support (backward compatible - defaults to False)
    is_radio: bool = False

    def __post_init__(self):
        """
        Post-initialization processing for backward compatibility
        and automatic field synchronization
        """
        # Run validation checks (warnings only for backward compatibility)
        self._validate_fields()

        # Auto-update content_type for radio
        if self.is_radio and self.content_type == 'LIVE':
            self.content_type = 'RADIO'
            self.quality = 'AUDIO'

    def _validate_fields(self):
        """
        Internal validation method that logs warnings instead of raising errors
        for backward compatibility
        """
        # Validate content_type consistency
        if self.mode == 'vod' and self.content_type == 'LIVE':
            logger.warning(
                f"Channel {self.name} ({self.channel_id}): "
                f"VOD mode with LIVE content_type - consider changing to VOD"
            )

        # Validate manifest consistency
        if self.session_manifest and self.manifest:
            logger.warning(
                f"Channel {self.name} ({self.channel_id}): "
                f"session_manifest=True but manifest URL is set - manifest will be ignored"
            )

    def to_dict(self) -> Dict:
        """Convert to dictionary format - backward compatible with new fields added"""
        result = {
            'Name': self.name,
            'Id': self.channel_id,
            'Provider': self.provider,
            'LogoUrl': self.logo_url,
            'ChannelNumber': self.channel_number,
            'Quality': self.quality,
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
            'StreamingFormat': self.streaming_format,
            # NEW: Radio fields (backward compatible addition)
            'IsRadio': self.is_radio,
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

    # NEW: Backward compatible enhancements

    @classmethod
    def create_live_channel(cls, name: str, channel_id: str, provider: str, **kwargs) -> 'StreamingChannel':
        """
        Factory method for live channels with proper defaults
        Backward compatible: Existing code can continue using direct instantiation
        """
        return cls(
            name=name,
            channel_id=channel_id,
            provider=provider,
            mode="live",
            content_type="LIVE",
            **kwargs
        )

    @classmethod
    def create_vod_channel(cls, name: str, content_id: str, provider: str, **kwargs) -> 'StreamingChannel':
        """
        Factory method for VOD content
        Backward compatible: Existing code can continue using direct instantiation
        """
        return cls(
            name=name,
            channel_id=content_id,
            provider=provider,
            mode="vod",
            content_type="VOD",
            **kwargs
        )

    @classmethod
    def create_radio_channel(cls, name: str, channel_id: str, provider: str, **kwargs) -> 'StreamingChannel':
        """
        Factory method for radio channels
        Backward compatible: Existing code can continue using direct instantiation
        """
        return cls(
            name=name,
            channel_id=channel_id,
            provider=provider,
            is_radio=True,
            content_type="RADIO",
            quality="AUDIO",
            **kwargs
        )

    def get_streaming_urls(self) -> List[str]:
        """
        Extract all relevant URLs for logging/validation
        New method - doesn't affect backward compatibility
        """
        urls = []
        if self.manifest:
            urls.append(self.manifest)
        if self.license_url:
            urls.append(self.license_url)
        if self.certificate_url:
            urls.append(self.certificate_url)
        return urls

    def requires_drm(self) -> bool:
        """
        Check if this channel needs DRM handling
        New method - doesn't affect backward compatibility
        """
        return bool(self.drm_config) or bool(self.license_url)

    def is_audio_content(self) -> bool:
        """
        Check if this is audio-only content (radio or audio track)
        New method - doesn't affect backward compatibility
        """
        return self.is_radio

    def detect_and_set_radio(self) -> None:
        """
        Auto-detect if this is likely a radio channel
        New method - doesn't affect backward compatibility
        """
        if self.is_radio:  # Already set
            return

        radio_indicators = [
            self.name.lower().startswith('radio'),
            'radio' in self.name.lower(),
            self.quality in ['audio', 'aac', 'mp3', 'AUDIO'],
            self.description and 'radio' in self.description.lower(),
            self.genre and 'radio' in self.genre.lower(),
        ]

        if any(radio_indicators):
            self.is_radio = True

            # Update quality if not set
            if not self.quality or self.quality.upper() not in [q.value for q in Quality]:
                self.quality = 'AUDIO'

            # Update content_type if it's still LIVE
            if self.content_type == 'LIVE':
                self.content_type = 'RADIO'

    # Compatibility properties (optional - for clearer naming)
    @property
    def dynamic_manifest(self) -> bool:
        """Alias for session_manifest with clearer name"""
        return self.session_manifest

    @dynamic_manifest.setter
    def dynamic_manifest(self, value: bool):
        """Setter for dynamic_manifest alias"""
        self.session_manifest = value

    @property
    def requires_session_manifest(self) -> bool:
        """Alternative property name for clarity"""
        return self.session_manifest

    def validate(self) -> List[str]:
        """
        Run comprehensive validation and return list of warnings/issues
        New method - doesn't affect backward compatibility
        """
        warnings = []

        # Check for missing required fields for streaming
        if not self.manifest and not self.manifest_script:
            warnings.append("No manifest URL or manifest script provided")

        # Check DRM configuration
        if self.license_url and not self.drm_config:
            warnings.append("License URL provided but no DRM configuration")

        # Check content type consistency
        if self.mode == 'vod' and self.content_type == 'LIVE':
            warnings.append("VOD mode should not have LIVE content_type")

        # Check radio consistency
        if self.is_radio and self.quality not in ['AUDIO', 'audio', None]:
            warnings.append(f"Radio channel has video quality setting: {self.quality}")

        return warnings