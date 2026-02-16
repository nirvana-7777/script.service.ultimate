# streaming_providers/providers/discovery/models.py
"""
Discovery+ Provider Models

Data models for Discovery+ channels and content.
"""
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from ...base.models import StreamingChannel, DRMConfig, LicenseConfig

from .constants import StreamingMode, CDMMode, VideoQuality, DRMSystem


@dataclass
class DiscoveryChannel:
    """
    Represents a Discovery+ channel/stream with all necessary streaming data.

    This is a Discovery-specific model that can be converted to the generic
    StreamingChannel model via to_streaming_channel().
    """

    # Core identification
    name: str
    channel_id: str  # distributionChannel ID (first UUID)
    edit_id: Optional[str] = None  # edit ID (second UUID) - used for playback

    # Visual elements
    logo_url: Optional[str] = None

    # Channel metadata
    channel_number: Optional[int] = None
    quality: Optional[str] = None
    description: Optional[str] = None

    # Streaming configuration
    mode: str = StreamingMode.LIVE.value
    session_manifest: bool = True
    manifest: Optional[str] = None
    manifest_script: Optional[str] = None

    # CDM settings
    cdm_type: Optional[str] = None
    use_cdm: bool = True
    cdm: Optional[str] = None
    cdm_mode: str = CDMMode.EXTERNAL.value

    # Video settings
    video: str = VideoQuality.BEST.value
    on_demand: bool = True
    speed_up: bool = False

    # Additional metadata
    content_type: str = "LIVE"
    genre: Optional[str] = None
    language: str = "de"
    country: str = "DE"

    # Streaming data
    license_url: Optional[str] = None
    certificate_url: Optional[str] = None
    streaming_format: Optional[str] = None

    # Event data (for events/VOD)
    start_time: Optional[int] = None
    end_time: Optional[int] = None

    # Internal tracking - provider-specific data
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_distribution_data(
            cls,
            distribution_data: Dict[str, Any],
            included_by_id: Dict[str, Any]
    ) -> "DiscoveryChannel":
        """
        Create DiscoveryChannel from distributionChannel API response.

        Args:
            distribution_data: The channel data from API response.data
            included_by_id: Map of included resources keyed by "type:id"
                          for resolving relationships (images, edits, etc.)

        Returns:
            Initialized DiscoveryChannel with metadata and relationships resolved

    Example:
        The included_by_id dictionary should be built from the 'included'
        array in the API response using:

            included_by_id = {}
            for item in response.get('included', []):
                key = f"{item['type']}:{item['id']}"
                included_by_id[key] = item

        Then create a channel from the first distribution data item:

            channel = DiscoveryChannel.from_distribution_data(
                response['data'][0],
                included_by_id
            )
            print(channel.name)  # Output: Eurosport 1
        """
        attributes = distribution_data.get("attributes", {})
        relationships = distribution_data.get("relationships", {})

        # Get edit ID
        edit_data = relationships.get("edit", {}).get("data", {})
        edit_id = edit_data.get("id")

        # Extract logo
        logo_url = cls._extract_logo_url(relationships, included_by_id)

        return cls(
            name=attributes.get("name", "Unknown Channel"),
            channel_id=distribution_data.get("id", ""),
            edit_id=edit_id,
            logo_url=logo_url,
            description=attributes.get("description", ""),
            mode=StreamingMode.LIVE.value,
            session_manifest=True,
            manifest_script=f"editid={edit_id}" if edit_id else None,
            cdm=f"editid={edit_id}" if edit_id else None,
            raw_data=distribution_data.copy(),
        )

    @classmethod
    def from_event_api_data(
            cls,
            api_data: Dict[str, Any],
            included_by_id: Dict[str, Any],
            **kwargs: Any
    ) -> "DiscoveryChannel":
        """
        Create DiscoveryChannel from event/VOD API response data.

        Args:
            api_data: Event/VOD data from API response
            included_by_id: Map of included resources
            **kwargs: Additional parameters to override defaults

        Returns:
            Initialized DiscoveryChannel for VOD content
        """
        attributes = api_data.get("attributes", {})
        relationships = api_data.get("relationships", {})

        # Get edit ID (for VOD, the ID itself is often the edit_id)
        edit_id = api_data.get("id")

        # Extract logo
        logo_url = cls._extract_logo_url(relationships, included_by_id)

        channel = cls(
            name=attributes.get("name", "Unknown Event"),
            channel_id=api_data.get("id", ""),
            edit_id=edit_id,
            logo_url=logo_url,
            content_type="VOD",
            mode=StreamingMode.VOD.value,
            session_manifest=True,
            manifest_script=f"editid={edit_id}" if edit_id else None,
            cdm=f"editid={edit_id}" if edit_id else None,
            raw_data=api_data.copy(),
            **kwargs
        )

        # Set event timestamps if available
        if "scheduleStart" in attributes:
            channel.start_time = cls._parse_timestamp(attributes["scheduleStart"])
        if "scheduleEnd" in attributes:
            channel.end_time = cls._parse_timestamp(attributes["scheduleEnd"])

        return channel

    @staticmethod
    def _extract_logo_url(
            relationships: Dict[str, Any],
            included_by_id: Dict[str, Any]
    ) -> Optional[str]:
        """
        Extract logo URL from relationship data.

        Args:
            relationships: Relationship data from API response
            included_by_id: Map of included resources

        Returns:
            Logo URL or None if not found
        """
        images_data = relationships.get("images", {}).get("data", [])
        for image_ref in images_data:
            image_id = image_ref.get("id")
            image_type = image_ref.get("type")
            if image_id and image_type:
                key = f"{image_type}:{image_id}"
                image_item = included_by_id.get(key)
                if image_item:
                    img_attrs = image_item.get("attributes", {})
                    logo_url = (
                            img_attrs.get("src") or
                            img_attrs.get("url") or
                            img_attrs.get("secureUrl")
                    )
                    if logo_url:
                        return logo_url
        return None

    @staticmethod
    def _parse_timestamp(timestamp_str: str) -> Optional[int]:
        """
        Parse ISO 8601 timestamp to Unix timestamp.

        Args:
            timestamp_str: ISO 8601 timestamp string (e.g., "2024-01-15T20:00:00Z")

        Returns:
            Unix timestamp (seconds since epoch) or None if parsing fails
        """
        try:
            # Handle both Z and +00:00 formats
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return int(dt.timestamp())
        except (ValueError, TypeError, AttributeError):
            return None

    def set_streaming_data(
            self,
            manifest_url: str,
            license_url: Optional[str] = None,
            drm_token: Optional[str] = None,
            streaming_format: str = "dash",
    ) -> None:
        """
        Configure streaming-specific data.

        Args:
            manifest_url: Manifest URL for streaming
            license_url: License URL for DRM
            drm_token: DRM token for authorization
            streaming_format: Streaming format (e.g., 'dash')
        """
        self.manifest = manifest_url
        self.streaming_format = streaming_format

        if license_url:
            self.license_url = license_url
            self.cdm_type = DRMSystem.WIDEVINE.value
            if drm_token:
                self.raw_data["drm_token"] = drm_token

    def to_streaming_channel(self, provider_name: str = "discovery") -> "StreamingChannel":
        """
        Convert to generic StreamingChannel object.

        Args:
            provider_name: Provider identifier

        Returns:
            Generic StreamingChannel instance with all data transferred
        """
        from ...base.models import StreamingChannel, DRMConfig

        # Create DRM config if we have license URL
        drm_config = None
        if self.license_url:
            headers = {}
            if "drm_token" in self.raw_data:
                headers["Authorization"] = f"Bearer {self.raw_data['drm_token']}"

            drm_config = DRMConfig(
                system=DRMSystem.WIDEVINE,  # ✅ Use system field
                priority=1,
                license=LicenseConfig(
                    server_url=self.license_url,
                    req_headers=json.dumps(headers),
                    req_data="{CHA-RAW}",
                    use_http_get_request=False,
                ),
            )

        channel = StreamingChannel(
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
            drm_config=drm_config,
        )

        # Transfer raw_data
        channel.raw_data = self.raw_data.copy()

        # Store edit_id and timestamps in raw_data for later use
        if self.edit_id:
            channel.raw_data["edit_id"] = self.edit_id
        if self.start_time:
            channel.raw_data["start_time"] = self.start_time
        if self.end_time:
            channel.raw_data["end_time"] = self.end_time

        return channel

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format.

        Returns:
            Dictionary representation of the channel
        """
        return {
            "Name": self.name,
            "Id": self.channel_id,
            "EditId": self.edit_id,
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
            "ContentType": self.content_type,
            "Description": self.description,
            "Language": self.language,
            "Country": self.country,
            "StreamingFormat": self.streaming_format,
        }

    def __str__(self) -> str:
        return (
            f"DiscoveryChannel(name='{self.name}', id='{self.channel_id}', "
            f"edit_id='{self.edit_id}', type='{self.content_type}')"
        )

    def __repr__(self) -> str:
        return self.__str__()