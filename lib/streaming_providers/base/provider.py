# streaming_providers/base/provider.py
from abc import ABC, abstractmethod
from typing import Dict, List, Optional
import json
from datetime import datetime

from .models.streaming_channel import StreamingChannel
from .models.drm_models import DRMConfig

class StreamingProvider(ABC):
    """
    Abstract base class for streaming providers
    """

    def __init__(self, country: str = 'DE'):
        self.country = country
        self.channels: List[StreamingChannel] = []
        self._http_manager = None

    @property
    def http_manager(self):
        """
        Return the provider's HTTP manager instance

        Returns:
            HTTPManager instance if available, None otherwise
        """
        return getattr(self, '_http_manager', None)

    @http_manager.setter
    def http_manager(self, value):
        """
        Set the provider's HTTP manager instance

        Args:
            value: HTTPManager instance to set
        """
        self._http_manager = value

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'joyn', 'zdf', 'ard')"""
        pass

    @property
    @abstractmethod
    def provider_label(self) -> str:
        """Return the provider label (e.g., 'JOYN', 'ZDF', 'RTL+')"""
        pass


    @property
    @abstractmethod
    def uses_dynamic_manifests(self) -> bool:
        """
        Return True if provider uses truly dynamic manifests (timestamps, session-dependent)
        Return False if provider uses static manifests or manifests that can be fetched once
        """
        pass

    @abstractmethod
    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """
        Fetch channels from the provider

        Returns:
            List of StreamingChannel objects (may have empty manifests)
        """
        pass

#    def get_drm_configs(self, channel: StreamingChannel, **kwargs) -> List[DRMConfig]:
#        """
#        Get all DRM configurations for a channel

#        Args:
 #           channel: Channel to get DRM configs for
  #          **kwargs: Additional parameters

   #     Returns:
    #        List of DRMConfig objects (can be empty if no DRM is used)
     #   """
      #  return []

    @abstractmethod
    def get_drm(self, channel_id: str, **kwargs) -> List[DRMConfig]:
        """
        Get all DRM configurations for a channel by ID

        Args:
            channel_id: ID of the channel to get DRM configs for
            **kwargs: Additional parameters (e.g., country)

        Returns:
            List of DRMConfig objects (can be empty if no DRM is used)
        """
        return []
    
    def get_epg(self, channel_id: str,
               start_time: Optional[datetime] = None,
               end_time: Optional[datetime] = None,
               **kwargs) -> List[Dict]:
        """
        Get EPG data for a channel

        Args:
            channel_id: Channel ID to get EPG for
            start_time: Optional start time for EPG window
            end_time: Optional end time for EPG window
            **kwargs: Additional parameters

        Returns:
            List of EPG entries (each containing start/end times, title, description, etc.)
        """
        return []

    @staticmethod
    def get_epg_xmltv(self, **kwargs) -> Optional[str]:
        """
        Get complete EPG data for this provider in XMLTV format.
        
        This method should be implemented by concrete providers to return
        the entire EPG as a properly formatted XMLTV string.

        Args:
            **kwargs: Additional parameters (e.g., country, date range)

        Returns:
            XMLTV formatted string, or None if EPG is not available
        """
        return None  # Default implementation - providers can override

    @abstractmethod
    def enrich_channel_data(self, channel: StreamingChannel, **kwargs) -> Optional[StreamingChannel]:
        """
        Enrich channel with additional data including manifest URL and other info

        Args:
            channel: Channel to enrich
            **kwargs: Additional parameters

        Returns:
            The enriched StreamingChannel with manifest and additional info, or None if failed
        """
        return None

    @abstractmethod
    def get_manifest(self, channel_id: str, **kwargs) -> Optional[str]:
        """
        Get manifest URL for a specific channel by ID

        Args:
            channel_id: ID of the channel to get manifest for
            **kwargs: Additional parameters (e.g., country)

        Returns:
            Manifest URL string, or None if not available
        """
        return None

    def get_dynamic_manifest_params(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        """
        Optional: Get dynamic manifest parameters for a channel
        """
        return None

    def to_output_format(self, channels: List[StreamingChannel] = None) -> Dict:
        """Convert channels to output format"""
        if channels is None:
            channels = self.channels

        return {
            'Provider': self.provider_name,
            'Country': self.country,
            'Channels': [channel.to_dict() for channel in channels]
        }

    def to_json(self, channels: List[StreamingChannel] = None, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_output_format(channels), indent=indent, ensure_ascii=False)
