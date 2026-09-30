# streaming_providers/base/provider.py - Enhanced with Static Metadata
"""
Streaming Provider Base Class with Static Metadata Support

New Features:
- Class attributes for static metadata (PROVIDER_LABEL, etc.)
- Static methods to get metadata without instantiation
- Backward compatible with existing @property methods

Restructure note: this class used to hold every method itself (~90 methods,
~1900 lines). The capability areas — HTTP setup, auth, EPG, VOD, bookmarks,
recordings, timers, favorites, catchup, subscriptions, static metadata — have
been split into mixins under `provider_mixins/`, one file per area.
StreamingProvider composes all of them, so every existing method, property,
and signature is still available on it exactly as before; nothing that
imports `StreamingProvider` (or `AuthType`) from this module needs to change.
"""

import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Tuple

from ..providers.auth import AuthContext, AuthStatus  # noqa: F401  (re-exported for callers)
from .auth_type import AuthType  # noqa: F401  (re-exported for callers)
from .models import DRMConfig, Event, StreamingChannel
from .provider_mixins.auth import ProviderAuthMixin
from .provider_mixins.bookmarks import ProviderBookmarksMixin
from .provider_mixins.catchup import ProviderCatchupMixin
from .provider_mixins.epg import ProviderEpgMixin
from .provider_mixins.favorites import ProviderFavoritesMixin
from .provider_mixins.http import ProviderHttpMixin
from .provider_mixins.metadata import ProviderMetadataMixin
from .provider_mixins.recordings import ProviderRecordingsMixin
from .provider_mixins.subscriptions import ProviderSubscriptionsMixin
from .provider_mixins.timers import ProviderTimersMixin
from .provider_mixins.vod import ProviderVodMixin


class StreamingProvider(
    ABC,
    ProviderMetadataMixin,
    ProviderHttpMixin,
    ProviderAuthMixin,
    ProviderEpgMixin,
    ProviderVodMixin,
    ProviderBookmarksMixin,
    ProviderRecordingsMixin,
    ProviderTimersMixin,
    ProviderFavoritesMixin,
    ProviderCatchupMixin,
    ProviderSubscriptionsMixin,
):
    """
    Abstract base class for streaming providers with centralized HTTP and auth management
    """

    # Class attributes for static metadata (accessible without instantiation)
    PROVIDER_LABEL: ClassVar[str] = ""
    """Base provider label without country suffix (e.g., 'Joyn', 'RTL+')"""

    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = []
    """Authentication types supported by this provider"""

    PROVIDER_LOGO: ClassVar[str] = ""
    """URL to provider logo"""

    SUPPORTED_COUNTRIES: ClassVar[List[str]] = []
    """List of ISO country codes this provider supports (empty = single country)"""

    def __init__(self, country: str = "DE"):
        self.country = country
        self.channels: List[StreamingChannel] = []
        self._http_manager = None
        self._default_user_agent = "StreamingProvider/1.0"
        self.authenticator = None  # Optional: set by concrete providers

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'joyn', 'zdf', 'ard')"""
        pass

    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """Fetch channels from the provider"""
        return []

    def get_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kwargs,
    ) -> List[Event]:
        """
        Fetch one-time events (concerts, sports matches, etc.) from the provider.

        Args:
            start_time: Optional lower bound — only return events ending after this time.
            end_time: Optional upper bound — only return events starting before this time.
                      If neither is provided, the provider returns all known events
                      (both upcoming and currently live).

        Returns:
            List of Event objects, or empty list if provider has no events.
        """
        return []

    def get_drm(self, content_id: str, drm_variant: Optional[str] = None, **kwargs) -> List[DRMConfig]:
        """Get all DRM configurations for a channel by ID

        Args:
            content_id: Content identifier
            drm_variant: Optional DRM variant (e.g., 'auto', 'software')
            **kwargs: Additional provider-specific parameters
        """
        return []

    def enrich_channel_data(
        self, channel: StreamingChannel, **kwargs
    ) -> Optional[StreamingChannel]:
        """Optional: Enrich channel with additional data including manifest URL.
        Override in subclasses that need pre-fetching of manifests/DRM before playback."""
        return None

    @abstractmethod
    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        """Get manifest URL for a specific channel by ID"""
        return None

    def get_manifest_headers(self, content_id: str, **kwargs) -> Dict[str, str]:
        """
        Return headers for manifest requests.
        Override if provider requires specific headers.
        """
        return {}

    def get_segment_headers(self, content_id: str, **kwargs) -> Dict[str, str]:
        """
        Return headers for segment requests (used by proxy).
        Default implementation uses manifest headers.
        """
        return self.get_manifest_headers(content_id, **kwargs)

    def get_manifest_with_headers(self, content_id: str, **kwargs) -> Tuple[Optional[str], Dict[str, str]]:
        """
        Convenience method that returns (manifest_url, headers).
        Default implementation uses get_manifest() and get_manifest_headers().
        Providers can override if they need more complex logic.
        """
        url = self.get_manifest(content_id, **kwargs)
        headers = self.get_manifest_headers(content_id, **kwargs)
        return url, headers

    def get_dynamic_manifest_params(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        """Optional: Get dynamic manifest parameters for a channel"""
        return None

    def to_output_format(self, channels: List[StreamingChannel] = None) -> Dict:
        """Convert channels to output format"""
        if channels is None:
            channels = self.channels

        return {
            "Provider": self.provider_name,
            "Country": self.country,
            "Channels": [channel.to_dict() for channel in channels],
        }

    def to_json(self, channels: List[StreamingChannel] = None, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_output_format(channels), indent=indent, ensure_ascii=False)