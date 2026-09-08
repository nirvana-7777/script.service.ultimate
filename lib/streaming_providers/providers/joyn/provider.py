# streaming_providers/providers/joyn/provider.py
# -*- coding: utf-8 -*-
"""
Joyn Provider - Pure Orchestrator
Wires together authentication, channel, and VOD managers
"""

from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional, Tuple, Union
from datetime import datetime
import dataclasses

from ...base.models import DRMConfig, StreamingChannel, Event, ContentType
from ...base.models.proxy_models import ProxyConfig
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from .auth import JoynAuthenticator
from .channel_manager import JoynChannelManager
from .vod_manager import JoynVodManager
from .epg_manager import JoynEpgManager
from .catchup_manager import JoynCatchupManager
from .constants import (
    DEFAULT_PLATFORM,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    JOYN_USER_AGENT,
    JOYN_LOGO,
    SUPPORTED_COUNTRIES,
    COUNTRY_TENANT_MAPPING,
    DEFAULT_EPG_WINDOW_HOURS,
)
from ...base.models.vod import VodCategory, VodItem


@dataclass
class JoynConfig:
    """Configuration dataclass for Joyn Provider"""
    country: str = "de"
    platform: str = DEFAULT_PLATFORM
    config_dir: Optional[str] = None
    proxy_config: Optional[ProxyConfig] = None
    proxy_url: Optional[str] = None
    timeout: int = DEFAULT_REQUEST_TIMEOUT
    max_retries: int = DEFAULT_MAX_RETRIES


class JoynProvider(StreamingProvider):
    """
    Joyn streaming provider - Pure orchestrator
    """

    PROVIDER_LABEL: ClassVar[str] = "Joyn"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = [
        "client_credentials",
        "user_credentials",
    ]
    PROVIDER_LOGO: ClassVar[str] = JOYN_LOGO
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = SUPPORTED_COUNTRIES

    def __init__(
            self,
            config: Optional[JoynConfig] = None,
            **kwargs,
    ):
        """
        Initialize Joyn provider

        Args:
            config: JoynConfig dataclass. If None, will construct from kwargs.
        """
        # Backward compatibility: construct config from kwargs if not provided
        if config is None:
            config = JoynConfig(**kwargs)

        if not self.validate_country(config.country):
            supported = ", ".join(self.SUPPORTED_COUNTRIES)
            raise ValueError(f"Unsupported country: {config.country}. Joyn supports: {supported}")

        super().__init__(country=config.country)

        self.config = config
        self.platform = config.platform
        self.distribution_tenant = COUNTRY_TENANT_MAPPING.get(config.country, "JOYN")

        # 1. SETUP HTTP MANAGER
        self.http_manager = self._setup_http_manager(
            provider_name="joyn",
            proxy_config=config.proxy_config,
            proxy_url=config.proxy_url,
            config_dir=config.config_dir,
            user_agent=JOYN_USER_AGENT,
            timeout=config.timeout,
            max_retries=config.max_retries,
        )

        # 2. SETUP AUTHENTICATION
        self.authenticator = JoynAuthenticator(
            country=config.country,
            platform=config.platform,
            config_dir=config.config_dir,
            http_manager=self.http_manager,
            proxy_config=self.http_manager.config.proxy_config,
        )

        # 3. SETUP MANAGERS
        self.channel_manager = JoynChannelManager(provider=self)
        self.vod_manager = JoynVodManager(provider=self)
        self.epg_manager = JoynEpgManager(provider=self)
        self.catchup_manager = JoynCatchupManager(provider=self)

        # Initial authentication
        try:
            self.bearer_token = self.authenticator.get_bearer_token()
        except Exception as e:
            logger.warning(f"Could not authenticate during initialization: {e}")
            self.bearer_token = None

    # ============================================================================
    # PROVIDER PROPERTIES
    # ============================================================================

    @property
    def provider_name(self) -> str:
        return "joyn"

    @property
    def provider_label(self) -> str:
        country_map = {
            "de": "Joyn Germany",
            "at": "Joyn Austria",
            "ch": "Joyn Switzerland",
        }
        return country_map.get(self.config.country, f"Joyn ({self.config.country.upper()})")

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    @property
    def implements_epg(self) -> bool:
        return self.epg_manager.implements_epg

    @property
    def epg_window(self) -> Tuple[int, int]:
        return self.epg_manager.epg_window

    @property
    def implements_vod(self) -> bool:
        return self.vod_manager.implements_vod

    @property
    def catchup_window(self) -> int:
        return self.catchup_manager.catchup_window

    @property
    def supports_catchup(self) -> bool:
        return self.catchup_manager.supports_catchup

    # ============================================================================
    # DELEGATED METHODS
    # ============================================================================

    def authenticate(self, **kwargs) -> str:
        self.bearer_token = self.authenticator.get_bearer_token(
            force_refresh=kwargs.get("force_refresh", False)
        )
        return self.bearer_token

    def refresh_authentication(self) -> str:
        self.bearer_token = self.authenticator.get_bearer_token(force_refresh=True)
        return self.bearer_token

    def get_channels(
            self,
            time_window_hours: int = DEFAULT_EPG_WINDOW_HOURS,
            fetch_manifests: bool = False,
            populate_streaming_data: bool = True,
            **kwargs,
    ) -> List[StreamingChannel]:
        return self.channel_manager.get_channels(
            time_window_hours=time_window_hours,
            fetch_manifests=fetch_manifests,
            populate_streaming_data=populate_streaming_data,
            **kwargs,
        )

    def get_events(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Event]:
        return self.epg_manager.get_events(start_time, end_time, **kwargs)

    def get_epg(
            self,
            channel_id: str,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List:
        return self.epg_manager.get_epg(channel_id, start_time, end_time, **kwargs)

    def get_epg_grid(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            channel_ids: Optional[List[str]] = None,
            **kwargs,
    ) -> Dict[str, List]:
        return self.epg_manager.get_epg_grid(start_time, end_time, channel_ids, **kwargs)

    def get_program_details(self, program_id: str, **kwargs) -> Optional[Dict]:
        return self.epg_manager.get_program_details(program_id, **kwargs)

    # ============================================================================
    # MANIFEST/PLAYBACK METHODS
    # ============================================================================

    def get_manifest(
            self,
            content_id: str,
            content_type: str = ContentType.LIVE,
            video_config: Optional[Dict] = None,
            **kwargs,
    ) -> Optional[str]:
        """
        Get manifest URL - routes to VOD or Channel manager based on content_id.
        Joyn VOD IDs contain an underscore (e.g., d_p203osk1gxp), Live IDs do not (e.g., sat1-de).
        """
        if "_" in content_id or content_type == ContentType.VOD:
            return self.vod_manager.get_vod_manifest(content_id, video_config, **kwargs)

        return self.channel_manager.get_manifest(
            content_id=content_id,
            content_type=content_type,
            video_config=video_config,
            **kwargs,
        )

    def get_manifest_headers(self, content_id: str, **kwargs) -> Dict[str, str]:
        """Get manifest headers"""
        return self.channel_manager.get_manifest_headers(content_id, **kwargs)

    def get_drm(
            self,
            content_id: str,
            content_type: str = ContentType.LIVE,
            video_config: Optional[Dict] = None,
            **kwargs,
    ) -> List[DRMConfig]:
        """
        Get DRM configurations - routes to VOD or Channel manager based on content_id.
        """
        if "_" in content_id or content_type == ContentType.VOD:
            return self.vod_manager.get_vod_drm(content_id, video_config, **kwargs)

        return self.channel_manager.get_drm(
            content_id=content_id,
            content_type=content_type,
            video_config=video_config,
            **kwargs,
        )

    def enrich_channel_data(
            self,
            channel: StreamingChannel,
            video_config: Optional[Dict] = None,
            **kwargs,
    ) -> Optional[StreamingChannel]:
        return self.channel_manager.enrich_channel_data(channel, video_config, **kwargs)

    def populate_streaming_data(
            self,
            channels: List[StreamingChannel],
            video_config: Optional[Dict] = None,
            max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> List[StreamingChannel]:
        return self.channel_manager.populate_streaming_data(channels, video_config, max_retries)

    def get_dynamic_manifest_params(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        return None

    def get_vod_category(self, content_id: str = "", **kwargs) -> List[Union[VodCategory, VodItem]]:
        return self.vod_manager.get_vod_category(content_id, **kwargs)

    def search_vod(
            self,
            query: str,
            cursor: Optional[str] = None,
            page_size: int = 24,
            **kwargs,
    ) -> Dict:
        return self.vod_manager.search(query, cursor, page_size, **kwargs)

    def get_vod_item_details(self, content_id: str, **kwargs) -> Optional[Dict]:
        item = self.vod_manager.get_content_details(content_id, **kwargs)
        if item:
            return dataclasses.asdict(item.to_vod_item(self.provider_name, self.config.country))
        return None

    def get_vod_manifest(
            self,
            content_id: str,
            video_config: Optional[Dict] = None,
            **kwargs,
    ) -> Optional[str]:
        return self.vod_manager.get_vod_manifest(content_id, video_config, **kwargs)

    def get_vod_drm(
            self,
            content_id: str,
            video_config: Optional[Dict] = None,
            **kwargs,
    ) -> List[DRMConfig]:
        return self.vod_manager.get_vod_drm(content_id, video_config, **kwargs)

    def get_vod_manifest_with_headers(
            self,
            content_id: str,
            video_config: Optional[Dict] = None,
            **kwargs,
    ) -> Tuple[Optional[str], Dict[str, str]]:
        return self.vod_manager.get_vod_manifest_with_headers(content_id, video_config, **kwargs)

    def to_output_format(self, channels: List[StreamingChannel] = None) -> Dict:
        if channels is None:
            channels = self.channel_manager.channels if self.channel_manager else []
        return {
            "Provider": self.provider_name,
            "Country": self.config.country,
            "Channels": [channel.to_dict() for channel in channels],
        }

    def to_json(self, channels: List[StreamingChannel] = None, indent: int = 2) -> str:
        import json
        return json.dumps(self.to_output_format(channels), indent=indent, ensure_ascii=False)