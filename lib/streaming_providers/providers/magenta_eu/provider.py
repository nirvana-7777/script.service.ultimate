# streaming_providers/providers/magenta_eu/provider.py
# -*- coding: utf-8 -*-
from typing import Dict, Optional, List
import json
import time
from datetime import datetime, timedelta

from ...base.provider import StreamingProvider
from ...base.models import DRMConfig, LicenseConfig, DRMSystem
from ...base.models.streaming_channel import StreamingChannel
from ...base.network import HTTPManagerFactory, ProxyConfigManager
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .auth import MagentaAuthenticator, MagentaCredentials
from .constants import (
    SUPPORTED_COUNTRIES,
    DEFAULT_COUNTRY,
    USER_AGENT,
    API_ENDPOINTS,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DRM_SYSTEM_WIDEVINE,
    DRM_REQUEST_HEADERS,
    WV_URL,
    CONTENT_TYPE_LIVE,
    STREAMING_FORMAT_DASH,
    get_base_url,
    get_bifrost_url,
    get_natco_key,
    get_app_key,
    get_language
)


class MagentaProvider(StreamingProvider):
    """Magenta TV streaming provider implementation"""

    def __init__(self, country: str = DEFAULT_COUNTRY,
                 config_dir: Optional[str] = None,
                 proxy_config: Optional[ProxyConfig] = None,
                 proxy_url: Optional[str] = None):
        """
        Initialize Magenta provider
        """
        super().__init__(country=country)

        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}")

        # Setup proxy configuration
        self.proxy_config = (
                proxy_config or
                (ProxyConfig.from_url(proxy_url) if proxy_url else None) or
                self._load_proxy_from_manager(config_dir)
        )

        if self.proxy_config:
            logger.info("Using proxy configuration for Magenta TV")
        else:
            logger.debug("No proxy configuration found for Magenta TV")

        # Create HTTP manager
        self.http_manager = HTTPManagerFactory.create_for_provider(
            provider_name='magenta_eu',
            proxy_config=self.proxy_config,
            user_agent=USER_AGENT,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES
        )

        # Create authenticator
        self.authenticator = MagentaAuthenticator(
            country=country,
            config_dir=config_dir,
            http_manager=self.http_manager,
            proxy_config=self.proxy_config
        )

        # Authenticate
        try:
            self.bearer_token = self.authenticator.get_bearer_token()
        except Exception as e:
            logger.warning(f"Could not authenticate during initialization: {e}")
            self.bearer_token = None

    def _load_proxy_from_manager(self, config_dir: Optional[str]) -> Optional[ProxyConfig]:
        """Load proxy configuration from ProxyConfigManager"""
        try:
            proxy_manager = ProxyConfigManager(config_dir)
            return proxy_manager.get_proxy_config('magenta_eu', self.country)
        except Exception as e:
            logger.warning(f"Could not load proxy from ProxyConfigManager: {e}")
            return None

    @property
    def provider_name(self) -> str:
        return 'magenta_eu'

    @property
    def provider_label(self) -> str:
        return f'Magenta TV ({self.country.upper()})'

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    def authenticate(self, **kwargs) -> str:
        """Authenticate and return bearer token"""
        self.bearer_token = self.authenticator.get_bearer_token(force_refresh=kwargs.get('force_refresh', False))
        return self.bearer_token

    def get_dynamic_manifest_params(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        return None

    def refresh_authentication(self) -> str:
        """Force refresh authentication"""
        self.bearer_token = self.authenticator.get_bearer_token(force_refresh=True)
        return self.bearer_token

    def fetch_channels(self, **kwargs) -> List[StreamingChannel]:
        """Fetch available channels from Magenta TV"""
        try:
            # Get user account to ensure we have channel map ID
            self.authenticator.get_user_account()

            channels_url = API_ENDPOINTS['EPG_CHANNELS'].format(
                bifrost_url=get_bifrost_url(self.country)
            )

            # Get channel map ID from authenticator
            channel_map_id = ""
            if (self.authenticator._current_token and
                    isinstance(self.authenticator._current_token,
                               self.authenticator.__class__.__bases__[0].MagentaAuthToken)):
                channel_map_id = self.authenticator._current_token.channel_map_id or ""

            params = {
                'channelMap_id': channel_map_id,
                'includeVirtualChannels': 'true',
                'natco_key': get_natco_key(self.country),
                'app_language': get_language(self.country),
                'natco_code': self.country
            }

            headers = self.authenticator._config.get_auth_headers(
                call_type="GUEST_USER",
                flow="START_UP",
                step="EPG_CHANNEL"
            )

            response = self.http_manager.get(
                channels_url,
                operation='channels',
                headers=headers,
                params=params,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            channels_data = response.json()
            channels = self._process_channels_response(channels_data)

            logger.info(f"Successfully fetched {len(channels)} channels for country {self.country}")
            return channels

        except Exception as e:
            raise Exception(f"Error fetching channels from Magenta TV: {e}")

    def _process_channels_response(self, response_data: Dict) -> List[StreamingChannel]:
        """Process channels response and convert to StreamingChannel objects"""
        if 'channels' not in response_data:
            raise Exception("Invalid channels response structure")

        channels = []
        for channel_data in response_data['channels']:
            try:
                # Extract channel information
                title = channel_data.get('title', 'Unknown Channel')
                logo = channel_data.get('channel_logo', '')
                manifest = channel_data.get('video_src_dash', '')
                pid = channel_data.get('pid_dash', '')
                station_id = channel_data.get('station_id', '')
                channel_number = channel_data.get('channel_number', '')
                media_pid = channel_data.get('media_pid', '')

                # Build manifest script
                manifest_script_parts = []
                if channel_number:
                    manifest_script_parts.append(f"chno={channel_number}")
                if station_id:
                    manifest_script_parts.append(f"epgid={station_id}")
                if media_pid:
                    manifest_script_parts.append(f"media={media_pid}")

                manifest_script = " ".join(manifest_script_parts) if manifest_script_parts else ""

                # Create streaming channel
                streaming_channel = StreamingChannel(
                    name=title,
                    channel_id=station_id or pid or title,
                    provider=self.provider_name,
                    logo_url=logo,
                    mode="live",
                    session_manifest=False,
                    manifest=manifest,
                    manifest_script=manifest_script,
                    cdm_type=DRM_SYSTEM_WIDEVINE,
                    use_cdm=True,
                    cdm=f"pid={pid}" if pid else "",
                    cdm_mode='external',
                    video='best',
                    on_demand=True,
                    speed_up=True,
                    content_type=CONTENT_TYPE_LIVE,
                    country=self.country.upper(),
                    language=get_language(self.country),
                    streaming_format=STREAMING_FORMAT_DASH
                )

                channels.append(streaming_channel)

            except Exception as e:
                logger.warning(f"Error processing channel data: {e}")

        return channels

    def enrich_channel_data(self, channel: StreamingChannel, **kwargs) -> Optional[StreamingChannel]:
        """
        Enrich channel with streaming data
        Magenta TV provides manifest URLs directly in channel data,
        so this mainly ensures DRM configuration is set up
        """
        try:
            if not channel.manifest:
                return None

            # Get DRM config
            drm_config = self.get_drm_config(channel)
            if drm_config:
                channel.drm_config = drm_config

            return channel

        except Exception as e:
            logger.warning(f"Error enriching channel data for {channel.name}: {e}")
            return None

    def get_manifest(self, channel_id: str, **kwargs) -> Optional[str]:
        """
        Get manifest URL for a specific channel by ID
        For Magenta TV, manifests are already provided in channel data
        """
        # Since manifests are provided directly in channel data,
        # this would need to fetch channel data again or use cached data
        return None

    def get_drm_configs(self, channel: StreamingChannel, **kwargs) -> List[DRMConfig]:
        """Get DRM configurations for channel"""
        drm_config = self.get_drm_config(channel)
        return [drm_config] if drm_config else []

    def get_drm_config(self, channel: StreamingChannel, **kwargs) -> Optional[DRMConfig]:
        """Get DRM configuration for channel"""
        try:
            pid = channel.cdm.replace("pid=", "") if channel.cdm else ""
            if not pid:
                return None

            license_url = f"{WV_URL}{pid}"

            headers = DRM_REQUEST_HEADERS.copy()
            headers.update({
                'Authorization': f'Bearer {self.bearer_token}',
                'Origin': get_base_url(self.country),
                'Referer': f"{get_base_url(self.country)}/",
            })

            return DRMConfig(
                system=DRMSystem.WIDEVINE,
                license_url=license_url,
                headers=headers,
                challenge_data=b'',
                session_id=str(int(time.time()))
            )

        except Exception as e:
            logger.warning(f"Error creating DRM config for {channel.name}: {e}")
            return None

    def validate_credentials(self, credentials: MagentaCredentials) -> bool:
        """Validate Magenta TV credentials"""
        try:
            # Test authentication with provided credentials
            temp_authenticator = MagentaAuthenticator(
                country=credentials.country,
                config_dir=self.authenticator.settings_manager.config_dir if hasattr(
                    self.authenticator.settings_manager, 'config_dir') else None,
                http_manager=self.http_manager,
                proxy_config=self.proxy_config,
                credentials=credentials
            )

            token = temp_authenticator.get_bearer_token()
            return bool(token and len(token) > 0)

        except Exception as e:
            logger.debug(f"Credential validation failed: {e}")
            return False

    def get_supported_countries(self) -> List[str]:
        """Get list of supported countries"""
        return SUPPORTED_COUNTRIES.copy()