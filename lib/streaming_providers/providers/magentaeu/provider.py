# streaming_providers/providers/magentaeu/provider.py
# -*- coding: utf-8 -*-
import time
from typing import Dict, Optional, List

from ...base.auth import UserPasswordCredentials
from ...base.provider import StreamingProvider
from ...base.models import DRMConfig, LicenseConfig, DRMSystem
from ...base.models.streaming_channel import StreamingChannel
from ...base.network import ProxyConfigManager
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .auth import MagentaAuthenticator
from .constants import (
    SUPPORTED_COUNTRIES,
    DEFAULT_COUNTRY,
    USER_AGENT,
    API_ENDPOINTS,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DRM_SYSTEM_WIDEVINE,
    DRM_REQUEST_HEADERS,
    MAGENTA_TV_PL_LOGO,
    WV_URL,
    CONTENT_TYPE_LIVE,
    STREAMING_FORMAT_DASH,
    get_bifrost_url,
    get_natco_key,
    get_guest_headers,
    get_base_url,
    get_language, MAX_TV_LOGO
)


class MagentaProvider(StreamingProvider):
    def __init__(self, country: str = DEFAULT_COUNTRY,
                 config_dir: Optional[str] = None,
                 proxy_config: Optional[ProxyConfig] = None,
                 proxy_url: Optional[str] = None):

        logger.info(f"=== MagentaProvider.__init__ START for country: {country} ===")
        super().__init__(country=country)

        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"Unsupported country: {country}")

        # ✅ BEFORE: Complex proxy resolution logic (10+ lines)
        # self.proxy_config = (
        #     proxy_config or
        #     (ProxyConfig.from_url(proxy_url) if proxy_url else None) or
        #     self._load_proxy_from_manager(config_dir)
        # )
        #
        # self.http_manager = HTTPManagerFactory.create_for_provider(
        #     provider_name='magentaeu',
        #     proxy_config=self.proxy_config,
        #     user_agent=USER_AGENT,
        #     timeout=DEFAULT_REQUEST_TIMEOUT,
        #     max_retries=DEFAULT_MAX_RETRIES
        # )

        # ✅ AFTER: Using abstraction with automatic proxy resolution (6 lines)
        self.http_manager = self._setup_http_manager(
            provider_name='magentaeu',
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=USER_AGENT,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES
        )

        # Initialize attributes
        self._device_id = None
        self._session_id = None
        self.bearer_token = None
        self._channels_cache = None
        self._channels_cache_timestamp = 0
        self._cache_ttl = 3600

        # Create authenticator
        self.authenticator = MagentaAuthenticator(
            country=country,
            config_dir=config_dir,
            http_manager=self.http_manager,
            proxy_config=self.http_manager.config.proxy_config  # Use resolved proxy
        )

        logger.info(f"=== MagentaProvider.__init__ COMPLETE ===")

    def _load_proxy_from_manager(self, config_dir: Optional[str]) -> Optional[ProxyConfig]:
        """Load proxy configuration from ProxyConfigManager"""
        try:
            proxy_manager = ProxyConfigManager(config_dir)
            return proxy_manager.get_proxy_config('magentaeu', self.country)
        except Exception as e:
            logger.warning(f"Could not load proxy from ProxyConfigManager: {e}")
            return None

    @property
    def provider_name(self) -> str:
        return 'magentaeu'

    @property
    def provider_label(self) -> str:
        if self.country.lower() == 'hr':
            return "Max TV (HR)"
        else:
            return f'Magenta TV ({self.country.upper()})'

    @property
    def provider_logo(self) -> str:
        if self.country.lower() == 'hr':
            return MAX_TV_LOGO
        elif self.country.lower() == 'pl':
            return MAGENTA_TV_PL_LOGO
        else:
            return ''

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    def authenticate(self, **kwargs) -> str:
        logger.info(f"=== MagentaProvider.authenticate() CALLED with kwargs: {kwargs} ===")
        self.bearer_token = self.authenticator.get_bearer_token(force_refresh=kwargs.get('force_refresh', False))
        logger.info(f"=== MagentaProvider.authenticate() COMPLETE ===")
        return self.bearer_token

    def get_dynamic_manifest_params(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        return None

    def refresh_authentication(self) -> str:
        """Force refresh authentication"""
        self.bearer_token = self.authenticator.get_bearer_token(force_refresh=True)
        return self.bearer_token

    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """Fetch available channels from Magenta TV - no authentication required"""
        try:
            # USE AUTHENTICATOR'S SESSION IDs (single source of truth)
            device_id = self.authenticator.current_token.device_id if self.authenticator.current_token else ""
            session_id = self.authenticator.current_token.session_id if self.authenticator.current_token else ""

            channels_url = API_ENDPOINTS['EPG_CHANNELS'].format(
                bifrost_url=get_bifrost_url(self.country)
            )

            headers = get_guest_headers(self.country, device_id, session_id)

            params = {
                'channelMap_id': '',
                'includeVirtualChannels': 'true',
                'natco_key': get_natco_key(self.country),
                'app_language': get_language(self.country),
                'natco_code': self.country
            }

            logger.debug(f"Fetching channels with device_id: {device_id}, session_id: {session_id}")

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

            self._channels_cache = channels
            self._channels_cache_timestamp = time.time()

            logger.info(f"Successfully fetched {len(channels)} channels for country {self.country}")
            return channels

        except Exception as e:
            logger.error(f"Error fetching channels from Magenta TV: {e}")
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                logger.error(f"Response content: {e.response.text}")
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

            # Get DRM config (this requires authentication)
            drm_config = self.get_drm_config(channel)
            if drm_config:
                channel.drm_config = drm_config

            return channel

        except Exception as e:
            logger.warning(f"Error enriching channel data for {channel.name}: {e}")
            return None

    def get_manifest(self, channel_id: str, **kwargs) -> Optional[str]:
        if self._channels_cache:
            for channel in self._channels_cache:
                if channel.channel_id == channel_id:
                    return channel.manifest
        return None

    def get_drm(self, channel_id: str, **kwargs) -> List[DRMConfig]:
        """Get DRM configurations for channel by ID"""
        logger.info(f"=== get_drm_configs_by_id CALLED for channel_id: {channel_id} ===")

        # Find channel in cache
        channel = None
        if self._channels_cache:
            for cached_channel in self._channels_cache:
                if cached_channel.channel_id == channel_id:
                    channel = cached_channel
                    break

        if not channel:
            logger.warning(f"Channel with ID {channel_id} not found in cache")
            return []

        # Get DRM config using the existing method
        drm_config = self.get_drm_config(channel, **kwargs)
        return [drm_config] if drm_config else []

    def get_drm_configs(self, channel: StreamingChannel, **kwargs) -> List[DRMConfig]:
        """Get DRM configurations for channel"""
        logger.info(f"=== get_drm_configs CALLED for channel: {channel.name} ===")
        drm_config = self.get_drm_config(channel)
        return [drm_config] if drm_config else []

    def get_drm_config(self, channel: StreamingChannel, **kwargs) -> Optional[DRMConfig]:
        """Get DRM configuration for channel with correct authentication"""
        try:
            import json
            import base64
            from .auth import MagentaAuthToken, decode_jwt

            pid = channel.cdm.replace("pid=", "") if channel.cdm else ""
            logger.info(f"=== get_drm_config: Extracted PID: {pid} ===")

            if not pid:
                logger.debug(f"No PID found for channel {channel.name}")
                return None

            license_url = f"{WV_URL}{pid}"

            # Get access token (authenticate if needed)
            if not self.bearer_token:
                try:
                    self.authenticate()
                except Exception as e:
                    logger.warning(f"Authentication failed for DRM config: {e}")
                    return None

            access_token = self.bearer_token
            if not access_token:
                logger.warning("No bearer token available for DRM config")
                return None

            # Remove 'Bearer ' prefix if present
            if access_token.startswith('Bearer '):
                access_token = access_token[7:]

            # Decode JWT token to get account details
            try:
                # Get current token from authenticator
                current_token = self.authenticator.current_token

                # Use the helper method if token is MagentaAuthToken
                if isinstance(current_token, MagentaAuthToken) and hasattr(current_token, 'get_jwt_claims'):
                    decoded_payload = current_token.get_jwt_claims()
                    if not decoded_payload:
                        logger.warning("Failed to get JWT claims from token")
                        return None
                else:
                    # Fallback: use decode_jwt helper
                    decoded_payload = decode_jwt(access_token, verify=False)

            except Exception as e:
                logger.warning(f"Error decoding JWT token for DRM: {e}")
                return None

            # Extract account information from JWT payload
            account_id = decoded_payload.get('dc_cts_accountId', '')
            persona_token = decoded_payload.get('dc_cts_personaToken', '')

            if not account_id or not persona_token:
                logger.warning("Missing account ID or persona token in JWT payload")
                return None

            # Create reencoded session for Basic auth
            import base64
            reencoded_session = f"{get_base_url(self.country)}/{account_id}:{persona_token}"
            basic_auth = base64.b64encode(reencoded_session.encode()).decode()

            # Build license headers
            headers = {
                'Authorization': f'Basic {basic_auth}',
                'Content-Type': DRM_REQUEST_HEADERS.get('Content-Type', 'application/octet-stream'),
                'Origin': get_base_url(self.country),
                'Referer': f"{get_base_url(self.country)}/",
                'User-Agent': USER_AGENT
            }

            # Remove any None values from headers
            headers = {k: v for k, v in headers.items() if v is not None}

            # Create DRM configuration using LicenseConfig
            import json
            drm_config = DRMConfig(
                system=DRMSystem.WIDEVINE,
                priority=1,
                license=LicenseConfig(
                    server_url=license_url,
                    req_headers=json.dumps(headers),
                    req_data="{CHA-RAW}",
                    use_http_get_request=False
                )
            )

            logger.debug(f"DRM config created successfully for channel {channel.name}")
            return drm_config

        except Exception as e:
            logger.warning(f"Error creating DRM config for {channel.name}: {e}")
            return None

    def validate_credentials(self, credentials: UserPasswordCredentials) -> bool:
        """Validate Magenta TV credentials"""
        try:
            # Test authentication with provided credentials
            temp_authenticator = MagentaAuthenticator(
#                country=credentials.country,
                config_dir=self.authenticator.settings_manager.config_dir if hasattr(
                    self.authenticator.settings_manager, 'config_dir') else None,
                http_manager=self.http_manager,
                proxy_config=self.http_manager.config.proxy_config,
                credentials=credentials
            )

            token = temp_authenticator.get_bearer_token()
            return bool(token and len(token) > 0)

        except Exception as e:
            logger.debug(f"Credential validation failed: {e}")
            return False

    @staticmethod
    def get_supported_countries() -> List[str]:
        """Get list of supported countries"""
        return SUPPORTED_COUNTRIES.copy()