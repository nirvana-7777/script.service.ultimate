# streaming_providers/providers/magenta2/provider.py
# -*- coding: utf-8 -*-
from typing import Dict, Optional, List, Any, Tuple
import json
import base64
import time
import uuid
import re
from datetime import datetime, timedelta

from ...base.provider import StreamingProvider
from ...base.models import DRMConfig, LicenseConfig, DRMSystem
from ...base.models.streaming_channel import StreamingChannel
from ...base.network import HTTPManagerFactory, ProxyConfigManager
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .models import Magenta2Channel, Magenta2PlaybackRestrictedException
from .auth import Magenta2Authenticator, Magenta2Credentials, Magenta2UserCredentials
from .discovery import DiscoveryService
from .endpoint_manager import EndpointManager
from .config_models import ProviderConfig
from .token_flow_manager import PersonaResult
from .constants import (
    SUPPORTED_COUNTRIES,
    DEFAULT_COUNTRY,
    DEFAULT_PLATFORM,
    MAGENTA2_PLATFORMS,
    MAGENTA2_CLIENT_IDS,
    CONTENT_TYPE_LIVE,
    CONTENT_TYPE_VOD,
    MODE_LIVE,
    MODE_VOD,
    DRM_SYSTEM_WIDEVINE,
    DRM_REQUEST_HEADERS,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_EPG_WINDOW_HOURS,
    ERROR_CODES, MAGENTA2_LOGO
)


class Magenta2Provider(StreamingProvider):
    """
    Magenta2 streaming provider implementation with enhanced dynamic discovery
    """

    def __init__(self, country: str = DEFAULT_COUNTRY,
                 platform: str = DEFAULT_PLATFORM,
                 config_dir: Optional[str] = None,
                 proxy_config: Optional[ProxyConfig] = None,
                 proxy_url: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None):
        """
        Initialize Magenta2 provider with enhanced discovery
        """
        super().__init__(country=country)

        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}")

        self.platform = platform
        self.platform_config = MAGENTA2_PLATFORMS.get(platform, MAGENTA2_PLATFORMS[DEFAULT_PLATFORM])
        self.terminal_type = self.platform_config['terminal_type']

        # Generate session ID and device ID
        self.session_id = self._generate_uuid()
        self.device_id = self._generate_device_id()

        # Setup proxy configuration
        self.proxy_config = (
                proxy_config or
                (ProxyConfig.from_url(proxy_url) if proxy_url else None) or
                self._load_proxy_from_manager(config_dir)
        )

        if self.proxy_config:
            logger.info("Using proxy configuration for Magenta2")
        else:
            logger.debug("No proxy configuration found for Magenta2")

        # Create HTTP manager
        self.http_manager = HTTPManagerFactory.create_for_provider(
            provider_name='magenta2',
            proxy_config=self.proxy_config,
            user_agent=self.platform_config['user_agent'],
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES
        )

        # Initialize discovery service
        self.discovery_service = DiscoveryService(
            platform=platform,
            terminal_type=self.terminal_type,
            device_id=self.device_id,
            session_id=self.session_id,
            http_manager=self.http_manager,
            proxy_config=self.proxy_config
        )

        # Initialize endpoint manager (will be populated after discovery)
        self.endpoint_manager: Optional[EndpointManager] = None
        self.provider_config: Optional[ProviderConfig] = None

        # 🚨 INITIALIZE AUTHENTICATOR FIRST (with minimal config)
        # Use fallback client IDs initially
        fallback_client_id = MAGENTA2_CLIENT_IDS.get(platform, MAGENTA2_CLIENT_IDS[DEFAULT_PLATFORM])

        if username and password:
            # Use user credentials for complete authentication flow
            credentials = Magenta2UserCredentials(
                client_id=fallback_client_id,  # Use fallback initially
                platform=platform,
                country=country,
                device_id=self.device_id,
                username=username,
                password=password
            )
            logger.info("Using user credentials for authentication")
        else:
            # Use client credentials for TAA-only flow
            credentials = Magenta2Credentials(
                client_id=fallback_client_id,  # Use fallback initially
                platform=platform,
                country=country,
                device_id=self.device_id
            )
            logger.info("Using client credentials for authentication")

        # Create authenticator with minimal configuration
        self.authenticator = Magenta2Authenticator(
            country=country,
            platform=platform,
            config_dir=config_dir,
            http_manager=self.http_manager,
            credentials=credentials,
            endpoints={},  # Empty initially, will be updated after discovery
            client_model=f"ftv-{platform}",  # Use fallback initially
            device_model=f"{platform.upper()}_FTV",  # Use fallback initially
            sam3_client_id=fallback_client_id,  # Use fallback initially
            session_id=self.session_id,
            device_id=self.device_id,
            provider_config=None
        )

        # 🚨 NOW PERFORM CONFIGURATION DISCOVERY (authenticator exists)
        try:
            self._perform_configuration_discovery()
        except Exception as e:
            logger.error(f"Configuration discovery failed: {e}")
            raise

        # 🚨 UPDATE AUTHENTICATOR WITH DISCOVERED CONFIG
        if self.provider_config:
            # Update authenticator with discovered client_id and models
            self.authenticator.provider_config = self.provider_config  # ✅ Store the config
            logger.info("✓ ProviderConfig stored in authenticator")

            # Also update TokenFlowManager if it exists
            if hasattr(self.authenticator, 'token_flow_manager') and self.authenticator.token_flow_manager:
                self.authenticator.token_flow_manager.provider_config = self.provider_config
                logger.info("✓ ProviderConfig also stored in TokenFlowManager")

            if self.provider_config.bootstrap.sam3_client_id:
                # Use public method if available, otherwise update directly
                if hasattr(self.authenticator, 'update_sam3_client_id'):
                    self.authenticator.update_sam3_client_id(self.provider_config.bootstrap.sam3_client_id)
                else:
                    self.authenticator._sam3_client_id = self.provider_config.bootstrap.sam3_client_id

                if self.authenticator.credentials:
                    self.authenticator.credentials.client_id = self.provider_config.bootstrap.sam3_client_id
                logger.debug(
                    f"Updated authenticator with SAM3 client ID: {self.provider_config.bootstrap.sam3_client_id}")

            if self.provider_config.bootstrap.client_model:
                if hasattr(self.authenticator, 'update_client_model'):
                    self.authenticator.update_client_model(self.provider_config.bootstrap.client_model)
                else:
                    self.authenticator._client_model = self.provider_config.bootstrap.client_model
                logger.debug(f"Updated authenticator with client model: {self.provider_config.bootstrap.client_model}")

            if self.provider_config.bootstrap.device_model:
                if hasattr(self.authenticator, 'update_device_model'):
                    self.authenticator.update_device_model(self.provider_config.bootstrap.device_model)
                else:
                    self.authenticator._device_model = self.provider_config.bootstrap.device_model
                logger.debug(f"Updated authenticator with device model: {self.provider_config.bootstrap.device_model}")

            # Update authenticator with device token and MPX account if available
            if self.provider_config.manifest:
                device_token = self.provider_config.get_device_token()
                authorize_tokens_url = self.provider_config.get_authorize_tokens_url()

                if device_token:
                    self.authenticator.set_device_token(device_token, authorize_tokens_url)
                    logger.debug("Device token configured in authenticator")

                # CRITICAL: Pass MPX account PID for account URI construction
                if self.provider_config.manifest.mpx.account_pid:
                    self.authenticator.set_mpx_account_pid(self.provider_config.manifest.mpx.account_pid)
                    logger.debug(f"MPX account PID configured: {self.provider_config.manifest.mpx.account_pid}")

                # Pass OpenID configuration if available
                if self.provider_config.openid:
                    self.authenticator.set_openid_config(self.provider_config.openid.raw_data)

            # Update authenticator with discovered endpoints using public methods
            if self.endpoint_manager:
                # Get all endpoints
                all_endpoints = {
                    name: info.url
                    for name, info in self.endpoint_manager.get_all_endpoints().items()
                }

                # Update authenticator with discovered endpoints using public method
                if hasattr(self.authenticator, 'update_dynamic_endpoints'):
                    self.authenticator.update_dynamic_endpoints(all_endpoints)
                    logger.info(f"✓ Updated authenticator with {len(all_endpoints)} endpoints")
                elif hasattr(self.authenticator, 'update_endpoints'):
                    self.authenticator.update_endpoints(all_endpoints)
                    logger.info(f"✓ Updated authenticator with {len(all_endpoints)} endpoints")
                else:
                    logger.warning("No public method available to update endpoints")

                # Specifically update SAM3 client with QR code URL
                qr_url = self.endpoint_manager.get_endpoint('login_qr_code')
                if qr_url and hasattr(self.authenticator, 'update_sam3_qr_code_url'):
                    success = self.authenticator.update_sam3_qr_code_url(qr_url)
                    if success:
                        logger.info("✓ Successfully updated SAM3 client with QR code URL")
                    else:
                        logger.warning("✗ Failed to update SAM3 client with QR code URL")

        # Initialize auth tokens (lazy - populated on first use)
        self.device_token = None
        self._persona_cache: Optional[PersonaResult] = None
        self._smil_cache: Dict[str, Tuple[float, Dict]] = {}  # channel_id -> (timestamp, smil_data)
        self._smil_cache_ttl = 3600

        logger.info("Magenta2 provider initialization completed successfully")

        logger.info("Magenta2 provider initialization completed successfully")

    @staticmethod
    def _generate_uuid() -> str:
        """Generate UUID for session"""
        return str(uuid.uuid4())

    @staticmethod
    def _generate_device_id() -> str:
        """Generate device ID"""
        return str(uuid.uuid4())

    @staticmethod
    def _generate_call_id() -> str:
        """Generate call ID for requests"""
        return str(uuid.uuid4())

    def _load_proxy_from_manager(self, config_dir: Optional[str]) -> Optional[ProxyConfig]:
        """Load proxy configuration from ProxyConfigManager"""
        try:
            proxy_manager = ProxyConfigManager(config_dir)
            return proxy_manager.get_proxy_config('magenta2', self.country)
        except Exception as e:
            logger.warning(f"Could not load proxy from ProxyConfigManager: {e}")
            return None

    def _perform_configuration_discovery(self) -> None:
        """
        Perform complete configuration discovery using discovery service
        """
        logger.info("Performing Magenta2 configuration discovery")

        try:
            # Perform discovery
            self.provider_config = self.discovery_service.discover_provider_config()

            if not self.provider_config or not self.provider_config.is_complete:
                logger.warning("Configuration discovery incomplete, some features may not work")

            # Initialize endpoint manager with discovered configuration
            self.endpoint_manager = EndpointManager(self.provider_config)

            # DEBUG: Check if QR code endpoint is discovered
            if self.endpoint_manager:
                qr_url = self.endpoint_manager.get_endpoint('login_qr_code')
                if qr_url:
                    logger.info(f"✓ QR code endpoint discovered in endpoint manager: {qr_url}")

                    # PROPER FIX: Use public method to update SAM3 client
                    if hasattr(self.authenticator, 'update_sam3_qr_code_url'):
                        success = self.authenticator.update_sam3_qr_code_url(qr_url)
                        if success:
                            logger.info("✓ Successfully updated SAM3 client with QR code URL")
                        else:
                            logger.warning("✗ Failed to update SAM3 client with QR code URL")

                    # Also debug the current status
                    if hasattr(self.authenticator, 'get_sam3_client_status'):
                        status = self.authenticator.get_sam3_client_status()
                        logger.debug(f"SAM3 client status after update: {status}")
                else:
                    logger.warning("✗ QR code endpoint NOT found in endpoint manager")

            if self.provider_config and self.provider_config.manifest:
                device_token = self.provider_config.get_device_token()
                authorize_tokens_url = self.provider_config.get_authorize_tokens_url()

                if device_token:
                    logger.info(f"✓ Device token discovered (length: {len(device_token)})")
                else:
                    logger.warning("⚠️ No device token found in manifest")

                if authorize_tokens_url:
                    logger.info(f"✓ Line auth endpoint discovered: {authorize_tokens_url}")
                else:
                    logger.warning("⚠️ No authorize tokens URL found in manifest")

                if self.provider_config.manifest.mpx.account_pid:
                    logger.info(f"✓ MPX account PID discovered: {self.provider_config.manifest.mpx.account_pid}")

            # Validate critical endpoints
            missing_endpoints = self.endpoint_manager.validate_critical_endpoints()
            if missing_endpoints:
                logger.warning(f"Missing critical endpoints: {missing_endpoints}")
            else:
                logger.info("All critical endpoints available")

            # Log discovery statistics
            stats = self.endpoint_manager.get_stats()
            logger.info(
                f"Discovery complete: {stats['dynamic_endpoints']} dynamic endpoints, "
                f"{stats['fallback_endpoints']} fallback endpoints, "
                f"complete: {stats['is_complete']}"
            )

        except Exception as e:
            logger.error(f"Configuration discovery failed: {e}")
            self._create_fallback_configuration()
            raise

    def _create_fallback_configuration(self) -> None:
        """Create fallback configuration when discovery fails"""
        logger.warning("Creating fallback configuration")

        from .config_models import BootstrapConfig, ProviderConfig

        bootstrap_config = BootstrapConfig(
            client_model=f"ftv-{self.platform}",
            device_model=f"{self.platform.upper()}_FTV"
        )

        self.provider_config = ProviderConfig(bootstrap=bootstrap_config)
        self.endpoint_manager = EndpointManager(self.provider_config)

        logger.info("Fallback configuration created")

    def _get_dcm_headers(self) -> Dict[str, str]:
        """Get headers for DCM requests"""
        return {
            'User-Agent': self.platform_config['user_agent'],
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'x-dt-session-id': self.session_id,
            'x-dt-call-id': self._generate_call_id()
        }

    def _get_api_headers(self, require_auth: bool = False) -> Dict[str, str]:
        """Get headers for API requests"""
        headers = {
            'User-Agent': self.platform_config['user_agent'],
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        if require_auth:
            persona_token = self._ensure_authenticated()
            headers['Authorization'] = f'Basic {persona_token}'

        return headers

    @property
    def provider_name(self) -> str:
        return 'magenta2'

    @property
    def provider_label(self) -> str:
        return 'Magenta TV 2.0'

    @property
    def provider_logo(self) -> str:
        return MAGENTA2_LOGO

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    def get_discovery_status(self) -> Dict[str, Any]:
        """Get discovery and configuration status"""
        if not self.discovery_service:
            return {'error': 'Discovery service not initialized'}

        status = self.discovery_service.get_discovery_status()

        if self.endpoint_manager:
            status['endpoints'] = self.endpoint_manager.get_stats()

        return status

    def refresh_configuration(self, force: bool = False) -> bool:
        """
        Refresh provider configuration

        Args:
            force: Force refresh even if cache is valid

        Returns:
            bool: True if refresh successful
        """
        try:
            logger.info("Refreshing provider configuration")

            new_config = self.discovery_service.discover_provider_config(force_refresh=force)

            if new_config and new_config.is_complete:
                self.provider_config = new_config
                self.endpoint_manager = EndpointManager(new_config)

                # Update authenticator with new config
                if new_config.manifest:
                    device_token = new_config.manifest.raw_data.get('deviceToken')
                    authorize_tokens_url = new_config.manifest.raw_data.get('authorizeTokensUrl')
                    if device_token:
                        self.authenticator.set_device_token(device_token, authorize_tokens_url)

                    if new_config.manifest.mpx.account_pid:
                        self.authenticator.set_mpx_account_pid(new_config.manifest.mpx.account_pid)

                logger.info("Configuration refresh successful")
                return True
            else:
                logger.warning("Configuration refresh incomplete")
                return False

        except Exception as e:
            logger.error(f"Configuration refresh failed: {e}")
            return False

    def register_device(self) -> bool:
        """
        Perform device registration and authentication
        Useful for initial setup or device token refresh
        """
        try:
            logger.info("Performing device registration")

            if not self.authenticator:
                logger.error("Authenticator not available for device registration")
                return False

            # PROPER: Use public method instead of checking protected attribute
            if hasattr(self.authenticator, 'perform_device_authentication'):
                success = self.authenticator.perform_device_authentication()
                if success:
                    logger.info("✓ Device registration successful")
                    return True
                else:
                    logger.warning("Device registration failed")
                    return False
            else:
                logger.warning("Device authentication not supported in current authenticator")
                return False

        except Exception as e:
            logger.error(f"Device registration failed: {e}")
            return False

    def get_persona_token(self, force_refresh: bool = False) -> str:
        """Get persona token with accurate expiry-based caching"""
        # Check in-memory cache first
        if not force_refresh and self._persona_cache and self._persona_cache.success:
            current_time = time.time()
            # Check if cached token is still valid (with 1-minute buffer)
            if current_time < (self._persona_cache.expires_at - 60):
                logger.debug(f"Using in-memory cached persona token (expires at {time.ctime(self._persona_cache.expires_at)})")
                return self._persona_cache.persona_token
            else:
                # Cache expired
                self._persona_cache = None
                logger.debug("In-memory persona cache expired")

        # Get from TokenFlowManager (now returns PersonaResult with expiry)
        persona_result = self.authenticator.token_flow_manager.get_persona_token(
            force_refresh=force_refresh
        )

        if not persona_result.success:
            raise Exception(f"Failed to get persona token: {persona_result.error}")

        # Cache the entire PersonaResult with expiry
        self._persona_cache = persona_result
        logger.debug(f"Cached persona token in memory (expires at {time.ctime(persona_result.expires_at)})")

        return persona_result.persona_token

    def _ensure_authenticated(self) -> str:
        """Ensure we have a valid persona token with accurate caching"""
        return self.get_persona_token(force_refresh=False)

    def clear_persona_cache(self):
        """Clear in-memory persona cache"""
        self._persona_cache = None
        logger.debug("Cleared in-memory persona cache")

    def get_dynamic_manifest_params(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        return None

    @staticmethod
    def _extract_channel_id_from_entry(entry: Dict) -> Optional[str]:
        """Extract the correct channel ID from era$mediaPids"""
        try:
            stations = entry.get('stations', {})
            if not stations:
                return None

            # Get the first station
            station_id = next(iter(stations.keys()))
            station_info = stations[station_id]

            # Extract from era$mediaPids (this is the correct ID for API calls)
            era_media_pids = station_info.get('era$mediaPids', {})
            channel_id = era_media_pids.get('urn:theplatform:tv:location:any')

            if channel_id:
                logger.debug(f"Extracted channel ID from era$mediaPids: {channel_id}")
                return channel_id

            # Fallback to guid if era$mediaPids not available
            fallback_id = entry.get('guid')
            if fallback_id:
                logger.warning(f"Using fallback channel ID from guid: {fallback_id}")
                return fallback_id

            logger.warning("No channel ID found in entry")
            return None

        except Exception as e:
            logger.warning(f"Error extracting channel ID from entry: {e}")
            return None

    def _build_scaled_image_url(self, original_url: str) -> Optional[str]:
        """Build scaled image URL using image scaling service"""
        if not original_url:
            return None

        if not self.provider_config or not self.provider_config.manifest:
            return original_url  # Fallback to original URL

        image_config = self.provider_config.manifest.image_config

        # Check if we have the required scaling parameters
        if not image_config.scaling_base_url or not image_config.scaling_call_parameter:
            return original_url

        # Parse the call parameter (e.g., "client=ftp22")
        call_params = {}
        for param in image_config.scaling_call_parameter.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                call_params[key] = value

        # Build the scaling URL
        base_url = image_config.scaling_base_url.rstrip('/')

        # Add required parameters
        params = {
            **call_params,  # client=ftp22
            'x': '120',
            'y': '42',
            'ar': 'keep',  # aspect ratio
            'src': original_url  # original image URL
        }

        # Build query string
        query_string = '&'.join([f"{k}={self._url_encode(v)}" for k, v in params.items()])

        return f"{base_url}/iss?{query_string}"

    def _process_channel_stations_response_optimized(
            self,
            response_data: Dict,
            prefer_highest_quality: bool = True
    ) -> List[StreamingChannel]:
        """Ultra-optimized single-pass processing"""

        if 'entries' not in response_data:
            return []

        quality_rank = {'SD': 1, 'HD': 2, 'UHD': 3, '4K': 3}
        best_entries = {}
        channels = []

        for entry in response_data['entries']:
            try:
                stations = entry.get('stations', {})
                if not stations:
                    continue

                station_info = next(iter(stations.values()))
                display_number = entry.get('dt$displayChannelNumber')

                if display_number is None:
                    # Process immediately if no number (no filtering needed)
                    channel = self._create_channel_from_entry(entry, station_info, display_number)
                    if channel:
                        channels.append(channel)
                    continue

                # Extract quality for comparison
                quality = station_info.get('dt$quality', 'SD')
                current_rank = quality_rank.get(quality, 1)

                # Check if we need to replace existing entry
                existing = best_entries.get(display_number)
                if not existing:
                    best_entries[display_number] = (entry, station_info, current_rank)
                else:
                    _, _, existing_rank = existing
                    if (prefer_highest_quality and current_rank > existing_rank) or \
                            (not prefer_highest_quality and current_rank < existing_rank):
                        best_entries[display_number] = (entry, station_info, current_rank)

            except Exception:
                continue

        # Convert best entries to channels
        for display_number, (entry, station_info, _) in best_entries.items():
            channel = self._create_channel_from_entry(entry, station_info, display_number)
            if channel:
                channels.append(channel)

        return channels

    def _create_channel_from_entry(self, entry, station_info, display_number):
        """Helper to create StreamingChannel from entry data"""
        try:
            title = station_info.get('title') or entry.get('title', 'Unknown Channel')
            title = title.replace(" - Main", "")

            channel_id = self._extract_channel_id_from_entry(entry)
            if not channel_id:
                return None

            # Logo processing
            logo_url = None
            thumbnails = station_info.get('thumbnails', {})
            for logo_type in ['stationLogo', 'stationLogoColored']:
                if logo_type in thumbnails:
                    original_url = thumbnails[logo_type].get('url')
                    if original_url:
                        logo_url = self._build_scaled_image_url(original_url)
                        break

            magenta2_channel = Magenta2Channel(
                name=title,
                channel_id=channel_id,
                logo_url=logo_url,
                mode=MODE_LIVE,
                content_type=CONTENT_TYPE_LIVE,
                country=self.country,
                raw_data=entry
            )

            streaming_channel = magenta2_channel.to_streaming_channel(
                provider_name=self.provider_name
            )
            streaming_channel.channel_number = display_number
            streaming_channel.quality = station_info.get('dt$quality', 'SD')

            return streaming_channel

        except Exception as e:
            logger.warning(f"Error creating channel from entry: {e}")
            return None

    def get_channels(self,
                       time_window_hours: int = DEFAULT_EPG_WINDOW_HOURS,
                       fetch_manifests: bool = False,
                       populate_streaming_data: bool = True,
                       prefer_highest_quality: bool = True,
                       **kwargs) -> List[StreamingChannel]:
        """
        Fetch available channels from Magenta2 API
        """
        try:
            headers = self._get_api_headers(require_auth=False)

            # Use the discovered channel stations endpoint
            url = None
            if self.endpoint_manager:
                url = self.endpoint_manager.get_endpoint('channel_stations')
                if not url:
                    url = self.endpoint_manager.get_endpoint('channel_list')
                if not url and self.endpoint_manager.has_endpoint('mpx_feed_entitledChannelsFeed'):
                    url = self.endpoint_manager.get_endpoint('mpx_feed_entitledChannelsFeed')

            # Final fallback
            if not url:
                url = "https://feed.entertainment.tv.theplatform.eu/f/mdeprod/mdeprod-channel-stations-main"

            url += "?lang=short-de&sort=dt%24displayChannelNumber&range=1-1000"

            logger.debug(f"Fetching channels from: {url}")
            response = self.http_manager.get(
                url,
                operation='api',
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            channels_data = response.json()

            # ✅ USE OPTIMIZED SINGLE-PASS PROCESSING
            channels = self._process_channel_stations_response_optimized(channels_data, prefer_highest_quality)

            logger.info(
                f"Successfully fetched {len(channels)} channels for country {self.country} "
                f"(quality preference: {'highest' if prefer_highest_quality else 'lowest'})"
            )
            return channels

        except Exception as e:
            raise Exception(f"Error fetching channels from Magenta2 API: {e}")

    def _get_channels_from_mpx_feeds(self) -> List[StreamingChannel]:
        """Get channels from MPX feeds discovered in manifest"""
        try:
            if not self.endpoint_manager:
                return []

            entitled_channels_url = self.endpoint_manager.get_endpoint('mpx_feed_entitledChannelsFeed')
            if not entitled_channels_url:
                return []

            self._ensure_authenticated()

            headers = self._get_api_headers(require_auth=True)
            response = self.http_manager.get(
                entitled_channels_url,
                operation='mpx_feed',
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            feed_data = response.json()
            return self._parse_mpx_feed_response(feed_data)

        except Exception as e:
            logger.warning(f"Failed to get channels from MPX feed: {e}")
            return []

    def _parse_mpx_feed_response(self, feed_data: Dict) -> List[StreamingChannel]:
        """Parse MPX feed response into channels"""
        channels = []
        entries = feed_data.get('entries', [])

        for entry in entries:
            try:
                title = entry.get('title', 'Unknown')
                channel_id = entry.get('guid', '').split('/')[-1] if entry.get('guid') else ''

                if not channel_id:
                    continue

                channel = Magenta2Channel(
                    name=title,
                    channel_id=channel_id,
                    content_type=CONTENT_TYPE_LIVE,
                    country=self.country,
                    raw_data=entry
                )

                streaming_channel = channel.to_streaming_channel(
                    provider_name=self.provider_name
                )
                channels.append(streaming_channel)

            except Exception as e:
                logger.warning(f"Error parsing MPX channel entry: {e}")

        return channels

    def _process_channels_response(self, response_data: Dict) -> List[StreamingChannel]:
        """Process API response and convert to StreamingChannel objects"""
        channels = []

        if isinstance(response_data, list):
            channel_list = response_data
        elif isinstance(response_data, dict):
            if 'channels' in response_data:
                channel_list = response_data['channels']
            elif 'data' in response_data:
                channel_list = response_data['data']
            else:
                channel_list = [response_data]
        else:
            logger.warning("Unexpected channel response format")
            return channels

        for channel_data in channel_list:
            try:
                channel_id = channel_data.get('id', channel_data.get('channelId', ''))
                if not channel_id:
                    logger.warning("Channel missing ID, skipping")
                    continue

                title = channel_data.get('title', channel_data.get('name', 'Unknown Channel'))
                stream_type = channel_data.get('type', 'LIVE')
                quality = channel_data.get('quality', '')

                logo_url = None
                if 'logo' in channel_data:
                    if isinstance(channel_data['logo'], dict) and 'url' in channel_data['logo']:
                        logo_url = channel_data['logo']['url']
                    elif isinstance(channel_data['logo'], str):
                        logo_url = channel_data['logo']
                elif 'image' in channel_data:
                    logo_url = channel_data['image']

                content_type = CONTENT_TYPE_LIVE if stream_type.upper() == 'LIVE' else CONTENT_TYPE_VOD
                mode = MODE_LIVE if stream_type.upper() == 'LIVE' else MODE_VOD

                magenta2_channel = Magenta2Channel(
                    name=title,
                    channel_id=channel_id,
                    logo_url=logo_url,
                    mode=mode,
                    content_type=content_type,
                    country=self.country,
                    raw_data=channel_data
                )

                if quality:
                    magenta2_channel.name = f"{title} ({quality})"

                streaming_channel = magenta2_channel.to_streaming_channel(
                    provider_name=self.provider_name
                )
                channels.append(streaming_channel)

            except Exception as e:
                logger.warning(f"Error processing channel data: {e}")

        return channels

    def get_entitlement_token(self, content_id: str, content_type: str = CONTENT_TYPE_LIVE) -> str:
        """
        Get entitlement token using persona_token Basic auth
        """
        # Ensure we're authenticated with persona token
        self._ensure_authenticated()

        # Use persona token (Basic auth) for entitlement
        headers = self._get_api_headers(require_auth=True)

        payload = {
            "content_id": content_id,
            "content_type": content_type
        }

        url = self.endpoint_manager.get_endpoint(
            'entitlement') if self.endpoint_manager else 'https://entitlement.p7s1.io/api/user/entitlement-token'

        try:
            logger.debug(f"Requesting entitlement token with persona token for: {content_id}")
            response = self.http_manager.post(
                url,
                operation='auth',
                headers=headers,
                json_data=payload,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )

            if response.status_code == 400:
                try:
                    error_data = response.json()
                    error_list = error_data if isinstance(error_data, list) else [error_data]

                    if len(error_list) > 0:
                        error = error_list[0]
                        code = error.get("code", error.get("errorCode", "UNKNOWN"))
                        msg = error.get("msg", error.get("message", "No error message provided"))

                        if code == ERROR_CODES['PLAYBACK_RESTRICTED']:
                            raise Magenta2PlaybackRestrictedException(f"Playback restricted for {content_id}: {msg}")
                        else:
                            raise Exception(f"Entitlement error for {content_id} ({code}): {msg}")
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    raise Exception(f"Bad response for {content_id} (400), failed to parse error: {e}")

            response.raise_for_status()
            data = response.json()

            if 'entitlement_token' in data:
                return data['entitlement_token']
            elif 'entitlementToken' in data:
                return data['entitlementToken']
            elif 'token' in data:
                return data['token']
            else:
                raise KeyError("No entitlement token found in response")

        except Magenta2PlaybackRestrictedException:
            raise
        except KeyError as e:
            logger.error(f"No entitlement token in response for {content_id}: {e}")
            logger.debug(f"Auth state: {self.authenticator.debug_authentication_state()}")
            raise Exception(f"No entitlement token in response for {content_id}: {e}")
        except Exception as e:
            logger.error(f"Error getting entitlement token for {content_id}: {e}")
            logger.debug(f"Auth state: {self.authenticator.debug_authentication_state()}")
            raise Exception(f"Error getting entitlement token for {content_id}: {e}")

    def get_channel_playlist(self, channel_id: str, entitlement_token: str) -> Dict:
        """Get channel playlist data"""
        if self.endpoint_manager and self.endpoint_manager.has_endpoint('channel_playlist'):
            url = self.endpoint_manager.get_endpoint('channel_playlist').format(channel_id=channel_id)
        else:
            url = f"https://api.magentatv.de/v1/channel/{channel_id}/playlist"

        headers = {
            'Authorization': f'Bearer {entitlement_token}',
            'User-Agent': self.platform_config['user_agent'],
            'Accept': 'application/json'
        }

        try:
            response = self.http_manager.get(
                url,
                operation='manifest',
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            raise Exception(f"Error getting playlist for {channel_id}: {e}")

    def populate_streaming_data(self, channels: List[StreamingChannel],
                                max_retries: int = DEFAULT_MAX_RETRIES) -> List[StreamingChannel]:
        """Populate streaming data (manifest, DRM) for all channels"""
        self._ensure_authenticated()

        successful_channels = []

        for channel in channels:
            retries = 0
            success = False
            is_restricted = False

            while retries < max_retries and not success and not is_restricted:
                try:
                    logger.debug(f"Getting entitlement token for: {channel.name} (attempt {retries + 1})")

                    entitlement_token = self.get_entitlement_token(
                        content_id=channel.channel_id,
                        content_type=channel.content_type
                    )

                    logger.debug(f"Getting playlist data for: {channel.name}")

                    playlist_data = self.get_channel_playlist(
                        channel.channel_id,
                        entitlement_token
                    )

                    manifest_url = playlist_data.get('manifestUrl', playlist_data.get('manifest'))
                    license_url = playlist_data.get('licenseUrl', playlist_data.get('license'))
                    certificate_url = playlist_data.get('certificateUrl', playlist_data.get('certificate'))
                    streaming_format = playlist_data.get('streamingFormat', playlist_data.get('format', 'dash'))

                    if manifest_url:
                        channel.manifest = manifest_url
                        channel.cdm_type = DRM_SYSTEM_WIDEVINE
                        channel.cdm = f"pid={channel.channel_id}"
                        channel.license_url = license_url
                        channel.certificate_url = certificate_url
                        channel.streaming_format = streaming_format

                        logger.info(f"Streaming data populated for: {channel.name}")
                        successful_channels.append(channel)
                        success = True
                    else:
                        raise Exception("No manifest URL in response")

                except Magenta2PlaybackRestrictedException as e:
                    logger.warning(f"Playback restricted for {channel.name}: {e}")
                    is_restricted = True

                except Exception as e:
                    retries += 1
                    if retries < max_retries:
                        logger.debug(f"Retry {retries}/{max_retries} for {channel.name}: {e}")
                        time.sleep(1)
                    else:
                        logger.error(f"Failed to get streaming data for {channel.name}: {e}")

        logger.info(f"Streaming data population complete:")
        logger.info(f"  Successful: {len(successful_channels)}")
        logger.info(f"  Failed/Restricted: {len(channels) - len(successful_channels)}")
        logger.info(f"  Total: {len(channels)}")

        return successful_channels

    def enrich_channel_data(self, channel: StreamingChannel, **kwargs) -> Optional[StreamingChannel]:
        """Get manifest URL for a specific channel and configure DRM"""
        self._ensure_authenticated()

        try:
            entitlement_token = self.get_entitlement_token(
                content_id=channel.channel_id,
                content_type=channel.content_type
            )

            playlist_data = self.get_channel_playlist(
                channel.channel_id,
                entitlement_token
            )

            manifest_url = playlist_data.get('manifestUrl', playlist_data.get('manifest'))
            if not manifest_url:
                return None

            channel.manifest = manifest_url
            channel.streaming_format = playlist_data.get('streamingFormat', playlist_data.get('format', 'dash'))

            license_url = playlist_data.get('licenseUrl', playlist_data.get('license'))
            if license_url:
                widevine_url = self.endpoint_manager.get_endpoint(
                    'widevine_license') if self.endpoint_manager else license_url

                drm_config = DRMConfig(
                    system=DRMSystem.WIDEVINE,
                    priority=1,
                    license=LicenseConfig(
                        server_url=widevine_url,
                        server_certificate=playlist_data.get('certificateUrl', playlist_data.get('certificate')),
                        req_headers=json.dumps({
                            'User-Agent': self.platform_config['user_agent'],
                            'Content-Type': DRM_REQUEST_HEADERS['Content-Type']
                        }),
                        req_data="{CHA-RAW}",
                        use_http_get_request=False
                    )
                )
                channel.drm_config = drm_config
                channel.cdm_type = DRM_SYSTEM_WIDEVINE
                channel.cdm = f"pid={channel.channel_id}"

            return channel

        except Exception as e:
            logger.error(f"Error getting manifest for {channel.name}: {e}")
            return None

    @staticmethod
    def _parse_smil_for_mpd(smil_content: str, channel_id: str) -> Optional[str]:
        """
        Parse SMIL response to extract MPD URL from <video src="..."> tag

        Args:
            smil_content: Raw SMIL XML content
            channel_id: Channel ID for logging

        Returns:
            MPD URL string or None if not found
        """
        try:
            logger.debug(f"Parsing SMIL response for channel {channel_id} (length: {len(smil_content)} chars)")

            # First check for error cases
            error_title_pattern = r'<ref[^>]*title="([^"]*)"[^>]*abstract="([^"]*)"[^>]*>'
            error_match = re.search(error_title_pattern, smil_content)

            if error_match:
                title = error_match.group(1)
                abstract = error_match.group(2)
                logger.warning(f"SMIL error response for channel {channel_id}: {title} - {abstract}")

                # Check for specific error patterns
                if "errorFiles/Unavailable.flv" in smil_content:
                    logger.error(f"SMIL returned unavailable content for channel {channel_id}")
                    return None
                if "Invalid Token" in title or "InvalidAuthToken" in smil_content:
                    logger.error(f"Invalid authentication token for channel {channel_id}")
                    return None
                if "403" in smil_content:
                    logger.error(f"Access forbidden (403) for channel {channel_id}")
                    return None

            # Look for <video src="..."> tag first (primary source)
            video_src_pattern = r'<video\s+src="([^"]+)"'
            video_match = re.search(video_src_pattern, smil_content)

            if video_match:
                mpd_url = video_match.group(1)
                logger.debug(f"Found MPD URL in <video> tag for channel {channel_id}")

                # Log additional info if available in ref tag
                ref_info_pattern = r'<ref[^>]*src="([^"]*)"[^>]*title="([^"]*)"[^>]*abstract="([^"]*)"'
                ref_info_match = re.search(ref_info_pattern, smil_content)
                if ref_info_match and ref_info_match.group(1) == mpd_url:
                    title = ref_info_match.group(2)
                    abstract = ref_info_match.group(3)
                    logger.debug(f"Stream info: {title} - {abstract}")

                return mpd_url

            # Fallback to <ref src="..."> tag if <video> not found
            ref_src_pattern = r'<ref\s+src="([^"]+)"'
            ref_match = re.search(ref_src_pattern, smil_content)

            if ref_match:
                mpd_url = ref_match.group(1)
                logger.debug(f"Found MPD URL in <ref> tag for channel {channel_id}")

                # Extract title and abstract from the ref tag
                ref_full_pattern = r'<ref[^>]*src="%s"[^>]*title="([^"]*)"[^>]*abstract="([^"]*)"' % re.escape(mpd_url)
                ref_full_match = re.search(ref_full_pattern, smil_content)
                if ref_full_match:
                    title = ref_full_match.group(1)
                    abstract = ref_full_match.group(2)
                    logger.debug(f"Stream info: {title} - {abstract}")

                return mpd_url

            # If we get here, no MPD URL was found
            logger.warning(f"No MPD URL found in SMIL response for channel {channel_id}")

            # Log the full SMIL content for debugging in case of unexpected format
            if len(smil_content) < 1000:  # Only log if it's reasonably short
                logger.debug(f"Full SMIL content: {smil_content}")
            else:
                logger.debug(f"SMIL content preview: {smil_content[:500]}...")

            return None

        except Exception as e:
            logger.error(f"Error parsing SMIL response for channel {channel_id}: {e}")
            return None

    def get_manifest(self, channel_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs) -> Optional[str]:
        """Get MPD manifest URL using cached SMIL data"""
        smil_data = self._get_smil_data(channel_id)
        return smil_data.get('mpd_url') if smil_data else None

    def _get_smil_data(self, channel_id: str) -> Optional[Dict[str, Any]]:
        """Get complete SMIL data with caching"""
        # Check cache first
        now = time.time()
        if channel_id in self._smil_cache:
            timestamp, cached_data = self._smil_cache[channel_id]
            if now - timestamp < self._smil_cache_ttl:
                logger.debug(f"Using cached SMIL data for {channel_id}")
                return cached_data
            else:
                # Cache expired
                del self._smil_cache[channel_id]

        try:
            smil_content = self._get_smil_content(channel_id)
            if not smil_content:
                logger.error(f"No SMIL content received for channel {channel_id}")
                return None

            # 🚨 ADD VALIDATION: Check if we got actual SMIL content
            if len(smil_content.strip()) == 0:
                logger.error(f"Empty SMIL content for channel {channel_id}")
                return None

            if '<smil' not in smil_content.lower():
                logger.error(f"Invalid SMIL content for channel {channel_id}: {smil_content[:200]}...")
                return None

            mpd_url = self._parse_smil_for_mpd(smil_content, channel_id)
            release_pid = self._extract_release_pid_from_smil(smil_content)

            smil_data = {
                'content': smil_content,
                'mpd_url': mpd_url,
                'release_pid': release_pid,
                'channel_id': channel_id
            }

            # Only cache if we have valid data
            if mpd_url or release_pid:
                self._smil_cache[channel_id] = (now, smil_data)
                logger.debug(f"Cached SMIL data for {channel_id}")
            else:
                logger.warning(f"No MPD URL or releasePid found for {channel_id}, not caching")

            return smil_data

        except Exception as e:
            logger.error(f"Error getting SMIL data for channel {channel_id}: {e}")
            return None

    def _get_smil_content(self, channel_id: str) -> Optional[str]:
        """Get SMIL content for a channel to extract releasePid and release concurrency lock"""
        logger.debug(f"🔵 ENTER _get_smil_content for channel: {channel_id}")

        try:
            logger.debug("🔵 Step 1: Calling _ensure_authenticated()")
            persona_token = self._ensure_authenticated()
            logger.debug(f"🔵 _ensure_authenticated() SUCCESS, token length: {len(persona_token)}")

            if not persona_token:
                logger.error(f"No persona token!:")
                return None

            selector_service = self.endpoint_manager.get_endpoint('mpx_selector')
            if not selector_service:
                logger.error(f"No selector service!:")
                return None

            account_pid = self.provider_config.manifest.mpx.account_pid
            if not account_pid:
                logger.error(f"No account pid!:")
                return None

            # Use the same client_id as in the original SMIL request
            client_id = "a8198f31-b406-4177-8dee-f6216c356c75"
            smil_url = f"{selector_service}{account_pid}/media/{channel_id}?format=smil&formats=MPEG-DASH&tracking=true&clientId={client_id}"

            headers = {
                'Authorization': f'Basic {persona_token}',
                'User-Agent': self.platform_config['user_agent'],  # Platform user agent
                'Accept': 'application/smil+xml, application/xml;q=0.9, */*;q=0.8'
            }

            logger.debug(f"SMIL Request URL: {smil_url}")
            logger.debug(f"SMIL Request Headers:")
            for key, value in headers.items():
                if key == 'Authorization':
                    # Don't log full auth token for security, but show it exists
                    logger.debug(f"  {key}: Basic [REDACTED] (length: {len(persona_token)})")
                else:
                    logger.debug(f"  {key}: {value}")

            # Also debug the persona token structure
            try:
                # Try to decode to see what's in there
                decoded = base64.b64decode(persona_token).decode('utf-8')
                logger.debug(f"Decoded persona token preview: {decoded[:100]}...")
            except Exception as decode_error:
                logger.debug(f"Could not decode persona token: {decode_error}")

            response = self.http_manager.get(
                smil_url,
                operation='manifest_smil_drm',
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )

            if response.status_code == 200:
                smil_content = response.text

                if not smil_content:
                    logger.error("Empty SMIL content received")
                    return None

                # RELEASE CONCURRENCY LOCK IMMEDIATELY AFTER GETTING SMIL
                from .concurrency import extract_and_release_lock
                extract_and_release_lock(
                    smil_content,
                    self.http_manager,
                    client_id=client_id,  # Use the same client_id as SMIL request
                    user_agent=self.platform_config['user_agent']  # Platform user agent
                )

                return smil_content
            else:
                logger.error(f"Failed to get SMIL content for DRM: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error getting SMIL content for DRM: {e}")
            return None

    @staticmethod
    def _url_encode(value: str) -> str:
        """URL encode a string"""
        from urllib.parse import quote
        return quote(value, safe='')

    @staticmethod
    def _extract_release_pid_from_smil(smil_content: str) -> Optional[str]:
        """Extract releasePid from SMIL trackingData parameter"""
        try:
            # Look for trackingData parameter in ref tag
            tracking_data_pattern = r'<param name="trackingData" value="([^"]*)"'
            match = re.search(tracking_data_pattern, smil_content)

            if not match:
                logger.warning("No trackingData found in SMIL content")
                return None

            tracking_data = match.group(1)
            logger.debug(f"Found trackingData: {tracking_data}")

            # Extract pid from trackingData (pid=value)
            pid_pattern = r'pid=([^|]+)'
            pid_match = re.search(pid_pattern, tracking_data)

            if pid_match:
                release_pid = pid_match.group(1)
                logger.debug(f"Extracted releasePid: {release_pid}")
                return release_pid
            else:
                logger.warning("No pid found in trackingData")
                return None

        except Exception as e:
            logger.error(f"Error extracting releasePid from SMIL: {e}")
            return None

    @staticmethod
    def _extract_persona_jwt_from_token(persona_token: str) -> Optional[str]:
        """
        Extract the raw persona JWT token from Base64-encoded persona token

        The persona token format is: Base64(account_uri + ":" + persona_jwt)
        This method decodes it and extracts just the persona_jwt part.
        """
        try:
            decoded = base64.b64decode(persona_token).decode('utf-8')
            last_colon_index = decoded.rfind(':')

            if last_colon_index == -1:
                logger.error("No colon found in decoded persona token")
                return None

            persona_jwt = decoded[last_colon_index + 1:]

            if not persona_jwt.startswith('eyJ'):
                logger.error(f"Extracted token doesn't look like a JWT")
                return None

            return persona_jwt
        except Exception as e:
            logger.error(f"Error extracting persona JWT token: {e}")
            return None

    def get_drm(self, channel_id: str, content_type: str = CONTENT_TYPE_LIVE,
                **kwargs) -> List[DRMConfig]:
        """Get DRM configuration using unified SMIL data"""
        try:
            smil_data = self._get_smil_data(channel_id)
            if not smil_data:
                logger.error(f"No SMIL data found for channel {channel_id}")
                return []

            if not smil_data.get('release_pid'):
                logger.error(f"No releasePid found in SMIL for channel {channel_id}")
                # Debug what we do have
                logger.debug(f"SMIL data keys: {list(smil_data.keys())}")
                if 'content' in smil_data and smil_data['content']:
                    logger.debug(f"SMIL content preview: {smil_data['content'][:500]}...")
                return []

            release_pid = smil_data['release_pid']

            # Get persona token
            persona_token = self._ensure_authenticated()

            # Extract the persona JWT from the Base64-encoded persona token
            raw_persona_jwt = self._extract_persona_jwt_from_token(persona_token)
            if not raw_persona_jwt:
                logger.error("Failed to extract persona JWT from persona token")
                return []

            # Get widevine endpoint
            widevine_endpoint = self.endpoint_manager.get_endpoint('widevine_license')
            if not widevine_endpoint:
                logger.error("No widevine license endpoint available")
                return []

            # Get account URI
            account_uri = self._get_account_uri()
            encoded_account_uri = self._url_encode(account_uri)

            # Build license URL with the extracted JWT
            license_url = (f"{widevine_endpoint}?"
                           f"schema=1.0&"
                           f"releasePid={release_pid}&"
                           f"token={raw_persona_jwt}&"
                           f"account={encoded_account_uri}")

            # Create DRM config
            drm_config = DRMConfig(
                system=DRMSystem.WIDEVINE,
                priority=1,
                license=LicenseConfig(
                    server_url=license_url,
                    server_certificate=None,
                    req_headers=json.dumps({
                        'User-Agent': self.platform_config['user_agent'],
                        'Content-Type': 'application/octet-stream'
                    }),
                    req_data="{CHA-RAW}",
                    use_http_get_request=False
                )
            )

            logger.info(f"✓ DRM configuration created for channel {channel_id} (releasePid: {release_pid})")
            return [drm_config]

        except Exception as e:
            logger.error(f"Error getting DRM configs for channel {channel_id}: {e}")
            return []

    def _get_account_uri(self) -> str:
        """Get account URI with fallback logic"""
        if self.provider_config and self.provider_config.manifest:
            account_uri = self.provider_config.manifest.mpx.get_account_uri()
            if account_uri:
                return account_uri

        # Fallback
        return "http://access.auth.theplatform.com/data/Account/2709353023"

    def get_epg(self, channel_id: str, start_time: Optional[datetime] = None,
                end_time: Optional[datetime] = None, **kwargs) -> List[Dict]:
        """Get EPG data for a channel"""
        try:
            if start_time is None:
                start_time = datetime.now()
            if end_time is None:
                end_time = datetime.now() + timedelta(hours=DEFAULT_EPG_WINDOW_HOURS)

            headers = self._get_api_headers(require_auth=False)

            url = self.endpoint_manager.get_endpoint(
                'epg') if self.endpoint_manager else 'https://api.magentatv.de/proxy/device/epg'

            params = {
                'channelId': channel_id,
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            }

            response = self.http_manager.get(
                url,
                operation='api',
                headers=headers,
                params=params,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.error(f"Error getting EPG for channel {channel_id}: {e}")
            return []

    def debug_authentication(self) -> Dict[str, Any]:
        """
        Debug authentication state and token flow

        Returns comprehensive information about the current authentication state,
        token availability, and TokenFlowManager status.
        """
        result: Dict[str, Any] = {
            'provider': {
                'provider_name': self.provider_name,
                'country': self.country,
                'platform': self.platform
            }
        }

        # Try to get current persona token status
        try:
            persona_token = self.get_persona_token(force_refresh=False)
            persona_info: Dict[str, Any] = {
                'available': True,
                'length': len(persona_token),
                'preview': persona_token[:50] + '...'
            }

            # Try to extract and verify the JWT inside
            try:
                persona_jwt = self._extract_persona_jwt_from_token(persona_token)
                persona_info['jwt_available'] = bool(persona_jwt)
                if persona_jwt:
                    persona_info['jwt_length'] = len(persona_jwt)
                    persona_info['jwt_preview'] = persona_jwt[:50] + '...'
            except Exception as e:
                persona_info['jwt_extraction_error'] = str(e)

            result['persona_token'] = persona_info

        except Exception as e:
            result['persona_token'] = {
                'available': False,
                'error': str(e)
            }

        # TokenFlowManager status
        if hasattr(self.authenticator, 'token_flow_manager') and self.authenticator.token_flow_manager:
            result['token_flow_manager'] = {
                'available': True,
                'token_status': self.authenticator.token_flow_manager.get_token_status()
            }
        else:
            result['token_flow_manager'] = {
                'available': False,
                'error': 'TokenFlowManager not initialized'
            }

        # Authenticator capabilities
        if hasattr(self.authenticator, 'get_authentication_capabilities'):
            result['authentication_capabilities'] = self.authenticator.get_authentication_capabilities()

        # Endpoint manager info
        if self.endpoint_manager:
            result['endpoints'] = {
                'has_taa_auth': self.endpoint_manager.has_endpoint('taa_auth'),
                'has_entitlement': self.endpoint_manager.has_endpoint('entitlement'),
                'has_widevine_license': self.endpoint_manager.has_endpoint('widevine_license'),
                'has_mpx_selector': self.endpoint_manager.has_endpoint('mpx_selector'),
                'total_endpoints': len(self.endpoint_manager.get_all_endpoints()),
            }

        # SAM3 client status
        if hasattr(self.authenticator, 'get_sam3_client_status'):
            result['sam3_client'] = self.authenticator.get_sam3_client_status()

        return result