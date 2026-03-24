# streaming_providers/providers/magenta2/provider.py
# -*- coding: utf-8 -*-
import base64
import json
import time
import uuid
from datetime import datetime, timedelta
from urllib.parse import quote
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from ...base.models import DRMConfig, DRMSystem, LicenseConfig, StreamingChannel, Event
from ...base.models.auth import AuthState
from ...base.models.proxy_models import ProxyConfig
from ...base.network import HTTPManagerFactory, ProxyConfigManager
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from .recordings_manager import RecordingsManager
from .smil_manager import SmilManager
from .vod_manager import VodManager
from .auth import Magenta2Authenticator, Magenta2Credentials, Magenta2UserCredentials
from .config_models import ProviderConfig
from .constants import (
    CONTENT_TYPE_LIVE,
    DEFAULT_COUNTRY,
    DEFAULT_EPG_WINDOW_HOURS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PLATFORM,
    DEFAULT_REQUEST_TIMEOUT,
    DRM_REQUEST_HEADERS,
    DRM_SYSTEM_WIDEVINE,
    ERROR_CODES,
    MAGENTA2_CLIENT_IDS,
    MAGENTA2_FALLBACK_ACCOUNT_URI,
    MAGENTA2_LOGO,
    MAGENTA2_PLATFORMS,
    MODE_LIVE,
    QUALITY_RANK,
    SUPPORTED_COUNTRIES,
)
from .discovery import DiscoveryService
from ..lib_theplatform import (
    TheplatformChannel,
    fetch_distribution_rights,
    fetch_entitled_channels_feed,
    extract_persona_jwt,
    build_licence_url,
    build_widevine_drm_config,
)
from .endpoint_manager import EndpointManager
from .models import Magenta2Channel, Magenta2PlaybackRestrictedException
from .token_flow_manager import PersonaResult


class Magenta2Provider(StreamingProvider):
    PROVIDER_LABEL: ClassVar[str] = "Magenta TV 2.0"
    PROVIDER_LOGO: ClassVar[str] = MAGENTA2_LOGO
    """
    Magenta2 streaming provider implementation with enhanced dynamic discovery
    """

    def __init__(
        self,
        country: str = DEFAULT_COUNTRY,
        platform: str = DEFAULT_PLATFORM,
        config_dir: Optional[str] = None,
        proxy_config: Optional[ProxyConfig] = None,
        proxy_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        """
        Initialize Magenta2 provider with enhanced discovery
        """
        super().__init__(country=country)

        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(
                f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}"
            )

        self.platform = platform
        self.platform_config = MAGENTA2_PLATFORMS.get(
            platform, MAGENTA2_PLATFORMS[DEFAULT_PLATFORM]
        )
        self.terminal_type = self.platform_config["terminal_type"]

        # Generate session ID, device ID, and serial number.
        # serial_number is stable for the lifetime of this provider instance.
        self.session_id = self._generate_uuid()
        self.device_id = self._generate_uuid()
        self.serial_number = self._generate_uuid()

        # Setup proxy configuration
        self.proxy_config = (
            proxy_config
            or (ProxyConfig.from_url(proxy_url) if proxy_url else None)
            or self._load_proxy_from_manager(config_dir)
        )

        if self.proxy_config:
            logger.info("Using proxy configuration for Magenta2")
        else:
            logger.debug("No proxy configuration found for Magenta2")

        # Create HTTP manager
        self.http_manager = HTTPManagerFactory.create_for_provider(
            provider_name="magenta2",
            proxy_config=self.proxy_config,
            user_agent=self.platform_config["user_agent"],
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES,
        )

        # Initialize discovery service
        self.discovery_service = DiscoveryService(
            platform=platform,
            terminal_type=self.terminal_type,
            device_id=self.device_id,
            session_id=self.session_id,
            http_manager=self.http_manager,
            proxy_config=self.proxy_config,
        )

        # Initialize endpoint manager (will be populated after discovery)
        self.endpoint_manager: Optional[EndpointManager] = None
        self.provider_config: Optional[ProviderConfig] = None
        self._vod_manager: Optional[VodManager] = None
        self._recordings_manager: Optional[RecordingsManager] = None
        self._smil_manager: Optional[SmilManager] = None

        # 🚨 INITIALIZE AUTHENTICATOR FIRST (with minimal config)
        # Use fallback client IDs initially
        fallback_client_id = MAGENTA2_CLIENT_IDS.get(
            platform, MAGENTA2_CLIENT_IDS[DEFAULT_PLATFORM]
        )

        if username and password:
            # Use user credentials for complete authentication flow
            credentials = Magenta2UserCredentials(
                client_id=fallback_client_id,  # Use fallback initially
                platform=platform,
                country=country,
                device_id=self.device_id,
                username=username,
                password=password,
            )
            logger.info("Using user credentials for authentication")
        else:
            # Use client credentials for TAA-only flow
            credentials = Magenta2Credentials(
                client_id=fallback_client_id,  # Use fallback initially
                platform=platform,
                country=country,
                device_id=self.device_id,
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
            provider_config=None,
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
            if (
                hasattr(self.authenticator, "token_flow_manager")
                and self.authenticator.token_flow_manager
            ):
                self.authenticator.token_flow_manager.provider_config = self.provider_config
                logger.info("✓ ProviderConfig also stored in TokenFlowManager")

            if self.provider_config.bootstrap.sam3_client_id:
                # Use public method if available, otherwise update directly
                if hasattr(self.authenticator, "update_sam3_client_id"):
                    self.authenticator.update_sam3_client_id(
                        self.provider_config.bootstrap.sam3_client_id
                    )
                else:
                    self.authenticator._sam3_client_id = (
                        self.provider_config.bootstrap.sam3_client_id
                    )

                if self.authenticator.credentials:
                    self.authenticator.credentials.client_id = (
                        self.provider_config.bootstrap.sam3_client_id
                    )
                logger.debug(
                    f"Updated authenticator with SAM3 client ID: {self.provider_config.bootstrap.sam3_client_id}"
                )

            if self.provider_config.bootstrap.client_model:
                if hasattr(self.authenticator, "update_client_model"):
                    self.authenticator.update_client_model(
                        self.provider_config.bootstrap.client_model
                    )
                else:
                    self.authenticator._client_model = self.provider_config.bootstrap.client_model
                logger.debug(
                    f"Updated authenticator with client model: {self.provider_config.bootstrap.client_model}"
                )

            if self.provider_config.bootstrap.device_model:
                if hasattr(self.authenticator, "update_device_model"):
                    self.authenticator.update_device_model(
                        self.provider_config.bootstrap.device_model
                    )
                else:
                    self.authenticator._device_model = self.provider_config.bootstrap.device_model
                logger.debug(
                    f"Updated authenticator with device model: {self.provider_config.bootstrap.device_model}"
                )

            # Update authenticator with device token and MPX account if available
            if self.provider_config.manifest:
                device_token = self.provider_config.get_device_token()
                authorize_tokens_url = self.provider_config.get_authorize_tokens_url()

                if device_token:
                    self.authenticator.set_device_token(device_token, authorize_tokens_url)
                    logger.debug("Device token configured in authenticator")

                # CRITICAL: Pass MPX account PID for account URI construction
                if self.provider_config.manifest.mpx.account_pid:
                    self.authenticator.set_mpx_account_pid(
                        self.provider_config.manifest.mpx.account_pid
                    )
                    logger.debug(
                        f"MPX account PID configured: {self.provider_config.manifest.mpx.account_pid}"
                    )

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
                if hasattr(self.authenticator, "update_dynamic_endpoints"):
                    self.authenticator.update_dynamic_endpoints(all_endpoints)
                    logger.info(f"✓ Updated authenticator with {len(all_endpoints)} endpoints")
                elif hasattr(self.authenticator, "update_endpoints"):
                    self.authenticator.update_endpoints(all_endpoints)
                    logger.info(f"✓ Updated authenticator with {len(all_endpoints)} endpoints")
                else:
                    logger.warning("No public method available to update endpoints")

                # Specifically update SAM3 client with QR code URL
                qr_url = self.endpoint_manager.get_endpoint("login_qr_code")
                if qr_url and hasattr(self.authenticator, "update_sam3_qr_code_url"):
                    success = self.authenticator.update_sam3_qr_code_url(qr_url)
                    if success:
                        logger.info("✓ Successfully updated SAM3 client with QR code URL")
                    else:
                        logger.warning("✗ Failed to update SAM3 client with QR code URL")

        # Initialize VodManager now that config is discovered
        if self.provider_config and self.endpoint_manager:
            self._vod_manager = VodManager(
                http_manager=self.http_manager,
                provider_name=self.provider_name,
                bootstrap=self.endpoint_manager.config.bootstrap,
                provider_config=self.endpoint_manager.config,
                session_id=self.session_id,
                serial_number=self.serial_number,
                auth_headers_callback=self._vod_auth_headers,
            )
            logger.info("✓ VodManager initialized with discovered config")

            self._recordings_manager = RecordingsManager(
                http_manager=self.http_manager,
                provider_name=self.provider_name,
                provider_config=self.endpoint_manager.config,
                auth_headers_callback=self._pvr_auth_headers,
            )
            logger.info("✓ RecordingsManager initialized with discovered config")

            self._smil_manager = SmilManager(
                http_manager=self.http_manager,
                provider_name=self.provider_name,
                session_id=self.session_id,
                call_id_callback=self._generate_call_id,
                auth_callback=self._ensure_authenticated,
                platform_config=self.platform_config,
                endpoint_manager=self.endpoint_manager,
                provider_config=self.endpoint_manager.config,
                vod_manager=self._vod_manager,
            )
            logger.info("✓ SmilManager initialized with discovered config")

        # Initialize auth tokens (lazy - populated on first use)
        self.device_token = None
        self._persona_cache: Optional[PersonaResult] = None
        # GUID → manifest_script URL; populated by get_recordings() so that
        # get_manifest() / get_drm() can inject smil_base_url automatically
        # without requiring callers (e.g. DRMOperations) to know about it.
        self._recording_url_cache: Dict[str, str] = {}
        # release_pid → mpd_url / release_pid; keyed by release_pid because
        # channel_id is now set to tp_ch.release_pid in get_channels(), so
        # content_id arriving in get_manifest() / get_drm() is a release_pid.
        self._live_manifest_cache: Dict[str, str] = {}
        self._live_pid_cache: Dict[str, str] = {}
        # Full StreamingChannel list from the last successful get_channels() call.
        # None until get_channels() has run at least once.
        self._cached_channels: Optional[List[StreamingChannel]] = None

        # station_uri → {title, logo_url, quality}; fetched once at init time
        # from the unauthenticated channel-stations feed.  get_channels() reads
        # this dict instead of making a fresh network call every time.
        # channel_id (= release_pid) comes from the entitled-channels feed
        # (authenticated), NOT from this call — this call only supplies display
        # metadata (name, logo, quality, channel number).
        self._station_metadata: Dict[str, Dict] = self._fetch_station_metadata()

        logger.info("Magenta2 provider initialization completed successfully")

    @staticmethod
    def _generate_uuid() -> str:
        """Generate a UUID string. Used for session IDs, device IDs, and call IDs."""
        return str(uuid.uuid4())

    def _generate_call_id(self) -> str:
        """Generate a fresh call ID for each individual request."""
        return self._generate_uuid()

    def _load_proxy_from_manager(self, config_dir: Optional[str]) -> Optional[ProxyConfig]:
        """Load proxy configuration from ProxyConfigManager"""
        try:
            proxy_manager = ProxyConfigManager(config_dir)
            return proxy_manager.get_proxy_config("magenta2", self.country)
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
                qr_url = self.endpoint_manager.get_endpoint("login_qr_code")
                if qr_url:
                    logger.info(f"✓ QR code endpoint discovered in endpoint manager: {qr_url}")

                    # PROPER FIX: Use public method to update SAM3 client
                    if hasattr(self.authenticator, "update_sam3_qr_code_url"):
                        success = self.authenticator.update_sam3_qr_code_url(qr_url)
                        if success:
                            logger.info("✓ Successfully updated SAM3 client with QR code URL")
                        else:
                            logger.warning("✗ Failed to update SAM3 client with QR code URL")

                    # Also debug the current status
                    if hasattr(self.authenticator, "get_sam3_client_status"):
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
                    logger.info(
                        f"✓ MPX account PID discovered: {self.provider_config.manifest.mpx.account_pid}"
                    )

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
            device_model=f"{self.platform.upper()}_FTV",
        )

        self.provider_config = ProviderConfig(bootstrap=bootstrap_config)
        self.endpoint_manager = EndpointManager(self.provider_config)

        logger.info("Fallback configuration created")

    def _get_dcm_headers(self) -> Dict[str, str]:
        """Get headers for DCM requests"""
        return {
            "User-Agent": self.platform_config["user_agent"],
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-dt-session-id": self.session_id,
            "x-dt-call-id": self._generate_call_id(),
        }

    def _get_api_headers(self, require_auth: bool = False) -> Dict[str, str]:
        """Get headers for API requests"""
        headers = {
            "User-Agent": self.platform_config["user_agent"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if require_auth:
            persona_token = self._ensure_authenticated()
            headers["Authorization"] = f"Basic {persona_token}"

        return headers

    @property
    def provider_name(self) -> str:
        return "magenta2"

    @property
    def provider_label(self) -> str:
        return "Magenta TV 2.0"

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    @property
    def implements_epg(self) -> bool:
        return False

    @property
    def implements_recordings(self) -> bool:
        return True

    @property
    def catchup_window(self) -> int:
        # This provider offers 4 hours of catchup
        return 4

    @property
    def supported_auth_types(self) -> List[str]:
        return ["network_based"]

    @property
    def primary_token_scope(self) -> Optional[str]:
        return "persona"

    @property
    def token_scopes(self) -> List[str]:
        return ["yo_digital", "tvhubs", "taa", "persona"]

    def get_discovery_status(self) -> Dict[str, Any]:
        """Get discovery and configuration status"""
        if not self.discovery_service:
            return {"error": "Discovery service not initialized"}

        status = self.discovery_service.get_discovery_status()

        if self.endpoint_manager:
            status["endpoints"] = self.endpoint_manager.get_stats()

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
                    device_token = new_config.manifest.raw_data.get("deviceToken")
                    authorize_tokens_url = new_config.manifest.raw_data.get("authorizeTokensUrl")
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
            if hasattr(self.authenticator, "perform_device_authentication"):
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
                logger.debug(
                    f"Using in-memory cached persona token (expires at {time.ctime(self._persona_cache.expires_at)})"
                )
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
        logger.debug(
            f"Cached persona token in memory (expires at {time.ctime(persona_result.expires_at)})"
        )

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
            stations = entry.get("stations", {})
            if not stations:
                return None

            # Get the first station
            station_id = next(iter(stations.keys()))
            station_info = stations[station_id]

            # Extract from era$mediaPids (this is the correct ID for API calls)
            era_media_pids = station_info.get("era$mediaPids", {})
            channel_id = era_media_pids.get("urn:theplatform:tv:location:any")

            if channel_id:
                logger.debug(f"Extracted channel ID from era$mediaPids: {channel_id}")
                return channel_id

            # Fallback to guid if era$mediaPids not available
            fallback_id = entry.get("guid")
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
        for param in image_config.scaling_call_parameter.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                call_params[key] = value

        # Build the scaling URL
        base_url = image_config.scaling_base_url.rstrip("/")

        # Add required parameters
        params = {
            **call_params,  # client=ftp22
            "x": "120",
            "y": "42",
            "ar": "keep",  # aspect ratio
            "src": original_url,  # original image URL
        }

        # Build query string
        query_string = "&".join([f"{k}={quote(v, safe='')}" for k, v in params.items()])

        return f"{base_url}/iss?{query_string}"

    def _process_channel_stations_response_optimized(
        self, response_data: Dict, prefer_highest_quality: bool = True
    ) -> List[StreamingChannel]:
        """Ultra-optimized single-pass processing"""

        if "entries" not in response_data:
            return []

        best_entries = {}
        channels = []

        for entry in response_data["entries"]:
            try:
                stations = entry.get("stations", {})
                if not stations:
                    continue

                station_info = next(iter(stations.values()))
                display_number = entry.get("dt$displayChannelNumber")

                if display_number is None:
                    # Process immediately if no number (no filtering needed)
                    channel = self._create_channel_from_entry(entry, station_info, display_number)
                    if channel:
                        channels.append(channel)
                    continue

                # Extract quality for comparison using the shared QUALITY_RANK constant
                quality = station_info.get("dt$quality", "SD")
                current_rank = QUALITY_RANK.get(quality, 1)

                # Check if we need to replace existing entry
                existing = best_entries.get(display_number)
                if not existing:
                    best_entries[display_number] = (entry, station_info, current_rank)
                else:
                    _, _, existing_rank = existing
                    if (prefer_highest_quality and current_rank > existing_rank) or (
                        not prefer_highest_quality and current_rank < existing_rank
                    ):
                        best_entries[display_number] = (
                            entry,
                            station_info,
                            current_rank,
                        )

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
            title = station_info.get("title") or entry.get("title", "Unknown Channel")
            title = title.replace(" - Main", "")

            channel_id = self._extract_channel_id_from_entry(entry)
            if not channel_id:
                return None

            # Logo processing
            logo_url = None
            thumbnails = station_info.get("thumbnails", {})
            for logo_type in ["stationLogo", "stationLogoColored"]:
                if logo_type in thumbnails:
                    original_url = thumbnails[logo_type].get("url")
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
                raw_data=entry,
            )

            streaming_channel = magenta2_channel.to_streaming_channel(
                provider_name=self.provider_name
            )
            streaming_channel.channel_number = display_number
            streaming_channel.quality = station_info.get("dt$quality", "SD")

            return streaming_channel

        except Exception as e:
            logger.warning(f"Error creating channel from entry: {e}")
            return None

    def _fetch_station_metadata(self) -> Dict[str, Dict]:
        """
        Fetch the channel-stations feed and return a lookup map keyed by the
        theplatform Station URI (the key of the stations dict, e.g.
        "http://data.entertainment.tv.theplatform.eu/…/Station/265808936224").

        This matches listings[0].stationId in the entitled-channels feed, which
        is what TheplatformChannel.station_id contains after parsing.

        Note: era$mediaPids["urn:theplatform:tv:location:any"] is a short opaque
        PID used for other purposes — it is NOT the mapping key.

        Each value is a dict with:
            title    – display name (" - Main" suffix already stripped)
            logo_url – scaled logo URL or None
            quality  – "HD", "SD", etc.
        """
        metadata: Dict[str, Dict] = {}
        try:
            url = None
            if self.endpoint_manager:
                url = (
                    self.endpoint_manager.get_endpoint("channel_stations")
                    or self.endpoint_manager.get_endpoint("channel_list")
                )
            url = url or "https://feed.entertainment.tv.theplatform.eu/f/mdeprod/mdeprod-channel-stations-main"
            url += "?lang=short-de&sort=dt%24displayChannelNumber&range=1-1000"

            headers = self._get_api_headers(require_auth=False)
            response = self.http_manager.get(
                url, operation="api", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()

            for entry in data.get("entries", []):
                try:
                    stations = entry.get("stations", {})
                    if not stations:
                        continue
                    # The stations dict key IS the Station URI, matching
                    # listings[0].stationId in the entitled-channels feed.
                    # era$mediaPids["urn:theplatform:tv:location:any"] is a
                    # short opaque PID — a different identifier entirely.
                    station_uri = next(iter(stations.keys()))
                    station_info = stations[station_uri]

                    title = (station_info.get("title") or entry.get("title", "")).replace(" - Main", "")
                    quality = station_info.get("dt$quality", "SD")

                    logo_url = None
                    thumbnails = station_info.get("thumbnails", {})
                    for logo_type in ["stationLogo", "stationLogoColored"]:
                        if logo_type in thumbnails:
                            original_url = thumbnails[logo_type].get("url")
                            if original_url:
                                logo_url = self._build_scaled_image_url(original_url)
                                break

                    # Keep highest-quality entry when duplicates exist
                    existing = metadata.get(station_uri)
                    if not existing or QUALITY_RANK.get(quality, 1) > QUALITY_RANK.get(existing["quality"], 1):
                        metadata[station_uri] = {
                            "title": title,
                            "logo_url": logo_url,
                            "quality": quality,
                        }
                except Exception as exc:
                    logger.debug(f"_fetch_station_metadata: skipping entry: {exc}")

            logger.debug(f"_fetch_station_metadata: built metadata for {len(metadata)} stations")
        except Exception as exc:
            logger.warning(f"_fetch_station_metadata: failed, channels will have no names: {exc}")

        return metadata

    def get_channels(
        self,
        time_window_hours: int = DEFAULT_EPG_WINDOW_HOURS,
        fetch_manifests: bool = False,
        populate_streaming_data: bool = True,
        prefer_highest_quality: bool = True,
        **kwargs,
    ) -> List[StreamingChannel]:
        """
        Fetch available channels from Magenta2 via the entitled-channels flow.

        Uses lib_theplatform to:
          1. Call getApplicableDistributionRights (license_service_url from manifest).
          2. Fetch the entitled-channels feed filtered by those rights.
          3. Merge with station metadata pre-fetched at init time (unauthenticated).
          4. Convert each TheplatformChannel to a StreamingChannel, enriched with
             metadata from the stations feed.

        Results are cached after the first successful call.  Subsequent calls
        return directly from the cache without hitting the network again.

        Note: channel_id (= release_pid) comes exclusively from the
        entitled-channels feed (step 2, authenticated).  The station-metadata
        dict fetched at init time supplies only display data (name, logo, quality).
        """
        # ── Cache guard ───────────────────────────────────────────────────────
        # After the first successful call _cached_channels holds the full list.
        # Return it directly — no network calls, no re-parsing.
        if hasattr(self, "_cached_channels") and self._cached_channels:
            logger.debug("get_channels: returning from cache (no network calls)")
            return list(self._cached_channels)

        try:
            cid = f"{self.session_id}::{self._generate_call_id()}"
            user_agent = self.platform_config["user_agent"]

            # ── Step 1: resolve distribution rights ──────────────────────────
            rights_url = (
                self.provider_config.manifest.mpx.license_service_url
                if self.provider_config and self.provider_config.manifest
                else None
            )
            if not rights_url:
                raise RuntimeError(
                    "No license_service_url available – configuration discovery may have failed"
                )

            persona_token = self._ensure_authenticated()
            auth_headers = {
                "Authorization": f"Basic {persona_token}",
                "Origin": "https://www.magenta.tv",
                "Referer": "https://www.magenta.tv/",
            }

            distribution_rights = fetch_distribution_rights(
                http_manager=self.http_manager,
                rights_url=rights_url,
                cid=cid,
                user_agent=user_agent,
                timeout=DEFAULT_REQUEST_TIMEOUT,
                extra_headers=auth_headers,
            )

            # ── Step 2: fetch entitled-channels feed ─────────────────────────
            feed_url = (
                self.endpoint_manager.get_endpoint("mpx_feed_entitledChannelsFeed")
                if self.endpoint_manager
                else None
            ) or "https://feed.entertainment.tv.theplatform.eu/f/mdeprod/mdeprod-entitled-channels"

            tp_channels: List[TheplatformChannel] = fetch_entitled_channels_feed(
                http_manager=self.http_manager,
                feed_url=feed_url,
                distribution_rights=distribution_rights,
                cid=cid,
                user_agent=user_agent,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )

            # ── Step 3: use station metadata pre-fetched at init time ────────
            # _station_metadata was populated from the unauthenticated
            # channel-stations feed during __init__.  No network call needed.
            station_metadata = self._station_metadata

            # ── Step 4: convert to StreamingChannel ──────────────────────────
            channels: List[StreamingChannel] = []
            for tp_ch in tp_channels:
                try:
                    meta = station_metadata.get(tp_ch.station_id, {})
                    name = meta.get("title") or tp_ch.station_id
                    logo_url = meta.get("logo_url")
                    quality = meta.get("quality")

                    magenta2_channel = Magenta2Channel(
                        name=name,
                        channel_id=tp_ch.release_pid,
                        logo_url=logo_url,
                        mode=MODE_LIVE,
                        content_type=CONTENT_TYPE_LIVE,
                        country=self.country,
                        raw_data=tp_ch.extra,
                    )
                    streaming_channel = magenta2_channel.to_streaming_channel(
                        provider_name=self.provider_name
                    )
                    streaming_channel.channel_number = tp_ch.channel_number
                    streaming_channel.quality = quality
                    streaming_channel.manifest = tp_ch.mpd_url
                    if tp_ch.hls_url:
                        streaming_channel.hls_url = tp_ch.hls_url

                    # Cache manifest URL and releasePid keyed by release_pid,
                    # which is now the channel's channel_id (content_id).
                    self._live_manifest_cache[tp_ch.release_pid] = tp_ch.mpd_url
                    self._live_pid_cache[tp_ch.release_pid] = tp_ch.release_pid

                    channels.append(streaming_channel)
                except Exception as exc:
                    logger.warning(f"get_channels: skipping channel {tp_ch.station_id}: {exc}")

            logger.info(
                f"Successfully fetched {len(channels)} entitled channels "
                f"for country {self.country} "
                f"({len(station_metadata)} stations with metadata)"
            )
            # Persist the full channel list so subsequent get_channels() calls
            # return immediately from cache without any network requests.
            self._cached_channels: List[StreamingChannel] = channels
            return channels

        except Exception as e:
            raise Exception(f"Error fetching channels from Magenta2 API: {e}")

    def get_events(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Event]:
        return []

    def get_entitlement_token(self, content_id: str, content_type: str = CONTENT_TYPE_LIVE) -> str:
        """
        Get entitlement token using persona_token Basic auth
        """
        # Ensure we're authenticated with persona token
        self._ensure_authenticated()

        # Use persona token (Basic auth) for entitlement
        headers = self._get_api_headers(require_auth=True)

        payload = {"content_id": content_id, "content_type": content_type}

        url = (
            self.endpoint_manager.get_endpoint("entitlement")
            if self.endpoint_manager
            else "https://entitlement.p7s1.io/api/user/entitlement-token"
        )

        try:
            logger.debug(f"Requesting entitlement token with persona token for: {content_id}")
            response = self.http_manager.post(
                url,
                operation="auth",
                headers=headers,
                json_data=payload,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )

            if response.status_code == 400:
                try:
                    error_data = response.json()
                    error_list = error_data if isinstance(error_data, list) else [error_data]

                    if len(error_list) > 0:
                        error = error_list[0]
                        code = error.get("code", error.get("errorCode", "UNKNOWN"))
                        msg = error.get("msg", error.get("message", "No error message provided"))

                        if code == ERROR_CODES["PLAYBACK_RESTRICTED"]:
                            raise Magenta2PlaybackRestrictedException(
                                f"Playback restricted for {content_id}: {msg}"
                            )
                        else:
                            raise Exception(f"Entitlement error for {content_id} ({code}): {msg}")
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    raise Exception(
                        f"Bad response for {content_id} (400), failed to parse error: {e}"
                    )

            response.raise_for_status()
            data = response.json()

            if "entitlement_token" in data:
                return data["entitlement_token"]
            elif "entitlementToken" in data:
                return data["entitlementToken"]
            elif "token" in data:
                return data["token"]
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
        if self.endpoint_manager and self.endpoint_manager.has_endpoint("channel_playlist"):
            url = self.endpoint_manager.get_endpoint("channel_playlist").format(
                channel_id=channel_id
            )
        else:
            url = f"https://api.magentatv.de/v1/channel/{channel_id}/playlist"

        headers = {
            "Authorization": f"Bearer {entitlement_token}",
            "User-Agent": self.platform_config["user_agent"],
            "Accept": "application/json",
        }

        try:
            response = self.http_manager.get(
                url,
                operation="manifest",
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            raise Exception(f"Error getting playlist for {channel_id}: {e}")

    def populate_streaming_data(
        self, channels: List[StreamingChannel], max_retries: int = DEFAULT_MAX_RETRIES
    ) -> List[StreamingChannel]:
        """Populate streaming data (manifest, DRM) for all channels"""
        self._ensure_authenticated()

        successful_channels = []

        for channel in channels:
            retries = 0
            success = False
            is_restricted = False

            while retries < max_retries and not success and not is_restricted:
                try:
                    logger.debug(
                        f"Getting entitlement token for: {channel.name} (attempt {retries + 1})"
                    )

                    entitlement_token = self.get_entitlement_token(
                        content_id=channel.channel_id, content_type=channel.content_type
                    )

                    logger.debug(f"Getting playlist data for: {channel.name}")

                    playlist_data = self.get_channel_playlist(channel.channel_id, entitlement_token)

                    manifest_url = playlist_data.get("manifestUrl", playlist_data.get("manifest"))
                    license_url = playlist_data.get("licenseUrl", playlist_data.get("license"))
                    certificate_url = playlist_data.get(
                        "certificateUrl", playlist_data.get("certificate")
                    )
                    streaming_format = playlist_data.get(
                        "streamingFormat", playlist_data.get("format", "dash")
                    )

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

    def _get_tvhubs_bearer(self) -> Optional[str]:
        """
        Return a valid tvhubs-scoped access_token for use as Bearer.

        The tvhubs token has audience "https://tvhubs.telekom.de" and is what
        the real device sends in Authorization: Bearer for all tvhubs/wcps calls.

        If the stored token is expired, refreshes it automatically using the
        shared refresh_token via sam3_client.refresh_access_token("tvhubs").
        Falls back to None if unavailable (caller falls back to persona_jwt).
        """
        import time as _time
        try:
            tfm = self.authenticator.token_flow_manager
            token_data = tfm.session_manager.load_scoped_token(
                self.provider_name, "tvhubs", self.country
            )
            if not token_data or not token_data.get("access_token"):
                return None

            # Check if expired
            issued_at = token_data.get("issued_at", 0)
            expires_in = token_data.get("expires_in", 7200)
            if _time.time() < issued_at + expires_in - 60:
                # Still valid (with 60s safety margin)
                return token_data["access_token"]

            # Expired — refresh using the shared refresh_token.
            # The refresh_token lives in top-level session data (shared across
            # all subordinate tokens: tvhubs, taa, yo_digital).
            logger.debug("tvhubs token expired, refreshing via sam3_client")
            sam3 = tfm.sam3_client

            # Load shared refresh_token from session storage if not on instance
            shared_rt = (
                sam3.refresh_token
                if sam3 and sam3.refresh_token
                else (
                    (tfm.session_manager.load_session(self.provider_name, self.country) or {})
                    .get("refresh_token")
                )
            )
            if not shared_rt:
                logger.warning("Cannot refresh tvhubs token: no shared refresh_token found")
                return None

            # Inject into sam3_client so refresh_access_token can use it
            sam3.refresh_token = shared_rt
            new_token = sam3.refresh_access_token("tvhubs")
            if new_token:
                # Persist the refreshed token
                tfm._save_tvhubs_token({
                    "access_token": new_token,
                    "token_type": "Bearer",
                    "expires_in": 7200,
                })
                logger.debug("tvhubs token refreshed successfully")
                return new_token

            logger.warning("tvhubs token refresh failed")
        except Exception as exc:
            logger.debug(f"Could not load/refresh tvhubs token: {exc}")
        return None

    def _vod_auth_headers(self) -> Dict[str, str]:
        """
        Build authentication headers for VOD endpoints, platform-aware.

        Authorization Bearer uses the tvhubs-scoped token (audience
        https://tvhubs.telekom.de) — this is what the real device sends
        and what the server uses for partner entitlement decisions.
        Falls back to persona_jwt if tvhubs token is unavailable.

        ftv-web:     x-dt-session-id / x-dt-call-id, origin, referer,
                     x-permissionflagpersonalizeduireco
        ftv-android: x-stbserialnumber, dt-session-id / dt-call-id (no x- prefix),
                     accept-encoding: gzip
        """
        persona_token = self._ensure_authenticated()
        # Prefer tvhubs token as Bearer — it carries correct entitlement scope.
        tvhubs_token = self._get_tvhubs_bearer()
        if tvhubs_token:
            auth_value = f"Bearer {tvhubs_token}"
            logger.debug("VOD auth: using tvhubs token as Bearer")
        else:
            persona_jwt = self._extract_persona_jwt_from_token(persona_token)
            auth_value = (
                f"Bearer {persona_jwt}" if persona_jwt else f"Basic {persona_token}"
            )
            logger.debug("VOD auth: tvhubs token unavailable, falling back to persona_jwt")

        client_model: str = (
            self.provider_config.bootstrap.client_model
            if self.provider_config and self.provider_config.bootstrap
            else f"ftv-{self.platform}"
        )
        is_web = client_model == "ftv-web"

        if is_web:
            return {
                "Authorization": auth_value,
                "x-mpx-authorization": f"Basic {persona_token}",
                "x-dt-session-id": self.session_id,
                "x-dt-call-id": self._generate_call_id(),
                "origin": "https://www.magenta.tv",
                "referer": "https://www.magenta.tv/",
                "user-agent": self.platform_config["user_agent"],
                "accept": "*/*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "de-DE,de;q=0.9",
                "x-permissionflagpersonalizeduireco": "false",
            }
        else:
            return {
                "Authorization": auth_value,
                "x-mpx-authorization": f"Basic {persona_token}",
                "x-stbserialnumber": self.serial_number,
                "dt-session-id": self.session_id,
                "dt-call-id": self._generate_call_id(),
                "user-agent": self.platform_config["user_agent"],
                "accept-encoding": "gzip",
            }


    def _pvr_auth_headers(self) -> Dict[str, str]:
        """
        Build authentication headers for nPVR (Audience) recording endpoints.

        The nPVR Audience API authenticates with ``Authorization: Basic
        {persona_token}`` — the same Base64-encoded persona token used for
        MPX licence and entitlement requests, *not* a Bearer JWT.

        A ``CID`` correlation header (session::call) is included to match
        real-device request patterns observed in the API.
        """
        persona_token = self._ensure_authenticated()
        return {
            "Authorization": f"Basic {persona_token}",
            "User-Agent": self.platform_config["user_agent"],
            "Accept-Encoding": "gzip",
            "CID": f"{self.session_id}::{self._generate_call_id()}",
        }

    def get_vod_category(self, content_id: str = "", **kwargs):
        """
        Return the children of a VOD node.

        Args:
            content_id: Opaque node identifier produced by a previous
                        get_vod_category call (e.g. "lane:322341",
                        "series:GN_SERIES_20914057").  Empty string → root.
            cursor:     Opaque continuation token from a previous response's
                        next_cursor field.  None → first page.
                        Encoded as a plain integer string by VodManager
                        (the $offset value for the next UnstructuredGrid call).
            page_size:  Number of items to request per page (default from
                        VOD_DEFAULT_PAGE_SIZE).  Passed straight through to
                        VodManager and then to the $size query parameter.
        """
        if not self._vod_manager:
            raise RuntimeError("VodManager not available - configuration discovery may have failed")
        return self._vod_manager.get_children(content_id=content_id, **kwargs)


    def get_recordings(self, include_deleted: bool = False, **kwargs):
        """Return a list of Recording objects from the nPVR backend."""
        if not self._recordings_manager:
            raise RuntimeError(
                "RecordingsManager not available — configuration discovery may have failed"
            )
        recordings = self._recordings_manager.get_recordings(
            include_deleted=include_deleted, **kwargs
        )
        # Cache content_id → manifest_script so get_manifest() / get_drm()
        # can inject smil_base_url automatically without callers needing to
        # know about it (e.g. DRMOperations passes only content_id).
        for rec in recordings:
            if rec.content_id and rec.manifest_script:
                self._recording_url_cache[rec.content_id] = rec.manifest_script
        return recordings

    def delete_recording(self, recording_id: str, **kwargs) -> None:
        """Permanently delete a recording on the nPVR backend."""
        if not self._recordings_manager:
            raise RuntimeError(
                "RecordingsManager not available — configuration discovery may have failed"
            )
        self._recordings_manager.delete_recording(recording_id)

    def get_recording_manifest(self, recording_id: str, **kwargs) -> Optional[str]:
        """
        Return the playback URL for a specific recording by ID.

        For recordings already in memory (returned by get_recordings), the
        manifest_script field already contains the playback URL.  This method
        performs a fresh API lookup — use it only when the Recording object is
        not available.
        """
        if not self._recordings_manager:
            return None
        return self._recordings_manager.get_recording_manifest(recording_id)

    def enrich_channel_data(
        self, channel: StreamingChannel, **kwargs
    ) -> Optional[StreamingChannel]:
        """Get manifest URL for a specific channel and configure DRM"""
        self._ensure_authenticated()

        try:
            entitlement_token = self.get_entitlement_token(
                content_id=channel.channel_id, content_type=channel.content_type
            )

            playlist_data = self.get_channel_playlist(channel.channel_id, entitlement_token)

            manifest_url = playlist_data.get("manifestUrl", playlist_data.get("manifest"))
            if not manifest_url:
                return None

            channel.manifest = manifest_url
            channel.streaming_format = playlist_data.get(
                "streamingFormat", playlist_data.get("format", "dash")
            )

            license_url = playlist_data.get("licenseUrl", playlist_data.get("license"))
            if license_url:
                widevine_url = (
                    self.endpoint_manager.get_endpoint("widevine_license")
                    if self.endpoint_manager
                    else license_url
                )

                drm_config = DRMConfig(
                    system=DRMSystem.WIDEVINE,
                    priority=1,
                    license=LicenseConfig(
                        server_url=widevine_url,
                        server_certificate=playlist_data.get(
                            "certificateUrl", playlist_data.get("certificate")
                        ),
                        req_headers=json.dumps(
                            {
                                "User-Agent": self.platform_config["user_agent"],
                                "Content-Type": DRM_REQUEST_HEADERS["Content-Type"],
                            }
                        ),
                        req_data="{CHA-RAW}",
                        use_http_get_request=False,
                    ),
                )
                channel.drm_config = drm_config
                channel.cdm_type = DRM_SYSTEM_WIDEVINE
                channel.cdm = f"pid={channel.channel_id}"

            return channel

        except Exception as e:
            logger.error(f"Error getting manifest for {channel.name}: {e}")
            return None


    def get_manifest(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs
    ) -> Optional[str]:
        """Get MPD manifest URL.

        For live channels whose manifest was already fetched by get_channels(),
        return the cached MPD URL directly without a SMIL round-trip.
        VOD and recordings fall through to SmilManager as before.
        """
        if content_type == CONTENT_TYPE_LIVE and content_id in self._live_manifest_cache:
            logger.debug(f"get_manifest: cache hit for live channel {content_id}")
            return self._live_manifest_cache[content_id]

        if not self._smil_manager:
            raise RuntimeError("SmilManager not available")
        # Inject smil_base_url from recording cache when not already supplied.
        # Ensures recordings use link.theplatform.eu (from playbackUrl) instead
        # of the selector endpoint (link.api.eu.theplatform.com).
        if "smil_base_url" not in kwargs and content_id in self._recording_url_cache:
            kwargs["smil_base_url"] = self._recording_url_cache[content_id]
            logger.debug(f"Injected smil_base_url from recording cache for {content_id}")
        return self._smil_manager.get_manifest(content_id, content_type, **kwargs)

    def get_catchup_manifest(
        self, channel_id: str, start_time: int, end_time: int, **kwargs
    ) -> Optional[str]:
        """Get catchup manifest URL via SmilManager."""
        if not self._smil_manager:
            raise RuntimeError("SmilManager not available")
        return self._smil_manager.get_catchup_manifest(
            channel_id, start_time, end_time, **kwargs
        )





    @staticmethod
    def _extract_persona_jwt_from_token(persona_token: str) -> Optional[str]:
        """
        Extract the raw persona JWT token from Base64-encoded persona token

        The persona token format is: Base64(account_uri + ":" + persona_jwt)
        This method decodes it and extracts just the persona_jwt part.
        """
        try:
            decoded = base64.b64decode(persona_token).decode("utf-8")
            last_colon_index = decoded.rfind(":")

            if last_colon_index == -1:
                logger.error("No colon found in decoded persona token")
                return None

            persona_jwt = decoded[last_colon_index + 1:]

            if not persona_jwt.startswith("eyJ"):
                logger.error(f"Extracted token doesn't look like a JWT")
                return None

            return persona_jwt
        except Exception as e:
            logger.error(f"Error extracting persona JWT token: {e}")
            return None

    def get_drm(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs
    ) -> List[DRMConfig]:
        """Get DRM configuration.

        For live channels whose releasePid was cached by get_channels(), build
        the Widevine licence URL directly using lib_theplatform — no SMIL fetch.
        VOD and recordings fall through to SmilManager as before.
        """
        if content_type == CONTENT_TYPE_LIVE and content_id in self._live_pid_cache:
            release_pid = content_id  # content_id IS the release_pid
            logger.debug(
                f"get_drm: building licence directly for live channel "
                f"(releasePid: {release_pid})"
            )
            try:
                persona_token = self._ensure_authenticated()
                raw_jwt = extract_persona_jwt(persona_token)
                if not raw_jwt:
                    logger.error("get_drm: failed to extract persona JWT")
                    return []

                widevine_endpoint = (
                    self.endpoint_manager.get_endpoint("widevine_license")
                    if self.endpoint_manager
                    else None
                )
                if not widevine_endpoint:
                    logger.error("get_drm: no widevine_license endpoint available")
                    return []

                account_uri = (
                    self.provider_config.manifest.mpx.get_account_uri()
                    if self.provider_config and self.provider_config.manifest
                    else None
                ) or MAGENTA2_FALLBACK_ACCOUNT_URI

                licence_url = build_licence_url(
                    widevine_endpoint=widevine_endpoint,
                    release_pid=release_pid,
                    persona_jwt=raw_jwt,
                    account_uri=account_uri,
                )
                return [build_widevine_drm_config(
                    licence_url=licence_url,
                    user_agent=self.platform_config["user_agent"],
                )]
            except Exception as exc:
                logger.error(f"get_drm: direct licence build failed for {content_id}: {exc}")
                return []

        if not self._smil_manager:
            raise RuntimeError("SmilManager not available")
        # Same smil_base_url injection as get_manifest — keeps both consistent.
        if "smil_base_url" not in kwargs and content_id in self._recording_url_cache:
            kwargs["smil_base_url"] = self._recording_url_cache[content_id]
            logger.debug(f"Injected smil_base_url from recording cache for {content_id}")
        return self._smil_manager.get_drm(content_id, content_type, **kwargs)

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kwargs,
    ) -> List[Dict]:
        """Get EPG data for a channel"""
        try:
            if start_time is None:
                start_time = datetime.now()
            if end_time is None:
                end_time = datetime.now() + timedelta(hours=DEFAULT_EPG_WINDOW_HOURS)

            headers = self._get_api_headers(require_auth=False)

            url = (
                self.endpoint_manager.get_endpoint("epg")
                if self.endpoint_manager
                else "https://api.magentatv.de/proxy/device/epg"
            )

            params = {
                "channelId": channel_id,
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
            }

            response = self.http_manager.get(
                url,
                operation="api",
                headers=headers,
                params=params,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.error(f"Error getting EPG for channel {channel_id}: {e}")
            return []

    def _calculate_auth_state(self, context) -> "AuthState":
        """
        Custom auth state calculation for Magenta2.
        Checks persona token with its special structure.
        """
        # Get persona token data
        persona_token = context.get_token(self.provider_name, "persona", self.country)

        if not persona_token:
            logger.debug("No persona token found")
            return AuthState.NOT_AUTHENTICATED

        # Validate persona token structure
        if not isinstance(persona_token, dict) or "persona_token" not in persona_token:
            logger.warning("Invalid persona token structure")
            return AuthState.NOT_AUTHENTICATED

        # Check if persona token is expired
        if "expires_at" in persona_token:
            current_time = time.time()
            expires_at = persona_token["expires_at"]

            # Add 5-minute buffer
            if current_time >= (expires_at - 300):
                logger.debug(
                    f"Persona token expired (expires_at: {expires_at}, now: {current_time})"
                )
                return AuthState.EXPIRED

        # Token exists and is valid
        logger.debug("Persona token is valid")
        return AuthState.AUTHENTICATED

    def _calculate_readiness(self, context) -> Tuple[bool, str]:
        """
        Custom readiness calculation for Magenta2.
        Ready if we have a valid persona token.
        """
        # Get persona token data
        persona_token = context.get_token(self.provider_name, "persona", self.country)

        if not persona_token:
            return False, "No persona token available"

        # Validate structure
        if not isinstance(persona_token, dict) or "persona_token" not in persona_token:
            return False, "Invalid persona token structure"

        # Check expiration
        if "expires_at" in persona_token:
            current_time = time.time()
            expires_at = persona_token["expires_at"]

            # Add 5-minute buffer
            if current_time >= (expires_at - 300):
                # Token expired but might be refreshable
                # Check if we have yo_digital token with refresh capability
                yo_token = context.get_token(self.provider_name, "yo_digital", self.country)
                if yo_token and "refresh_token" in yo_token:
                    # Check if yo_digital refresh token is still valid
                    if (
                        "refresh_token_expires_in" in yo_token
                        and "refresh_token_issued_at" in yo_token
                    ):
                        refresh_expires_at = (
                            yo_token["refresh_token_issued_at"]
                            + yo_token["refresh_token_expires_in"]
                        )
                        if current_time < (refresh_expires_at - 300):
                            return (
                                True,
                                "Persona token expired but can be refreshed via yo_digital",
                            )

                return (
                    False,
                    f"Persona token expired (expired at {time.ctime(expires_at)})",
                )

        # Valid persona token
        return True, "Has valid persona token"

    def get_auth_details(self, context) -> Dict[str, Any]:
        """
        Provide Magenta2-specific auth details.
        Shows status of all token scopes.
        """
        details = {}

        # Check all token scopes
        for scope in self.token_scopes:
            token = context.get_token(self.provider_name, scope, self.country)

            if not token:
                details[scope] = {"available": False}
                continue

            scope_info = {"available": True}

            # Handle persona token specially
            if scope == "persona":
                if "expires_at" in token:
                    current_time = time.time()
                    expires_at = token["expires_at"]
                    scope_info["expires_at"] = expires_at
                    scope_info["is_expired"] = current_time >= expires_at
                    scope_info["time_remaining"] = int(max(0, expires_at - current_time))

                if "composed_at" in token:
                    scope_info["composed_at"] = token["composed_at"]

            # Handle yo_digital token
            elif scope == "yo_digital":
                if "access_token_expires_in" in token and "access_token_issued_at" in token:
                    current_time = time.time()
                    expires_at = token["access_token_issued_at"] + token["access_token_expires_in"]
                    scope_info["access_token_expires_at"] = expires_at
                    scope_info["access_token_is_expired"] = current_time >= expires_at

                if "refresh_token_expires_in" in token and "refresh_token_issued_at" in token:
                    current_time = time.time()
                    refresh_expires_at = (
                        token["refresh_token_issued_at"] + token["refresh_token_expires_in"]
                    )
                    scope_info["refresh_token_expires_at"] = refresh_expires_at
                    scope_info["refresh_token_is_expired"] = current_time >= refresh_expires_at
                    scope_info["has_refresh_token"] = True

            # Standard token handling (tvhubs, taa)
            else:
                if "expires_in" in token and "issued_at" in token:
                    current_time = time.time()
                    expires_at = token["issued_at"] + token["expires_in"]
                    scope_info["expires_at"] = expires_at
                    scope_info["is_expired"] = current_time >= expires_at

            details[scope] = scope_info

        return details

    def debug_authentication(self) -> Dict[str, Any]:
        """
        Debug authentication state and token flow

        Returns comprehensive information about the current authentication state,
        token availability, and TokenFlowManager status.
        """
        result: Dict[str, Any] = {
            "provider": {
                "provider_name": self.provider_name,
                "country": self.country,
                "platform": self.platform,
            }
        }

        # Try to get current persona token status
        try:
            persona_token = self.get_persona_token(force_refresh=False)
            persona_info: Dict[str, Any] = {
                "available": True,
                "length": len(persona_token),
                "preview": persona_token[:50] + "...",
            }

            # Try to extract and verify the JWT inside
            try:
                persona_jwt = self._extract_persona_jwt_from_token(persona_token)
                persona_info["jwt_available"] = bool(persona_jwt)
                if persona_jwt:
                    persona_info["jwt_length"] = len(persona_jwt)
                    persona_info["jwt_preview"] = persona_jwt[:50] + "..."
            except Exception as e:
                persona_info["jwt_extraction_error"] = str(e)

            result["persona_token"] = persona_info

        except Exception as e:
            result["persona_token"] = {"available": False, "error": str(e)}

        # TokenFlowManager status
        if (
            hasattr(self.authenticator, "token_flow_manager")
            and self.authenticator.token_flow_manager
        ):
            result["token_flow_manager"] = {
                "available": True,
                "token_status": self.authenticator.token_flow_manager.get_token_status(),
            }
        else:
            result["token_flow_manager"] = {
                "available": False,
                "error": "TokenFlowManager not initialized",
            }

        # Authenticator capabilities
        if hasattr(self.authenticator, "get_authentication_capabilities"):
            result["authentication_capabilities"] = (
                self.authenticator.get_authentication_capabilities()
            )

        # Endpoint manager info
        if self.endpoint_manager:
            result["endpoints"] = {
                "has_taa_auth": self.endpoint_manager.has_endpoint("taa_auth"),
                "has_entitlement": self.endpoint_manager.has_endpoint("entitlement"),
                "has_widevine_license": self.endpoint_manager.has_endpoint("widevine_license"),
                "has_mpx_selector": self.endpoint_manager.has_endpoint("mpx_selector"),
                "total_endpoints": len(self.endpoint_manager.get_all_endpoints()),
            }

        # SAM3 client status
        if hasattr(self.authenticator, "get_sam3_client_status"):
            result["sam3_client"] = self.authenticator.get_sam3_client_status()

        return result