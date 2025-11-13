# streaming_providers/providers/magenta2/discovery.py
import time
from typing import Dict, Optional, Any

from ...base.network import HTTPManager
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .config_models import BootstrapConfig, ManifestConfig, OpenIDConfig, ProviderConfig
from .constants import (
    MAGENTA2_BOOTSTRAP_URL,
    MAGENTA2_MANIFEST_URL,
    SUBSCRIBER_TYPES,
    DEFAULT_REQUEST_TIMEOUT,
    BOOTSTRAP_CACHE_DURATION,
    OPENID_CONFIG_CACHE_DURATION
)


class DiscoveryService:
    """
    Service for dynamic discovery of Magenta2 endpoints and configuration
    """

    def __init__(self, platform: str, terminal_type: str, device_id: str, session_id: str,
                 http_manager: HTTPManager, proxy_config: Optional[ProxyConfig] = None):
        self.platform = platform
        self.terminal_type = terminal_type
        self.device_id = device_id
        self.session_id = session_id
        self.http_manager = http_manager
        self.proxy_config = proxy_config
        self.subscriber_type = SUBSCRIBER_TYPES.get(platform, 'FTV_OTT_DT')

        # Cache storage
        self._bootstrap_config: Optional[BootstrapConfig] = None
        self._manifest_config: Optional[ManifestConfig] = None
        self._openid_config: Optional[OpenIDConfig] = None
        self._last_bootstrap: Optional[float] = None
        self._last_manifest: Optional[float] = None
        self._last_openid: Optional[float] = None

    def discover_provider_config(self, force_refresh: bool = False) -> ProviderConfig:
        """
        Perform complete provider configuration discovery

        Returns:
            ProviderConfig: Complete provider configuration
        """
        logger.info("Starting Magenta2 provider configuration discovery")

        try:
            # Step 1: Bootstrap discovery
            bootstrap_config = self.discover_bootstrap(force_refresh)
            if not bootstrap_config:
                raise Exception("Bootstrap discovery failed - cannot proceed")

            # Step 2: Manifest discovery (includes device token)
            manifest_config = self.discover_manifest(force_refresh)

            # IMPORTANT: Update bootstrap with manifest data
            if manifest_config:
                bootstrap_config.update_from_manifest(manifest_config)

                # Log device token status
                device_token = manifest_config.get_device_token()
                if device_token:
                    logger.info("✓ Device token obtained from manifest")
                else:
                    logger.warning("⚠️ No device token found in manifest")

            # Step 3: OpenID discovery (if bootstrap provided OpenID config URL)
            openid_config = None
            if bootstrap_config.openid_config_url:
                try:
                    openid_config = self.discover_openid_config(force_refresh)
                except Exception as e:
                    logger.warning(f"OpenID discovery failed: {e}")

            provider_config = ProviderConfig(
                bootstrap=bootstrap_config,
                manifest=manifest_config,
                openid=openid_config
            )

            # Log MPX account info for persona token composition
            if manifest_config and manifest_config.mpx:
                account_uri = manifest_config.mpx.get_account_uri()
                logger.info(f"✓ MPX account URI for persona token: {account_uri}")

            return provider_config

        except Exception as e:
            logger.error(f"Configuration discovery failed: {e}")
            self._create_fallback_configuration()
            raise

    def discover_bootstrap(self, force_refresh: bool = False) -> Optional[BootstrapConfig]:
        """
        Discover bootstrap configuration

        Returns:
            BootstrapConfig: Bootstrap configuration, None if failed
        """
        # Check cache
        if not force_refresh and self._bootstrap_config and self._last_bootstrap:
            cache_age = time.time() - self._last_bootstrap
            if cache_age < BOOTSTRAP_CACHE_DURATION:
                logger.debug("Using cached bootstrap configuration")
                return self._bootstrap_config

        try:
            logger.info("Discovering bootstrap configuration")

            terminal_type = self.terminal_type.lower().replace('_', '-')
            url = MAGENTA2_BOOTSTRAP_URL.format(terminal_type=terminal_type)

            params = {
                'deviceid': self.device_id,
                'sid': self.session_id,
                '$redirect': 'false'
            }

            headers = self._get_dcm_headers()

            response = self.http_manager.get(
                url,
                operation='bootstrap',
                headers=headers,
                params=params,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            bootstrap_data = response.json()
            self._bootstrap_config = BootstrapConfig.from_api_response(bootstrap_data, self.platform)
            self._last_bootstrap = time.time()

            logger.info(
                f"Bootstrap discovery successful: "
                f"clientModel={self._bootstrap_config.client_model}, "
                f"deviceModel={self._bootstrap_config.device_model}"
            )

            # Log critical endpoints
            if self._bootstrap_config.taa_url:
                logger.debug(f"TAA URL: {self._bootstrap_config.taa_url}")
            if self._bootstrap_config.device_tokens_url:
                logger.debug(f"Device tokens URL: {self._bootstrap_config.device_tokens_url}")

            return self._bootstrap_config

        except Exception as e:
            logger.error(f"Bootstrap discovery failed: {e}")
            # Don't cache failed attempts
            self._bootstrap_config = None
            self._last_bootstrap = None
            return None

    def discover_manifest(self, force_refresh: bool = False) -> Optional[ManifestConfig]:
        """
        ENHANCED: Discover manifest configuration including device token
        Uses correct manifest endpoint parameters

        Returns:
            ManifestConfig: Manifest configuration, None if failed
        """
        # Check cache
        if not force_refresh and self._manifest_config and self._last_manifest:
            cache_age = time.time() - self._last_manifest
            if cache_age < BOOTSTRAP_CACHE_DURATION:
                logger.debug("Using cached manifest configuration")
                return self._manifest_config

        try:
            logger.info("Discovering manifest configuration")

            # Determine manifest URL - prefer device_tokens_url from bootstrap
            if self._bootstrap_config and self._bootstrap_config.device_tokens_url:
                manifest_url = self._bootstrap_config.device_tokens_url
                logger.debug(f"Using bootstrap device_tokens_url for manifest: {manifest_url}")
            else:
                terminal_type = self.terminal_type.lower().replace('_', '-')
                manifest_url = MAGENTA2_MANIFEST_URL.format(terminal_type=terminal_type)
                logger.debug(f"Using fallback manifest URL: {manifest_url}")

            # Build correct manifest parameters
            from .constants import (
                MAGENTA2_APP_NAME,
                MAGENTA2_APP_VERSION,
                MAGENTA2_RUNTIME_VERSION,
                MANIFEST_MODEL_MAPPINGS,
                MANIFEST_FIRMWARE_MAPPINGS
            )

            params = {
                'model': MANIFEST_MODEL_MAPPINGS.get(self.platform, 'DT:ATV-AndroidTV'),
                'deviceId': self.device_id,
                'appname': MAGENTA2_APP_NAME,
                'appVersion': MAGENTA2_APP_VERSION,
                'firmware': MANIFEST_FIRMWARE_MAPPINGS.get(self.platform, 'API level 30'),
                'runtimeVersion': MAGENTA2_RUNTIME_VERSION,
                'duid': self.device_id  # Same as deviceId
            }

            logger.debug(f"Manifest request params: {params}")

            headers = self._get_dcm_headers()

            response = self.http_manager.get(
                manifest_url,
                operation='manifest_discovery',
                headers=headers,
                params=params,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            manifest_data = response.json()
            self._manifest_config = ManifestConfig.from_api_response(manifest_data)
            self._last_manifest = time.time()

            # ENHANCED: Log device token and critical auth info
            device_token = self._manifest_config.get_device_token()
            authorize_tokens_url = self._manifest_config.get_authorize_tokens_url()

            if device_token:
                logger.info("✓ Device token found in manifest")
                logger.debug(f"Device token preview: {device_token[:20]}...{device_token[-10:]}")
            else:
                logger.warning("⚠️ Device token NOT found in manifest response")

            if authorize_tokens_url:
                logger.debug(f"Authorize tokens URL: {authorize_tokens_url}")

            # Log MPX account info (critical for persona token)
            mpx_account_pid = self._manifest_config.mpx.account_pid
            account_uri = self._manifest_config.mpx.get_account_uri()
            logger.info(f"MPX account PID: {mpx_account_pid}")
            logger.info(f"MPX account URI: {account_uri}")

            logger.info(
                f"Manifest discovery successful: "
                f"MPX account={mpx_account_pid}, "
                f"DRM endpoints={len([k for k in self._manifest_config.drm.__dict__.keys() if self._manifest_config.drm.__dict__[k]])}, "
                f"TV hubs={len(self._manifest_config.tv_hubs.base_urls)}"
            )

            return self._manifest_config

        except Exception as e:
            logger.error(f"Manifest discovery failed: {e}")
            # Don't cache failed attempts
            self._manifest_config = None
            self._last_manifest = None
            return None

    def discover_openid_config(self, force_refresh: bool = False) -> Optional[OpenIDConfig]:
        """
        Discover OpenID Connect configuration

        Returns:
            OpenIDConfig: OpenID configuration, None if failed
        """
        # Check cache
        if not force_refresh and self._openid_config and self._last_openid:
            cache_age = time.time() - self._last_openid
            if cache_age < OPENID_CONFIG_CACHE_DURATION:
                logger.debug("Using cached OpenID configuration")
                return self._openid_config

        try:
            if not self._bootstrap_config or not self._bootstrap_config.openid_config_url:
                logger.warning("No OpenID config URL available from bootstrap")
                return None

            logger.info("Discovering OpenID configuration")

            openid_url = self._bootstrap_config.openid_config_url

            response = self.http_manager.get(
                openid_url,
                operation='openid_discovery',
                headers={'Accept': 'application/json'},
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            openid_data = response.json()
            self._openid_config = OpenIDConfig.from_api_response(openid_data)
            self._last_openid = time.time()

            logger.info(f"OpenID discovery successful: token_endpoint={self._openid_config.token_endpoint}")
            return self._openid_config

        except Exception as e:
            logger.error(f"OpenID discovery failed: {e}")
            # Don't cache failed attempts
            self._openid_config = None
            self._last_openid = None
            return None

    def _get_dcm_headers(self) -> Dict[str, str]:
        """Get headers for DCM requests"""
        from .constants import MAGENTA2_PLATFORMS, DEFAULT_PLATFORM

        platform_config = MAGENTA2_PLATFORMS.get(self.platform, MAGENTA2_PLATFORMS[DEFAULT_PLATFORM])

        return {
            'User-Agent': platform_config['user_agent'],
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'x-dt-session-id': self.session_id,
            'x-dt-call-id': self._generate_call_id()
        }

    @staticmethod
    def _generate_call_id() -> str:
        """Generate call ID for requests"""
        import uuid
        return str(uuid.uuid4())

    def get_discovery_status(self) -> Dict[str, Any]:
        """Get discovery service status"""
        status = {
            'bootstrap_available': self._bootstrap_config is not None,
            'manifest_available': self._manifest_config is not None,
            'openid_available': self._openid_config is not None,
        }

        if self._bootstrap_config:
            status['bootstrap'] = {
                'client_model': self._bootstrap_config.client_model,
                'device_model': self._bootstrap_config.device_model,
                'has_device_tokens_url': bool(self._bootstrap_config.device_tokens_url),
                'has_openid_config_url': bool(self._bootstrap_config.openid_config_url),
                'has_taa_url': bool(self._bootstrap_config.taa_url),
            }

        if self._manifest_config:
            device_token = self._manifest_config.get_device_token()
            status['manifest'] = {
                'mpx_account_pid': self._manifest_config.mpx.account_pid,
                'mpx_account_uri': self._manifest_config.mpx.get_account_uri(),
                'feed_count': len(self._manifest_config.mpx.feeds),
                'has_device_token': bool(device_token),
                'device_token_preview': device_token[:20] + '...' if device_token else None,
                'drm_endpoints': {
                    'widevine': bool(self._manifest_config.drm.widevine_license_url),
                    'vod_widevine': bool(self._manifest_config.drm.vod_widevine_license_url),
                    'fairplay': bool(self._manifest_config.drm.fairplay_license_url),
                },
                'tvhub_count': len(self._manifest_config.tv_hubs.base_urls),
            }

        if self._openid_config:
            status['openid'] = {
                'has_token_endpoint': bool(self._openid_config.token_endpoint),
                'has_authorization_endpoint': bool(self._openid_config.authorization_endpoint),
            }

        # Cache status
        now = time.time()
        status['cache'] = {
            'bootstrap_age': now - self._last_bootstrap if self._last_bootstrap else None,
            'manifest_age': now - self._last_manifest if self._last_manifest else None,
            'openid_age': now - self._last_openid if self._last_openid else None,
        }

        return status

    def clear_cache(self) -> None:
        """Clear all discovery cache"""
        self._bootstrap_config = None
        self._manifest_config = None
        self._openid_config = None
        self._last_bootstrap = None
        self._last_manifest = None
        self._last_openid = None
        logger.info("Discovery cache cleared")