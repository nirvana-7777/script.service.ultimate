# streaming_providers/providers/magenta2/provider.py
# -*- coding: utf-8 -*-
"""
Magenta2 streaming provider.

This module contains only lifecycle, authentication, and the thin public API
that delegates to the three domain managers:

    ChannelManager  – channel discovery, entitlement, streaming-data population
    PlaybackManager – manifest / DRM routing (live fast-path + SMIL fallback)
    VodManager      – VOD catalogue browsing
    RecordingsManager – nPVR (list / delete / manifest)
    SmilManager     – SMIL-based manifest and DRM for VOD / recordings
"""
import uuid
from datetime import datetime, timedelta
from typing import Any, ClassVar, Dict, List, Optional, Tuple, cast
from urllib.parse import quote

from ...base.models import DRMConfig, StreamingChannel, Event
from ...base.models.auth import AuthState
from ...base.models.proxy_models import ProxyConfig
from ...base.network import HTTPManagerFactory, ProxyConfigManager
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from .recordings_manager import RecordingsManager
from .smil_manager import SmilManager
from .vod_manager import VodManager
from .auth import Magenta2Authenticator, Magenta2Credentials, Magenta2UserCredentials
from .channel_manager import ChannelManager
from .playback_manager import PlaybackManager
from .config_models import BootstrapConfig, ProviderConfig
from .constants import (
    CONTENT_TYPE_LIVE,
    DEFAULT_COUNTRY,
    DEFAULT_EPG_WINDOW_HOURS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PLATFORM,
    DEFAULT_REQUEST_TIMEOUT,
    MAGENTA2_CLIENT_IDS,
    MAGENTA2_LOGO,
    MAGENTA2_PLATFORMS,
    SUPPORTED_COUNTRIES,
)
from .discovery import DiscoveryService
from .endpoint_manager import EndpointManager
from .models import Magenta2PlaybackRestrictedException  # noqa: F401 – re-exported
from .auth_bridge import AuthBridge


class Magenta2Provider(StreamingProvider):
    PROVIDER_LABEL: ClassVar[str] = "Magenta TV 2.0"
    PROVIDER_LOGO: ClassVar[str] = MAGENTA2_LOGO
    """
    Magenta2 streaming provider implementation with enhanced dynamic discovery.
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

        # Stable UUIDs for the lifetime of this provider instance.
        self.session_id = self._generate_uuid()
        self.device_id = self._generate_uuid()
        self.serial_number = self._generate_uuid()

        # ── Proxy ────────────────────────────────────────────────────────────
        self.proxy_config = (
            proxy_config
            or (ProxyConfig.from_url(proxy_url) if proxy_url else None)
            or self._load_proxy_from_manager(config_dir)
        )
        if self.proxy_config:
            logger.info("Using proxy configuration for Magenta2")
        else:
            logger.debug("No proxy configuration found for Magenta2")

        # ── HTTP manager ─────────────────────────────────────────────────────
        self.http_manager = HTTPManagerFactory.create_for_provider(
            provider_name="magenta2",
            proxy_config=self.proxy_config,
            user_agent=self.platform_config["user_agent"],
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES,
        )

        # ── Discovery service ────────────────────────────────────────────────
        self.discovery_service = DiscoveryService(
            platform=platform,
            terminal_type=self.terminal_type,
            device_id=self.device_id,
            session_id=self.session_id,
            http_manager=self.http_manager,
            proxy_config=self.proxy_config,
        )

        # Both are assigned concrete values by _perform_configuration_discovery()
        # (or _create_fallback_configuration()) before __init__ returns.  We use
        # cast(None) as a typed sentinel so the class-level annotation stays
        # non-Optional -- callers and other methods see EndpointManager /
        # ProviderConfig directly, with no Optional unwrapping needed.
        self.endpoint_manager = cast(EndpointManager, cast(object, None))
        self.provider_config = cast(ProviderConfig, cast(object, None))

        # ── Authenticator (minimal config; updated after discovery) ──────────
        fallback_client_id = MAGENTA2_CLIENT_IDS.get(
            platform, MAGENTA2_CLIENT_IDS[DEFAULT_PLATFORM]
        )

        if username and password:
            credentials: Magenta2Credentials | Magenta2UserCredentials = (
                Magenta2UserCredentials(
                    client_id=fallback_client_id,
                    platform=platform,
                    country=country,
                    device_id=self.device_id,
                    username=username,
                    password=password,
                )
            )
            logger.info("Using user credentials for authentication")
        else:
            credentials = Magenta2Credentials(
                client_id=fallback_client_id,
                platform=platform,
                country=country,
                device_id=self.device_id,
            )
            logger.info("Using client credentials for authentication")

        self.authenticator = Magenta2Authenticator(
            country=country,
            platform=platform,
            config_dir=config_dir,
            http_manager=self.http_manager,
            credentials=credentials,
            endpoints={},
            client_model=f"ftv-{platform}",
            device_model=f"{platform.upper()}_FTV",
            sam3_client_id=fallback_client_id,
            session_id=self.session_id,
            device_id=self.device_id,
            provider_config=None,
        )

        # ── Configuration discovery ──────────────────────────────────────────
        # _perform_configuration_discovery always assigns self.endpoint_manager
        # and self.provider_config (either from discovery or from the fallback).
        # Re-raise so callers see the error; do NOT silently swallow it.
        try:
            self._perform_configuration_discovery()
        except Exception as e:
            logger.error(f"Configuration discovery failed: {e}")
            raise

        # ── Update authenticator with discovered config ───────────────────────
        self._configure_authenticator_from_discovery(self.provider_config, self.endpoint_manager)

        # ── recording content_id → manifest_script; shared with PlaybackManager ──
        self._recording_url_cache: Dict[str, str] = {}

        # ── Domain managers ──────────────────────────────────────────────────
        self._vod_manager: Optional[VodManager] = None
        self._recordings_manager: Optional[RecordingsManager] = None
        self._smil_manager: Optional[SmilManager] = None

        self._vod_manager = VodManager(
            http_manager=self.http_manager,
            provider_name=self.provider_name,
            bootstrap=self.endpoint_manager.config.bootstrap,
            provider_config=self.endpoint_manager.config,
            session_id=self.session_id,
            serial_number=self.serial_number,
            auth_headers_callback=self._vod_auth_headers,
        )
        logger.info("✓ VodManager initialized")

        self._recordings_manager = RecordingsManager(
            http_manager=self.http_manager,
            provider_name=self.provider_name,
            provider_config=self.endpoint_manager.config,
            auth_headers_callback=self._pvr_auth_headers,
        )
        logger.info("✓ RecordingsManager initialized")

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
        logger.info("✓ SmilManager initialized")

        self._channel_manager = ChannelManager(
            http_manager=self.http_manager,
            provider_name=self.provider_name,
            country=country,
            platform_config=self.platform_config,
            session_id=self.session_id,
            serial_number=self.serial_number,
            endpoint_manager=self.endpoint_manager,
            provider_config=self.provider_config,
            auth_callback=self._ensure_authenticated,
            build_scaled_image_url_callback=self._build_scaled_image_url,
            catchup_window=self.catchup_window,
        )
        logger.info("✓ ChannelManager initialized")

        self._playback_manager = PlaybackManager(
            channel_manager=self._channel_manager,
            smil_manager=self._smil_manager,
            endpoint_manager=self.endpoint_manager,
            provider_config=self.provider_config,
            platform_config=self.platform_config,
            auth_callback=self._ensure_authenticated,
            recording_url_cache=self._recording_url_cache,
        )
        logger.info("✓ PlaybackManager initialized")

        # ── Auth bridge ───────────────────────────────────────────────────────
        self.device_token = None
        self._auth = AuthBridge(
            authenticator=self.authenticator,
            provider_name=self.provider_name,
            country=self.country,
            platform=self.platform,
            platform_config=self.platform_config,
            provider_config=self.provider_config,
            session_id=self.session_id,
            serial_number=self.serial_number,
            generate_call_id=self._generate_call_id,
        )

        logger.info("Magenta2 provider initialization completed successfully")

    # ------------------------------------------------------------------ #
    # Static / utility                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _generate_uuid() -> str:
        return str(uuid.uuid4())

    def _generate_call_id(self) -> str:
        return self._generate_uuid()

    def _load_proxy_from_manager(self, config_dir: Optional[str]) -> Optional[ProxyConfig]:
        try:
            proxy_manager = ProxyConfigManager(config_dir)
            return proxy_manager.get_proxy_config("magenta2", self.country)
        except Exception as e:
            logger.warning(f"Could not load proxy from ProxyConfigManager: {e}")
            return None

    # ------------------------------------------------------------------ #
    # Provider properties                                                  #
    # ------------------------------------------------------------------ #

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

    # ------------------------------------------------------------------ #
    # Configuration discovery                                              #
    # ------------------------------------------------------------------ #

    def _perform_configuration_discovery(self) -> None:
        """
        Run discovery and initialise EndpointManager.

        Always sets both self.provider_config and self.endpoint_manager — either
        from the live discovery result or from the fallback (via
        _create_fallback_configuration).  Callers may therefore assert both are
        non-None after this method returns without raising.
        """
        logger.info("Performing Magenta2 configuration discovery")
        try:
            self.provider_config = self.discovery_service.discover_provider_config()

            if not self.provider_config or not self.provider_config.is_complete:
                logger.warning("Configuration discovery incomplete, some features may not work")

            self.endpoint_manager = EndpointManager(self.provider_config)

            qr_url = self.endpoint_manager.get_endpoint("login_qr_code")
            if qr_url:
                logger.info(f"✓ QR code endpoint discovered: {qr_url}")
                if hasattr(self.authenticator, "update_sam3_qr_code_url"):
                    success = self.authenticator.update_sam3_qr_code_url(qr_url)
                    logger.info(
                        "✓ SAM3 client updated with QR code URL"
                        if success
                        else "✗ Failed to update SAM3 client with QR code URL"
                    )
                if hasattr(self.authenticator, "get_sam3_client_status"):
                    logger.debug(
                        f"SAM3 client status: {self.authenticator.get_sam3_client_status()}"
                    )
            else:
                logger.warning("✗ QR code endpoint NOT found")

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
                        f"✓ MPX account PID discovered: "
                        f"{self.provider_config.manifest.mpx.account_pid}"
                    )

            missing_endpoints = self.endpoint_manager.validate_critical_endpoints()
            if missing_endpoints:
                logger.warning(f"Missing critical endpoints: {missing_endpoints}")
            else:
                logger.info("All critical endpoints available")

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
        """Create minimal fallback configuration when discovery fails."""
        logger.warning("Creating fallback configuration")
        bootstrap_config = BootstrapConfig(
            client_model=f"ftv-{self.platform}",
            device_model=f"{self.platform.upper()}_FTV",
        )
        self.provider_config = ProviderConfig(bootstrap=bootstrap_config)
        self.endpoint_manager = EndpointManager(self.provider_config)
        logger.info("Fallback configuration created")

    def _configure_authenticator_from_discovery(
        self,
        cfg: ProviderConfig,
        endpoint_manager: EndpointManager,
    ) -> None:
        """
        Push discovered config values (client_id, models, device token, MPX PID,
        endpoints) into the authenticator and its TokenFlowManager.

        Parameters are passed explicitly (not read from self) so the type checker
        knows they are non-None.
        """
        self.authenticator.provider_config = cfg
        logger.info("✓ ProviderConfig stored in authenticator")

        if (
            hasattr(self.authenticator, "token_flow_manager")
            and self.authenticator.token_flow_manager
        ):
            self.authenticator.token_flow_manager.provider_config = cfg
            logger.info("✓ ProviderConfig stored in TokenFlowManager")

        if cfg.bootstrap.sam3_client_id:
            if hasattr(self.authenticator, "update_sam3_client_id"):
                self.authenticator.update_sam3_client_id(cfg.bootstrap.sam3_client_id)
            else:
                self.authenticator._sam3_client_id = cfg.bootstrap.sam3_client_id
            if self.authenticator.credentials:
                self.authenticator.credentials.client_id = cfg.bootstrap.sam3_client_id
            logger.debug(
                f"Updated authenticator SAM3 client ID: {cfg.bootstrap.sam3_client_id}"
            )

        if cfg.bootstrap.client_model:
            if hasattr(self.authenticator, "update_client_model"):
                self.authenticator.update_client_model(cfg.bootstrap.client_model)
            else:
                self.authenticator._client_model = cfg.bootstrap.client_model
            logger.debug(f"Updated authenticator client model: {cfg.bootstrap.client_model}")

        if cfg.bootstrap.device_model:
            if hasattr(self.authenticator, "update_device_model"):
                self.authenticator.update_device_model(cfg.bootstrap.device_model)
            else:
                self.authenticator._device_model = cfg.bootstrap.device_model
            logger.debug(f"Updated authenticator device model: {cfg.bootstrap.device_model}")

        if cfg.manifest:
            device_token = cfg.get_device_token()
            authorize_tokens_url = cfg.get_authorize_tokens_url()
            if device_token:
                self.authenticator.set_device_token(device_token, authorize_tokens_url)
                logger.debug("Device token configured in authenticator")
            if cfg.manifest.mpx.account_pid:
                self.authenticator.set_mpx_account_pid(cfg.manifest.mpx.account_pid)
                logger.debug(f"MPX account PID configured: {cfg.manifest.mpx.account_pid}")
            if cfg.openid:
                self.authenticator.set_openid_config(cfg.openid.raw_data)

        all_endpoints = {
            name: info.url
            for name, info in endpoint_manager.get_all_endpoints().items()
        }
        if hasattr(self.authenticator, "update_dynamic_endpoints"):
            self.authenticator.update_dynamic_endpoints(all_endpoints)
            logger.info(f"✓ Updated authenticator with {len(all_endpoints)} endpoints")
        elif hasattr(self.authenticator, "update_endpoints"):
            self.authenticator.update_endpoints(all_endpoints)
            logger.info(f"✓ Updated authenticator with {len(all_endpoints)} endpoints")
        else:
            logger.warning("No public method available to update endpoints")

        qr_url = endpoint_manager.get_endpoint("login_qr_code")
        if qr_url and hasattr(self.authenticator, "update_sam3_qr_code_url"):
            success = self.authenticator.update_sam3_qr_code_url(qr_url)
            logger.info(
                "✓ SAM3 client updated with QR code URL"
                if success
                else "✗ Failed to update SAM3 client with QR code URL"
            )

    def get_discovery_status(self) -> Dict[str, Any]:
        """Return discovery and endpoint statistics."""
        if not self.discovery_service:
            return {"error": "Discovery service not initialized"}
        status = self.discovery_service.get_discovery_status()
        status["endpoints"] = self.endpoint_manager.get_stats()
        return status

    def refresh_configuration(self, force: bool = False) -> bool:
        """Re-run configuration discovery."""
        try:
            logger.info("Refreshing provider configuration")
            new_config = self.discovery_service.discover_provider_config(force_refresh=force)

            if new_config and new_config.is_complete:
                self.provider_config = new_config
                self.endpoint_manager = EndpointManager(new_config)

                if new_config.manifest:
                    device_token: Any = new_config.manifest.raw_data.get("deviceToken")
                    authorize_tokens_url: Any = new_config.manifest.raw_data.get(
                        "authorizeTokensUrl"
                    )
                    if device_token:
                        self.authenticator.set_device_token(device_token, authorize_tokens_url)
                    if new_config.manifest.mpx.account_pid:
                        self.authenticator.set_mpx_account_pid(
                            new_config.manifest.mpx.account_pid
                        )

                self._auth.update_provider_config(new_config)
                logger.info("Configuration refresh successful")
                return True
            else:
                logger.warning("Configuration refresh incomplete")
                return False

        except Exception as e:
            logger.error(f"Configuration refresh failed: {e}")
            return False

    def register_device(self) -> bool:
        """Perform device registration / authentication."""
        try:
            logger.info("Performing device registration")
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

    # ------------------------------------------------------------------ #
    # Authentication — thin delegates to AuthBridge                        #
    # ------------------------------------------------------------------ #

    def get_persona_token(self, force_refresh: bool = False) -> str:
        """Return a valid persona token (cached). Delegates to AuthBridge."""
        return self._auth.get_persona_token(force_refresh=force_refresh)

    def _ensure_authenticated(self) -> str:
        """Return a valid persona token (lazy auth). Delegates to AuthBridge."""
        return self._auth.ensure_authenticated()

    def clear_persona_cache(self) -> None:
        """Discard the in-memory persona token cache. Delegates to AuthBridge."""
        self._auth.clear_persona_cache()

    def _vod_auth_headers(self) -> Dict[str, str]:
        """Build auth headers for VOD endpoints. Delegates to AuthBridge."""
        return self._auth.vod_auth_headers()

    def _pvr_auth_headers(self) -> Dict[str, str]:
        """Build auth headers for nPVR endpoints. Delegates to AuthBridge."""
        return self._auth.pvr_auth_headers()

    # ------------------------------------------------------------------ #
    # Image scaling                                                        #
    # ------------------------------------------------------------------ #

    def _build_scaled_image_url(self, original_url: str) -> Optional[str]:
        """Return a scaled logo URL using the image scaling service."""
        if not original_url:
            return None
        if not self.provider_config or not self.provider_config.manifest:
            return original_url

        image_config = self.provider_config.manifest.image_config
        if not image_config.scaling_base_url or not image_config.scaling_call_parameter:
            return original_url

        call_params: Dict[str, str] = {}
        for param in image_config.scaling_call_parameter.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                call_params[key] = value

        base_url = image_config.scaling_base_url.rstrip("/")
        params = {**call_params, "x": "120", "y": "42", "ar": "keep", "src": original_url}
        query_string = "&".join([f"{k}={quote(v, safe='')}" for k, v in params.items()])
        return f"{base_url}/iss?{query_string}"

    # ------------------------------------------------------------------ #
    # Header helpers                                                       #
    # ------------------------------------------------------------------ #

    def _get_dcm_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.platform_config["user_agent"],
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-dt-session-id": self.session_id,
            "x-dt-call-id": self._generate_call_id(),
        }

    def _get_api_headers(self, require_auth: bool = False) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "User-Agent": self.platform_config["user_agent"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if require_auth:
            persona_token = self._ensure_authenticated()
            headers["Authorization"] = f"Basic {persona_token}"
        return headers

    # ------------------------------------------------------------------ #
    # Public StreamingProvider API                                         #
    # ------------------------------------------------------------------ #

    def get_dynamic_manifest_params(
        self, channel: StreamingChannel, **kwargs: Any
    ) -> Optional[str]:
        return None

    def get_channels(
        self,
        time_window_hours: int = DEFAULT_EPG_WINDOW_HOURS,
        fetch_manifests: bool = False,
        populate_streaming_data: bool = True,
        prefer_highest_quality: bool = True,
        **kwargs: Any,
    ) -> List[StreamingChannel]:
        return self._channel_manager.get_channels(
            time_window_hours=time_window_hours,
            fetch_manifests=fetch_manifests,
            populate_streaming=populate_streaming_data,
            prefer_highest_quality=prefer_highest_quality,
            **kwargs,
        )

    def get_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kwargs: Any,
    ) -> List[Event]:
        return []

    def get_manifest(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs: Any
    ) -> Optional[str]:
        return self._playback_manager.get_manifest(content_id, content_type, **kwargs)

    def get_drm(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs: Any
    ) -> List[DRMConfig]:
        return self._playback_manager.get_drm(content_id, content_type, **kwargs)

    def get_catchup_manifest(
        self, content_id: str, start_time: int, end_time: int, drm_variant: Optional[str] = "auto", **kwargs: Any
    ) -> Optional[str]:
        return self._playback_manager.get_catchup_manifest(
            content_id, start_time, end_time, drm_variant, **kwargs
        )

    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kwargs: Any,
    ) -> Any:
        """Return children of a VOD node (empty string → root)."""
        if not self._vod_manager:
            raise RuntimeError(
                "VodManager not available — configuration discovery may have failed"
            )
        return self._vod_manager.get_children(
            content_id=content_id,
            cursor=cursor,
            page_size=page_size,
            **kwargs,
        )

    def search_vod(
            self,
            query: str,
            cursor: Optional[str] = None,
            page_size: int = 24,
            **kwargs: Any,
    ) -> Any:
        """Search the VOD catalogue. Delegates to VodManager.search()."""
        if not self._vod_manager:
            raise RuntimeError(
                "VodManager not available — configuration discovery may have failed"
            )
        return self._vod_manager.search(
            query=query,
            cursor=cursor,
            page_size=page_size,
            **kwargs,
        )

    def get_recordings(self, include_deleted: bool = False, **kwargs: Any) -> Any:
        """Return a list of Recording objects from the nPVR backend."""
        if not self._recordings_manager:
            raise RuntimeError(
                "RecordingsManager not available — configuration discovery may have failed"
            )
        recordings = self._recordings_manager.get_recordings(
            include_deleted=include_deleted, **kwargs
        )
        for rec in recordings:
            if rec.content_id and rec.manifest_script:
                self._recording_url_cache[rec.content_id] = rec.manifest_script
        return recordings

    def delete_recording(self, recording_id: str, **kwargs: Any) -> None:
        if not self._recordings_manager:
            raise RuntimeError(
                "RecordingsManager not available — configuration discovery may have failed"
            )
        self._recordings_manager.delete_recording(recording_id)

    def get_recording_manifest(self, recording_id: str, **kwargs: Any) -> Optional[str]:
        """Return the playback URL for a recording by ID (fresh API lookup)."""
        if not self._recordings_manager:
            return None
        return self._recordings_manager.get_recording_manifest(recording_id)

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        """Fetch EPG data for a channel."""
        try:
            if start_time is None:
                start_time = datetime.now()
            if end_time is None:
                end_time = datetime.now() + timedelta(hours=DEFAULT_EPG_WINDOW_HOURS)

            headers = self._get_api_headers(require_auth=False)
            url: str = (
                self.endpoint_manager.get_endpoint("epg")
                or "https://api.magentatv.de/proxy/device/epg"
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
            return response.json()  # type: ignore[no-any-return]
        except Exception as e:
            logger.error(f"Error getting EPG for channel {channel_id}: {e}")
            return []

    # ------------------------------------------------------------------ #
    # Auth state / readiness introspection                                 #
    # ------------------------------------------------------------------ #

    def _calculate_auth_state(self, context: Any) -> AuthState:
        """Delegates to AuthBridge."""
        return self._auth.calculate_auth_state(context)

    def _calculate_readiness(self, context: Any) -> Tuple[bool, str]:
        """Delegates to AuthBridge."""
        return self._auth.calculate_readiness(context)

    def get_auth_details(self, context: Any) -> Dict[str, Any]:
        """Delegates to AuthBridge."""
        return self._auth.get_auth_details(self.token_scopes, context)

    def debug_authentication(self) -> Dict[str, Any]:
        """Return comprehensive auth-state and token-flow diagnostic info."""
        result: Dict[str, Any] = {
            "provider": {
                "provider_name": self.provider_name,
                "country": self.country,
                "platform": self.platform,
            }
        }

        try:
            persona_token = self.get_persona_token(force_refresh=False)
            persona_info: Dict[str, Any] = {
                "available": True,
                "length": len(persona_token),
                "preview": persona_token[:50] + "...",
            }
            try:
                persona_jwt = PlaybackManager.extract_persona_jwt_from_token(persona_token)
                persona_info["jwt_available"] = bool(persona_jwt)
                if persona_jwt:
                    persona_info["jwt_length"] = len(persona_jwt)
                    persona_info["jwt_preview"] = persona_jwt[:50] + "..."
            except Exception as e:
                persona_info["jwt_extraction_error"] = str(e)
            result["persona_token"] = persona_info
        except Exception as e:
            result["persona_token"] = {"available": False, "error": str(e)}

        tfm = getattr(self.authenticator, "token_flow_manager", None)
        if tfm is not None:
            result["token_flow_manager"] = {
                "available": True,
                "token_status": tfm.get_token_status(),
            }
        else:
            result["token_flow_manager"] = {
                "available": False,
                "error": "TokenFlowManager not initialized",
            }

        if hasattr(self.authenticator, "get_authentication_capabilities"):
            result["authentication_capabilities"] = (
                self.authenticator.get_authentication_capabilities()
            )

        result["endpoints"] = {
            "has_taa_auth": self.endpoint_manager.has_endpoint("taa_auth"),
            "has_entitlement": self.endpoint_manager.has_endpoint("entitlement"),
            "has_widevine_license": self.endpoint_manager.has_endpoint("widevine_license"),
            "has_mpx_selector": self.endpoint_manager.has_endpoint("mpx_selector"),
            "total_endpoints": len(self.endpoint_manager.get_all_endpoints()),
        }

        if hasattr(self.authenticator, "get_sam3_client_status"):
            result["sam3_client"] = self.authenticator.get_sam3_client_status()

        return result