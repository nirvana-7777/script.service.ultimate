# streaming_providers/providers/discovery/provider.py
"""
Discovery+ Streaming Provider

Thin orchestrator that wires together the three domain managers:
  - DiscoveryChannelManager   (channel extraction + CMS route discovery)
  - DiscoveryEventManager     (sport schedule / live event fetching)
  - DiscoveryPlaybackManager  (playback tokens, manifest extraction, DRM)

All heavy logic lives in those managers.  This class owns the shared caches,
handles authentication, and exposes the public StreamingProvider interface.
"""
from datetime import datetime
from typing import ClassVar, Dict, List, Optional

from ...base.models.proxy_models import ProxyConfig
from ...base.models import DRMConfig, StreamingChannel, Event
from ...base.provider import AuthType, StreamingProvider
from ...base.utils.logger import logger

from .auth import (
    DiscoveryAuthenticator,
    DiscoveryAnonymousCredentials,
    DiscoveryUserCredentials,
)
from .channel_manager import DiscoveryChannelManager
from .constants import (
    DEFAULT_COUNTRY,
    DEFAULT_PLATFORM_OS,
    DISCOVERY_LOGO,
    DISCOVERY_USERS_ME_URL,
    PlatformOS,
    SUPPORTED_AUTH_TYPES,
    SUPPORTED_COUNTRIES,
    get_user_agent,
)
from .event_manager import DiscoveryEventManager
from .exceptions import ManifestFetchError
from .models import DiscoveryChannel
from .playback_manager import DiscoveryPlaybackManager


class DiscoveryProvider(StreamingProvider):
    """
    Discovery+ streaming provider implementation with dynamic endpoint discovery.

    Features:
    - Multi-country support (EMEA region)
    - Anonymous and user authentication
    - Live channels and VOD content
    - DRM-protected streams (Widevine on Linux, PlayReady on Windows)
    - OS platform spoofing via PlatformOS (see constants.DEFAULT_PLATFORM_OS)
    - Provider cache pattern for efficient channel management
    - Dynamic CMS route discovery from ``/home`` navigation graph

    Delegates to three managers:
      channel_manager  — channel extraction, CMS route discovery
      event_manager    — sport schedule / live event fetching
      playback_manager — playback tokens, manifest & DRM extraction
    """

    # =========================================================================
    # STATIC METADATA
    # =========================================================================
    PROVIDER_LABEL: ClassVar[str] = "Discovery+"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = SUPPORTED_AUTH_TYPES
    PROVIDER_LOGO: ClassVar[str] = DISCOVERY_LOGO
    SUPPORTED_COUNTRIES: ClassVar[str] = SUPPORTED_COUNTRIES  # "*" = all countries

    def __init__(
            self,
            country: str = DEFAULT_COUNTRY,
            auth_type: str = "anonymous",
            username: Optional[str] = None,
            password: Optional[str] = None,
            config_dir: Optional[str] = None,
            settings_manager=None,
            proxy_config: Optional[ProxyConfig] = None,
            proxy_url: Optional[str] = None,
            platform_os: Optional[PlatformOS] = None,
    ):
        """
        Initialize Discovery+ provider.

        Args:
            country: Country code (e.g., 'de', 'uk', 'at')
            auth_type: Authentication type ("anonymous" or "user_credentials")
            username: Username (required for user_credentials)
            password: Password (required for user_credentials)
            config_dir: Optional config directory override
            settings_manager: Settings manager instance
            proxy_config: Optional proxy configuration
            proxy_url: Optional proxy URL string
            platform_os: OS platform to spoof (PlatformOS.LINUX or PlatformOS.WINDOWS).
                         Defaults to DEFAULT_PLATFORM_OS from constants.
                         LINUX  → Widevine + Chrome on Linux
                         WINDOWS → PlayReady + Edge on Windows

        Raises:
            ValueError: If country not supported or credentials missing
        """
        if not self.validate_country(country):
            raise ValueError(
                f"Unsupported country: {country}. "
                f"Provide a valid ISO-3166-1 alpha-2 country code (e.g. 'de', 'uk')."
            )

        super().__init__(country=country)

        self.platform_os: PlatformOS = (
            platform_os if platform_os is not None else DEFAULT_PLATFORM_OS
        )
        self.auth_type = auth_type
        self._settings_manager = settings_manager

        # ------------------------------------------------------------------
        # Shared caches (owned here; passed by reference into each manager)
        # ------------------------------------------------------------------
        # DiscoveryChannel objects keyed by edit_id (the playback identifier)
        self._channels_cache: Dict[str, DiscoveryChannel] = {}
        # Navigation routes discovered from /home: { route_id: label }
        self._cms_routes: Dict[str, str] = {}
        # Playback info cache: { edit_id: (expiry_timestamp, playback_data) }
        self._playback_cache: Dict[str, tuple] = {}

        # ------------------------------------------------------------------
        # HTTP manager
        # ------------------------------------------------------------------
        self.http_manager = self._setup_http_manager(
            provider_name="discovery",
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=get_user_agent(self.platform_os),
            timeout=30,
            max_retries=3,
        )

        # ------------------------------------------------------------------
        # Credentials
        # Priority:
        #   1. Explicit username/password passed at construction time
        #   2. Stored user credentials from CredentialManager
        #   3. Anonymous fallback
        # ------------------------------------------------------------------
        if auth_type == "user_credentials":
            if not username or not password:
                raise ValueError(
                    "Username and password required for user_credentials auth"
                )
            self.credentials = DiscoveryUserCredentials(
                username=username,
                password=password,
            )
        else:
            stored = None
            try:
                from ...base.auth.credential_manager import CredentialManager
                _cm = CredentialManager(config_dir=config_dir)
                stored = _cm.load_credentials("discovery", country)
                logger.debug(
                    f"CredentialManager lookup for discovery ({country}): "
                    f"{type(stored).__name__ if stored else 'None'}"
                )
            except Exception as e:
                logger.debug(
                    f"Could not load stored credentials via CredentialManager: {e}"
                )

            if stored and stored.validate() and hasattr(stored, "username"):
                logger.info(
                    f"Found stored user credentials for discovery ({country}), "
                    "upgrading from anonymous to user authentication"
                )
                self.credentials = DiscoveryUserCredentials(
                    username=stored.username,
                    password=stored.password,
                )
                self.auth_type = "user_credentials"
            else:
                logger.debug(
                    f"No stored user credentials found for discovery ({country}), "
                    "using anonymous authentication"
                )
                self.credentials = DiscoveryAnonymousCredentials()

        # ------------------------------------------------------------------
        # Authenticator
        # ------------------------------------------------------------------
        _device_id = None
        if self._settings_manager:
            try:
                _device_id = self._settings_manager.get_device_id(
                    "discovery", country
                )
                logger.debug(f"Resolved device_id from settings: {_device_id}")
            except Exception as e:
                logger.debug(
                    f"Could not resolve device_id from settings: {e}"
                )

        self.authenticator = DiscoveryAuthenticator(
            country=country,
            settings_manager=None,
            config_dir=config_dir,
            http_manager=self.http_manager,
            proxy_config=self.http_manager.config.proxy_config,
            credentials=self.credentials,
            platform_os=self.platform_os,
            device_id=_device_id,
        )

        try:
            self.bearer_token = self.authenticator.get_bearer_token()
            self.token_info = self.authenticator.get_token_info()
            logger.info(f"Authentication successful (type: {self.auth_type})")
        except Exception as e:
            logger.warning(
                f"Could not authenticate during initialization: {e}"
            )
            self.bearer_token = None
            self.token_info = None

        # ------------------------------------------------------------------
        # Domain managers — all share the same cache references
        # ------------------------------------------------------------------
        self.channel_manager = DiscoveryChannelManager(
            provider=self,
            channels_cache=self._channels_cache,
            cms_routes=self._cms_routes,
        )
        self.event_manager = DiscoveryEventManager(
            provider=self,
            channels_cache=self._channels_cache,
            cms_routes=self._cms_routes,
        )
        self.playback_manager = DiscoveryPlaybackManager(
            provider=self,
            playback_cache=self._playback_cache,
        )

        # Eagerly discover CMS routes so get_events() works even if
        # get_channels() has not been called first.
        self.channel_manager.init_cms_routes()

    # =========================================================================
    # Provider identity
    # =========================================================================

    @property
    def provider_name(self) -> str:
        return "discovery"

    @property
    def provider_label(self) -> str:
        country_map = {
            "de": "Discovery+ Germany",
            "at": "Discovery+ Austria",
            "ch": "Discovery+ Switzerland",
            "dk": "Discovery+ Denmark",
            "fi": "Discovery+ Finland",
            "no": "Discovery+ Norway",
            "se": "Discovery+ Sweden",
            "it": "Discovery+ Italy",
            "nl": "Discovery+ Netherlands",
            "es": "Discovery+ Spain",
            "uk": "Discovery+ UK",
            "ie": "Discovery+ Ireland",
        }
        return country_map.get(
            self.country,
            f"Discovery+ ({self.country.upper()})"
        )

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

    @property
    def uses_dynamic_manifests(self) -> bool:
        return True

    @property
    def implements_epg(self) -> bool:
        return False

    # =========================================================================
    # Authentication helpers
    # =========================================================================

    def get_auth_headers(self) -> Dict[str, str]:
        return self._build_provider_headers(
            base_headers={
                "User-Agent": get_user_agent(self.platform_os),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            auth_type=AuthType.BEARER,
        )

    def authenticate(self, **kwargs) -> str:
        self.bearer_token = self.authenticator.get_bearer_token(
            force_refresh=kwargs.get("force_refresh", False)
        )
        self.token_info = self.authenticator.get_token_info()
        return self.bearer_token

    def refresh_authentication(self) -> str:
        return self.authenticate(force_refresh=True)

    def is_anonymous(self) -> bool:
        if self.token_info:
            return self.token_info.get("anonymous", True)
        return True

    # =========================================================================
    # Country helpers
    # =========================================================================

    @classmethod
    def supports_multiple_countries(cls) -> bool:
        return cls.SUPPORTED_COUNTRIES == ["*"]

    @classmethod
    def validate_country(cls, country: str) -> bool:
        if cls.SUPPORTED_COUNTRIES == ["*"]:
            return bool(country and country.isalpha() and len(country) == 2)
        return country.lower() in [c.lower() for c in cls.SUPPORTED_COUNTRIES]

    def get_user_country(self) -> Optional[str]:
        """
        Detect the user's current country via the /users/me endpoint.

        Returns:
            Two-letter lowercase country code (e.g. ``"de"``) or None.
        """
        try:
            headers = self.get_auth_headers()
            response = self.http_manager.get(
                DISCOVERY_USERS_ME_URL,
                operation="users_me",
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
            territory = (
                data.get("data", {})
                    .get("attributes", {})
                    .get("currentLocationTerritory")
            )
            if territory:
                country_code = territory.lower()
                logger.debug(
                    f"Detected user country from /users/me: {country_code}"
                )
                return country_code
            logger.warning(
                "/users/me response missing currentLocationTerritory"
            )
            return None
        except Exception as e:
            logger.error(f"Failed to fetch user country from /users/me: {e}")
            return None

    # =========================================================================
    # Public StreamingProvider interface — delegates to managers
    # =========================================================================

    def get_channels(
            self,
            fetch_manifests: bool = False,
            populate_streaming_data: bool = True,
            **kwargs,
    ) -> List[StreamingChannel]:
        """Fetch available channels from the Discovery+ CMS."""
        return self.channel_manager.fetch_channels(
            fetch_manifests=fetch_manifests,
            populate_streaming_data=populate_streaming_data,
        )

    def get_events(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Event]:
        """Fetch sport schedule events from Discovery+."""
        return self.event_manager.fetch_events(
            start_time=start_time,
            end_time=end_time,
            **kwargs,
        )

    def populate_streaming_data(
            self,
            channels: List[StreamingChannel],
            max_retries: int = 3,
    ) -> List[StreamingChannel]:
        """Populate streaming data for a list of channels."""
        return self.playback_manager.populate_streaming_data(
            channels, max_retries=max_retries
        )

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        """
        Get manifest URL for a channel or event by ID.

        ``content_id`` is the ``edit_id`` (playback identifier), so it is
        passed directly to the playback manager — no cache indirection needed.
        """
        try:
            playback_data = self.playback_manager.get_cached_playback_info(
                edit_id=content_id
            )
            streaming_data = self.playback_manager.extract_streaming_data(
                playback_data
            )
            return streaming_data.get("manifest_url")
        except ManifestFetchError:
            raise
        except Exception as e:
            logger.error(
                f"Error getting manifest for {content_id}: {e}"
            )
            return None

    def get_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """
        Get all DRM configurations for a channel or event by ID.

        ``content_id`` is the ``edit_id`` (playback identifier), so it is
        passed directly to the playback manager — no cache indirection needed.
        """
        try:
            playback_data = self.playback_manager.get_cached_playback_info(
                edit_id=content_id
            )
            streaming_data = self.playback_manager.extract_streaming_data(
                playback_data
            )
            if not streaming_data["license_url"]:
                return []
            drm_config = self.playback_manager.build_drm_config(streaming_data)
            return [drm_config] if drm_config else []
        except Exception as e:
            logger.error(
                f"Error getting DRM configs for {content_id}: {e}"
            )
            return []

    def get_epg(
            self,
            channel_id: str,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Dict]:
        """Get EPG data for a channel (not yet implemented)."""
        logger.info(
            f"EPG data requested for channel {channel_id} — not yet implemented"
        )
        return []