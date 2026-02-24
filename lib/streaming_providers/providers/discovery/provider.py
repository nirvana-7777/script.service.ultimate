# streaming_providers/providers/discovery/provider.py
"""
Discovery+ Streaming Provider

Provides access to Discovery+ live channels and VOD content with proper
authentication, DRM support, and channel management.
"""
import json
import time
import uuid
import secrets
import base64
from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Any

from ...base.models import DRMConfig, DRMSystem, LicenseConfig
from ...base.models.proxy_models import ProxyConfig
from ...base.models.streaming_channel import StreamingChannel
from ...base.provider import AuthType, StreamingProvider
from ...base.utils.logger import logger

from .auth import (
    DiscoveryAuthenticator,
    DiscoveryAnonymousCredentials,
    DiscoveryUserCredentials,
)
from .constants import (
    DEFAULT_COUNTRY,
    DEFAULT_TENANT,
    DEFAULT_PLATFORM_OS,
    DISCOVERY_LOGO,
    DRMSystem as DiscoveryDRMSystem,
    DRM_SYSTEM_PLAYREADY,
    PlatformOS,
    SUPPORTED_AUTH_TYPES,
    SUPPORTED_COUNTRIES,
    CMS_INCLUDE_PARAMS,
    CMS_PAGE_SIZE,
    CHANNEL_COLLECTIONS,
    CHANNEL_ITEM_TYPES,
    get_default_capabilities,
    get_default_device_info,
    get_device_info_template,
    get_disco_client,
    get_drm_request_headers,
    get_user_agent,
)
from .exceptions import (
    PlaybackRestrictedException,
    ChannelNotFoundError,
    ManifestFetchError,
)
from .models import DiscoveryChannel


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
    """

    # ============================================================================
    # STATIC METADATA
    # ============================================================================
    PROVIDER_LABEL: ClassVar[str] = "Discovery+"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = SUPPORTED_AUTH_TYPES
    PROVIDER_LOGO: ClassVar[str] = DISCOVERY_LOGO
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = SUPPORTED_COUNTRIES

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
                         LINUX  → Widevine + Chrome on Linux (original behaviour)
                         WINDOWS → PlayReady + Edge on Windows

        Raises:
            ValueError: If country not supported or credentials missing
        """
        if not self.validate_country(country):
            supported = ", ".join(self.SUPPORTED_COUNTRIES)
            raise ValueError(
                f"Unsupported country: {country}. Discovery+ supports: {supported}"
            )

        super().__init__(country=country)

        # OS platform used for all device/header/DRM spoofing
        self.platform_os: PlatformOS = platform_os if platform_os is not None else DEFAULT_PLATFORM_OS

        self.auth_type = auth_type
        self._settings_manager = settings_manager

        # Provider cache for DiscoveryChannel objects
        self._channels_cache: Dict[str, DiscoveryChannel] = {}

        # Playback info cache: {edit_id: (expiry_timestamp, playback_data)}
        # Entries are valid until expiry_timestamp (derived from drm_expiration,
        # or 23 hours from fetch time as a safe fallback for the 24h token window).
        self._playback_cache: Dict[str, tuple] = {}

        # Setup HTTP manager using abstraction
        self.http_manager = self._setup_http_manager(
            provider_name="discovery",
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=get_user_agent(self.platform_os),
            timeout=30,
            max_retries=3,
        )

        # Create appropriate credentials.
        # Priority:
        #   1. Explicit username/password passed at construction time
        #   2. Stored user credentials from CredentialManager (same /config path
        #      the authenticator uses — does not depend on injected settings_manager)
        #   3. Anonymous fallback
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
                logger.debug(f"Could not load stored credentials via CredentialManager: {e}")

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

        # Create authenticator with dynamic endpoint discovery.
        # settings_manager is intentionally not passed so the authenticator
        # self-constructs its own SettingsManager via the backward-compat path,
        # identical to how JoynAuthenticator works. This ensures it always
        # resolves the correct /config path via the environment variable.
        self.authenticator = DiscoveryAuthenticator(
            country=country,
            settings_manager=None,
            config_dir=config_dir,
            http_manager=self.http_manager,
            proxy_config=self.http_manager.config.proxy_config,
            credentials=self.credentials,
        )

        # Authenticate
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

    @property
    def provider_name(self) -> str:
        """Provider identifier"""
        return "discovery"

    @property
    def provider_label(self) -> str:
        """Return country-specific label"""
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
        """Provider logo URL"""
        return self.PROVIDER_LOGO

    @property
    def supported_auth_types(self) -> List[str]:
        """Supported authentication types"""
        return self.SUPPORTED_AUTH_TYPES

    @property
    def uses_dynamic_manifests(self) -> bool:
        """Discovery+ uses session-based manifests"""
        return True

    @property
    def implements_epg(self) -> bool:
        """Discovery+ does not implement native EPG"""
        return False

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication"""
        return self._build_provider_headers(
            base_headers={
                "User-Agent": get_user_agent(self.platform_os),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            auth_type=AuthType.BEARER,
        )

    def authenticate(self, **kwargs) -> str:
        """Authenticate and return bearer token"""
        self.bearer_token = self.authenticator.get_bearer_token(
            force_refresh=kwargs.get("force_refresh", False)
        )
        self.token_info = self.authenticator.get_token_info()
        return self.bearer_token

    def refresh_authentication(self) -> str:
        """Force refresh authentication"""
        return self.authenticate(force_refresh=True)

    def is_anonymous(self) -> bool:
        """Check if using anonymous authentication"""
        if self.token_info:
            return self.token_info.get("anonymous", True)
        return True

    def get_channels(
            self,
            fetch_manifests: bool = False,
            populate_streaming_data: bool = True,
            **kwargs,
    ) -> List[StreamingChannel]:
        """
        Fetch available channels from Discovery+ CMS.

        Args:
            fetch_manifests: Whether to immediately populate streaming data
            populate_streaming_data: Whether to populate streaming data
            **kwargs: Additional parameters

        Returns:
            List of StreamingChannel objects
        """
        try:
            headers = self._get_auth_headers()

            # Fetch home route with all needed includes
            url = self.authenticator.cms_home_endpoint
            params = {
                "include": CMS_INCLUDE_PARAMS,
                "decorators": "viewingHistory,isFavorite,contentAction,badges",
                "page[items.size]": CMS_PAGE_SIZE,
            }

            response = self.http_manager.get(
                url,
                operation="cms",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            data = response.json()

            # Extract channels and cache DiscoveryChannel objects
            discovery_channels = self._extract_distribution_channels(data)

            # Cache the original DiscoveryChannel objects
            self._channels_cache = {
                ch.channel_id: ch for ch in discovery_channels
            }

            # Convert to StreamingChannel objects
            streaming_channels = [
                ch.to_streaming_channel(self.provider_name)
                for ch in discovery_channels
            ]

            logger.info(
                f"Found {len(streaming_channels)} distribution channels"
            )

            # Populate streaming data if requested
            if fetch_manifests and populate_streaming_data and streaming_channels:
                streaming_channels = self.populate_streaming_data(
                    streaming_channels
                )

            return streaming_channels

        except Exception as e:
            logger.error(f"Error fetching channels: {e}")
            return []

    def _extract_distribution_channels(
            self, data: Dict
    ) -> List[DiscoveryChannel]:
        """
        Extract distributionChannel objects from CMS response.

        Args:
            data: Parsed JSON response from CMS home route

        Returns:
            List of DiscoveryChannel objects (not StreamingChannel!)
        """
        channels = []

        # Build lookup of included items by ID and type
        included_by_id = {}
        for item in data.get("included", []):
            item_id = item.get("id")
            item_type = item.get("type")
            if item_id and item_type:
                key = f"{item_type}:{item_id}"
                included_by_id[key] = item

        # Find all distributionChannel objects in included
        for item in data.get("included", []):
            if item.get("type") == "distributionChannel":
                channel = self._create_discovery_channel_from_distribution(
                    item, included_by_id
                )
                if channel:
                    channels.append(channel)

        return channels

    @staticmethod
    def _create_discovery_channel_from_distribution(
            distribution_data: Dict,
            included_by_id: Dict
    ) -> Optional[DiscoveryChannel]:
        """
        Create a DiscoveryChannel from distributionChannel object.

        Args:
            distribution_data: The distributionChannel object from CMS
            included_by_id: Lookup dictionary of all included items

        Returns:
            DiscoveryChannel object or None if invalid
        """
        try:
            # Use the factory method from DiscoveryChannel
            discovery_channel = DiscoveryChannel.from_distribution_data(
                distribution_data, included_by_id
            )

            logger.debug(
                f"Created channel: {discovery_channel.name} "
                f"(edit_id: {discovery_channel.edit_id})"
            )

            return discovery_channel

        except Exception as e:
            logger.error(
                f"Error creating channel from distribution data: {e}"
            )
            return None

    def _build_playback_payload(self, edit_id: str) -> Dict[str, Any]:
        """
        Build playback payload for the API.

        Args:
            edit_id: Content edit ID

        Returns:
            Playback request payload
        """
        # Generate Google PAL nonce
        nonce = secrets.token_bytes(256)
        google_pal_nonce = base64.b64encode(nonce).decode('ascii')

        return {
            "appBundle": "dplus",
            "advertisingInfo": {
                "adBlockerDetection": False,
                "debug": {},
                "device": {},
                "googlePALNonce": google_pal_nonce,
                "server": {
                    "deviceId": "",
                    "iabTCFString": "",
                    "isLimitedAdTracking": 0,
                    "nielsenAppId": "",
                },
                "ssaiProvider": {"version": "2.2.0"},
            },
            "consumptionType": "streaming",
            "deviceInfo": get_default_device_info(self.platform_os),
            "editId": edit_id,
            "capabilities": get_default_capabilities(self.platform_os),
            "gdpr": False,
            "firstPlay": False,
            "playbackSessionId": str(uuid.uuid4()),
            "applicationSessionId": str(uuid.uuid4()),
            "userPreferences": {
                "videoQuality": "best",
                "uiLanguage": f"{self.country}-DE".upper()
            },
            "features": ["mlp"],
        }

    def get_playback_info(self, edit_id: str, **kwargs) -> Dict:
        """
        Get playback information using edit_id.

        Args:
            edit_id: Edit ID for content
            **kwargs: Additional parameters

        Returns:
            Playback info dictionary

        Raises:
            ValueError: If edit_id not provided
            PlaybackRestrictedException: If playback restricted
        """
        if not edit_id:
            raise ValueError("edit_id is required for playback")

        headers = self._get_auth_headers()
        payload = self._build_playback_payload(edit_id)

        try:
            response = self.http_manager.post(
                self.authenticator.playback_endpoint,
                operation="playback",
                headers=headers,
                json=payload,
                timeout=30,
            )

            if response.status_code >= 400:
                error_text = response.text
                logger.error(f"Playback error response: {error_text}")
                if "PLAYBACK_RESTRICTED" in error_text:
                    raise PlaybackRestrictedException(
                        reason=f"Playback restricted for {edit_id}",
                        error_code="PLAYBACK_RESTRICTED"
                    )
                response.raise_for_status()

            response.raise_for_status()
            return response.json()

        except PlaybackRestrictedException:
            raise
        except Exception as e:
            raise ManifestFetchError(
                f"Error getting playback info for edit_id {edit_id}: {e}"
            )

    def _get_cached_playback_info(self, edit_id: str) -> Dict:
        """
        Return playback info for edit_id, using a cache keyed on expiry time.

        Tokens issued by Discovery+ are valid for 24 hours. The cache entry
        is kept until the drm_expiration timestamp returned in the response
        (minus a 60-second safety margin). If no expiration is present in the
        response, a fallback TTL of 23 hours is used.

        Args:
            edit_id: Content edit ID

        Returns:
            Playback info dictionary (from cache or freshly fetched)
        """
        now = time.time()
        cached = self._playback_cache.get(edit_id)

        if cached:
            expiry, data = cached
            if now < expiry:
                logger.debug(
                    f"Playback cache hit for edit_id {edit_id} "
                    f"(expires in {int(expiry - now)}s)"
                )
                return data
            else:
                logger.debug(f"Playback cache expired for edit_id {edit_id}, re-fetching")

        data = self.get_playback_info(edit_id=edit_id)

        # Determine expiry from drm_expiration field if available
        expiry = None
        try:
            drm_expiration_str = (
                data.get("drm", {}).get("expirationDate")
            )
            if drm_expiration_str:
                from datetime import timezone
                dt = datetime.fromisoformat(
                    drm_expiration_str.replace("Z", "+00:00")
                )
                # Apply a 60-second safety margin
                expiry = dt.timestamp() - 60
        except Exception as e:
            logger.debug(f"Could not parse drm_expiration: {e}")

        if expiry is None or expiry <= now:
            # Fallback: 23 hours from now
            expiry = now + 23 * 3600
            logger.debug(
                f"Using fallback 23h TTL for playback cache (edit_id: {edit_id})"
            )

        self._playback_cache[edit_id] = (expiry, data)
        logger.debug(
            f"Playback cache stored for edit_id {edit_id} "
            f"(expires in {int(expiry - now)}s)"
        )
        return data

    @staticmethod
    def extract_streaming_data(playback_data: Dict) -> Dict[str, Any]:
        """
        Extract streaming URLs and DRM info from playback response.

        Detects whichever DRM scheme is present in the response — either
        'widevine' (Linux/Chrome) or 'playready' (Windows/Edge) — and
        records it as ``drm_system`` so callers can build the correct DRMConfig
        without needing to know the active PlatformOS.

        Args:
            playback_data: Playback API response

        Returns:
            Dictionary with:
              manifest_url     – DASH manifest URL
              license_url      – DRM license server URL (or None)
              drm_system       – 'widevine' | 'playready' | None
              drm_auth         – JWT auth token extracted from license URL (or None)
              streaming_format – 'dash' (always for Discovery+)
              drm_expiration   – ISO-8601 expiration string (or None)
              fallback_manifest – Fallback manifest URL (or None)
        """
        result = {
            "manifest_url": None,
            "license_url": None,
            "drm_system": None,
            "drm_auth": None,
            "streaming_format": "dash",
            "drm_expiration": None,
            "fallback_manifest": None,
        }

        try:
            # Extract main manifest
            manifest = playback_data.get("manifest", {})
            if manifest:
                result["manifest_url"] = manifest.get("url")
                result["streaming_format"] = manifest.get("format", "dash")

            # Extract fallback manifest if available
            fallback = playback_data.get("fallback", {})
            if fallback:
                fallback_manifest = fallback.get("manifest", {})
                if fallback_manifest:
                    result["fallback_manifest"] = fallback_manifest.get("url")

            # Extract DRM info — check both schemes in priority order.
            # The server returns exactly the scheme(s) matching the capabilities
            # we advertised in the playback request (widevine for Linux,
            # playready for Windows). We probe both so this method stays
            # stateless and works regardless of which platform produced the response.
            drm = playback_data.get("drm", {})
            if drm:
                result["drm_expiration"] = drm.get("expirationDate")
                schemes = drm.get("schemes", {})

                # Preference order: widevine → playready (mirrors Linux default)
                scheme_priority = ["widevine", "playready"]
                for scheme_name in scheme_priority:
                    scheme = schemes.get(scheme_name, {})
                    if scheme and scheme.get("licenseUrl"):
                        result["license_url"] = scheme["licenseUrl"]
                        result["drm_system"] = scheme_name

                        # Extract JWT auth token from the license URL if present
                        if "auth=" in result["license_url"]:
                            import urllib.parse
                            parsed = urllib.parse.urlparse(result["license_url"])
                            query = urllib.parse.parse_qs(parsed.query)
                            if "auth" in query:
                                result["drm_auth"] = query["auth"][0]
                        break  # Stop at first found scheme

            # Extract CDN info
            cdn = playback_data.get("cdn", {})
            if cdn:
                result["cdn_provider"] = cdn.get("provider")

        except Exception as e:
            logger.error(f"Error extracting streaming data: {e}")

        return result

    def _build_drm_config(self, streaming_data: Dict[str, Any]) -> Optional[DRMConfig]:
        """
        Build a DRMConfig from extracted streaming data.

        Selects the correct DRMSystem based on the scheme returned by the
        server (recorded in ``streaming_data["drm_system"]``).  Falls back to
        the active ``self.platform_os`` when the scheme is absent so the caller
        never has to make this decision themselves.

        Supported schemes:
          'widevine'  → DRMSystem.WIDEVINE  (Linux/Chrome path)
          'playready' → DRMSystem.PLAYREADY (Windows/Edge path)

        Args:
            streaming_data: Dictionary returned by extract_streaming_data()

        Returns:
            DRMConfig instance or None if no license URL is available
        """
        license_url = streaming_data.get("license_url")
        if not license_url:
            return None

        # Resolve DRM system from what the server actually returned,
        # falling back to platform_os expectation if not present.
        drm_system_str = streaming_data.get("drm_system")
        if drm_system_str == "playready":
            drm_system = DRMSystem.PLAYREADY
        elif drm_system_str == "widevine":
            drm_system = DRMSystem.WIDEVINE
        else:
            # Fallback: derive from active platform
            drm_system = (
                DRMSystem.PLAYREADY
                if self.platform_os == PlatformOS.WINDOWS
                else DRMSystem.WIDEVINE
            )
            logger.debug(
                f"drm_system not in streaming_data, inferred from platform_os "
                f"({self.platform_os.value}): {drm_system.name}"
            )

        license_headers = get_drm_request_headers(self.platform_os)

        return DRMConfig(
            system=drm_system,
            priority=1,
            license=LicenseConfig(
                server_url=license_url,
                req_headers=json.dumps(license_headers),
                req_data="{CHA-RAW}",
                use_http_get_request=False,
            ),
        )

    def populate_streaming_data(
            self,
            channels: List[StreamingChannel],
            max_retries: int = 3,
    ) -> List[StreamingChannel]:
        """
        Populate streaming data for channels using cached DiscoveryChannel data.

        Args:
            channels: List of StreamingChannel objects to populate
            max_retries: Maximum retry attempts per channel

        Returns:
            List of successfully populated channels
        """
        successful_channels = []

        for channel in channels:
            retries = 0
            success = False
            is_restricted = False

            while retries < max_retries and not success and not is_restricted:
                try:
                    # Get DiscoveryChannel from cache
                    disco_channel = self._channels_cache.get(channel.channel_id)

                    if not disco_channel:
                        logger.warning(
                            f"Channel {channel.name} not in cache, skipping"
                        )
                        break

                    # Get edit_id from cached DiscoveryChannel
                    edit_id = disco_channel.edit_id

                    if not edit_id:
                        logger.warning(
                            f"No edit_id for channel {channel.name}, skipping"
                        )
                        break

                    logger.debug(
                        f"Getting playback info for: {channel.name} "
                        f"(edit_id: {edit_id}, attempt {retries + 1})"
                    )

                    playback_data = self._get_cached_playback_info(edit_id=edit_id)
                    streaming_data = self.extract_streaming_data(playback_data)

                    if streaming_data["manifest_url"]:
                        channel.manifest = streaming_data["manifest_url"]
                        channel.streaming_format = streaming_data["streaming_format"]

                        if streaming_data["license_url"]:
                            drm_config = self._build_drm_config(streaming_data)
                            if drm_config:
                                channel.drm_config = drm_config
                            channel.license_url = streaming_data["license_url"]
                            channel.cdm_type = streaming_data["drm_system"]

                            # Store DRM token in DiscoveryChannel cache
                            if streaming_data["drm_auth"]:
                                disco_channel.raw_data["drm_auth"] = (
                                    streaming_data["drm_auth"]
                                )

                        logger.info(
                            f"Streaming data populated for: {channel.name}"
                        )
                        successful_channels.append(channel)
                        success = True
                    else:
                        raise ManifestFetchError("No manifest URL in response")

                except PlaybackRestrictedException as e:
                    logger.warning(
                        f"Playback restricted for {channel.name}: {e}"
                    )
                    is_restricted = True

                except Exception as e:
                    retries += 1
                    if retries < max_retries:
                        logger.debug(
                            f"Retry {retries}/{max_retries} for "
                            f"{channel.name}: {e}"
                        )
                        time.sleep(1)
                    else:
                        logger.error(
                            f"Failed to get streaming data for "
                            f"{channel.name}: {e}"
                        )

        logger.info(
            f"Streaming data population complete: "
            f"{len(successful_channels)}/{len(channels)}"
        )
        return successful_channels

    def enrich_channel_data(
            self,
            channel: StreamingChannel,
            **kwargs
    ) -> Optional[StreamingChannel]:
        """
        Get manifest URL for a specific channel and properly configure DRM.

        Args:
            channel: StreamingChannel to enrich
            **kwargs: Additional parameters

        Returns:
            Enriched StreamingChannel or None if failed
        """
        try:
            # Get DiscoveryChannel from cache
            disco_channel = self._channels_cache.get(channel.channel_id)

            if not disco_channel:
                logger.warning(
                    f"Channel {channel.name} not in cache, cannot enrich"
                )
                return None

            edit_id = disco_channel.edit_id

            if not edit_id:
                logger.warning(f"No edit_id found for channel {channel.name}")
                return None

            playback_data = self._get_cached_playback_info(edit_id=edit_id)
            streaming_data = self.extract_streaming_data(playback_data)

            if not streaming_data["manifest_url"]:
                return None

            channel.manifest = streaming_data["manifest_url"]
            channel.streaming_format = streaming_data["streaming_format"]

            # Configure DRM if license URL is present
            if streaming_data["license_url"]:
                drm_config = self._build_drm_config(streaming_data)
                if drm_config:
                    channel.drm_config = drm_config
                channel.cdm_type = streaming_data["drm_system"]

            return channel

        except Exception as e:
            logger.error(
                f"Error enriching channel data for {channel.name}: {e}"
            )
            return None

    def get_manifest(self, channel_id: str, **kwargs) -> Optional[str]:
        """
        Get manifest URL for a specific channel by ID.

        Args:
            channel_id: Channel identifier
            **kwargs: Additional parameters

        Returns:
            Manifest URL or None

        Raises:
            ChannelNotFoundError: If channel not in cache
        """
        try:
            # Get DiscoveryChannel from cache
            disco_channel = self._channels_cache.get(channel_id)

            if not disco_channel:
                raise ChannelNotFoundError(channel_id)

            edit_id = disco_channel.edit_id

            if not edit_id:
                raise ManifestFetchError(
                    f"No edit_id for channel {channel_id}"
                )

            playback_data = self._get_cached_playback_info(edit_id=edit_id)
            streaming_data = self.extract_streaming_data(playback_data)
            return streaming_data.get("manifest_url")

        except (ChannelNotFoundError, ManifestFetchError):
            raise
        except Exception as e:
            logger.error(
                f"Error getting manifest for channel {channel_id}: {e}"
            )
            return None

    def get_drm(self, channel_id: str, **kwargs) -> List[DRMConfig]:
        """
        Get all DRM configurations for a channel by ID.

        Args:
            channel_id: Channel identifier
            **kwargs: Additional parameters

        Returns:
            List of DRM configurations
        """
        try:
            # Get DiscoveryChannel from cache
            disco_channel = self._channels_cache.get(channel_id)

            if not disco_channel:
                logger.warning(
                    f"Channel {channel_id} not in cache for DRM"
                )
                return []

            edit_id = disco_channel.edit_id

            if not edit_id:
                return []

            playback_data = self._get_cached_playback_info(edit_id=edit_id)
            streaming_data = self.extract_streaming_data(playback_data)

            if not streaming_data["license_url"]:
                return []

            drm_config = self._build_drm_config(streaming_data)
            return [drm_config] if drm_config else []

        except Exception as e:
            logger.error(
                f"Error getting DRM configs for channel {channel_id}: {e}"
            )
            return []

    def get_epg(
            self,
            channel_id: str,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Dict]:
        """
        Get EPG data for a channel (not yet implemented).

        Args:
            channel_id: Channel identifier
            start_time: Start time for EPG data
            end_time: End time for EPG data
            **kwargs: Additional parameters

        Returns:
            Empty list (not implemented)
        """
        logger.info(
            f"EPG data requested for channel {channel_id} - "
            "not yet implemented"
        )
        return []