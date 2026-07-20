# streaming_providers/providers/magentaeu/provider.py
# -*- coding: utf-8 -*-
import time
import datetime
from typing import ClassVar, Dict, List, Optional, Tuple

from ...base.auth import UserPasswordCredentials
from ...base.models import DRMConfig, StreamingChannel, Event
from ...base.models.epg_models import EPGEntry, EPGProgramDetails
from ...base.models.proxy_models import ProxyConfig
from ...base.network import ProxyConfigManager
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from ..lib_theplatform import (
    build_catchup_url,
    build_licence_url,
    build_widevine_drm_config,
    parse_bifrost_epg_channel,
)
from .auth import MagentaAuthenticator
from .epg_manager import MagentaEUEpgManager
from .constants import (
    API_ENDPOINTS,
    CONTENT_TYPE_LIVE,
    DEFAULT_COUNTRY,
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT,
    DRM_SYSTEM_WIDEVINE,
    MAGENTA_TV_AT_LOGO,
    MAGENTA_TV_PL_LOGO,
    MAX_TV_LOGO,
    STREAMING_FORMAT_DASH,
    SUPPORTED_COUNTRIES,
    USER_AGENT,
    WV_URL,
    get_base_url,
    get_bifrost_url,
    get_language,
    get_natco_key,
)


class MagentaEUProvider(StreamingProvider):
    # Provider constants with country-specific logos
    PROVIDER_LOGO_AT: ClassVar[str] = MAGENTA_TV_AT_LOGO
    PROVIDER_LOGO_PL: ClassVar[str] = MAGENTA_TV_PL_LOGO
    PROVIDER_LOGO_HR: ClassVar[str] = MAX_TV_LOGO

    PROVIDER_LOGO: ClassVar[str] = ""

    SUPPORTED_COUNTRIES = SUPPORTED_COUNTRIES

    def __init__(
        self,
        country: str = DEFAULT_COUNTRY,
        config_dir: Optional[str] = None,
        proxy_config: Optional[ProxyConfig] = None,
        proxy_url: Optional[str] = None,
    ):

        logger.info(f"=== MagentaProvider.__init__ START for country: {country} ===")
        if not self.validate_country(country):
            supported = ", ".join(self.SUPPORTED_COUNTRIES)
            raise ValueError(
                f"Unsupported country: {country}. " f"MagentaTV EU supports: {supported}"
            )
        super().__init__(country=country)

        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"Unsupported country: {country}")

        self.http_manager = self._setup_http_manager(
            provider_name="magentaeu",
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=USER_AGENT,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES,
#            use_tls_impersonation=(country == "hr"),  # HR bifrost enforces strict JA3 fingerprinting
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
            proxy_config=self.http_manager.config.proxy_config,
        )

        # EPG manager — owns all schedule fetch/parse logic
        self.epg_manager = MagentaEUEpgManager(
            country=country,
            http_manager=self.http_manager,
            authenticator=self.authenticator,
        )
        logger.info(f"=== MagentaProvider.__init__ COMPLETE ===")

    def _load_proxy_from_manager(self, config_dir: Optional[str]) -> Optional[ProxyConfig]:
        """Load proxy configuration from ProxyConfigManager"""
        try:
            proxy_manager = ProxyConfigManager(config_dir)
            return proxy_manager.get_proxy_config("magentaeu", self.country)
        except Exception as e:
            logger.warning(f"Could not load proxy from ProxyConfigManager: {e}")
            return None

    @property
    def provider_name(self) -> str:
        return "magentaeu"

    @property
    def provider_label(self) -> str:
        if self.country.lower() == "hr":
            return "Max TV (HR)"
        else:
            return f"Magenta TV ({self.country.upper()})"

    @property
    def provider_logo(self) -> str:
        """Instance property that returns country-specific logo."""
        return self.get_static_logo(self.country)

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    @property
    def epg_window(self) -> Tuple[int, int]:
        return 7, 7

    @property
    def catchup_window(self) -> int:
        # This provider offers 168 hours (7 days) of catchup
        return 168

    @property
    def supported_auth_types(self) -> List[str]:
        return ["user_credentials"]

    def authenticate(self, **kwargs) -> str:
        logger.info(f"=== MagentaProvider.authenticate() CALLED with kwargs: {kwargs} ===")
        self.bearer_token = self.authenticator.get_bearer_token(
            force_refresh=kwargs.get("force_refresh", False)
        )
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
            device_id, session_id = self.authenticator.get_guest_session_ids()

            channels_url = API_ENDPOINTS["EPG_CHANNELS"].format(
                bifrost_url=get_bifrost_url(self.country)
            )

            from .constants import build_guest_headers

            headers = build_guest_headers(
                self.country, device_id, session_id, flow="START_UP"
            )

            params = {
                "channelMap_id": "",
                "includeVirtualChannels": "false",
                "includeSyntheticChannels": "false",
                "natco_key": get_natco_key(self.country),
                "app_language": get_language(self.country),
                "natco_code": self.country,
            }

            logger.debug(f"Fetching channels with device_id: {device_id}, session_id: {session_id}")

            response = self.http_manager.get(
                channels_url,
                operation="channels",
                headers=headers,
                params=params,
                timeout=DEFAULT_REQUEST_TIMEOUT,
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
            if hasattr(e, "response") and hasattr(e.response, "text"):
                logger.error(f"Response content: {e.response.text}")
            raise Exception(f"Error fetching channels from Magenta TV: {e}")

    def _process_channels_response(self, response_data: Dict) -> List[StreamingChannel]:
        """Process channels response and convert to StreamingChannel objects"""
        if "channels" not in response_data:
            raise Exception("Invalid channels response structure")

        channels = []
        for channel_data in response_data["channels"]:
            try:
                tp_channel = parse_bifrost_epg_channel(channel_data)
                if not tp_channel:
                    continue

                title = channel_data.get("title", "Unknown Channel")
                logo = channel_data.get("channel_logo", "")
                media_pid = channel_data.get("media_pid", "")
                is_audio = channel_data.get("is_audio", False)

                catchup_hours = channel_data.get("CatchupHours", self.catchup_window)

                manifest_script_parts = []
                if tp_channel.channel_number:
                    manifest_script_parts.append(f"chno={tp_channel.channel_number}")
                if tp_channel.station_id:
                    manifest_script_parts.append(f"epgid={tp_channel.station_id}")
                if media_pid:
                    manifest_script_parts.append(f"media={media_pid}")
                manifest_script = " ".join(manifest_script_parts) if manifest_script_parts else ""

                streaming_channel = StreamingChannel(
                    name=title,
                    content_id=tp_channel.station_id or tp_channel.release_pid or title,
                    provider=self.provider_name,
                    logo_url=logo,
                    mode="live",
                    session_manifest=False,
                    manifest=tp_channel.mpd_url,
                    manifest_script=manifest_script,
                    cdm_type=DRM_SYSTEM_WIDEVINE,
                    use_cdm=True,
                    cdm=f"pid={tp_channel.release_pid}" if tp_channel.release_pid else "",
                    cdm_mode="external",
                    video="best",
                    on_demand=True,
                    speed_up=True,
                    content_type=CONTENT_TYPE_LIVE,
                    country=self.country.upper(),
                    is_radio=is_audio,
                    language=get_language(self.country),
                    streaming_format=STREAMING_FORMAT_DASH,
                    catchup_hours=catchup_hours,
                )
                channels.append(streaming_channel)

            except Exception as e:
                logger.warning(f"Error processing channel data: {e}")

        return channels

    def get_events(
            self,
            start_time: Optional[datetime.datetime] = None,
            end_time: Optional[datetime.datetime] = None,
            **kwargs,
    ) -> List[Event]:
        return []

    def get_epg(self, channel_id: str, **kwargs) -> List[EPGEntry]:
        """
        Native EPG entry point called by EPGOperations when implements_epg=True.

        Delegates entirely to MagentaEUEpgManager and returns EPGEntry objects
        directly (the manager constructs these internally; no dict conversion
        happens at this layer).

        Parameters
        ----------
        channel_id:  Station ID (theplatform Station URI) — same value stored
                     as content_id on StreamingChannel.
        **kwargs:    Forwarded to the manager; recognised keys are
                     start_time and end_time (datetime objects).
        """
        if not self._ensure_channels_cache():
            return []
        return self.epg_manager.get_channel_epg(
            channel_id=channel_id,
            start_time=kwargs.get("start_time"),
            end_time=kwargs.get("end_time"),
        )

    def get_epg_grid(
        self,
        channel_ids: Optional[List[str]] = None,
        start_time: Optional[datetime.datetime] = None,
        end_time: Optional[datetime.datetime] = None,
        **kwargs,
    ) -> Dict[str, List[EPGEntry]]:
        """
        Get EPG data for multiple channels efficiently as EPGEntry objects.

        Uses get_channel_epg_batch() which fetches schedule data once per
        calendar day and extracts all channels in a single pass (8*D HTTP
        requests rather than 8*D*N).

        Note on wall-clock cost: each calendar day in the window requires 8
        sequential HTTP requests (3-hour blocks) with a 1-second sleep between
        them (~8 seconds minimum per day).  Do not call this without explicit
        channel_ids in a hot path — see the note on channel_ids=None below.

        Parameters
        ----------
        channel_ids: Channel IDs to fetch.  If None, all channels from the
                     channel cache are used — this triggers a full cache refresh
                     if the cache is stale and will be slow for large channel
                     lists across multi-day windows.
        start_time:  Window start (datetime, aware or naive-UTC, or None → today).
        end_time:    Window end   (datetime, aware or naive-UTC, or None → today).

        Returns
        -------
        Dictionary mapping channel_id -> List[EPGEntry], sorted by start time.
        Channels with no data map to an empty list.
        """
        if not self._ensure_channels_cache():
            return {}
        if channel_ids is None:
            channel_ids = [channel.channel_id for channel in self._channels_cache]

        return self.epg_manager.get_channel_epg_batch(
            channel_ids=channel_ids,
            start_time=start_time,
            end_time=end_time,
        )

    def get_program_details(self, program_id: str, **kwargs) -> Optional["EPGProgramDetails"]:
        """
        Get detailed metadata for a single programme as an EPGProgramDetails object.

        Returns None if the programme is not found or the request fails.

        Parameters
        ----------
        program_id: Programme identifier as returned by the schedule API.
        """
        if not self._ensure_channels_cache():
            return None
        return self.epg_manager.get_program_details(program_id)

    def enrich_channel_data(
        self, channel: StreamingChannel, **kwargs
    ) -> Optional[StreamingChannel]:
        """
        Enrich channel with streaming data.
        Magenta TV provides manifest URLs directly in channel data,
        so this mainly ensures DRM configuration is set up.
        """
        try:
            if not channel.manifest:
                return None

            drm_config = self.get_drm_config(channel)
            if drm_config:
                channel.drm_config = drm_config

            return channel

        except Exception as e:
            logger.warning(f"Error enriching channel data for {channel.name}: {e}")
            return None

    def _ensure_channels_cache(self, force_refresh: bool = False) -> bool:
        """Ensure channels cache is populated, fetch if empty or forced"""
        current_time = time.time()

        if (force_refresh or
                not self._channels_cache or
                (current_time - self._channels_cache_timestamp) > self._cache_ttl):

            try:
                self._channels_cache = self.get_channels()
                self._channels_cache_timestamp = current_time
                return True
            except Exception as e:
                logger.error(f"Failed to refresh channels cache: {e}")
                return False

        return True

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        """Get manifest URL for a channel by ID"""
        if not self._ensure_channels_cache():
            return None

        for channel in self._channels_cache:
            if channel.channel_id == content_id:
                return channel.manifest

        logger.warning(f"Channel {content_id} not found in available channels")
        return None

    def get_catchup_manifest(
            self, content_id: str, start_time: int, end_time: int, drm_variant: Optional[str] = "auto", **kwargs
    ) -> Optional[str]:
        """
        Get catchup manifest URL for Magenta TV.

        Returns the same manifest as get_manifest but extended with
        ?begin=YYYYMMDDTHHMMSS&end=YYYYMMDDTHHMMSS query parameters.

        Args:
            content_id: Channel identifier
            start_time: Start time as Unix timestamp (epoch seconds)
            end_time: End time as Unix timestamp (epoch seconds)
            **kwargs: Additional parameters (epg_id, etc.)

        Returns:
            Manifest URL with catchup time parameters, or None if channel not found
        """
        if not self._ensure_channels_cache():
            logger.warning(f"Cannot get catchup manifest for {content_id}, channels cache unavailable")
            return None

        base_manifest = self.get_manifest(content_id, **kwargs)
        if not base_manifest:
            logger.warning(f"Channel {content_id} not found or has no manifest")
            return None

        try:
            if isinstance(start_time, str):
                start_time = int(start_time)
            if isinstance(end_time, str):
                end_time = int(end_time)

            catchup_manifest = build_catchup_url(base_manifest, start_time, end_time)
            logger.debug(f"Catchup manifest for channel {content_id}: {catchup_manifest}")
            return catchup_manifest
        except Exception as e:
            logger.error(f"Error building catchup manifest for channel {content_id}: {e}")
            logger.warning(f"Falling back to live manifest for channel {content_id}")
            return base_manifest

    def get_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """Get DRM configurations for channel by ID"""
        logger.info(f"=== get_drm_configs_by_id CALLED for channel_id: {content_id} ===")

        if not self._ensure_channels_cache():
            logger.warning(f"Cannot get DRM for {content_id}, channels cache unavailable")
            return []

        channel = None
        for cached_channel in self._channels_cache:
            if cached_channel.channel_id == content_id:
                channel = cached_channel
                break

        if not channel:
            logger.warning(f"Channel with ID {content_id} not found in cache")
            return []

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
            from .auth import MagentaAuthToken, decode_jwt
            from .constants import ACC_URL

            pid = channel.cdm.replace("pid=", "") if channel.cdm else ""
            logger.info(f"=== get_drm_config: Extracted PID: {pid} ===")

            if not pid:
                logger.debug(f"No PID found for channel {channel.name}")
                return None

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

            if access_token.startswith("Bearer "):
                access_token = access_token[7:]

            try:
                current_token = self.authenticator.current_token
                if isinstance(current_token, MagentaAuthToken) and hasattr(
                    current_token, "get_jwt_claims"
                ):
                    decoded_payload = current_token.get_jwt_claims()
                    if not decoded_payload:
                        logger.warning("Failed to get JWT claims from token")
                        return None
                else:
                    decoded_payload = decode_jwt(access_token, verify=False)
            except Exception as e:
                logger.warning(f"Error decoding JWT token for DRM: {e}")
                return None

            account_id = decoded_payload.get("dc_cts_accountId", "")
            persona_token = decoded_payload.get("dc_cts_personaToken", "")

            if not account_id or not persona_token:
                logger.warning("Missing account ID or persona token in JWT payload")
                return None

            account_uri = f"{ACC_URL}/{account_id}"
            license_url = build_licence_url(
                widevine_endpoint=WV_URL,
                release_pid=pid,
                persona_jwt=persona_token,
                account_uri=account_uri,
            )
            logger.debug(f"License URL created: {license_url[:100]}...")

            drm_config = build_widevine_drm_config(
                licence_url=license_url,
                user_agent=USER_AGENT,
                origin=get_base_url(self.country),
            )
            logger.debug(f"DRM config created successfully for channel {channel.name}")
            return drm_config

        except Exception as e:
            logger.warning(f"Error creating DRM config for {channel.name}: {e}")
            return None

    def validate_credentials(self, credentials: UserPasswordCredentials) -> bool:
        """Validate Magenta TV credentials"""
        try:
            temp_authenticator = MagentaAuthenticator(
                config_dir=(
                    self.authenticator.settings_manager.config_dir
                    if hasattr(self.authenticator.settings_manager, "config_dir")
                    else None
                ),
                http_manager=self.http_manager,
                proxy_config=self.http_manager.config.proxy_config,
                credentials=credentials,
            )

            token = temp_authenticator.get_bearer_token()
            return bool(token and len(token) > 0)

        except Exception as e:
            logger.debug(f"Credential validation failed: {e}")
            return False

    @classmethod
    def get_supported_countries(cls) -> List[str]:
        """Get list of supported countries"""
        return cls.SUPPORTED_COUNTRIES.copy()

    @classmethod
    def get_static_logo(cls, country: str = None) -> str:
        """
        Override to provide country-specific logos.

        Args:
            country: Optional country code to get specific logo

        Returns:
            Logo URL for the specified country, or default if not available
        """
        if country:
            country_lower = country.lower()
            if country_lower == "at":
                return cls.PROVIDER_LOGO_AT
            elif country_lower == "hr":
                return cls.PROVIDER_LOGO_HR
            elif country_lower == "pl":
                return cls.PROVIDER_LOGO_PL
            elif country_lower == "hu":
                return cls.PROVIDER_LOGO_AT or cls.PROVIDER_LOGO_HR
            elif country_lower == "me":
                return cls.PROVIDER_LOGO_HR

        return cls.PROVIDER_LOGO_HR

    @classmethod
    def get_static_label(cls, country: str = None) -> str:
        """Override to provide country-specific labels including Max TV for Croatia"""
        if country and country.upper() == "HR":
            return "Max TV (HR)"
        elif country:
            return f"Magenta TV ({country.upper()})"
        else:
            return "Magenta TV"