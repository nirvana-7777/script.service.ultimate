# streaming_providers/providers/rtlplus/provider.py
import json
import time
from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Any

import requests

from ...base.models import DRMConfig, DRMSystem, LicenseConfig, StreamingChannel, Event
from ...base.models.proxy_models import ProxyConfig
from ...base.provider import StreamingProvider
from ...base.utils import logger
from .auth import RTLPlusAuthenticator
from .constants import RTLPlusConfig, RTLPlusDefaults, RTLPlusGraphQL
from .models import RTLPlusLiveEvent
from .vod_manager import RTLPlusVodManager
from .channel_manager import RTLPlusChannelManager

_MANIFEST_CACHE_TTL = 86400  # 1 day in seconds for VOD/events


class RTLPlusProvider(StreamingProvider):
    # Provider constants
    PROVIDER_LABEL: ClassVar[str] = "RTL+"
    PROVIDER_LOGO: ClassVar[str] = RTLPlusDefaults.RTLPLUS_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = [
        "client_credentials",
        "user_credentials",
    ]

    def __init__(
            self,
            country: str = "DE",
            config: Optional[Dict] = None,
            proxy_config: Optional[ProxyConfig] = None,
    ):
        super().__init__(country)

        # Initialize configuration
        self.rtl_config = RTLPlusConfig(config)

        # Setup HTTP manager
        self.http_manager = self._setup_http_manager(
            provider_name="rtlplus",
            proxy_config=proxy_config,
            user_agent=self.rtl_config.user_agent,
            timeout=self.rtl_config.timeout,
        )

        # Initialize authenticator
        self.authenticator = RTLPlusAuthenticator(
            client_version=self.rtl_config.client_version,
            device_id=self.rtl_config.device_id,
            proxy_config=proxy_config,
            http_manager=self.http_manager,
        )

        self.http_manager = self._share_http_manager_with_authenticator(self.authenticator)

        # Try authentication
        try:
            self.bearer_token = self.authenticator.get_bearer_token()
            logger.debug("RTL+ authentication successful during initialization")
        except Exception as e:
            logger.warning(f"RTL+ could not authenticate during initialization: {e}")
            self.bearer_token = None

        # Initialize managers
        self._vod_manager = RTLPlusVodManager(self)
        self.channel_manager = RTLPlusChannelManager(self)

        # Manifest cache for VOD/events
        self._manifest_cache: Dict[str, tuple] = {}

    @property
    def provider_name(self) -> str:
        return "rtlplus"

    @property
    def provider_label(self) -> str:
        return "RTL+"

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
    def supported_auth_types(self) -> List[str]:
        return ["user_credentials"]

    # --------------------------------------------------------------------------
    # Authentication Helpers
    # --------------------------------------------------------------------------

    def _get_rtlplus_authenticated_headers(self) -> Dict[str, str]:
        from ...base.auth.base_auth import TokenAuthLevel

        try:
            current_level = self.authenticator.get_current_token_level()
            force_upgrade = (
                    self.authenticator.has_user_credentials()
                    and current_level != TokenAuthLevel.USER_AUTHENTICATED
            )
            bearer_token = self.authenticator.get_bearer_token(force_upgrade=force_upgrade)
        except Exception as e:
            logger.error(f"Failed to get bearer token: {e}")
            raise

        return self.rtl_config.get_api_headers(access_token=bearer_token)

    # --------------------------------------------------------------------------
    # Linear TV Channels
    # --------------------------------------------------------------------------

    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """
        Get list of available linear TV channels from EPG grid.
        """
        try:
            channels = self.channel_manager.get_channels_as_streaming_channel_list()
            self.channels = channels
            return channels
        except Exception as e:
            logger.error(f"Error fetching RTL+ channels: {e}")
            return []

    # --------------------------------------------------------------------------
    # Events (Live Events)
    # --------------------------------------------------------------------------

    def get_events(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Event]:
        """Fetch upcoming / live RTL+ events from the editorial GraphQL endpoint."""
        raw_events = self._fetch_live_events()
        events: List[Event] = []

        for raw in raw_events:
            try:
                event = raw.to_event(provider=self.provider_name)
            except Exception as e:
                logger.warning(f"RTL+: Could not convert event '{raw.id}': {e}")
                continue

            if start_time and event.end_time and event.end_time < start_time:
                continue
            if end_time and event.start_time and event.start_time > end_time:
                continue

            events.append(event)

        logger.info(f"RTL+: Fetched {len(events)} events")
        return events

    def _fetch_live_events(self) -> List[RTLPlusLiveEvent]:
        headers = self._get_rtlplus_authenticated_headers()

        try:
            response = self.http_manager.get(
                self.rtl_config.graphql_endpoint,
                params=RTLPlusGraphQL.live_events_overview_page(),
                headers=headers,
                operation="api",
            )
            response.raise_for_status()
        except Exception as e:
            logger.error(f"RTL+: Failed to fetch events: {e}")
            return []

        return self._parse_live_events(response.json())

    @staticmethod
    def _parse_live_events(data: Dict[str, Any]) -> List[RTLPlusLiveEvent]:
        events: List[RTLPlusLiveEvent] = []
        seen: set = set()

        teaser_rows = data.get("data", {}).get("liveEventsOverview", {}).get("teaserRows", [])

        for row in teaser_rows:
            for element in (row.get("events") or []):
                if element is None:
                    continue
                if element.get("__typename") != "LiveEvent":
                    continue
                event_id = element.get("id", "")
                if not event_id or event_id in seen:
                    continue
                seen.add(event_id)
                try:
                    events.append(RTLPlusLiveEvent.from_api_node(element))
                except Exception as e:
                    logger.warning(f"RTL+: Skipping malformed event node: {e}")

        return events

    # --------------------------------------------------------------------------
    # VOD
    # --------------------------------------------------------------------------

    def get_vod_category(self, content_id: str = "", **kwargs):
        return self._vod_manager.get_vod_category(content_id=content_id, **kwargs)

    # --------------------------------------------------------------------------
    # Manifest & DRM (Dispatcher)
    # --------------------------------------------------------------------------

    @staticmethod
    def _is_linear_tv_channel(content_id: str) -> bool:
        """Determine if content_id refers to a linear TV channel."""
        return (
                ":" not in content_id
                and not content_id.startswith("rrn:")
                and not content_id.startswith("/")
                and not content_id.startswith("http")
        )

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        """
        Get manifest URL for content.

        For linear TV channels: uses new Bedrock layout API
        For VOD: uses existing GraphQL/Wurstland flow
        For live events: uses existing event manifest flow
        """
        if self._is_linear_tv_channel(content_id):
            return self.channel_manager.get_best_manifest_url(content_id)
        else:
            return self._get_manifest_vod_or_event(content_id, **kwargs)

    def _get_manifest_vod_or_event(self, content_id: str, **kwargs) -> Optional[str]:
        """Original manifest logic for VOD/events."""
        try:
            manifest_data = self._fetch_manifest_data(content_id)
            if manifest_data is None:
                return None

            quality_preference = ["dashhd", "dashfree", "dashsd"]

            for quality in quality_preference:
                for stream in manifest_data:
                    if stream.get("name") == quality:
                        sources = stream.get("sources", [])
                        non_yospace_sources = [s for s in sources if not s.get("isYospace", False)]

                        if non_yospace_sources:
                            selected_url = non_yospace_sources[0].get("url")
                            logger.info(f"RTL+ Selected Manifest URL: {selected_url}")
                            return selected_url

            for stream in manifest_data:
                sources = stream.get("sources", [])
                if sources:
                    fallback_url = sources[0].get("url")
                    logger.info(f"RTL+ Using Fallback Manifest URL: {fallback_url}")
                    return fallback_url

            logger.warning("RTL+ No valid manifest URL found in response")
            return None

        except requests.RequestException as e:
            logger.error(f"RTL+ Manifest HTTP Error: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"RTL+ Manifest JSON Parse Error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"RTL+ Manifest Unexpected Error: {str(e)}")
            return None

    def get_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """
        Get DRM configuration for content.

        For linear TV channels: uses new upfront token flow
        For VOD: uses existing manifest-based DRM
        """
        if self._is_linear_tv_channel(content_id):
            return self.channel_manager.get_drm_config_for_channel(content_id)
        else:
            return self._get_drm_vod_or_event(content_id, **kwargs)

    def _get_drm_vod_or_event(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """Original DRM logic for VOD/events."""
        try:
            manifest_data = self._fetch_manifest_data(content_id)
            if manifest_data is None:
                return []

            drm_configs = []
            access_token = self.authenticator.get_bearer_token()

            for stream in manifest_data:
                if stream.get("name") == "dashhd" and "licenses" in stream:
                    licenses = stream.get("licenses", [])

                    for license_info in licenses:
                        license_url = license_info.get("uri", {}).get("href")
                        if not license_url:
                            continue

                        if license_info.get("type") == "WIDEVINE":
                            drm_configs.append(DRMConfig(
                                system=DRMSystem.WIDEVINE,
                                priority=3,
                                license=LicenseConfig(
                                    server_url=license_url,
                                    req_headers=json.dumps(self.rtl_config.get_drm_headers(access_token)),
                                    req_data="{CHA-RAW}",
                                    use_http_get_request=False,
                                ),
                            ))
                        elif license_info.get("type") == "PLAYREADY":
                            drm_configs.append(DRMConfig(
                                system=DRMSystem.PLAYREADY,
                                priority=2,
                                license=LicenseConfig(
                                    server_url=license_url,
                                    req_headers=json.dumps(self.rtl_config.get_playready_drm_headers(access_token)),
                                    req_data="{CHA-RAW}",
                                    use_http_get_request=False,
                                ),
                            ))
                    break

            return drm_configs

        except Exception as e:
            logger.error(f"Error fetching DRM configs for RTL+ content {content_id}: {e}")
            return []

    def _fetch_manifest_data(self, content_id: str) -> Optional[list]:
        """Fetch raw manifest data for VOD/events, with cache."""
        now = time.monotonic()
        cached = self._manifest_cache.get(content_id)
        if cached is not None:
            data, ts = cached
            if (now - ts) < _MANIFEST_CACHE_TTL:
                logger.debug(f"RTL+ Manifest cache hit for {content_id}")
                return data

        # TODO: This legacy endpoint may eventually be migrated to Bedrock
        manifest_url = f"https://stus.player.streamingtech.de/watch-playout-variants/{content_id}?platform=web"

        headers = {"X-Auth-Token": self.authenticator.get_bearer_token()}
        response = self.http_manager.get(manifest_url, operation="manifest", headers=headers)
        response.raise_for_status()
        data = response.json()

        self._manifest_cache[content_id] = (data, now)
        return data

    def get_user_bearer_token(self) -> Optional[str]:
        """Get a user-authenticated bearer token, upgrading if necessary. Returns None if impossible."""
        from ...base.auth.base_auth import TokenAuthLevel
        current_level = self.authenticator.get_current_token_level()
        logger.debug(
            f"get_user_bearer_token: current_level={current_level}, has_user_credentials={self.authenticator.has_user_credentials()}")
        if current_level == TokenAuthLevel.USER_AUTHENTICATED:
            return self.authenticator.get_bearer_token()
        if self.authenticator.has_user_credentials():
            token = self.authenticator.get_bearer_token(force_upgrade=True)
            if self.authenticator.get_current_token_level() == TokenAuthLevel.USER_AUTHENTICATED:
                return token
        return None