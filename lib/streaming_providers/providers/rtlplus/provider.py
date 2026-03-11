# lib/streaming_providers/providers/rtlplus/provider.py
import json
import time
import datetime
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

_MANIFEST_CACHE_TTL = 86400  # 1 day in seconds


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
        self.channels_query_params = RTLPlusGraphQL.live_tv_stations()

        # ✅ Using HTTP manager abstraction
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

        # ✅ Share HTTP manager with authenticator
        self.http_manager = self._share_http_manager_with_authenticator(self.authenticator)

        # Try authentication
        try:
            self.bearer_token = self.authenticator.get_bearer_token()
            logger.debug(f"RTL+ authentication successful during initialization")
        except Exception as e:
            logger.warning(f"RTL+ could not authenticate during initialization: {e}")
            self.bearer_token = None

        self._vod_manager = RTLPlusVodManager(self)

        # Manifest cache: content_id -> (data, timestamp)
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
        # RTL+ provides relatively stable manifest URLs that can be fetched and cached
        return False

    @property
    def implements_epg(self) -> bool:
        return False

    @property
    def supported_auth_types(self) -> List[str]:
        return ["user_credentials"]

    # ============================================================================
    # OPTION 1: Provider-specific method (RECOMMENDED - No signature conflict)
    # ============================================================================
    def _get_rtlplus_authenticated_headers(self) -> Dict[str, str]:
        """
        Get headers with authentication and RTL+ specific headers.

        Upgrades from anonymous to user token only when user credentials are
        configured and the current token is not already at user level.  This
        prevents a full re-authentication round-trip on every single request
        once a valid user token is already held.
        """
        from ...base.auth.base_auth import TokenAuthLevel

        current_level = self.authenticator.get_current_token_level()
        force_upgrade = (
            self.authenticator.has_user_credentials()
            and current_level != TokenAuthLevel.USER_AUTHENTICATED
        )
        bearer_token = self.authenticator.get_bearer_token(force_upgrade=force_upgrade)
        return self.rtl_config.get_api_headers(access_token=bearer_token)

    def _get_event_manifest_headers(self) -> Dict[str, str]:
        access_token = self.authenticator.get_bearer_token()
        return self.rtl_config.get_event_manifest_headers(access_token=access_token)

    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """
        Fetch channels from RTL+ GraphQL API with authentication
        """
        try:
            # ✅ Use provider-specific method
            headers = self._get_rtlplus_authenticated_headers()

            response = self.http_manager.get(
                self.rtl_config.graphql_endpoint,
                operation="api",
                params=self.channels_query_params,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()

            channels = []
            if "data" in data and "liveTvStations" in data["data"]:
                for station in data["data"]["liveTvStations"]:
                    channel = self._parse_station_to_channel(station)
                    if channel:
                        channels.append(channel)

            self.channels = channels
            return channels

        except requests.RequestException as e:
            logger.error(f"Error fetching RTL+ channels: {e}")
            # Try to refresh auth token and retry once
            try:
                logger.info("Attempting to refresh authentication and retry...")
                self.authenticator.invalidate_token()
                headers = self._get_rtlplus_authenticated_headers()

                response = self.http_manager.get(
                    self.rtl_config.graphql_endpoint,
                    operation="api",
                    params=self.channels_query_params,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

                channels = []
                if "data" in data and "liveTvStations" in data["data"]:
                    for station in data["data"]["liveTvStations"]:
                        channel = self._parse_station_to_channel(station)
                        if channel:
                            channels.append(channel)

                self.channels = channels
                return channels
            except Exception as retry_e:
                logger.error(f"Retry failed: {retry_e}")
                return []
        except Exception as e:
            logger.error(f"Error parsing RTL+ channels: {e}")
            return []

    def get_events(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Event]:
        """
        Fetch upcoming / live RTL+ events from the editorial GraphQL endpoint.

        Filters by start_time / end_time if provided (both timezone-aware).
        """
        raw_events = self._fetch_live_events()
        events: List[Event] = []

        for raw in raw_events:
            try:
                event = raw.to_event(provider=self.provider_name)
            except Exception as e:
                logger.warning(f"RTL+: Could not convert event '{raw.id}': {e}")
                continue

            # Optional time-window filtering (delegate to caller semantics)
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
        """
        Extract LiveEvent nodes from the LiveEventsOverview GraphQL response.

        Response shape: data.liveEventsOverview.teaserRows[].events[]
        Static so it's unit-testable without provider state.
        """
        events: List[RTLPlusLiveEvent] = []
        seen: set = set()

        teaser_rows = (
            data.get("data", {})
            .get("liveEventsOverview", {})
            .get("teaserRows", [])
        )

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

    def get_vod_category(self, category_path, **kwargs):
        """Delegate VOD browsing to RTLPlusVodManager."""
        return self._vod_manager.get_vod_category(category_path, **kwargs)

    def _parse_station_to_channel(self, station: Dict) -> Optional[StreamingChannel]:
        """
        Parse a station object from RTL+ API to StreamingChannel
        """
        try:
            # Extract basic info
            name = station.get("name", "")
            channel_id = station.get("id", "")

            if not name or not channel_id:
                return None

            # Extract logo URL
            logo_url = None
            if "images" in station and "alternativeLandscapeUri" in station["images"]:
                logo_url = station["images"]["alternativeLandscapeUri"]

            # Determine if premium channel
            is_premium = station.get("isPremium", False)

            # Extract watch path for potential manifest fetching
            watch_path = None
            if "urlData" in station and "watchPath" in station["urlData"]:
                watch_path = station["urlData"]["watchPath"]

            # Create channel object
            channel = StreamingChannel(
                name=name,
                content_id=channel_id,
                provider=self.provider_name,
                logo_url=logo_url,
                mode="live",
                session_manifest=True,  # RTL+ uses dynamic manifests
                manifest=None,  # Will be set dynamically
                manifest_script=watch_path,  # Store watch path for manifest fetching
                content_type="LIVE",
                country=self.country,
                language="de",
            )

            # Set CDM settings for premium channels
            if is_premium:
                channel.use_cdm = True
                channel.cdm_type = "widevine"

            return channel

        except Exception as e:
            logger.warning(f"Error parsing station {station}: {e}")
            return None

    @staticmethod
    def _is_vod_rrn(content_id: str) -> bool:
        """True for episode / movie / clip RRNs from the videohub namespace."""
        return (
                content_id.startswith("rrn:watch:videohub:episode:")
                or content_id.startswith("rrn:watch:videohub:movie:")
                or content_id.startswith("rrn:watch:videohub:clip:")
        )

    def _fetch_manifest_data(self, content_id: str) -> Optional[list]:
        """
        Fetch raw manifest data for a given content_id, with a 1-day in-memory cache.

        Both get_manifest() and get_drm() call this method so the endpoint is
        only hit once per content_id per day, regardless of call order.
        """
        now = time.monotonic()
        cached = self._manifest_cache.get(content_id)
        if cached is not None:
            data, ts = cached
            if (now - ts) < _MANIFEST_CACHE_TTL:
                logger.debug(f"RTL+ Manifest cache hit for {content_id}")
                return data

        manifest_url = self.rtl_config.get_manifest_url(content_id)
        logger.debug(f"RTL+ Manifest Request: GET {manifest_url}")

        headers = self._get_event_manifest_headers()
        response = self.http_manager.get(manifest_url, operation="manifest", headers=headers)

        logger.debug(f"RTL+ Manifest Response: Status={response.status_code}")
        logger.debug(f"RTL+ Response Headers: {dict(response.headers)}")

        response.raise_for_status()
        data = response.json()

        logger.debug(f"RTL+ Manifest Data: {self._sanitize_manifest_log(data)}")
        self._manifest_cache[content_id] = (data, now)
        return data

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
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

            # Fallback logic
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

    @staticmethod
    def _sanitize_manifest_log(manifest_data: Dict) -> Dict:
        """
        Sanitize manifest data for logging (remove sensitive information)
        """
        try:
            # Create a copy to avoid modifying original
            sanitized = manifest_data.copy()

            # Remove or truncate potentially sensitive URLs
            if isinstance(sanitized, list):
                for stream in sanitized:
                    if isinstance(stream, dict):
                        if "sources" in stream:
                            for source in stream["sources"]:
                                if "url" in source:
                                    # Truncate long URLs for logging
                                    url = source["url"]
                                    if len(url) > 100:
                                        source["url"] = url[:100] + "..."
            return sanitized
        except Exception:
            return manifest_data

    def get_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """
        Get DRM configurations for a channel from RTL+ streaming API
        """
        try:
            manifest_data = self._fetch_manifest_data(content_id)
            if manifest_data is None:
                return []

            drm_configs = []

            # Get access token for license requests
            access_token = self.authenticator.get_bearer_token()

            # Look for dashhd streams (preferred quality) and extract DRM info
            for stream in manifest_data:
                if stream.get("name") == "dashhd" and "licenses" in stream:
                    licenses = stream.get("licenses", [])

                    for license_info in licenses:
                        license_url = license_info.get("uri", {}).get("href")
                        if not license_url:
                            continue

                        def create_drm_config(drm_system, priority, server_url, headers):
                            return DRMConfig(
                                system=drm_system,
                                priority=priority,
                                license=LicenseConfig(
                                    server_url=server_url,
                                    req_headers=json.dumps(headers),
                                    req_data="{CHA-RAW}",
                                    use_http_get_request=False,
                                ),
                            )

                        if license_info.get("type") == "WIDEVINE":
                            drm_configs.append(
                                create_drm_config(
                                    DRMSystem.WIDEVINE,
                                    3,
                                    license_url,
                                    self.rtl_config.get_drm_headers(access_token),
                                )
                            )
                        elif license_info.get("type") == "PLAYREADY":
                            drm_configs.append(
                                create_drm_config(
                                    DRMSystem.PLAYREADY,
                                    2,
                                    license_url,
                                    self.rtl_config.get_playready_drm_headers(access_token),
                                )
                            )
                        elif license_info.get("type") == "FAIRPLAY":
                            drm_configs.append(
                                create_drm_config(
                                    DRMSystem.FAIRPLAY,
                                    4,
                                    license_url,
                                    self.rtl_config.get_drm_headers(access_token),
                                )
                            )
                    break

            return drm_configs

        except requests.RequestException as e:
            logger.error(f"Error fetching DRM configs for RTL+ channel {content_id}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing DRM configs for RTL+ channel {content_id}: {e}")
            return []

    @staticmethod
    def get_epg_data(channel_id: str, **kwargs) -> Optional[Dict]:
        """
        Get EPG data for a channel
        """
        # RTL+ EPG implementation would go here
        # This is a placeholder for future implementation
        return None

    def get_license_url(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        """
        Get license URL for a DRM-protected channels
        """
        drm_configs = self.get_drm(channel.channel_id, **kwargs)
        if drm_configs:
            # Return the first license URL found
            return drm_configs[0].license.server_url
        return None