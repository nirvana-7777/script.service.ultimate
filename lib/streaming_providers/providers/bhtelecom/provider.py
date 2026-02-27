# streaming_providers/providers/bhtelecom/provider.py
# -*- coding: utf-8 -*-
"""
BH Telecom streaming provider implementation

Provides access to BH Telecom's live TV streaming service
with support for channel discovery and manifest URLs.
"""

import time
import datetime
from typing import ClassVar, Dict, List, Optional

from ...base.models.proxy_models import ProxyConfig
from ...base.models import DRMConfig, StreamingChannel, Event
from ...base.provider import AuthType, StreamingProvider
from ...base.utils.logger import logger
from .constants import (
    BHTELECOM_API_BASE_HEADERS,
    BHTELECOM_BASE_URLS,
    BHTELECOM_DOMAIN,
    BHTELECOM_HOST,
    BHTELECOM_LOGO,
    BHTELECOM_USER_AGENT,
    CONTENT_TYPE_LIVE,
    DEFAULT_BROWSER,
    DEFAULT_BROWSER_VERSION,
    DEFAULT_CHANNEL_CONFIG,
    DEFAULT_COUNTRY,
    DEFAULT_LANGUAGE,
    DEFAULT_MAX_RETRIES,
    DEFAULT_OS,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_STREAMING_FORMAT,
    DRM_SYSTEM_WIDEVINE,
    MODE_LIVE,
    SUPPORTED_COUNTRIES,
)


class BHTelecomProvider(StreamingProvider):
    """
    BH Telecom streaming provider implementation

    Supports live TV channels from BH Telecom's streaming service
    with dynamic CDN discovery and manifest URL generation.
    """

    # ============================================================================
    # STATIC METADATA
    # ============================================================================
    PROVIDER_LABEL: ClassVar[str] = "BH Telecom"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["anonymous"]
    PROVIDER_LOGO: ClassVar[str] = BHTELECOM_LOGO
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = SUPPORTED_COUNTRIES

    # Cache duration in seconds (1 hour)
    CACHE_TTL: ClassVar[int] = 3600

    def __init__(
            self,
            country: str = DEFAULT_COUNTRY,
            config_dir: Optional[str] = None,
            proxy_config: Optional[ProxyConfig] = None,
            proxy_url: Optional[str] = None,
            os: str = DEFAULT_OS,
            browser: str = DEFAULT_BROWSER,
            browser_version: str = DEFAULT_BROWSER_VERSION,
    ):
        if not self.validate_country(country):
            supported = ", ".join(self.SUPPORTED_COUNTRIES)
            raise ValueError(
                f"Unsupported country: {country}. "
                f"BH Telecom supports: {supported}"
            )

        super().__init__(country=country)

        self.os = os
        self.browser = browser
        self.browser_version = browser_version
        self.user_agent = self._build_user_agent()

        self.http_manager = self._setup_http_manager(
            provider_name="bhtelecom",
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=self.user_agent,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES,
        )

        # Internal state and caching
        self._cdn_url: Optional[str] = None
        self._channels_cache: List[StreamingChannel] = []
        self._cache_timestamp: float = 0

    def _build_user_agent(self) -> str:
        return (
            f"Mozilla/5.0 (X11; {self.os} x86_64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"{self.browser}/{self.browser_version}.0.0.0 Safari/537.36"
        )

    @property
    def provider_name(self) -> str:
        return "bhtelecom"

    @property
    def provider_label(self) -> str:
        return self.PROVIDER_LABEL

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    @property
    def implements_epg(self) -> bool:
        return False

    def authenticate(self, **kwargs) -> str:
        logger.debug("BH Telecom: No authentication required")
        return ""

    def refresh_authentication(self) -> str:
        return ""

    def _discover_cdn(self) -> str:
        if self._cdn_url:
            return self._cdn_url

        initial_url = BHTELECOM_BASE_URLS["INITIAL"]
        logger.debug(f"Discovering CDN from: {initial_url}")

        try:
            response = self.http_manager.get(initial_url, operation="api")
            cdn_data = response.json()
            cdn_host = cdn_data.get("cdn")

            if not cdn_host:
                raise ValueError("No 'cdn' field in response")

            self._cdn_url = f"https://{cdn_host}{BHTELECOM_DOMAIN}"
            logger.info(f"Discovered CDN URL: {self._cdn_url}")
            return self._cdn_url

        except Exception as e:
            logger.error(f"Failed to discover CDN: {e}")
            raise

    def get_channels(
            self,
            fetch_manifests: bool = False,
            populate_streaming_data: bool = True,
            force_refresh: bool = False,
            **kwargs,
    ) -> List[StreamingChannel]:
        """
        Fetch available channels with TTL caching.
        """
        current_time = time.time()

        # Use cache if valid and refresh not forced
        if not force_refresh and self._channels_cache and (current_time - self._cache_timestamp < self.CACHE_TTL):
            logger.debug("Returning BH Telecom channels from cache")
            return self._channels_cache

        logger.info("BH Telecom: Cache expired or force refresh requested. Fetching...")

        try:
            base_url = self._discover_cdn()
            channels_url = base_url + BHTELECOM_BASE_URLS["CHANNELS"]

            response = self.http_manager.get(channels_url, operation="api")
            channels_data = response.json()
            entries = channels_data.get("feed", [])

            if not entries:
                logger.warning("No channels found in response")
                return self._channels_cache  # Fallback to stale if empty

            # Parse new list
            new_channels = []
            for entry in entries:
                try:
                    channel = self._parse_channel(entry, base_url)
                    new_channels.append(channel)
                except Exception as e:
                    logger.error(f"Error parsing channel {entry.get('title', 'unknown')}: {e}")

            # Update cache and timestamp
            self._channels_cache = new_channels
            self._cache_timestamp = current_time

            if fetch_manifests and populate_streaming_data:
                self._channels_cache = self.populate_streaming_data(self._channels_cache, **kwargs)

            return self._channels_cache

        except Exception as e:
            if self._channels_cache:
                logger.error(f"Failed to refresh channels: {e}. Serving stale cache.")
                return self._channels_cache
            raise

    def get_events(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Event]:
        return []

    def _parse_channel(self, entry: Dict, base_url: str) -> StreamingChannel:
        channel_id = entry.get("ch")
        channel_name = entry.get("title")

        if not channel_id or not channel_name:
            raise ValueError("Missing required channel fields (ch or title)")

        server = entry.get("server", "")
        cid = entry.get("cid", "")
        manifest_url = f"{base_url}{server}/{channel_id}.mpd?n={cid}"
        logo_url = f"{base_url}{BHTELECOM_BASE_URLS['LOGOS']}{channel_id}.png"

        return StreamingChannel(
            name=channel_name,
            content_id=channel_id,
            provider=self.provider_name,
            logo_url=logo_url,
            manifest=manifest_url,
            country=self.country,
            language=DEFAULT_LANGUAGE,
            **DEFAULT_CHANNEL_CONFIG
        )

    def populate_streaming_data(
            self,
            channels: List[StreamingChannel],
            **kwargs,
    ) -> List[StreamingChannel]:
        successful_channels = []
        for channel in channels:
            if channel.manifest:
                successful_channels.append(channel)
        return successful_channels

    def enrich_channel_data(
            self,
            channel: StreamingChannel,
            **kwargs,
    ) -> Optional[StreamingChannel]:
        return channel if channel.manifest else None

    def get_manifest(
            self,
            channel_id: str,
            **kwargs,
    ) -> Optional[str]:
        # Hits the cache logically
        channels = self.get_channels(fetch_manifests=False)
        for channel in channels:
            if channel.channel_id == channel_id:
                return channel.manifest
        return None

    def get_drm(
            self,
            channel_id: str,
            **kwargs,
    ) -> List[DRMConfig]:
        return []

    def get_dynamic_manifest_params(
            self,
            channel: StreamingChannel,
            **kwargs,
    ) -> Optional[str]:
        return None

    def get_epg(
            self,
            channel_id: str,
            **kwargs,
    ) -> List[Dict]:
        return []

    def test_connection(self) -> Dict:
        result = {
            "provider": self.provider_name,
            "success": False,
            "cdn_discovered": False,
            "channels_fetched": False,
            "error": None,
        }
        try:
            # Force refresh to bypass cache for connection test
            base_url = self._discover_cdn()
            result["cdn_discovered"] = True
            result["cdn_url"] = base_url

            channels = self.get_channels(force_refresh=True)
            result["channels_fetched"] = True
            result["channel_count"] = len(channels)
            result["success"] = True
        except Exception as e:
            result["error"] = str(e)
        return result

    def close(self) -> None:
        if hasattr(self, 'http_manager') and self.http_manager:
            self.http_manager.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False