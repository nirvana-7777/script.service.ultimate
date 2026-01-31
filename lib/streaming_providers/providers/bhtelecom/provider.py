# streaming_providers/providers/bhtelecom/provider.py
# -*- coding: utf-8 -*-
"""
BH Telecom streaming provider implementation

Provides access to BH Telecom's live TV streaming service
with support for channel discovery and manifest URLs.
"""

import json
from typing import ClassVar, Dict, List, Optional

from ...base.models import DRMConfig, DRMSystem, LicenseConfig
from ...base.models.proxy_models import ProxyConfig
from ...base.models.streaming_channel import StreamingChannel
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
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["anonymous"]  # No auth currently
    PROVIDER_LOGO: ClassVar[str] = BHTELECOM_LOGO
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = SUPPORTED_COUNTRIES

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
        """
        Initialize BH Telecom provider

        Args:
            country: Country code (default: 'ba')
            config_dir: Optional config directory override
            proxy_config: Optional proxy configuration (highest priority)
            proxy_url: Optional proxy URL string (medium priority)
            os: Operating system identifier for User-Agent
            browser: Browser identifier for User-Agent
            browser_version: Browser version for User-Agent
        """
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

        # Build dynamic user agent
        self.user_agent = self._build_user_agent()

        # Setup HTTP manager using abstraction
        self.http_manager = self._setup_http_manager(
            provider_name="bhtelecom",
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=self.user_agent,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES,
        )

        # CDN URL (discovered dynamically)
        self._cdn_url: Optional[str] = None

    def _build_user_agent(self) -> str:
        """Build user agent string from configuration"""
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
        """Return provider label"""
        return self.PROVIDER_LABEL

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

    @property
    def uses_dynamic_manifests(self) -> bool:
        """BH Telecom uses static manifest URLs"""
        return False

    @property
    def implements_epg(self) -> bool:
        """BH Telecom does not currently provide EPG data"""
        return False

    def authenticate(self, **kwargs) -> str:
        """
        Authenticate with BH Telecom

        Currently returns empty string as no authentication is required

        Returns:
            Empty string (no authentication token)
        """
        logger.debug("BH Telecom: No authentication required")
        return ""

    def refresh_authentication(self) -> str:
        """
        Refresh authentication

        Currently returns empty string as no authentication is required

        Returns:
            Empty string (no authentication token)
        """
        return ""

    def _discover_cdn(self) -> str:
        """
        Discover the CDN URL from the initial endpoint

        Returns:
            Base CDN URL

        Raises:
            Exception: If CDN discovery fails
        """
        if self._cdn_url:
            return self._cdn_url

        initial_url = BHTELECOM_BASE_URLS["INITIAL"]

        logger.debug(f"Discovering CDN from: {initial_url}")

        try:
            response = self.http_manager.get(
                initial_url,
                operation="api"
            )

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
            **kwargs,
    ) -> List[StreamingChannel]:
        """
        Fetch available channels from BH Telecom

        Args:
            fetch_manifests: Whether to immediately populate streaming data
            populate_streaming_data: Whether to populate streaming data when fetch_manifests is True
            **kwargs: Additional parameters

        Returns:
            List of StreamingChannel objects
        """
        logger.info("Fetching BH Telecom channels...")

        try:
            # Discover CDN
            base_url = self._discover_cdn()

            # Fetch channels list
            channels_url = base_url + BHTELECOM_BASE_URLS["CHANNELS"]
            logger.debug(f"Fetching channels from: {channels_url}")

            response = self.http_manager.get(
                channels_url,
                operation="api"
            )

            channels_data = response.json()
            entries = channels_data.get("feed", [])

            if not entries:
                logger.warning("No channels found in response")
                return []

            logger.info(f"Found {len(entries)} channels")

            # Parse channels
            channels = []
            for entry in entries:
                try:
                    channel = self._parse_channel(entry, base_url)
                    channels.append(channel)
                except Exception as e:
                    logger.error(
                        f"Error parsing channel {entry.get('title', 'unknown')}: {e}"
                    )

            logger.info(f"Successfully parsed {len(channels)} channels")

            # Optionally populate streaming data
            if fetch_manifests and populate_streaming_data:
                channels = self.populate_streaming_data(channels, **kwargs)

            return channels

        except Exception as e:
            logger.error(f"Error fetching channels: {e}")
            raise

    def _parse_channel(self, entry: Dict, base_url: str) -> StreamingChannel:
        """
        Parse a channel entry from the API response

        Args:
            entry: Channel data dictionary
            base_url: Base URL for constructing full URLs

        Returns:
            StreamingChannel object
        """
        channel_id = entry.get("ch")
        channel_name = entry.get("title")

        if not channel_id or not channel_name:
            raise ValueError("Missing required channel fields (ch or title)")

        # Construct manifest URL
        server = entry.get("server", "")
        cid = entry.get("cid", "")
        manifest_url = f"{base_url}{server}/{channel_id}.mpd?n={cid}"

        # Construct logo URL
        logo_url = f"{base_url}{BHTELECOM_BASE_URLS['LOGOS']}{channel_id}.png"

        # Create channel with default configuration
        channel = StreamingChannel(
            name=channel_name,
            channel_id=channel_id,
            provider=self.provider_name,
            logo_url=logo_url,
            manifest=manifest_url,
            country=self.country,  # Use provider's country
            language=DEFAULT_LANGUAGE,  # Use "bs" for Bosnian
            **DEFAULT_CHANNEL_CONFIG
        )

        logger.debug(f"Parsed channel: {channel_name} (ID: {channel_id})")

        return channel

    def populate_streaming_data(
            self,
            channels: List[StreamingChannel],
            **kwargs,
    ) -> List[StreamingChannel]:
        """
        Populate streaming data for channels

        For BH Telecom, the manifest URLs are already set during parsing,
        so this method just validates and optionally adds DRM configuration.

        Args:
            channels: List of channels to populate
            **kwargs: Additional parameters

        Returns:
            List of channels with streaming data
        """
        logger.info(f"Validating streaming data for {len(channels)} channels")

        successful_channels = []

        for channel in channels:
            try:
                if not channel.manifest:
                    logger.warning(
                        f"Channel {channel.name} has no manifest URL"
                    )
                    continue

                # Future: Add DRM configuration here when needed
                # For now, channels are configured as non-DRM

                successful_channels.append(channel)

            except Exception as e:
                logger.error(
                    f"Error validating channel {channel.name}: {e}"
                )

        logger.info(
            f"Streaming data validation complete: "
            f"{len(successful_channels)}/{len(channels)} channels ready"
        )

        return successful_channels

    def enrich_channel_data(
            self,
            channel: StreamingChannel,
            **kwargs,
    ) -> Optional[StreamingChannel]:
        """
        Enrich channel with additional streaming data

        For BH Telecom, channels already have manifest URLs,
        so this validates and optionally adds DRM configuration.

        Args:
            channel: StreamingChannel to enrich
            **kwargs: Additional parameters

        Returns:
            The enriched StreamingChannel, or None if failed
        """
        try:
            if not channel.manifest:
                logger.warning(
                    f"Channel {channel.name} has no manifest URL"
                )
                return None

            # Future: Add DRM configuration here when needed
            # Currently, channels use no DRM

            logger.debug(f"Channel {channel.name} validated successfully")
            return channel

        except Exception as e:
            logger.error(f"Error enriching channel {channel.name}: {e}")
            return None

    def get_manifest(
            self,
            channel_id: str,
            **kwargs,
    ) -> Optional[str]:
        """
        Get manifest URL for a specific channel by ID

        Args:
            channel_id: ID of the channel to get manifest for
            **kwargs: Additional parameters

        Returns:
            Manifest URL string, or None if not available
        """
        try:
            channels = self.get_channels(fetch_manifests=False)

            for channel in channels:
                if channel.channel_id == channel_id:
                    return channel.manifest

            logger.warning(f"Channel {channel_id} not found")
            return None

        except Exception as e:
            logger.error(f"Error getting manifest for channel {channel_id}: {e}")
            return None

    def get_drm(
            self,
            channel_id: str,
            **kwargs,
    ) -> List[DRMConfig]:
        """
        Get DRM configurations for a channel

        Currently returns empty list as BH Telecom doesn't use DRM.
        Future implementation will add Widevine support.

        Args:
            channel_id: ID of the channel
            **kwargs: Additional parameters

        Returns:
            List of DRMConfig objects (currently empty)
        """
        # Future: Implement DRM configuration when needed
        logger.debug(
            f"BH Telecom: No DRM configuration for channel {channel_id}"
        )
        return []

    def get_dynamic_manifest_params(
            self,
            channel: StreamingChannel,
            **kwargs,
    ) -> Optional[str]:
        """
        Get parameters for dynamic manifest generation

        BH Telecom uses static manifests, so this returns None.

        Args:
            channel: StreamingChannel object
            **kwargs: Additional parameters

        Returns:
            None (static manifests used)
        """
        return None

    def get_epg(
            self,
            channel_id: str,
            **kwargs,
    ) -> List[Dict]:
        """
        Get EPG data for a channel

        Currently not implemented for BH Telecom.

        Args:
            channel_id: Channel ID to get EPG for
            **kwargs: Additional parameters

        Returns:
            Empty list (EPG not implemented)
        """
        logger.debug(f"BH Telecom: EPG not implemented for channel {channel_id}")
        return []

    def test_connection(self) -> Dict:
        """
        Test connection to BH Telecom services

        Returns:
            Dictionary with test results
        """
        result = {
            "provider": self.provider_name,
            "success": False,
            "cdn_discovered": False,
            "channels_fetched": False,
            "error": None,
        }

        try:
            # Test CDN discovery
            base_url = self._discover_cdn()
            result["cdn_discovered"] = True
            result["cdn_url"] = base_url

            # Test channel fetching
            channels = self.get_channels(fetch_manifests=False)
            result["channels_fetched"] = True
            result["channel_count"] = len(channels)

            result["success"] = True
            logger.info("BH Telecom connection test successful")

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"BH Telecom connection test failed: {e}")

        return result

    def close(self) -> None:
        """
        Close HTTP manager and cleanup resources

        Call this when you're done with the provider to avoid
        connection cleanup messages appearing in output.
        """
        if hasattr(self, 'http_manager') and self.http_manager:
            self.http_manager.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup"""
        self.close()

    def __del__(self):
        """Destructor - silent cleanup"""
        try:
            if hasattr(self, 'http_manager') and self.http_manager:
                # Close quietly without logging
                if hasattr(self.http_manager, '_session') and self.http_manager._session:
                    self.http_manager._session.close()
        except:
            pass  # Silent cleanup on deletion