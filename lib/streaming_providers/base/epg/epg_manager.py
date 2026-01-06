# ============================================================================
# EPG MANAGER - Refactored to work with EPGEntry objects internally
# ============================================================================

# !/usr/bin/env python3
# streaming_providers/base/epg/epg_manager.py
"""
EPG Manager - Central coordinator for EPG operations
Orchestrates cache, mapping, and parsing components

Refactored to use EPGEntry objects internally while maintaining
backward-compatible dictionary output for external consumers.

PROVIDER ENCODING IN BROADCAST IDs:
------------------------------------
The EPGManager now encodes provider information into broadcast IDs,
enabling provider identification during catchup operations:

Example workflow:
    # 1. EPG is fetched and parsed (provider is known)
    manager = EPGManager()
    epg_data = manager.get_epg("rtlplus", "rtl")
    # broadcast_id now contains encoded "rtlplus" provider hash

    # 2. Later, in catchup handler (only broadcast_id available)
    def get_catchup_stream(broadcast_id):
        # Identify provider from broadcast_id
        provider = manager.get_provider_from_broadcast_id(broadcast_id)
        # -> "rtlplus"

        # Now we can call the right provider's catchup API
        return provider_registry[provider].get_catchup(broadcast_id)

This solves the problem of needing provider information for catchup
when only the broadcast_id is passed from Kodi.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from ..models.epg_models import EPGEntry
from ..utils.environment import get_environment_manager, is_kodi_environment
from ..utils.logger import logger
from .epg_cache import EPGCache
from .epg_mapping import EPGMapping
from .epg_parser import EPGParser


class EPGManager:
    """
    Central manager for EPG operations.
    Coordinates cache management, channel mapping, and EPG parsing.

    Internal: Works with EPGEntry objects for type safety and validation
    External: Returns dictionaries for backward compatibility with C++ frontend

    All file operations are handled transparently by VFS - works in both
    Kodi and standard Python environments.
    """

    # Default EPG source URL (can be overridden by addon setting)
    DEFAULT_EPG_URL = "https://example.com/epg.xml.gz"

    def __init__(self, epg_url: Optional[str] = None):
        """
        Initialize EPG manager with all components.

        Args:
            epg_url: EPG source URL (if None, will be determined automatically)
        """
        # Initialize components - they handle paths internally
        self.cache = EPGCache(vfs_subdir="epg_cache")
        self.mapping = EPGMapping()  # No paths needed - handles internally
        self.parser = EPGParser()

        # Determine EPG URL with proper precedence
        self.epg_url = self._determine_epg_url(epg_url)

        logger.info(f"EPGManager: Initialized with EPG URL: {self.epg_url}")

    @staticmethod
    def _get_epg_url_from_settings() -> Optional[str]:
        """
        Get EPG URL from addon settings using SettingsManager.

        Returns:
            URL from settings, or None if not set
        """
        try:
            from ..settings.kodi_settings_bridge import KodiSettingsBridge

            bridge = KodiSettingsBridge()
            if bridge.is_kodi_environment():
                url = bridge.addon.getSetting("epg_xml_url")

                if url and url.strip():
                    logger.info(f"EPGManager: Using EPG URL from settings: {url}")
                    return url.strip()

        except Exception as e:
            logger.debug(f"EPGManager: Could not read EPG URL setting: {e}")

        return None

    @staticmethod
    def _get_default_time_range() -> tuple:
        """
        Get default time range for EPG queries (now to +12 hours).

        Returns:
            Tuple of (start_time, end_time) as Unix timestamps
        """
        now = datetime.now()
        start = int(now.timestamp())
        end = int((now + timedelta(hours=12)).timestamp())

        logger.debug(f"EPGManager: Using default time range: {start} to {end}")
        return start, end

    def get_epg(
        self,
        provider_name: str,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict]:
        """
        Get EPG data for a specific channel within a time range.

        This is the main entry point for EPG queries.

        EXTERNAL INTERFACE: Returns list of dictionaries for C++ compatibility.

        Args:
            provider_name: Name of provider (e.g., "rtlplus", "joyn_de")
            channel_id: Channel ID within provider
            start_time: Start of time range (datetime), None for now
            end_time: End of time range (datetime), None for now+12h

        Returns:
            List of EPG entries as dictionaries (empty on any error)
        """
        logger.info(f"EPGManager: Getting EPG for {provider_name}/{channel_id}")

        try:
            # Step 1: Map to EPG channel ID
            epg_channel_id = self.mapping.get_epg_channel_id(provider_name, channel_id)
            if not epg_channel_id:
                logger.warning(
                    f"EPGManager: No EPG mapping found for {provider_name}/{channel_id}"
                )
                return []

            logger.debug(f"EPGManager: Mapped to EPG channel ID: {epg_channel_id}")

            # Step 2: Get or download EPG XML
            xml_path = self.cache.get_or_download(self.epg_url)
            if not xml_path:
                logger.error("EPGManager: Failed to get EPG XML file")
                return []

            # Step 3: Convert datetime to Unix timestamps
            if start_time is None or end_time is None:
                default_start, default_end = self._get_default_time_range()
                start_ts = int(start_time.timestamp()) if start_time else default_start
                end_ts = int(end_time.timestamp()) if end_time else default_end
            else:
                start_ts = int(start_time.timestamp())
                end_ts = int(end_time.timestamp())

            logger.debug(f"EPGManager: Time range: {start_ts} to {end_ts}")

            # Step 4: Parse EPG for channel and time range (returns EPGEntry objects)
            # Pass provider_name to enable provider encoding in broadcast_id
            epg_entries: List[EPGEntry] = self.parser.parse_epg_for_channel(
                xml_path,
                epg_channel_id,
                start_ts,
                end_ts,
                provider_name,  # Enable provider encoding
            )

            logger.info(
                f"EPGManager: Retrieved {len(epg_entries)} EPG entries for "
                f"{provider_name}/{channel_id}"
            )

            # Step 5: Convert EPGEntry objects to dictionaries for external consumers
            return [entry.to_dict() for entry in epg_entries]

        except Exception as e:
            logger.error(f"EPGManager: Error getting EPG: {e}", exc_info=True)
            return []

    def get_epg_entries(
        self,
        provider_name: str,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[EPGEntry]:
        """
        Get EPG data as EPGEntry objects (for internal use).

        INTERNAL INTERFACE: Returns EPGEntry objects for type safety.

        Args:
            provider_name: Name of provider
            channel_id: Channel ID within provider
            start_time: Start of time range (datetime), None for now
            end_time: End of time range (datetime), None for now+12h

        Returns:
            List of EPGEntry objects (empty on any error)
        """
        logger.info(f"EPGManager: Getting EPG entries for {provider_name}/{channel_id}")

        try:
            epg_channel_id = self.mapping.get_epg_channel_id(provider_name, channel_id)
            if not epg_channel_id:
                logger.warning(
                    f"EPGManager: No EPG mapping found for {provider_name}/{channel_id}"
                )
                return []

            xml_path = self.cache.get_or_download(self.epg_url)
            if not xml_path:
                logger.error("EPGManager: Failed to get EPG XML file")
                return []

            if start_time is None or end_time is None:
                default_start, default_end = self._get_default_time_range()
                start_ts = int(start_time.timestamp()) if start_time else default_start
                end_ts = int(end_time.timestamp()) if end_time else default_end
            else:
                start_ts = int(start_time.timestamp())
                end_ts = int(end_time.timestamp())

            return self.parser.parse_epg_for_channel(
                xml_path,
                epg_channel_id,
                start_ts,
                end_ts,
                provider_name,  # Enable provider encoding
            )

        except Exception as e:
            logger.error(f"EPGManager: Error getting EPG entries: {e}", exc_info=True)
            return []

    def get_epg_for_provider(
        self,
        provider_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, List[Dict]]:
        """
        Get EPG data for all channels of a provider.

        EXTERNAL INTERFACE: Returns dictionaries for C++ compatibility.

        Args:
            provider_name: Name of provider
            start_time: Start of time range (datetime)
            end_time: End of time range (datetime)

        Returns:
            Dictionary mapping channel IDs to their EPG entries (as dicts)
        """
        logger.info(
            f"EPGManager: Getting EPG for all channels of provider '{provider_name}'"
        )

        result = {}

        # Get all mapped channels for this provider
        provider_mapping = self.mapping.get_provider_mapping(provider_name)

        if not provider_mapping:
            logger.warning(
                f"EPGManager: No channels mapped for provider '{provider_name}'"
            )
            return result

        # Get EPG for each channel
        for channel_id in provider_mapping.keys():
            epg_entries = self.get_epg(provider_name, channel_id, start_time, end_time)
            if epg_entries:
                result[channel_id] = epg_entries

        logger.info(
            f"EPGManager: Retrieved EPG for {len(result)} channels of provider '{provider_name}'"
        )

        return result

    def clear_cache(self) -> bool:
        """
        Clear EPG cache.

        Returns:
            True if cleared successfully
        """
        logger.info("EPGManager: Clearing EPG cache")
        return self.cache.clear_cache()

    def reload_mapping(self) -> bool:
        """
        Reload channel mapping from file.

        Returns:
            True if reloaded successfully
        """
        logger.info("EPGManager: Reloading channel mapping")
        return self.mapping.reload_mapping()

    def get_cache_info(self) -> Optional[Dict]:
        """
        Get information about EPG cache.

        Returns:
            Dictionary with cache info, or None if no cache
        """
        return self.cache.get_cache_info()

    def get_mapping_stats(self) -> Dict:
        """
        Get statistics about channel mapping.

        Returns:
            Dictionary with mapping statistics
        """
        return self.mapping.get_mapping_stats()

    def has_mapping_for_channel(self, provider_name: str, channel_id: str) -> bool:
        """
        Check if EPG mapping exists for a specific channel.

        Args:
            provider_name: Name of provider
            channel_id: Channel ID

        Returns:
            True if mapping exists
        """
        return self.mapping.has_mapping(provider_name, channel_id)

    def get_provider_from_broadcast_id(self, broadcast_id: int) -> Optional[str]:
        """
        Get provider name from an encoded broadcast ID.
        Useful for catchup operations where only broadcast_id is available.

        Args:
            broadcast_id: Encoded broadcast ID from EPG entry

        Returns:
            Provider name, or None if not found

        Example:
            # In catchup handler
            provider = manager.get_provider_from_broadcast_id(broadcast_id)
            if provider:
                # Get catchup stream from provider
                stream_url = get_catchup_stream(provider, broadcast_id)
        """
        return self.parser.get_provider_from_broadcast_id(broadcast_id)

    def _determine_epg_url(self, explicit_url: Optional[str]) -> str:
        """
        Determine EPG URL with proper precedence:
        1. Explicit parameter
        2. Kodi addon setting (if in Kodi)
        3. config.json (via environment manager)
        4. Environment variable ULTIMATE_EPG_URL
        5. Current cached URL (from metadata)
        6. Default fallback

        Args:
            explicit_url: Explicitly provided URL

        Returns:
            EPG URL as string
        """
        import os

        # 1. Explicit parameter (highest priority)
        if explicit_url:
            logger.debug(f"EPGManager: Using explicit EPG URL: {explicit_url}")
            return explicit_url

        # 2. Kodi addon setting (if in Kodi environment)
        try:
            if is_kodi_environment():
                import xbmcaddon

                addon = xbmcaddon.Addon()
                kodi_url = addon.getSetting("epg_xml_url")
                if (
                    kodi_url
                    and kodi_url.strip()
                    and kodi_url != "https://example.com/epg.xml.gz"
                ):
                    logger.info(
                        f"EPGManager: Using EPG URL from Kodi settings: {kodi_url}"
                    )
                    return kodi_url.strip()
        except Exception as e:
            logger.debug(f"EPGManager: Could not get EPG URL from Kodi settings: {e}")

        # 3. config.json via environment manager
        try:
            env_manager = get_environment_manager()
            config_url = env_manager.get_config("epg_url")
            if (
                config_url
                and config_url.strip()
                and config_url != "https://example.com/epg.xml.gz"
            ):
                logger.info(f"EPGManager: Using EPG URL from config.json: {config_url}")
                return config_url.strip()
        except Exception as e:
            logger.debug(
                f"EPGManager: Could not get EPG URL from environment manager: {e}"
            )

        # 4. Environment variable
        env_url = os.environ.get("ULTIMATE_EPG_URL")
        if env_url and env_url.strip() and env_url != "https://example.com/epg.xml.gz":
            logger.info(
                f"EPGManager: Using EPG URL from environment variable: {env_url}"
            )
            return env_url.strip()

        # 5. Try to get the last known URL from cache metadata
        try:
            # Check if we have cache metadata with a valid URL
            metadata = self.cache._get_metadata() if hasattr(self, "cache") else None
            if metadata and "url" in metadata:
                cached_url = metadata.get("url")
                if (
                    cached_url
                    and cached_url.strip()
                    and cached_url != "https://example.com/epg.xml.gz"
                ):
                    logger.info(
                        f"EPGManager: Using last known URL from cache metadata: {cached_url}"
                    )
                    return cached_url.strip()
        except Exception as e:
            logger.debug(f"EPGManager: Could not get URL from cache metadata: {e}")

        # 6. Default fallback (LAST RESORT - should rarely be used)
        default_url = "https://example.com/epg.xml.gz"
        logger.warning(
            f"EPGManager: No valid EPG URL found, using default: {default_url}"
        )
        logger.warning(
            "Please set ULTIMATE_EPG_URL environment variable or configure in settings!"
        )
        return default_url

    @staticmethod
    def verify_broadcast_id_provider(broadcast_id: int, provider_name: str) -> bool:
        """
        Verify if a broadcast ID belongs to a specific provider.

        Args:
            broadcast_id: Encoded broadcast ID
            provider_name: Provider name to verify

        Returns:
            True if broadcast_id was generated for this provider
        """
        return EPGEntry.verify_provider(broadcast_id, provider_name)
