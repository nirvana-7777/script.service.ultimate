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
"""

from datetime import datetime, timedelta
from typing import List, Dict, Optional
from .epg_cache import EPGCache
from .epg_mapping import EPGMapping
from .epg_parser import EPGParser
from ..models.epg_models import EPGEntry
from ..utils.logger import logger


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
            epg_url: EPG source URL (defaults to setting or DEFAULT_EPG_URL)
        """
        # Initialize components - they handle paths internally
        self.cache = EPGCache(vfs_subdir="epg_cache")
        self.mapping = EPGMapping()  # No paths needed - handles internally
        self.parser = EPGParser()

        # Get EPG URL from settings or use default
        self.epg_url = epg_url or self._get_epg_url_from_settings() or self.DEFAULT_EPG_URL

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
                url = bridge.addon.getSetting('epg_xml_url')

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
            end_time: Optional[datetime] = None
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
            epg_entries: List[EPGEntry] = self.parser.parse_epg_for_channel(
                xml_path,
                epg_channel_id,
                start_ts,
                end_ts
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
            end_time: Optional[datetime] = None
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
                end_ts
            )

        except Exception as e:
            logger.error(f"EPGManager: Error getting EPG entries: {e}", exc_info=True)
            return []

    def get_epg_for_provider(
            self,
            provider_name: str,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None
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
        logger.info(f"EPGManager: Getting EPG for all channels of provider '{provider_name}'")

        result = {}

        # Get all mapped channels for this provider
        provider_mapping = self.mapping.get_provider_mapping(provider_name)

        if not provider_mapping:
            logger.warning(f"EPGManager: No channels mapped for provider '{provider_name}'")
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
