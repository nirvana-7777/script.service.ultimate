#!/usr/bin/env python3
# streaming_providers/base/epg/epg_mapping.py
"""
EPG Channel Mapping Manager
Maps provider/channel IDs to EPG channel IDs from XMLTV
"""

import os
from typing import Optional, Dict
from ..utils.logger import logger
from ..utils.vfs import VFS


class EPGMapping:
    """
    Manages mapping between provider channel IDs and EPG channel IDs.
    Supports user-editable mapping with default fallback.

    Uses VFS for all file operations. Automatically detects addon resources
    path for default mapping (only used on first run to copy defaults).
    """

    # Mapping filename
    MAPPING_FILE = "epg_mapping.json"

    def __init__(self):
        """
        Initialize EPG mapping manager.
        Automatically detects environment and sets up paths.
        """
        # VFS for user data directory (where editable mapping lives)
        self.user_vfs = VFS(addon_subdir="")  # Root of addon data

        self.mapping: Dict[str, Dict[str, str]] = {}

        logger.info(f"EPGMapping: User mapping path: {self.user_vfs.base_path}")

        # Load mapping on initialization
        self._load_mapping()

    def _get_default_mapping_path(self) -> Optional[str]:
        """
        Get path to default mapping in addon resources.
        Only used on first run to copy defaults to user directory.

        Uses settings manager to detect paths if available.

        Returns:
            Path to default mapping file, or None if not found
        """
        try:
            # Try to use settings manager's kodi bridge to get addon path
            from ..settings.kodi_settings_bridge import KodiSettingsBridge

            bridge = KodiSettingsBridge()
            if bridge.is_kodi_environment():
                addon_info = bridge.get_addon_info()
                addon_path = addon_info.get('path')
                if addon_path:
                    default_path = os.path.join(addon_path, 'resources', 'config', self.MAPPING_FILE)
                    logger.debug(f"EPGMapping: Default mapping path (Kodi): {default_path}")
                    return default_path

            # Fallback to standard filesystem
            addon_path = os.getcwd()
            default_path = os.path.join(addon_path, 'resources', 'config', self.MAPPING_FILE)
            logger.debug(f"EPGMapping: Default mapping path (standard): {default_path}")
            return default_path

        except Exception as e:
            logger.warning(f"EPGMapping: Could not determine default mapping path: {e}")
            # Last resort fallback
            addon_path = os.getcwd()
            default_path = os.path.join(addon_path, 'resources', 'config', self.MAPPING_FILE)
            return default_path

    def _copy_default_to_user(self) -> bool:
        """
        Copy default mapping from addon resources to user directory.
        Only called on first run when user mapping doesn't exist.

        Returns:
            True if copied successfully or created empty mapping
        """
        default_path = self._get_default_mapping_path()

        if default_path and os.path.exists(default_path):
            # Read default mapping using standard file operations
            # (it's in addon resources, not in VFS user data)
            try:
                import json
                with open(default_path, 'r', encoding='utf-8') as f:
                    default_mapping = json.load(f)

                # Write to user VFS
                if self.user_vfs.write_json(self.MAPPING_FILE, default_mapping):
                    logger.info(f"EPGMapping: Copied default mapping to user directory")
                    return True
                else:
                    logger.error(f"EPGMapping: Failed to write default mapping to user directory")
                    return False

            except Exception as e:
                logger.error(f"EPGMapping: Failed to read/copy default mapping: {e}")
                # Fall through to create empty mapping

        # No default found or copy failed - create empty mapping
        logger.warning("EPGMapping: No default mapping found, creating empty mapping")
        empty_mapping = {}
        if self.user_vfs.write_json(self.MAPPING_FILE, empty_mapping):
            logger.info("EPGMapping: Created empty user mapping file")
            return True
        else:
            logger.error("EPGMapping: Failed to create empty user mapping")
            return False

    def _ensure_user_mapping_exists(self) -> bool:
        """
        Ensure user mapping file exists. Copy from default if needed.

        Returns:
            True if user mapping exists or was created successfully
        """
        # Check if user mapping already exists
        if self.user_vfs.exists(self.MAPPING_FILE):
            logger.debug("EPGMapping: User mapping file exists")
            return True

        # User mapping doesn't exist - copy from default or create empty
        logger.info("EPGMapping: User mapping not found, initializing...")
        return self._copy_default_to_user()

    def _load_mapping(self) -> bool:
        """
        Load mapping from user file.

        Returns:
            True if mapping loaded successfully
        """
        # Ensure user mapping exists (copy from default on first run)
        self._ensure_user_mapping_exists()

        # Load user mapping
        user_mapping = self.user_vfs.read_json(self.MAPPING_FILE)
        if user_mapping is not None:
            self.mapping = user_mapping
            logger.info(f"EPGMapping: Loaded mapping with {len(self.mapping)} providers")
            return True

        # Failed to load mapping
        logger.warning("EPGMapping: Failed to load mapping, using empty mapping")
        self.mapping = {}
        return False

    def get_epg_channel_id(self, provider_name: str, channel_id: str) -> Optional[str]:
        """
        Get EPG channel ID for a provider/channel combination.

        Args:
            provider_name: Name of provider (e.g., "rtlplus", "joyn_de")
            channel_id: Channel ID within provider

        Returns:
            EPG channel ID (e.g., "de.rtl"), or None if not mapped
        """
        # Get provider's mapping
        provider_mapping = self.mapping.get(provider_name)
        if not provider_mapping:
            logger.debug(f"EPGMapping: No mapping found for provider '{provider_name}'")
            return None

        # Get channel's EPG ID
        epg_id = provider_mapping.get(channel_id)
        if not epg_id:
            logger.debug(f"EPGMapping: No EPG ID found for '{provider_name}/{channel_id}'")
            return None

        logger.debug(f"EPGMapping: Mapped '{provider_name}/{channel_id}' -> '{epg_id}'")
        return epg_id

    def get_provider_mapping(self, provider_name: str) -> Dict[str, str]:
        """
        Get all channel mappings for a specific provider.

        Args:
            provider_name: Name of provider

        Returns:
            Dictionary mapping channel IDs to EPG IDs
        """
        return self.mapping.get(provider_name, {})

    def has_mapping(self, provider_name: str, channel_id: Optional[str] = None) -> bool:
        """
        Check if mapping exists for provider or specific channel.

        Args:
            provider_name: Name of provider
            channel_id: Optional channel ID to check

        Returns:
            True if mapping exists
        """
        if provider_name not in self.mapping:
            return False

        if channel_id is None:
            return True

        return channel_id in self.mapping[provider_name]

    def reload_mapping(self) -> bool:
        """
        Reload mapping from file (useful after user edits).

        Returns:
            True if reloaded successfully
        """
        logger.info("EPGMapping: Reloading mapping from file")
        return self._load_mapping()

    def get_mapping_stats(self) -> Dict:
        """
        Get statistics about current mapping.

        Returns:
            Dictionary with mapping statistics
        """
        total_providers = len(self.mapping)
        total_channels = sum(len(channels) for channels in self.mapping.values())

        user_mapping_path = self.user_vfs.join_path(self.MAPPING_FILE)

        return {
            'total_providers': total_providers,
            'total_channels': total_channels,
            'providers': list(self.mapping.keys()),
            'user_mapping_path': user_mapping_path,
            'user_mapping_exists': self.user_vfs.exists(self.MAPPING_FILE)
        }