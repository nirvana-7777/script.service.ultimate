#!/usr/bin/env python3
# streaming_providers/base/epg/epg_mapping.py
"""
EPG Channel Mapping Manager
Maps provider/channel IDs to EPG channel IDs from XMLTV

New provider-per-file format:
- Each provider has its own file: {provider}_epg_mapping.json
- File contains direct channel mappings without provider wrapper
"""

import glob
import os
from typing import Any, Dict, List, Optional

from ..utils.logger import logger
from ..utils.vfs import VFS


class EPGMapping:
    """
    Manages mapping between provider channel IDs and EPG channel IDs.
    Uses separate JSON files per provider for better organization.

    File format (per provider):
    {
      "_provider_name": "Display Name (optional)",
      "channel_id": {
        "epg_id": "tkmde_404",
        "name": "Channel Display Name"
      }
    }

    Fallback: If no mapping file exists or is corrupted, uses channel_id as epg_id.
    """

    # Mapping filename pattern
    MAPPING_FILE_PATTERN = "*_epg_mapping.json"
    MAPPING_FILE_SUFFIX = "_epg_mapping.json"

    def __init__(self):
        """
        Initialize EPG mapping manager.
        Sets up VFS and copies default mapping files from addon resources.
        """
        # VFS for user data directory
        self.user_vfs = VFS(addon_subdir="")  # Root of addon data

        # Cache for loaded provider mappings
        # Structure: {provider_name: {"mapping": {...}, "names": {...}}}
        self._cache: Dict[str, Dict[str, Any]] = {}

        logger.info(
            f"EPGMapping: Initialized with user path: {self.user_vfs.base_path}"
        )

        # Copy default mapping files from addon resources
        self._copy_default_mapping_files()

    @staticmethod
    def _get_default_mapping_files_dir() -> Optional[str]:
        """
        Get path to default mapping files directory in addon resources.

        Returns:
            Path to default mapping directory, or None if not found
        """
        try:
            # Try to use settings manager's kodi bridge to get addon path
            from ..settings.kodi_settings_bridge import KodiSettingsBridge

            bridge = KodiSettingsBridge()
            if bridge.is_kodi_environment():
                addon_info = bridge.get_addon_info()
                addon_path = addon_info.get("path")
                if addon_path:
                    default_dir = os.path.join(
                        addon_path, "resources", "config", "epg_mappings"
                    )
                    logger.debug(
                        f"EPGMapping: Default mapping dir (Kodi): {default_dir}"
                    )
                    return default_dir

            # Fallback to standard filesystem
            addon_path = os.getcwd()
            default_dir = os.path.join(
                addon_path, "resources", "config", "epg_mappings"
            )
            logger.debug(f"EPGMapping: Default mapping dir (standard): {default_dir}")
            return default_dir

        except Exception as e:
            logger.warning(f"EPGMapping: Could not determine default mapping dir: {e}")
            # Last resort fallback
            addon_path = os.getcwd()
            default_dir = os.path.join(
                addon_path, "resources", "config", "epg_mappings"
            )
            return default_dir

    def _copy_default_mapping_files(self) -> bool:
        """
        Copy all default mapping files from addon resources to user directory.
        Only called on first run.

        Returns:
            True if at least one file was copied or user files already exist
        """
        default_dir = self._get_default_mapping_files_dir()

        if not default_dir or not os.path.exists(default_dir):
            logger.warning("EPGMapping: No default mapping directory found")
            # Check if any user mapping files already exist
            user_files = self.user_vfs.list_files(pattern=self.MAPPING_FILE_PATTERN)
            if user_files:
                logger.info(
                    f"EPGMapping: Found {len(user_files)} existing user mapping files"
                )
                return True
            else:
                logger.warning("EPGMapping: No default files and no user files found")
                return False

        try:
            # Get list of default mapping files
            default_files = glob.glob(
                os.path.join(default_dir, self.MAPPING_FILE_PATTERN)
            )

            if not default_files:
                logger.warning(
                    f"EPGMapping: No default mapping files found in {default_dir}"
                )
                return False

            copied_count = 0

            for default_file in default_files:
                filename = os.path.basename(default_file)

                # Skip if user file already exists
                if self.user_vfs.exists(filename):
                    logger.debug(f"EPGMapping: User file already exists: {filename}")
                    continue

                # Read default file using standard file operations
                try:
                    with open(default_file, "r", encoding="utf-8") as f:
                        content = f.read()

                    # Write to user VFS
                    if self.user_vfs.write_text(filename, content):
                        logger.info(f"EPGMapping: Copied default mapping: {filename}")
                        copied_count += 1
                    else:
                        logger.error(
                            f"EPGMapping: Failed to write user mapping: {filename}"
                        )

                except Exception as e:
                    logger.error(f"EPGMapping: Failed to read/copy {filename}: {e}")
                    continue

            logger.info(f"EPGMapping: Copied {copied_count} default mapping files")
            return copied_count > 0

        except Exception as e:
            logger.error(f"EPGMapping: Failed to copy default mapping files: {e}")
            return False

    def _extract_provider_from_filename(self, filename: str) -> str:
        """
        Extract provider name from mapping filename.

        Args:
            filename: e.g., "magentaeu_at_epg_mapping.json"

        Returns:
            Provider name, e.g., "magentaeu_at"
        """
        if filename.endswith(self.MAPPING_FILE_SUFFIX):
            return filename[: -len(self.MAPPING_FILE_SUFFIX)]
        return filename

    def _get_mapping_filename(self, provider_name: str) -> str:
        """
        Get mapping filename for a provider.

        Args:
            provider_name: Provider name

        Returns:
            Filename, e.g., "magentaeu_at_epg_mapping.json"
        """
        return f"{provider_name}{self.MAPPING_FILE_SUFFIX}"

    def _load_provider_mapping(self, provider_name: str) -> Optional[Dict[str, Any]]:
        """
        Load mapping for a specific provider from file.
        Uses cache if already loaded.

        Args:
            provider_name: Provider name to load mapping for

        Returns:
            Dictionary with "mapping" and "names", or None if failed
        """
        # Check cache first
        if provider_name in self._cache:
            logger.debug(f"EPGMapping: Using cached mapping for '{provider_name}'")
            return self._cache[provider_name]

        filename = self._get_mapping_filename(provider_name)

        # Check if file exists
        if not self.user_vfs.exists(filename):
            logger.debug(
                f"EPGMapping: No mapping file found for provider '{provider_name}'"
            )
            return None

        try:
            # Load mapping from file
            raw_mapping = self.user_vfs.read_json(filename)
            if raw_mapping is None:
                logger.warning(
                    f"EPGMapping: Failed to parse mapping file for '{provider_name}'"
                )
                return None

            # Flatten the mapping
            mapping = {}
            names = {}

            for channel_id, channel_data in raw_mapping.items():
                # Skip metadata entries (those starting with underscore)
                if channel_id.startswith("_"):
                    continue

                # Handle both dict format and simple string format
                if isinstance(channel_data, dict):
                    # New format: { "epg_id": "...", "name": "..." }
                    epg_id = channel_data.get("epg_id")
                    name = channel_data.get("name", channel_id)
                elif isinstance(channel_data, str):
                    # Legacy simple format: just the epg_id string
                    epg_id = channel_data
                    name = channel_id
                else:
                    logger.warning(
                        f"EPGMapping: Invalid format for {provider_name}/{channel_id}"
                    )
                    continue

                if epg_id:
                    mapping[channel_id] = epg_id
                    names[channel_id] = name

            # Store in cache
            cached_data = {
                "mapping": mapping,
                "names": names,
                "provider_name": raw_mapping.get("_provider_name", provider_name),
            }
            self._cache[provider_name] = cached_data

            logger.info(
                f"EPGMapping: Loaded mapping for '{provider_name}' "
                f"with {len(mapping)} channels"
            )

            return cached_data

        except Exception as e:
            logger.error(
                f"EPGMapping: Failed to load mapping for '{provider_name}': {e}"
            )
            return None

    def get_epg_channel_id(self, provider_name: str, channel_id: str) -> Optional[str]:
        """
        Get EPG channel ID for a provider/channel combination.
        Falls back to channel_id if no mapping found.

        Args:
            provider_name: Name of provider (e.g., "rtlplus", "joyn_de")
            channel_id: Channel ID within provider

        Returns:
            EPG channel ID, or channel_id if no mapping found
        """
        # Load provider mapping
        provider_data = self._load_provider_mapping(provider_name)

        if not provider_data:
            # No mapping file exists - fall back to using channel_id as epg_id
            logger.debug(
                f"EPGMapping: No mapping file for '{provider_name}', "
                f"using channel_id as epg_id: '{channel_id}'"
            )
            return channel_id

        # Get channel's EPG ID
        epg_id = provider_data["mapping"].get(channel_id)

        if epg_id:
            logger.debug(
                f"EPGMapping: Mapped '{provider_name}/{channel_id}' -> '{epg_id}'"
            )
            return epg_id
        else:
            # Channel not in mapping - fall back to channel_id
            logger.debug(
                f"EPGMapping: No mapping for '{provider_name}/{channel_id}', "
                f"using channel_id as epg_id"
            )
            return channel_id

    def get_channel_name(self, provider_name: str, channel_id: str) -> Optional[str]:
        """
        Get display name for a channel.

        Args:
            provider_name: Name of provider
            channel_id: Channel ID within provider

        Returns:
            Channel display name, or None if not found
        """
        provider_data = self._load_provider_mapping(provider_name)

        if not provider_data:
            return None

        return provider_data["names"].get(channel_id)

    def get_provider_mapping(self, provider_name: str) -> Dict[str, str]:
        """
        Get all channel mappings for a specific provider.

        Args:
            provider_name: Name of provider

        Returns:
            Dictionary mapping channel IDs to EPG IDs
        """
        provider_data = self._load_provider_mapping(provider_name)

        if not provider_data:
            return {}

        return provider_data["mapping"].copy()

    def has_mapping(self, provider_name: str, channel_id: Optional[str] = None) -> bool:
        """
        Check if mapping exists for provider or specific channel.

        Args:
            provider_name: Name of provider
            channel_id: Optional channel ID to check

        Returns:
            True if mapping exists
        """
        provider_data = self._load_provider_mapping(provider_name)

        if not provider_data:
            return False

        if channel_id is None:
            return True

        return channel_id in provider_data["mapping"]

    def reload_mapping(self, provider_name: Optional[str] = None) -> bool:
        """
        Reload mapping from file. If provider_name is None, reload all.

        Args:
            provider_name: Provider name to reload, or None for all

        Returns:
            True if reloaded successfully
        """
        if provider_name is None:
            logger.info("EPGMapping: Reloading all mappings from files")
            self._cache.clear()
            return True
        else:
            logger.info(f"EPGMapping: Reloading mapping for '{provider_name}'")
            if provider_name in self._cache:
                del self._cache[provider_name]
            return self._load_provider_mapping(provider_name) is not None

    def get_mapping_stats(self) -> Dict:
        """
        Get statistics about current mapping.

        Returns:
            Dictionary with mapping statistics
        """
        # List all provider mapping files in user directory
        user_files = self.user_vfs.list_files(pattern=self.MAPPING_FILE_PATTERN)

        # Extract provider names from filenames
        providers = [self._extract_provider_from_filename(f) for f in user_files]

        # Get cached providers
        cached_providers = list(self._cache.keys())

        total_channels = sum(len(data["mapping"]) for data in self._cache.values())

        return {
            "total_providers": len(providers),
            "cached_providers": len(cached_providers),
            "total_channels": total_channels,
            "providers": providers,
            "cached_providers_list": cached_providers,
            "user_mapping_dir": self.user_vfs.base_path,
        }

    def list_providers_with_mappings(self) -> List[str]:
        """
        List all providers that have mapping files.

        Returns:
            List of provider names
        """
        user_files = self.user_vfs.list_files(pattern=self.MAPPING_FILE_PATTERN)
        return [self._extract_provider_from_filename(f) for f in user_files]
