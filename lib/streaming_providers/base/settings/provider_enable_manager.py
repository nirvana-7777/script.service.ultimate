# streaming_providers/base/settings/provider_enable_manager.py
"""
Provider Enable Manager - Handles provider enable/disable status with precedence:
1. Kodi settings (if in Kodi environment and setting exists)
2. providers_enabled.json file
3. Default to enabled (True)

Works in both Kodi and standalone environments.
"""

import time
from typing import Dict, Optional, Tuple, Any
from enum import Enum

from ..utils.logger import logger
from ..utils.environment import is_kodi_environment, get_vfs_instance


class EnableSource(Enum):
    """Source of the enable setting"""
    KODI = "kodi"
    FILE = "file"
    DEFAULT = "default"


class ProviderEnableManager:
    """
    Manages provider enable/disable status with proper precedence.
    Uses VFS for file operations to work in both Kodi and standalone.
    """

    DEFAULT_FILENAME = "providers_enabled.json"
    DEFAULT_VERSION = "1.0"
    CACHE_TTL = 30  # seconds

    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize the enable manager.

        Args:
            config_dir: Optional configuration directory (uses VFS default if None)
        """
        self.vfs = get_vfs_instance(config_dir=config_dir)
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_time: float = 0
        self._kodi_bridge = None

        # Try to initialize Kodi bridge if in Kodi environment
        if is_kodi_environment():
            try:
                from .settings.kodi_settings_bridge import KodiSettingsBridge
                self._kodi_bridge = KodiSettingsBridge(config_dir=config_dir)
                logger.debug("ProviderEnableManager: Kodi bridge initialized")
            except ImportError as e:
                logger.debug(f"ProviderEnableManager: Kodi bridge not available: {e}")
                self._kodi_bridge = None

    def _load_file(self, force_reload: bool = False) -> Dict[str, Any]:
        """
        Load providers_enabled.json file with caching.

        Args:
            force_reload: Force reload from disk ignoring cache

        Returns:
            Dictionary with file contents
        """
        current_time = time.time()

        # Check cache first
        if not force_reload and self._cache and (current_time - self._cache_time) < self.CACHE_TTL:
            return self._cache

        # Initialize default structure
        default_data = {
            "version": self.DEFAULT_VERSION,
            "providers": {}
        }

        # Check if file exists
        if not self.vfs.exists(self.DEFAULT_FILENAME):
            self._cache = default_data
            self._cache_time = current_time
            logger.debug(f"ProviderEnableManager: File {self.DEFAULT_FILENAME} not found, using defaults")
            return default_data

        try:
            # Read file via VFS
            data = self.vfs.read_json(self.DEFAULT_FILENAME)

            if not isinstance(data, dict):
                logger.warning(f"ProviderEnableManager: Invalid file format, using defaults")
                self._cache = default_data
                self._cache_time = current_time
                return default_data

            # Ensure required structure
            if "version" not in data:
                data["version"] = self.DEFAULT_VERSION

            if "providers" not in data or not isinstance(data["providers"], dict):
                data["providers"] = {}

            # Ensure all values are booleans
            for provider, value in list(data["providers"].items()):
                if not isinstance(value, bool):
                    try:
                        data["providers"][provider] = bool(value)
                    except (ValueError, TypeError):
                        logger.warning(f"ProviderEnableManager: Invalid value for {provider}, removing")
                        del data["providers"][provider]

            # Add last_updated if missing
            if "last_updated" not in data:
                data["last_updated"] = current_time

            # Update cache
            self._cache = data
            self._cache_time = current_time

            logger.debug(f"ProviderEnableManager: Loaded {len(data['providers'])} providers from file")
            return data

        except Exception as e:
            logger.error(f"ProviderEnableManager: Error loading {self.DEFAULT_FILENAME}: {e}")
            self._cache = default_data
            self._cache_time = current_time
            return default_data

    def _save_file(self, data: Dict[str, Any]) -> bool:
        """
        Save data to providers_enabled.json file.

        Args:
            data: Data to save

        Returns:
            True if successful, False otherwise
        """
        try:
            # Add/update metadata
            data["last_updated"] = time.time()
            if "version" not in data:
                data["version"] = self.DEFAULT_VERSION

            # Write via VFS
            success = self.vfs.write_json(self.DEFAULT_FILENAME, data)

            if success:
                # Update cache
                self._cache = data
                self._cache_time = time.time()
                logger.debug(f"ProviderEnableManager: Saved {len(data.get('providers', {}))} providers to file")
            else:
                logger.error(f"ProviderEnableManager: Failed to write to {self.DEFAULT_FILENAME}")

            return success

        except Exception as e:
            logger.error(f"ProviderEnableManager: Error saving {self.DEFAULT_FILENAME}: {e}")
            return False

    def _get_kodi_enabled_status(self, provider_name: str) -> Optional[bool]:
        logger.debug(f"DEBUG _get_kodi_enabled_status called with: '{provider_name}'")

        if not is_kodi_environment() or not self._kodi_bridge:
            logger.debug(f"DEBUG: Not in Kodi environment or bridge unavailable")
            return None

        try:
            parts = provider_name.rsplit('_', 1)
            logger.debug(f"DEBUG: Parts after split: {parts}")

            # Check country-specific setting first
            if len(parts) == 2 and len(parts[1]) in (2, 3):
                provider, country = parts
                country_setting = f"enable_{provider}_{country}"
                logger.debug(f"DEBUG: Looking for Kodi setting: '{country_setting}'")

                country_value = self._kodi_bridge.get_setting(country_setting)
                logger.debug(f"DEBUG: Kodi bridge returned value: '{country_value}' (type: {type(country_value)})")

                if country_value:
                    enabled = country_value.lower() in ['true', '1', 'yes']
                    logger.debug(f"DEBUG: Parsed '{country_value}' as enabled={enabled}")
                    return enabled
                else:
                    logger.debug(f"DEBUG: Kodi bridge returned empty/falsy value")

            # Try general provider setting
            general_setting = f"enable_{provider_name}"
            logger.debug(f"DEBUG: Trying general setting: '{general_setting}'")
            general_value = self._kodi_bridge.get_setting(general_setting)
            logger.debug(f"DEBUG: General Kodi returned: '{general_value}'")

            if general_value:
                enabled = general_value.lower() in ['true', '1', 'yes']
                logger.debug(f"DEBUG: General parsed as: {enabled}")
                return enabled

            logger.debug(f"DEBUG: No Kodi setting found for {provider_name}")
            return None

        except Exception as e:
            logger.debug(f"DEBUG: Exception in _get_kodi_enabled_status: {e}")
            return None

    def is_provider_enabled(self, provider_name: str) -> bool:
        """
        Check if provider is enabled using precedence rules.

        Precedence:
        1. Kodi settings (if in Kodi and setting exists)
        2. providers_enabled.json file
        3. Default to True

        Args:
            provider_name: Provider name (e.g., "joyn_de", "rtlplus")

        Returns:
            True if enabled, False if disabled
        """
        # 1. Check Kodi settings first
        kodi_enabled = self._get_kodi_enabled_status(provider_name)
        if kodi_enabled is not None:
            return kodi_enabled

        # 2. Check file
        data = self._load_file()
        file_enabled = data["providers"].get(provider_name)

        if file_enabled is not None:
            return file_enabled

        # 3. Default to enabled
        return True

    def get_enabled_source(self, provider_name: str) -> EnableSource:
        """
        Determine where the enabled status comes from.

        Args:
            provider_name: Provider name

        Returns:
            EnableSource enum (KODI, FILE, or DEFAULT)
        """
        # Check Kodi first
        kodi_enabled = self._get_kodi_enabled_status(provider_name)
        if kodi_enabled is not None:
            return EnableSource.KODI

        # Check file
        data = self._load_file()
        file_enabled = data["providers"].get(provider_name)

        if file_enabled is not None:
            return EnableSource.FILE

        return EnableSource.DEFAULT

    def set_provider_enabled(self, provider_name: str, enabled: bool) -> Tuple[bool, str]:
        """
        Set enabled status for a provider (writes to file only).

        Note: Cannot override Kodi settings. If provider is controlled by
        Kodi settings, this will return False.

        Args:
            provider_name: Provider name
            enabled: True to enable, False to disable

        Returns:
            Tuple of (success: bool, message: str)
        """
        # Check if controlled by Kodi
        source = self.get_enabled_source(provider_name)

        if source == EnableSource.KODI:
            message = f"Provider '{provider_name}' is controlled by Kodi settings. " \
                      f"Change the setting in Kodi addon settings."
            logger.warning(f"ProviderEnableManager: {message}")
            return False, message

        # Load current data
        data = self._load_file()

        # Update provider status
        data["providers"][provider_name] = bool(enabled)

        # Save to file
        success = self._save_file(data)

        if success:
            action = "enabled" if enabled else "disabled"
            message = f"Provider '{provider_name}' {action} in file"
            logger.info(f"ProviderEnableManager: {message}")
            return True, message
        else:
            message = f"Failed to save enabled status for '{provider_name}'"
            logger.error(f"ProviderEnableManager: {message}")
            return False, message

    def get_all_enabled_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get enabled status for all providers in file.

        Returns:
            Dictionary mapping provider names to their status info
        """
        data = self._load_file()
        result = {}

        for provider_name, enabled in data["providers"].items():
            source = self.get_enabled_source(provider_name)

            result[provider_name] = {
                "enabled": enabled,
                "source": source.value,
                "can_modify": source != EnableSource.KODI
            }

        return result

    def get_provider_status(self, provider_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed status for a specific provider.

        Args:
            provider_name: Provider name

        Returns:
            Dictionary with status info, or None if provider not in file
        """
        data = self._load_file()

        if provider_name not in data["providers"]:
            return None

        enabled = data["providers"][provider_name]
        source = self.get_enabled_source(provider_name)

        return {
            "provider": provider_name,
            "enabled": enabled,
            "source": source.value,
            "can_modify": source != EnableSource.KODI,
            "in_file": True
        }

    def delete_provider_setting(self, provider_name: str) -> Tuple[bool, str]:
        """
        Delete provider setting from file (reset to default).

        Args:
            provider_name: Provider name

        Returns:
            Tuple of (success: bool, message: str)
        """
        # Check if controlled by Kodi
        source = self.get_enabled_source(provider_name)

        if source == EnableSource.KODI:
            message = f"Cannot delete setting for '{provider_name}' - controlled by Kodi"
            logger.warning(f"ProviderEnableManager: {message}")
            return False, message

        # Load current data
        data = self._load_file()

        # Remove if exists
        if provider_name in data["providers"]:
            del data["providers"][provider_name]

            # Save to file
            success = self._save_file(data)

            if success:
                message = f"Deleted setting for '{provider_name}' from file"
                logger.info(f"ProviderEnableManager: {message}")
                return True, message
            else:
                message = f"Failed to delete setting for '{provider_name}'"
                logger.error(f"ProviderEnableManager: {message}")
                return False, message

        # Provider not in file
        message = f"Setting for '{provider_name}' not found in file"
        logger.debug(f"ProviderEnableManager: {message}")
        return True, message  # Already not in file, so success

    def reset_all_to_defaults(self) -> Tuple[bool, str]:
        """
        Reset all provider settings to defaults (empty file).

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Create default structure
            default_data = {
                "version": self.DEFAULT_VERSION,
                "last_updated": time.time(),
                "providers": {}
            }

            # Save empty file
            success = self._save_file(default_data)

            if success:
                message = "All provider settings reset to defaults"
                logger.info(f"ProviderEnableManager: {message}")
                return True, message
            else:
                message = "Failed to reset provider settings"
                logger.error(f"ProviderEnableManager: {message}")
                return False, message

        except Exception as e:
            message = f"Error resetting provider settings: {e}"
            logger.error(f"ProviderEnableManager: {message}")
            return False, message

    def get_file_info(self) -> Dict[str, Any]:
        """
        Get information about the providers_enabled.json file.

        Returns:
            Dictionary with file information
        """
        data = self._load_file()

        return {
            "filename": self.DEFAULT_FILENAME,
            "version": data.get("version", self.DEFAULT_VERSION),
            "last_updated": data.get("last_updated"),
            "provider_count": len(data.get("providers", {})),
            "file_exists": self.vfs.exists(self.DEFAULT_FILENAME),
            "file_path": self.vfs.get_file_path(self.DEFAULT_FILENAME) if hasattr(self.vfs, 'get_file_path') else "vfs"
        }

    def migrate_from_kodi(self) -> Tuple[bool, str, int]:
        """
        Migrate all Kodi enable settings to the file.
        Only copies settings that are explicitly set in Kodi.

        Returns:
            Tuple of (success: bool, message: str, migrated_count: int)
        """
        if not is_kodi_environment() or not self._kodi_bridge:
            return False, "Not in Kodi environment or Kodi bridge not available", 0

        try:
            # Load current file data
            data = self._load_file()
            migrated_count = 0

            # Discover all providers from Kodi settings
            try:
                kodi_providers = self._kodi_bridge.discover_all_providers()
            except AttributeError:
                # Fallback if discover_all_providers not available
                kodi_providers = {}

            # Check each provider
            for provider_name in kodi_providers:
                kodi_enabled = self._get_kodi_enabled_status(provider_name)

                if kodi_enabled is not None:
                    # Kodi has explicit setting, migrate to file
                    data["providers"][provider_name] = kodi_enabled
                    migrated_count += 1
                    logger.debug(f"ProviderEnableManager: Migrated {provider_name}={kodi_enabled}")

            if migrated_count > 0:
                # Save migrated data
                success = self._save_file(data)
                if success:
                    message = f"Migrated {migrated_count} provider settings from Kodi to file"
                    logger.info(f"ProviderEnableManager: {message}")
                    return True, message, migrated_count
                else:
                    message = "Failed to save migrated settings"
                    logger.error(f"ProviderEnableManager: {message}")
                    return False, message, 0
            else:
                message = "No Kodi provider settings found to migrate"
                logger.info(f"ProviderEnableManager: {message}")
                return True, message, 0

        except Exception as e:
            message = f"Error migrating from Kodi: {e}"
            logger.error(f"ProviderEnableManager: {message}")
            return False, message, 0