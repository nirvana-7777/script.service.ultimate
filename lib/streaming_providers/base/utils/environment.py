# streaming_providers/base/utils/environment.py
"""
Central environment detection and service management.
Provides unified access to VFS, logger, settings bridge, and other services.
"""

import os
import sys
import json
from typing import Dict, Any, Optional, TYPE_CHECKING, Union
from pathlib import Path

# Type hints to avoid circular imports
if TYPE_CHECKING:
    from .vfs import VFS
    from .logger import BaseLogger  # Changed from 'logger' to 'BaseLogger'
    from ..settings.kodi_settings_bridge import KodiSettingsBridge


class EnvironmentManager:
    """
    Central manager for environment detection and service coordination.
    """

    _instance: Optional['EnvironmentManager'] = None

    def __new__(cls) -> 'EnvironmentManager':
        if cls._instance is None:
            cls._instance = super(EnvironmentManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        self._initialized = True

        # Check for Kodi availability
        try:
            import xbmcaddon
            import xbmcvfs
            self._is_kodi = True
            self._kodi_import_error: Optional[Exception] = None
        except ImportError as import_err:
            self._is_kodi = False
            self._kodi_import_error = import_err

        self._addon: Any = None
        self._config: Dict[str, Any] = {}
        self._services: Dict[str, Any] = {}

        # Initialize based on environment
        if self._is_kodi:
            self._init_kodi()
        else:
            self._init_standalone()

        self._load_config()

    def _init_kodi(self) -> None:
        """Initialize Kodi-specific components"""
        try:
            # Import inside the method where we know Kodi is available
            import xbmcaddon as kodi_xbmcaddon
            import xbmcvfs as kodi_xbmcvfs

            # Create addon instance
            self._addon = kodi_xbmcaddon.Addon()

            self._config['environment'] = 'kodi'
            self._config['addon_id'] = self._addon.getAddonInfo('id')
            self._config['addon_name'] = self._addon.getAddonInfo('name')
            self._config['addon_version'] = self._addon.getAddonInfo('version')
            self._config['addon_path'] = self._addon.getAddonInfo('path')

            # Get profile path
            profile_info = self._addon.getAddonInfo('profile')
            profile_path = kodi_xbmcvfs.translatePath(profile_info)

            self._config['profile_path'] = str(profile_path)

            # Get settings
            default_country = self._addon.getSetting('default_country')
            self._config['default_country'] = str(default_country) if default_country else 'DE'

            server_port = self._addon.getSetting('server_port')
            try:
                self._config['server_port'] = int(str(server_port)) if server_port else 7777
            except ValueError:
                self._config['server_port'] = 7777

        except Exception as init_error:  # noqa: B902
            print(f"DEBUG: Exception type: {type(init_error).__name__}", file=sys.stderr)
            print(f"DEBUG: Exception message: {str(init_error)}", file=sys.stderr)
            # Log the error and fallback to standalone
            self._log_init_error("Kodi initialization failed", init_error)
            self._is_kodi = False
            self._init_standalone()

    @staticmethod
    def _log_init_error(message: str, error: Exception) -> None:
        """Log initialization errors (static method)"""
        # We can't use logger here yet, so print to stderr
        print(f"{message}: {error}", file=sys.stderr)

    def _init_standalone(self) -> None:
        """Initialize standalone mode components"""
        self._config['environment'] = 'standalone'
        self._config['addon_id'] = 'ultimate-backend-standalone'
        self._config['addon_name'] = 'Ultimate Backend'
        self._config['addon_version'] = '1.0.0'
        self._config['addon_path'] = os.path.dirname(os.path.abspath(__file__))

        # Default configuration paths
        config_home = os.environ.get('XDG_CONFIG_HOME') or os.path.join(str(Path.home()), '.config')
        self._config['config_dir'] = os.path.join(config_home, 'ultimate-backend')
        self._config['profile_path'] = self._config['config_dir']

        # Load environment variables with defaults
        self._config['default_country'] = os.environ.get('DEFAULT_COUNTRY', 'DE')

        try:
            self._config['server_port'] = int(os.environ.get('SERVER_PORT', '7777'))
        except ValueError as port_error:
            print(f"Invalid server port, using default: {port_error}", file=sys.stderr)
            self._config['server_port'] = 7777

        # Ensure config directory exists
        try:
            os.makedirs(self._config['config_dir'], exist_ok=True)
        except OSError as dir_error:
            print(f"Failed to create config directory: {dir_error}", file=sys.stderr)
            # Use temp directory as fallback
            import tempfile
            self._config['config_dir'] = tempfile.mkdtemp(prefix='ultimate-backend-')
            self._config['profile_path'] = self._config['config_dir']

    def _load_config(self) -> None:
        """Load additional configuration from files"""
        config_file = os.path.join(self._config['profile_path'], 'config.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    # Update config with file contents
                    for key, value in file_config.items():
                        if isinstance(value, (str, int, float, bool, type(None))):
                            self._config[key] = value
            except json.JSONDecodeError as json_error:
                print(f"Invalid JSON in config file: {json_error}", file=sys.stderr)
            except OSError as io_error:
                print(f"Failed to read config file: {io_error}", file=sys.stderr)

    def is_kodi(self) -> bool:
        """Check if running in Kodi environment"""
        return self._is_kodi

    def get_environment(self) -> str:
        """Get current environment name"""
        return str(self._config.get('environment', 'unknown'))

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self._config.get(key, default)

    def set_config(self, key: str, value: Union[str, int, float, bool, None]) -> None:
        """Set configuration value"""
        self._config[key] = value

        # Auto-save to config file in standalone mode
        if not self._is_kodi:
            config_file = os.path.join(self._config['profile_path'], 'config.json')
            try:
                # Read existing config
                existing_config = {}
                if os.path.exists(config_file):
                    with open(config_file, 'r', encoding='utf-8') as f:
                        existing_config = json.load(f)

                # Update with new value
                existing_config[key] = value

                # Write back
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(existing_config, f, indent=2, ensure_ascii=False)
            except OSError as save_error:
                print(f"Failed to save config: {save_error}", file=sys.stderr)
            except (TypeError, ValueError) as type_error:
                print(f"Config contains non-serializable data: {type_error}", file=sys.stderr)

    def get_vfs(self, subdir: str = "", config_dir: Optional[str] = None) -> 'VFS':
        """Get VFS instance with appropriate configuration"""
        # Import here to avoid circular imports
        from .vfs import VFS

        # Use provided config_dir, or environment default
        if config_dir is None:
            config_dir = self._config.get('profile_path', '')

        return VFS(config_dir=config_dir, addon_subdir=subdir)

    @staticmethod
    def get_logger() -> 'BaseLogger':
        """Get logger instance for current environment (static method)"""
        # Import here to avoid circular imports
        from .logger import logger as logger_instance
        return logger_instance

    def get_settings_bridge(self, addon_id: Optional[str] = None,
                            config_dir: Optional[str] = None) -> 'KodiSettingsBridge':
        """Get settings bridge instance"""
        # Import here to avoid circular imports
        from ..settings.kodi_settings_bridge import KodiSettingsBridge

        if config_dir is None:
            config_dir = self._config.get('profile_path', '')

        return KodiSettingsBridge(addon_id=addon_id, config_dir=config_dir)

    def get_manager(self) -> Any:
        """Get the configured streaming provider manager"""
        try:
            # Lazy import to avoid circular dependencies
            import importlib
            # Adjust this import path based on your actual module structure
            module = importlib.import_module('streaming_providers')
            if hasattr(module, 'get_configured_manager'):
                manager_func = module.get_configured_manager
                if callable(manager_func):
                    return manager_func()
                else:
                    raise ImportError("get_configured_manager is not callable")
            else:
                raise ImportError("get_configured_manager not found in streaming_providers module")
        except ImportError as manager_error:
            # Log error using the logger once we have it
            logger_instance = self.get_logger()
            logger_instance.error(f"Failed to import manager: {manager_error}")
            raise

    def get_service_config(self) -> Dict[str, Any]:
        """Get configuration for running the service"""
        return {
            'is_kodi': self._is_kodi,
            'port': self._config.get('server_port', 7777),
            'default_country': self._config.get('default_country', 'DE'),
            'profile_path': self._config.get('profile_path', ''),
            'addon_path': self._config.get('addon_path', '')
        }

    def debug_info(self) -> Dict[str, Any]:
        """Get debug information about the environment"""
        info: Dict[str, Any] = {
            'environment': self.get_environment(),
            'is_kodi': self._is_kodi,
            'python_version': sys.version,
            'platform': sys.platform,
        }

        # Add Kodi-specific info if available
        if self._is_kodi and self._addon:
            info['kodi_addon_id'] = self._addon.getAddonInfo('id')
            info['kodi_addon_version'] = self._addon.getAddonInfo('version')

        # Add import error info if present
        if hasattr(self, '_kodi_import_error') and self._kodi_import_error:
            info['kodi_import_error'] = str(self._kodi_import_error)

        # Create a safe config summary without sensitive paths
        safe_config: Dict[str, Any] = {}
        for key, value in self._config.items():
            if not key.endswith('_path') and key != 'config_dir' and key not in ['profile_path', 'addon_path']:
                if isinstance(value, (str, int, float, bool, type(None))):
                    safe_config[key] = value
                else:
                    safe_config[key] = str(type(value))

        info['config_summary'] = safe_config

        return info


# Global singleton instance
_env_manager: Optional[EnvironmentManager] = None


def get_environment_manager() -> EnvironmentManager:
    """Get the global environment manager instance"""
    global _env_manager
    print(f"DEBUG get_environment_manager(): _env_manager is {_env_manager}, id={id(_env_manager) if _env_manager else 'None'}", file=sys.stderr)
    if _env_manager is None:
        print(f"DEBUG get_environment_manager(): Creating new EnvironmentManager", file=sys.stderr)
        _env_manager = EnvironmentManager()
        print(f"DEBUG get_environment_manager(): Created _env_manager, id={id(_env_manager)}", file=sys.stderr)
    return _env_manager


def is_kodi_environment() -> bool:
    """Check if we're running in Kodi environment (convenience function)"""
    manager = get_environment_manager()
    print(f"DEBUG is_kodi_environment(): Got manager id={id(manager)}", file=sys.stderr)
    result = manager.is_kodi()
    print(f"DEBUG is_kodi_environment(): Returning {result}", file=sys.stderr)
    return result


def get_logger_instance() -> 'BaseLogger':
    """Get logger instance (convenience function)"""
    return EnvironmentManager.get_logger()


def get_vfs_instance(subdir: str = "", config_dir: Optional[str] = None) -> 'VFS':
    """Get VFS instance (convenience function)"""
    return get_environment_manager().get_vfs(subdir, config_dir)