# streaming_providers/base/drm/plugin_manager.py
"""
Manager for DRM configuration plugins with two-phase processing.
Handles plugin registration, discovery, and processing of DRM configs with PSSH data.
"""

import traceback
from typing import Dict, List, Optional

from ..models.drm_models import DRMConfig, DRMSystem, PSSHData
from ..utils.logger import logger
from .drm_plugin import DRMPlugin


class DRMPluginManager:
    """
    Manager for DRM configuration plugins.

    Supports two-phase processing:
    - Phase 1: GENERIC plugins (config generators, run before provider)
    - Phase 2: System-specific plugins (config transformers, run after provider)
    """

    def __init__(self, auto_discover: bool = True):
        """Initialize with empty plugin registry and optionally auto-discover plugins"""
        self.plugins: Dict[DRMSystem, DRMPlugin] = {}
        logger.debug("DRMPluginManager: Initialized with empty plugin registry")

        if auto_discover:
            logger.debug("DRMPluginManager: Auto-discovery enabled, discovering plugins...")
            discovered = self.discover_plugins()
            if discovered:
                logger.debug(
                    f"DRMPluginManager: Auto-discovery completed, {len(discovered)} plugins ready"
                )
            else:
                logger.debug("DRMPluginManager: Auto-discovery completed, no plugins found")

    def register_plugin(self, plugin: DRMPlugin) -> None:
        """
        Register a single plugin instance.

        Args:
            plugin: Configured plugin instance to register

        Raises:
            ValueError: If plugin is invalid or DRM system already has a plugin
        """
        if not isinstance(plugin, DRMPlugin):
            logger.warning(
                f"DRMPluginManager: Registration failed - invalid plugin type: {type(plugin)}"
            )
            raise ValueError("Only DRMPlugin instances can be registered")

        drm_system = plugin.supported_drm_system
        plugin_name = plugin.plugin_name

        if drm_system in self.plugins:
            existing_plugin = self.plugins[drm_system].plugin_name
            logger.warning(
                f"DRMPluginManager: Overwriting existing plugin '{existing_plugin}' "
                f"with '{plugin_name}' for DRM system {drm_system}"
            )

        self.plugins[drm_system] = plugin
        phase = "1-GENERIC" if drm_system == DRMSystem.GENERIC else "2-System-specific"
        logger.info(
            f"DRMPluginManager: Successfully registered plugin '{plugin_name}' "
            f"for DRM system {drm_system} (Phase: {phase})"
        )

    def discover_plugins(self) -> List[str]:
        """
        Discover and register all available DRM plugins by scanning filesystem.

        Scans only the plugins directory (not subdirectories) for Python files
        containing classes that inherit from DRMPlugin.

        Returns:
            List of discovered plugin names
        """
        import importlib.util
        import inspect
        import os

        logger.debug("DRMPluginManager: Starting filesystem-based plugin autodiscovery")

        # Get the directory where this plugin manager is located
        current_dir = os.path.dirname(os.path.abspath(__file__))
        plugins_dir = os.path.join(current_dir, "plugins")  # Scan the plugins subfolder

        # Check if plugins directory exists
        if not os.path.exists(plugins_dir):
            logger.debug(f"DRMPluginManager: Plugins directory does not exist: {plugins_dir}")
            return []

        logger.debug(f"DRMPluginManager: Scanning plugins directory: {plugins_dir}")

        registered = []
        failed_plugins = []
        scanned_files = []

        # Scan only the plugins directory (no subdirectories)
        try:
            files = os.listdir(plugins_dir)
        except OSError as e:
            logger.warning(f"DRMPluginManager: Error reading plugins directory: {e}")
            return []

        for filename in files:
            file_path = os.path.join(plugins_dir, filename)

            # Only process Python files (not directories or other files)
            if (
                    filename.endswith(".py")
                    and not filename.startswith("__")
                    and os.path.isfile(file_path)
            ):

                scanned_files.append(filename)

                logger.debug(f"DRMPluginManager: Scanning file: {filename}")

                try:
                    # Create module name from filename
                    module_name = os.path.splitext(filename)[0]

                    # Import the module dynamically
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    if spec is None or spec.loader is None:
                        logger.debug(
                            f"DRMPluginManager: Could not create module spec for {filename}"
                        )
                        continue

                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    # Find all classes in the module that inherit from DRMPlugin
                    plugin_classes = []
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        # Check if it's a DRMPlugin subclass (but not DRMPlugin itself)
                        if (
                                issubclass(obj, DRMPlugin)
                                and obj is not DRMPlugin
                                and obj.__module__ == module.__name__
                        ):
                            plugin_classes.append((name, obj))

                    if not plugin_classes:
                        logger.debug(f"DRMPluginManager: No DRMPlugin classes found in {filename}")
                        continue

                    logger.debug(
                        f"DRMPluginManager: Found {len(plugin_classes)} plugin class(es) in {filename}: {[name for name, _ in plugin_classes]}"
                    )

                    # Instantiate and register each plugin class found
                    for class_name, plugin_class in plugin_classes:
                        try:
                            logger.debug(
                                f"DRMPluginManager: Attempting to instantiate {class_name} from {filename}"
                            )

                            # Create plugin instance
                            plugin = plugin_class()
                            plugin_name = plugin.plugin_name
                            drm_system = plugin.supported_drm_system

                            logger.debug(
                                f"DRMPluginManager: Successfully created plugin '{plugin_name}' (class: {class_name}) supporting {drm_system}"
                            )

                            # Register the plugin
                            self.register_plugin(plugin)
                            registered.append(plugin_name)
                            logger.debug(
                                f"DRMPluginManager: Plugin '{plugin_name}' from {filename} successfully registered"
                            )

                        except Exception as e:
                            error_msg = (
                                f"Failed to instantiate {class_name} from {filename}: {str(e)}"
                            )
                            failed_plugins.append((f"{filename}::{class_name}", error_msg))
                            logger.warning(f"DRMPluginManager: {error_msg}")

                except Exception as e:
                    traceback_str = traceback.format_exc()
                    error_msg = f"Failed to process file {filename}: {str(e)}\n{traceback_str}"
                    failed_plugins.append((filename, error_msg))
                    logger.warning(f"DRMPluginManager: {error_msg}")

        # Log scanning summary
        logger.debug(
            f"DRMPluginManager: Filesystem scan completed - scanned {len(scanned_files)} Python files"
        )
        if scanned_files:
            logger.debug(f"DRMPluginManager: Scanned files: {scanned_files}")

        # Log final discovery results
        if registered:
            logger.info(
                f"DRMPluginManager: Filesystem autodiscovery completed - {len(registered)} plugins registered: {registered}"
            )
        else:
            logger.debug(
                "DRMPluginManager: Filesystem autodiscovery completed - no plugins were registered"
            )

        if failed_plugins:
            logger.debug(f"DRMPluginManager: {len(failed_plugins)} plugins/files failed to load:")
            for plugin_name, error in failed_plugins:
                logger.debug(f"  - {plugin_name}: {error}")

        return registered

    def has_generic_plugins(self) -> bool:
        """Check if any GENERIC plugins are registered"""
        return DRMSystem.GENERIC in self.plugins

    def has_system_specific_plugins(self) -> bool:
        """Check if any system-specific (non-GENERIC) plugins are registered"""
        return any(sys != DRMSystem.GENERIC for sys in self.plugins.keys())

    def process_generic_plugins(
            self,
            dummy_configs: List[DRMConfig],
            pssh_data_list: List[PSSHData],
            **kwargs
    ) -> List[DRMConfig]:
        """
        PHASE 1: Process through GENERIC plugins only.

        GENERIC plugins can CREATE configs from PSSH data.
        They receive a dummy config (DRMSystem.NONE) and PSSH data,
        and should return valid DRM configs or None.

        Args:
            dummy_configs: List with dummy config [DRMConfig(system=DRMSystem.NONE)]
            pssh_data_list: PSSH data extracted from manifest
            **kwargs: Additional context

        Returns:
            List of generated DRM configs, or empty list if generation failed
        """
        if not self.has_generic_plugins():
            logger.debug("Phase 1: No GENERIC plugins registered")
            return []

        if not pssh_data_list:
            logger.debug("Phase 1: No PSSH data available for GENERIC plugins")
            return []

        plugin = self.plugins[DRMSystem.GENERIC]
        logger.debug(f"Phase 1: Processing with GENERIC plugin '{plugin.plugin_name}'")

        generated_configs = []

        try:
            # Process each PSSH data entry
            for pssh_data in pssh_data_list:
                logger.debug(
                    f"Phase 1: Processing PSSH for system {pssh_data.system_id} "
                    f"with plugin '{plugin.plugin_name}'"
                )

                # Pass dummy config - plugin should return real config(s) or None
                result = plugin.process_drm_config(
                    dummy_configs[0],  # Dummy config
                    pssh_data,
                    **kwargs
                )

                if result:
                    generated_configs.append(result)
                    logger.debug(
                        f"Phase 1: Plugin '{plugin.plugin_name}' generated "
                        f"{result.system.value} config"
                    )

                    # If ClearKey found, return immediately
                    if result.system == DRMSystem.CLEARKEY:
                        logger.info(
                            f"Phase 1: ClearKey config found from GENERIC plugin, "
                            f"returning immediately"
                        )
                        return [result]

        except Exception as e:
            logger.error(
                f"Phase 1: GENERIC plugin '{plugin.plugin_name}' failed: {e}",
                exc_info=True
            )
            return []

        if generated_configs:
            logger.info(
                f"Phase 1: GENERIC plugin generated {len(generated_configs)} configs"
            )
        else:
            logger.debug("Phase 1: GENERIC plugin generated no configs")

        return generated_configs

    def process_system_specific_plugins(
            self,
            drm_configs: List[DRMConfig],
            pssh_data_list: List[PSSHData],
            **kwargs
    ) -> List[DRMConfig]:
        """
        PHASE 2: Process through system-specific plugins (EXCLUDE GENERIC).

        System-specific plugins TRANSFORM existing configs from the provider.
        GENERIC plugins are explicitly excluded from this phase.

        Args:
            drm_configs: DRM configs from the provider
            pssh_data_list: PSSH data extracted from manifest
            **kwargs: Additional context

        Returns:
            List of transformed DRM configs
        """
        if not drm_configs:
            logger.debug("Phase 2: No DRM configs to process")
            return []

        # Get system-specific plugins only (exclude GENERIC)
        system_plugins = {
            sys: plugin for sys, plugin in self.plugins.items()
            if sys != DRMSystem.GENERIC
        }

        if not system_plugins:
            logger.debug("Phase 2: No system-specific plugins registered, returning provider configs")
            return drm_configs

        logger.debug(
            f"Phase 2: Processing {len(drm_configs)} configs through "
            f"{len(system_plugins)} system-specific plugins"
        )

        # Create a mapping of DRM system to PSSH data for quick lookup
        pssh_by_system = {}
        for pssh_data in pssh_data_list:
            if pssh_data.drm_system:
                pssh_by_system[pssh_data.drm_system] = pssh_data
                logger.debug(
                    f"Phase 2: Mapped PSSH data for DRM system: {pssh_data.drm_system}"
                )

        processed_configs = []

        # Process each config through matching plugin
        for config in drm_configs:
            logger.debug(f"Phase 2: Processing DRM config for system: {config.system}")

            if config.system in system_plugins:
                plugin = system_plugins[config.system]
                pssh_data = pssh_by_system.get(config.system)

                if pssh_data:
                    logger.debug(
                        f"Phase 2: Using PSSH data for DRM system {config.system}"
                    )
                else:
                    logger.debug(
                        f"Phase 2: No PSSH data available for DRM system {config.system}"
                    )

                try:
                    logger.debug(
                        f"Phase 2: Processing with plugin '{plugin.plugin_name}'"
                    )

                    result = plugin.process_drm_config(config, pssh_data, **kwargs)

                    if result is not None:
                        # Check for ClearKey and return immediately if found
                        if result.system == DRMSystem.CLEARKEY:
                            logger.info(
                                f"Phase 2: ClearKey config found from plugin "
                                f"'{plugin.plugin_name}', returning immediately"
                            )
                            return [result]

                        processed_configs.append(result)
                        logger.debug(
                            f"Phase 2: Plugin '{plugin.plugin_name}' successfully "
                            f"processed config"
                        )
                    else:
                        logger.debug(
                            f"Phase 2: Plugin '{plugin.plugin_name}' filtered out config "
                            f"(returned None)"
                        )

                except Exception as e:
                    logger.warning(
                        f"Phase 2: Plugin '{plugin.plugin_name}' failed to process "
                        f"config: {str(e)}"
                    )
                    # On error, keep original config
                    processed_configs.append(config)
                    logger.debug(f"Phase 2: Using original config as fallback")
            else:
                # No plugin for this system, keep original
                logger.debug(
                    f"Phase 2: No plugin registered for DRM system {config.system}, "
                    f"passing through unchanged"
                )
                processed_configs.append(config)

        logger.info(
            f"Phase 2: Processed {len(drm_configs)} configs → {len(processed_configs)} configs"
        )
        return processed_configs

    def process_drm_configs(
            self,
            drm_configs: List[DRMConfig],
            pssh_data_list: List[PSSHData],
            **kwargs
    ) -> List[DRMConfig]:
        """
        Legacy method: Process configs through all plugins (generic first, then specific).

        This maintains backward compatibility but uses single-phase processing.
        For new code using two-phase flow, use process_generic_plugins() and
        process_system_specific_plugins() separately via DRMOperations.

        Args:
            drm_configs: List of DRM configs to process
            pssh_data_list: List of PSSH data extracted from manifest
            **kwargs: Additional context from the original method call

        Returns:
            List of processed DRM configs (may be modified, filtered, or unchanged)
        """
        if not drm_configs:
            logger.debug("DRMPluginManager: No DRM configs to process")
            return drm_configs

        logger.debug(
            f"DRMPluginManager: Processing {len(drm_configs)} DRM configs with "
            f"{len(pssh_data_list)} PSSH data entries (legacy single-phase mode)"
        )

        # Create a mapping of DRM system to PSSH data for quick lookup
        pssh_by_system = {}
        for pssh_data in pssh_data_list:
            if pssh_data.drm_system:
                pssh_by_system[pssh_data.drm_system] = pssh_data
                logger.debug(
                    f"DRMPluginManager: Mapped PSSH data for DRM system: {pssh_data.drm_system}"
                )

        # Separate generic and specific plugins
        generic_plugins = []
        specific_plugins = []

        for drm_system, plugin in self.plugins.items():
            if drm_system == DRMSystem.GENERIC:
                generic_plugins.append(plugin)
                logger.debug(f"DRMPluginManager: Found generic plugin '{plugin.plugin_name}'")
            else:
                specific_plugins.append((drm_system, plugin))

        # Process generic plugins first
        processed_configs = list(drm_configs)

        for plugin in generic_plugins:
            logger.debug(
                f"DRMPluginManager: Processing through generic plugin '{plugin.plugin_name}'"
            )
            try:
                # Generic plugins process all configs at once
                temp_configs = []
                for config in processed_configs:
                    pssh_data = pssh_by_system.get(config.system)
                    result = plugin.process_drm_config(config, pssh_data, **kwargs)
                    if result is not None:
                        temp_configs.append(result)

                # Check for ClearKey and return immediately if found
                for config in temp_configs:
                    if config.system == DRMSystem.CLEARKEY:
                        logger.info(
                            f"DRMPluginManager: ClearKey config found from generic plugin, "
                            f"returning immediately"
                        )
                        return [config]

                processed_configs = temp_configs

            except Exception as e:
                logger.warning(
                    f"DRMPluginManager: Generic plugin '{plugin.plugin_name}' failed: {str(e)}"
                )
                continue

        # Process specific plugins
        final_configs = []
        for config in processed_configs:
            logger.debug(f"DRMPluginManager: Processing DRM config for system: {config.system}")

            # Find specific plugin for this DRM system
            plugin = self.plugins.get(config.system)

            if plugin and plugin.supported_drm_system != DRMSystem.GENERIC:
                logger.debug(
                    f"DRMPluginManager: Found plugin '{plugin.plugin_name}' for "
                    f"DRM system {config.system}"
                )

                try:
                    pssh_data = pssh_by_system.get(config.system)
                    if pssh_data:
                        logger.debug(
                            f"DRMPluginManager: Using PSSH data for DRM system {config.system}"
                        )
                    else:
                        logger.debug(
                            f"DRMPluginManager: No PSSH data available for "
                            f"DRM system {config.system}"
                        )

                    processed_config = plugin.process_drm_config(config, pssh_data, **kwargs)
                    if processed_config is not None:
                        # Check for ClearKey and return immediately if found
                        if processed_config.system == DRMSystem.CLEARKEY:
                            logger.info(
                                f"DRMPluginManager: ClearKey config found from plugin "
                                f"'{plugin.plugin_name}', returning immediately"
                            )
                            return [processed_config]

                        final_configs.append(processed_config)
                        logger.debug(
                            f"DRMPluginManager: Plugin '{plugin.plugin_name}' successfully "
                            f"processed config"
                        )
                    else:
                        logger.debug(
                            f"DRMPluginManager: Plugin '{plugin.plugin_name}' filtered out "
                            f"config (returned None)"
                        )

                except Exception as e:
                    logger.warning(
                        f"DRMPluginManager: Plugin '{plugin.plugin_name}' failed to process "
                        f"config: {str(e)}"
                    )
                    final_configs.append(config)
                    logger.debug(f"DRMPluginManager: Using original config as fallback")
            else:
                logger.debug(
                    f"DRMPluginManager: No plugin registered for DRM system {config.system}, "
                    f"passing through unchanged"
                )
                final_configs.append(config)

        logger.debug(
            f"DRMPluginManager: Completed processing - {len(final_configs)} configs returned"
        )
        return final_configs

    def get_plugin(self, drm_system: DRMSystem) -> Optional[DRMPlugin]:
        """
        Get registered plugin for a DRM system.

        Args:
            drm_system: DRM system to get plugin for

        Returns:
            The plugin instance or None if not found
        """
        plugin = self.plugins.get(drm_system)
        if plugin:
            logger.debug(
                f"DRMPluginManager: Retrieved plugin '{plugin.plugin_name}' for "
                f"DRM system {drm_system}"
            )
        else:
            logger.debug(f"DRMPluginManager: No plugin found for DRM system {drm_system}")
        return plugin

    def list_plugins(self) -> Dict:
        """
        List all registered plugins with phase information.

        Returns:
            Dictionary mapping DRM system values to plugin info
        """
        plugin_list = {
            drm_system.value: {
                "name": plugin.plugin_name,
                "system": drm_system.value,
                "phase": "1-GENERIC" if drm_system == DRMSystem.GENERIC else "2-System-specific"
            }
            for drm_system, plugin in self.plugins.items()
        }
        logger.debug(f"DRMPluginManager: Currently registered plugins: {plugin_list}")
        return plugin_list

    def clear_plugins(self) -> None:
        """Clear all registered plugins"""
        plugin_count = len(self.plugins)
        self.plugins.clear()
        logger.info(f"DRMPluginManager: Cleared {plugin_count} registered plugins")