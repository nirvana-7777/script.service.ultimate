# streaming_providers/base/drm/plugin_manager.py
from typing import Dict, List, Optional
from ..models.drm_models import DRMConfig, DRMSystem, PSSHData
from .drm_plugin import DRMPlugin
from ..utils.logger import logger
import traceback


class DRMPluginManager:
    """
    Manager for DRM configuration plugins.
    
    Handles plugin registration, discovery, and processing of DRM configs with PSSH data.
    """

    def __init__(self, auto_discover: bool = True):
        """Initialize with empty plugin registry and optionally auto-discover plugins"""
        self.plugins: Dict[DRMSystem, DRMPlugin] = {}
        logger.debug("DRMPluginManager: Initialized with empty plugin registry")
        
        if auto_discover:
            logger.debug("DRMPluginManager: Auto-discovery enabled, discovering plugins...")
            discovered = self.discover_plugins()
            if discovered:
                logger.debug(f"DRMPluginManager: Auto-discovery completed, {len(discovered)} plugins ready")
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
            logger.warning(f"DRMPluginManager: Registration failed - invalid plugin type: {type(plugin)}")
            raise ValueError("Only DRMPlugin instances can be registered")
            
        drm_system = plugin.supported_drm_system
        plugin_name = plugin.plugin_name
        
        if drm_system in self.plugins:
            existing_plugin = self.plugins[drm_system].plugin_name
            logger.warning(f"DRMPluginManager: Registration failed - DRM system {drm_system} already has plugin '{existing_plugin}' registered")
            raise ValueError(f"DRM system {drm_system} already has plugin '{existing_plugin}' registered")
            
        self.plugins[drm_system] = plugin
        logger.debug(f"DRMPluginManager: Successfully registered plugin '{plugin_name}' for DRM system {drm_system}")

    def discover_plugins(self) -> List[str]:
        """
        Discover and register all available DRM plugins by scanning filesystem.
        
        Scans only the plugins directory (not subdirectories) for Python files
        containing classes that inherit from DRMPlugin.

        Returns:
            List of discovered plugin names
        """
        import os
        import importlib.util
        import inspect
        
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
            if (filename.endswith('.py') and 
                not filename.startswith('__') and 
                os.path.isfile(file_path)):
                
                scanned_files.append(filename)
                
                logger.debug(f"DRMPluginManager: Scanning file: {filename}")
                
                try:
                    # Create module name from filename
                    module_name = os.path.splitext(filename)[0]
                    
                    # Import the module dynamically
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    if spec is None or spec.loader is None:
                        logger.debug(f"DRMPluginManager: Could not create module spec for {filename}")
                        continue
                        
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Find all classes in the module that inherit from DRMPlugin
                    plugin_classes = []
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        # Check if it's a DRMPlugin subclass (but not DRMPlugin itself)
                        if (issubclass(obj, DRMPlugin) and 
                            obj is not DRMPlugin and 
                            obj.__module__ == module.__name__):
                            plugin_classes.append((name, obj))
                    
                    if not plugin_classes:
                        logger.debug(f"DRMPluginManager: No DRMPlugin classes found in {filename}")
                        continue
                        
                    logger.debug(f"DRMPluginManager: Found {len(plugin_classes)} plugin class(es) in {filename}: {[name for name, _ in plugin_classes]}")
                    
                    # Instantiate and register each plugin class found
                    for class_name, plugin_class in plugin_classes:
                        try:
                            logger.debug(f"DRMPluginManager: Attempting to instantiate {class_name} from {filename}")
                            
                            # Create plugin instance
                            plugin = plugin_class()
                            plugin_name = plugin.plugin_name
                            drm_system = plugin.supported_drm_system
                            
                            logger.debug(f"DRMPluginManager: Successfully created plugin '{plugin_name}' (class: {class_name}) supporting {drm_system}")
                            
                            # Register the plugin
                            self.register_plugin(plugin)
                            registered.append(plugin_name)
                            logger.debug(f"DRMPluginManager: Plugin '{plugin_name}' from {filename} successfully registered")
                            
                        except Exception as e:
                            error_msg = f"Failed to instantiate {class_name} from {filename}: {str(e)}"
                            failed_plugins.append((f"{filename}::{class_name}", error_msg))
                            logger.warning(f"DRMPluginManager: {error_msg}")
                    
                except Exception as e:
                    traceback_str = traceback.format_exc()
                    error_msg = f"Failed to process file {filename}: {str(e)}\n{traceback_str}"
                    failed_plugins.append((filename, error_msg))
                    logger.warning(f"DRMPluginManager: {error_msg}")
        
        # Log scanning summary
        logger.debug(f"DRMPluginManager: Filesystem scan completed - scanned {len(scanned_files)} Python files")
        if scanned_files:
            logger.debug(f"DRMPluginManager: Scanned files: {scanned_files}")
        
        # Log final discovery results
        if registered:
            logger.debug(f"DRMPluginManager: Filesystem autodiscovery completed successfully - {len(registered)} plugins registered: {registered}")
        else:
            logger.debug("DRMPluginManager: Filesystem autodiscovery completed - no plugins were registered")
            
        if failed_plugins:
            logger.debug(f"DRMPluginManager: {len(failed_plugins)} plugins/files failed to load:")
            for plugin_name, error in failed_plugins:
                logger.debug(f"  - {plugin_name}: {error}")

        return registered

    def process_drm_configs(self, 
                           drm_configs: List[DRMConfig], 
                           pssh_data_list: List[PSSHData],
                           **kwargs) -> List[DRMConfig]:
        """
        Process a list of DRM configs through registered plugins using PSSH data.
        Generic plugins are processed first, and if any ClearKey config is found,
        only that config is returned.

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

        logger.debug(f"DRMPluginManager: Processing {len(drm_configs)} DRM configs with {len(pssh_data_list)} PSSH data entries")

        # Create a mapping of DRM system to PSSH data for quick lookup
        pssh_by_system = {}
        for pssh_data in pssh_data_list:
            if pssh_data.drm_system:
                pssh_by_system[pssh_data.drm_system] = pssh_data
                logger.debug(f"DRMPluginManager: Mapped PSSH data for DRM system: {pssh_data.drm_system}")

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
            logger.debug(f"DRMPluginManager: Processing through generic plugin '{plugin.plugin_name}'")
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
                        logger.debug(f"DRMPluginManager: ClearKey config found, returning immediately")
                        return [config]
                
                processed_configs = temp_configs
                
            except Exception as e:
                logger.warning(f"DRMPluginManager: Generic plugin '{plugin.plugin_name}' failed: {str(e)}")
                continue

        # Process specific plugins
        final_configs = []
        for config in processed_configs:
            logger.debug(f"DRMPluginManager: Processing DRM config for system: {config.system}")
            
            # Find specific plugin for this DRM system
            plugin = self.plugins.get(config.system)
            
            if plugin:
                logger.debug(f"DRMPluginManager: Found plugin '{plugin.plugin_name}' for DRM system {config.system}")
                
                try:
                    pssh_data = pssh_by_system.get(config.system)
                    if pssh_data:
                        logger.debug(f"DRMPluginManager: Using PSSH data for DRM system {config.system}")
                    else:
                        logger.debug(f"DRMPluginManager: No PSSH data available for DRM system {config.system}")
                    
                    processed_config = plugin.process_drm_config(config, pssh_data, **kwargs)
                    if processed_config is not None:
                        # Check for ClearKey and return immediately if found
                        if processed_config.system == DRMSystem.CLEARKEY:
                            logger.debug(f"DRMPluginManager: ClearKey config found, returning immediately")
                            return [processed_config]
                        
                        final_configs.append(processed_config)
                        logger.debug(f"DRMPluginManager: Plugin '{plugin.plugin_name}' successfully processed config")
                    else:
                        logger.debug(f"DRMPluginManager: Plugin '{plugin.plugin_name}' filtered out config (returned None)")
                    
                except Exception as e:
                    logger.warning(f"DRMPluginManager: Plugin '{plugin.plugin_name}' failed to process config: {str(e)}")
                    final_configs.append(config)
                    logger.debug(f"DRMPluginManager: Using original config as fallback")
            else:
                logger.debug(f"DRMPluginManager: No plugin registered for DRM system {config.system}, passing through unchanged")
                final_configs.append(config)
                
        logger.debug(f"DRMPluginManager: Completed processing - {len(final_configs)} configs returned")
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
            logger.debug(f"DRMPluginManager: Retrieved plugin '{plugin.plugin_name}' for DRM system {drm_system}")
        else:
            logger.debug(f"DRMPluginManager: No plugin found for DRM system {drm_system}")
        return plugin

    def list_plugins(self) -> Dict[DRMSystem, str]:
        """
        List all registered plugins.

        Returns:
            Dictionary mapping DRM systems to plugin names
        """
        plugin_list = {drm_system: plugin.plugin_name for drm_system, plugin in self.plugins.items()}
        logger.debug(f"DRMPluginManager: Currently registered plugins: {plugin_list}")
        return plugin_list

    def clear_plugins(self) -> None:
        """Clear all registered plugins"""
        plugin_count = len(self.plugins)
        self.plugins.clear()
        logger.debug(f"DRMPluginManager: Cleared {plugin_count} registered plugins")
