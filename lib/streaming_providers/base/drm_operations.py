# ============================================================================
# streaming_providers/base/drm_operations.py
"""
DRM-related operations.
"""

from typing import Dict, List

from .drm import DRMPluginManager
from .models import DRMSystem
from .utils.logger import logger


class DRMOperations:
    """Handles all DRM-related operations."""

    def __init__(self, registry):
        self.registry = registry
        self.drm_plugin_manager = DRMPluginManager()
        logger.debug("DRMOperations: Initialized")

    def get_channel_drm_configs(
        self, provider_name: str, channel_id: str, **kwargs
    ) -> List:
        """Get DRM configurations for a channel."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        drm_configs = provider.get_drm(channel_id, **kwargs)

        # Extract PSSH if needed
        pssh_data_list = []
        if drm_configs and self.drm_plugin_manager.plugins:
            if self._needs_pssh_extraction(drm_configs):
                manifest_url = provider.get_manifest(channel_id, **kwargs)
                if manifest_url:
                    pssh_data_list = self._extract_pssh_from_manifest(manifest_url)

        # Process through plugins
        processed = self.drm_plugin_manager.process_drm_configs(
            drm_configs, pssh_data_list, **kwargs
        )

        logger.info(f"Processed DRM for '{channel_id}': {len(processed)} configs")
        return processed

    def _needs_pssh_extraction(self, drm_configs) -> bool:
        """Check if PSSH extraction is needed."""
        config_systems = {config.system for config in drm_configs}
        plugin_systems = set(self.drm_plugin_manager.plugins.keys())

        return bool(
            config_systems & plugin_systems or DRMSystem.GENERIC in plugin_systems
        )

    def _extract_pssh_from_manifest(self, manifest_url: str) -> List:
        """Extract PSSH data from manifest."""
        import requests

        from .utils.manifest_parser import ManifestParser

        try:
            response = requests.get(manifest_url, timeout=10)
            response.raise_for_status()
            return ManifestParser.extract_pssh_from_manifest(
                response.text, manifest_url
            )
        except Exception as e:
            logger.warning(f"Failed to extract PSSH: {e}")
            return []

    def list_drm_plugins(self) -> Dict:
        """List registered DRM plugins."""
        return self.drm_plugin_manager.list_plugins()

    def clear_drm_plugins(self):
        """Clear all DRM plugins."""
        self.drm_plugin_manager.clear_plugins()
