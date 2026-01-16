# ============================================================================
# streaming_providers/base/drm_operations.py
"""
DRM-related operations with caching and optimized PSSH extraction.
"""

import time
from threading import Lock
from typing import Dict, List, Optional, Tuple

from .drm import DRMPluginManager
from .models import DRMSystem
from .utils.logger import logger


class PSSHCache:
    """Thread-safe cache for PSSH data"""

    def __init__(self, ttl_seconds: int = 3600):
        self.cache: Dict[str, Tuple[List, float]] = {}
        self.ttl = ttl_seconds
        self.lock = Lock()

    def get(self, key: str) -> Optional[List]:
        """Get cached PSSH data if not expired"""
        with self.lock:
            if key in self.cache:
                pssh_list, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    logger.debug(f"Cache HIT for {key}")
                    return pssh_list
                else:
                    logger.debug(f"Cache EXPIRED for {key}")
                    del self.cache[key]
        return None

    def set(self, key: str, pssh_list: List):
        """Cache PSSH data"""
        with self.lock:
            self.cache[key] = (pssh_list, time.time())
            logger.debug(f"Cache SET for {key}")

    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            logger.debug("Cache CLEARED")


class DRMOperations:
    """Handles all DRM-related operations."""

    def __init__(self, registry, cache_ttl: int = 3600):
        self.registry = registry
        self.drm_plugin_manager = DRMPluginManager()
        self.pssh_cache = PSSHCache(ttl_seconds=cache_ttl)
        logger.debug("DRMOperations: Initialized with caching")

    def get_channel_drm_configs(self, provider_name: str, channel_id: str, **kwargs) -> List:
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
                    # Try cache first
                    cache_key = f"{provider_name}:{channel_id}"
                    pssh_data_list = self.pssh_cache.get(cache_key)

                    if pssh_data_list is None:
                        # Cache miss - extract and cache
                        pssh_data_list = self._extract_pssh_from_manifest(manifest_url)
                        if pssh_data_list:
                            self.pssh_cache.set(cache_key, pssh_data_list)

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

        return bool(config_systems & plugin_systems or DRMSystem.GENERIC in plugin_systems)

    @staticmethod
    def _extract_pssh_from_manifest(manifest_url: str) -> List:
        """Extract PSSH data from manifest with single segment fallback."""
        import requests

        from .utils.manifest_parser import ManifestParser

        try:
            response = requests.get(manifest_url, timeout=10)
            response.raise_for_status()
            manifest_content = response.text

            # Extract from manifest content
            pssh_list = ManifestParser._extract_from_manifest_content(manifest_content)

            # Check if we need segment extraction
            needs_segment_extraction = not pssh_list or any(
                not p.pssh_box or not p.key_ids for p in pssh_list
            )

            if needs_segment_extraction:
                logger.debug("PSSH incomplete in manifest, extracting from init segment")

                # Extract ONE init segment URL
                init_segment_url = ManifestParser.extract_single_init_segment_url(
                    manifest_content, manifest_url
                )

                if init_segment_url:
                    # Get expected system IDs
                    expected_system_ids = [p.system_id for p in pssh_list] if pssh_list else []

                    segment_pssh = ManifestParser._extract_from_single_segment(
                        init_segment_url, expected_system_ids
                    )

                    if segment_pssh:
                        # Merge or replace
                        return ManifestParser._merge_pssh_data(pssh_list, segment_pssh)
                else:
                    logger.warning("Could not extract init segment URL from manifest")

            return pssh_list

        except Exception as e:
            logger.warning(f"Failed to extract PSSH: {e}")
            return []

    def list_drm_plugins(self) -> Dict:
        """List registered DRM plugins."""
        return self.drm_plugin_manager.list_plugins()

    def clear_drm_plugins(self):
        """Clear all DRM plugins."""
        self.drm_plugin_manager.clear_plugins()

    def clear_pssh_cache(self):
        """Clear PSSH cache."""
        self.pssh_cache.clear()
