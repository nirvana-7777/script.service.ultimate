# ============================================================================
# streaming_providers/base/drm_operations.py
"""
DRM-related operations with caching and optimized PSSH extraction.
Two-phase plugin processing: GENERIC plugins first, then system-specific.
"""

import time
from threading import Lock
from typing import Dict, List, Optional, Tuple

from .drm import DRMPluginManager
from .models import DRMSystem, DRMConfig
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


class DRMConfigCache:
    """Thread-safe cache for DRM configurations (ClearKey only, no expiry)"""

    def __init__(self):
        self.cache: Dict[str, List] = {}
        self.lock = Lock()

    def get(self, key: str) -> Optional[List]:
        """Get cached DRM configs"""
        with self.lock:
            if key in self.cache:
                logger.debug(f"DRM Config Cache HIT for {key}")
                return self.cache[key]
        return None

    def set(self, key: str, drm_configs: List):
        """Cache DRM configs (only if contains ClearKey)"""
        with self.lock:
            self.cache[key] = drm_configs
            logger.debug(f"DRM Config Cache SET for {key}")

    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            logger.debug("DRM Config Cache CLEARED")


class DRMOperations:
    """Handles all DRM-related operations."""

    def __init__(self, registry, cache_ttl: int = 3600):
        self.registry = registry
        self.drm_plugin_manager = DRMPluginManager()
        self.pssh_cache = PSSHCache(ttl_seconds=cache_ttl)
        self.drm_config_cache = DRMConfigCache()
        logger.debug("DRMOperations: Initialized with two-phase plugin processing")

    def get_channel_drm_configs(self, provider_name: str, channel_id: str, **kwargs) -> List:
        """
        Get DRM configurations for a channel with two-phase plugin processing.

        Phase 1: GENERIC plugins (pre-provider) - can generate configs from PSSH
        Phase 2: System-specific plugins (post-provider) - transform provider configs
        """
        cache_key = f"{provider_name}:{channel_id}"

        # Step 1: Check DRM config cache (ClearKey configs)
        cached_configs = self.drm_config_cache.get(cache_key)
        if cached_configs is not None:
            logger.info(f"Using cached DRM configs for '{channel_id}'")
            return cached_configs

        # Step 2: PHASE 1 - Try GENERIC plugins first (if registered)
        if DRMSystem.GENERIC in self.drm_plugin_manager.plugins:
            logger.debug(f"Phase 1: Attempting GENERIC plugin processing for '{channel_id}'")

            generic_configs = self._try_generic_plugins(provider_name, channel_id, cache_key, **kwargs)

            if generic_configs:  # Plugin successfully generated configs
                logger.info(f"Phase 1: GENERIC plugin generated {len(generic_configs)} configs for '{channel_id}'")

                # Cache if contains ClearKey
                if self._has_clearkey_config(generic_configs):
                    logger.info(f"Caching ClearKey DRM configs from GENERIC plugin for '{channel_id}'")
                    self.drm_config_cache.set(cache_key, generic_configs)

                return generic_configs
            else:
                logger.debug(f"Phase 1: GENERIC plugin returned no configs, proceeding to provider")

        # Step 3: Get configs from provider (GENERIC plugins didn't provide configs)
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        drm_configs = provider.get_drm(channel_id, **kwargs)

        # Step 4: PHASE 2 - Extract PSSH if needed for system-specific plugins
        pssh_data_list = []
        if drm_configs and self.drm_plugin_manager.has_system_specific_plugins():
            if self._needs_pssh_extraction(drm_configs):
                # Try PSSH cache first (might have been fetched in Phase 1)
                pssh_data_list = self.pssh_cache.get(cache_key)

                if pssh_data_list is None:
                    # Cache miss - fetch manifest and extract
                    logger.debug(f"Phase 2: PSSH cache miss for {cache_key}, fetching manifest")
                    manifest_url = provider.get_manifest(channel_id, **kwargs)
                    if manifest_url:
                        pssh_data_list = self._extract_pssh_from_manifest(manifest_url, provider_name)
                        if pssh_data_list:
                            self.pssh_cache.set(cache_key, pssh_data_list)
                else:
                    logger.debug(f"Phase 2: Using cached PSSH for {cache_key}")

        # Step 5: PHASE 2 - Process through system-specific plugins (EXCLUDE GENERIC)
        processed = self.drm_plugin_manager.process_system_specific_plugins(
            drm_configs, pssh_data_list, **kwargs
        )

        # Step 6: Cache if contains ClearKey config
        if self._has_clearkey_config(processed):
            logger.info(f"Caching ClearKey DRM configs from provider for '{channel_id}'")
            self.drm_config_cache.set(cache_key, processed)

        logger.info(f"Processed DRM for '{channel_id}': {len(processed)} configs")
        return processed

    def _try_generic_plugins(
            self,
            provider_name: str,
            channel_id: str,
            cache_key: str,
            **kwargs
    ) -> Optional[List[DRMConfig]]:
        """
        Try to generate configs using GENERIC plugins.
        Returns configs if successful, None otherwise.
        """
        # Get PSSH data (from cache or manifest)
        pssh_data_list = self.pssh_cache.get(cache_key)

        if pssh_data_list is None:
            logger.debug(f"GENERIC plugin: Fetching PSSH for '{provider_name}' / {channel_id}'")
            provider = self.registry.get_provider(provider_name)
            if not provider:
                logger.warning(f"Provider '{provider_name}' not found for GENERIC plugin")
                return None

            manifest_url = provider.get_manifest(channel_id, **kwargs)
            logger.debug(f" GENERIC plugin: pssh from '{manifest_url}'")
            if manifest_url:
                pssh_data_list = self._extract_pssh_from_manifest(manifest_url, provider_name)
                if pssh_data_list:
                    self.pssh_cache.set(cache_key, pssh_data_list)

        if not pssh_data_list:
            logger.debug(f"GENERIC plugin: No PSSH data available for '{channel_id}'")
            return None

        # Create a dummy config to pass to GENERIC plugin
        dummy_configs = [DRMConfig(system=DRMSystem.NONE, priority=0)]

        # Let GENERIC plugins try to generate configs
        generic_configs = self.drm_plugin_manager.process_generic_plugins(
            dummy_configs, pssh_data_list, **kwargs
        )

        return generic_configs if generic_configs else None

    @staticmethod
    def _has_clearkey_config(drm_configs: List) -> bool:
        """Check if any config is a ClearKey config"""
        return any(config.system == DRMSystem.CLEARKEY for config in drm_configs)

    def _needs_pssh_extraction(self, drm_configs) -> bool:
        """Check if PSSH extraction is needed for system-specific plugins."""
        config_systems = {config.system for config in drm_configs}
        # Exclude GENERIC from this check (it's handled separately)
        plugin_systems = {
            sys for sys in self.drm_plugin_manager.plugins.keys()
            if sys != DRMSystem.GENERIC
        }

        return bool(config_systems & plugin_systems)

    def _extract_pssh_from_manifest(self, manifest_url: str, provider_name: Optional[str] = None) -> List:
        """Extract PSSH data from manifest using the provider's HTTPManager."""
        from .utils.manifest_parser import ManifestParser
        from .network import HTTPManager

        # 1. Validate the URL before attempting the request
        if not manifest_url or not manifest_url.startswith(('http://', 'https://')):
            logger.error(f"Invalid manifest URL provided: '{manifest_url}'. Cannot extract PSSH.")
            return []

        try:
            # 2. Resolve the correct HTTP manager
            http = None
            if provider_name:
                # Use the registry passed during __init__ to get the provider instance
                provider = self.registry.get_provider(provider_name)
                if provider:
                    # Access the pre-configured http_manager property of the provider
                    http = provider.http_manager
                    logger.debug(f"Using configured HTTPManager for provider: {provider_name}")

            # Fallback to default if no provider-specific manager is found
            if not http:
                logger.debug("No provider manager found; using default HTTPManager")
                http = HTTPManager()

            # 3. Perform the request (HTTPManager follows redirects by default)
            # The 'operation' parameter helps the manager choose the right proxy settings
            response = http.get(manifest_url, timeout=10, operation="api")
            response.raise_for_status()
            manifest_content = response.text

            # 4. Standard PSSH extraction logic
            pssh_list = ManifestParser._extract_from_manifest_content(manifest_content)

            # Check if we need segment extraction
            needs_segment_extraction = not pssh_list or any(
                not p.pssh_box or not p.key_ids for p in pssh_list
            )

            if needs_segment_extraction:
                logger.debug("PSSH incomplete in manifest, extracting from init segment")
                init_segment_url = ManifestParser.extract_single_init_segment_url(
                    manifest_content, manifest_url
                )

                if init_segment_url:
                    # Reuse the same configured http manager for the segment download
                    segment_pssh = ManifestParser._extract_from_single_segment(
                        init_segment_url,
                        [p.system_id for p in pssh_list] if pssh_list else []
                    )

                    if segment_pssh:
                        return ManifestParser._merge_pssh_data(pssh_list, segment_pssh)

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

    def clear_drm_config_cache(self):
        """Clear DRM config cache."""
        self.drm_config_cache.clear()