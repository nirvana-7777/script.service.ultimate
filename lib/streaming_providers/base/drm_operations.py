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

    @staticmethod
    def _is_manifest_encrypted(manifest_content: str) -> bool:
        """
        Check if manifest contains any DRM/encryption markers.
        Returns True if encrypted, False if unencrypted.

        Uses the new DRM models for consistent detection.
        """
        import re
        from ..base.models.drm import DRMSystem

        # First, try to extract PSSH data using ManifestParser
        from .utils.manifest_parser import ManifestParser
        pssh_list = ManifestParser._extract_from_manifest_content(manifest_content)

        if pssh_list:
            # If we got PSSHData objects with valid DRM systems, it's encrypted!
            for pssh in pssh_list:
                if pssh.drm_system and pssh.drm_system != DRMSystem.NONE:
                    logger.debug(f"Detected DRM system: {pssh.drm_system.value} from PSSH data")
                    return True

        # Fallback: Check for ContentProtection elements with known DRM UUIDs
        # But now use DRMSystem.from_uuid() for detection!
        cp_pattern = re.compile(
            r'<ContentProtection[^>]*schemeIdUri="urn:uuid:([^"]+)"[^>]*>',
            re.IGNORECASE
        )

        for match in cp_pattern.finditer(manifest_content):
            uuid = match.group(1).lower()

            # Use DRMSystem.from_uuid() - it handles normalization!
            drm_system = DRMSystem.from_uuid(uuid)
            if drm_system:
                logger.debug(f"Detected DRM system: {drm_system.value} (UUID: {uuid})")
                return True

        # Also check for cenc:default_KID (indicates encryption even without DRM system)
        if re.search(r'(?:cenc:)?default_KID\s*=', manifest_content, re.IGNORECASE):
            logger.debug("Detected cenc:default_KID attribute (encrypted)")
            return True

        # Check for PSSH boxes directly
        if re.search(r'<(?:cenc:)?pssh[^>]*>', manifest_content, re.IGNORECASE):
            logger.debug("Detected PSSH box (encrypted)")
            return True

        logger.debug("No DRM/encryption markers found (unencrypted)")
        return False

    @staticmethod
    def _validate_clearkey_configs(
            drm_configs: List[DRMConfig],
            pssh_data_list: List
    ) -> List[DRMConfig]:
        """
        Validate that ClearKey configs contain at least one key for required key_ids.
        Returns configs if at least one valid key exists, empty list if no valid keys.

        Having a subset of valid keys is acceptable (e.g., only lower resolutions),
        but having NO valid keys means decryption will fail entirely.
        """
        if not pssh_data_list:
            logger.warning("No PSSH data available for ClearKey validation")
            return drm_configs

        # Extract all required key_ids from PSSH
        required_key_ids = set()
        for pssh_data in pssh_data_list:
            if pssh_data.key_ids:
                # Normalize key_ids to lowercase without hyphens for comparison
                required_key_ids.update(kid.lower().replace("-", "") for kid in pssh_data.key_ids)

        if not required_key_ids:
            logger.warning("No key_ids found in PSSH data")
            return drm_configs

        validated_configs = []
        has_valid_clearkey = False

        for config in drm_configs:
            if config.system != DRMSystem.CLEARKEY:
                validated_configs.append(config)
                continue

            # Validate ClearKey config
            if not config.license or not config.license.keyids:
                logger.warning(f"ClearKey config missing license.keyids")
                continue

            # Check if config provides keys for any required key_ids
            # Normalize provided KIDs to lowercase without hyphens for comparison
            provided_kids = {kid.lower().replace("-", "") for kid in config.license.keyids.keys()}

            # Find intersection - keys that are both required and provided
            valid_keys = required_key_ids & provided_kids

            if valid_keys:
                has_valid_clearkey = True
                if len(valid_keys) == len(required_key_ids):
                    logger.info(
                        f"ClearKey config validated: all {len(required_key_ids)} required keys present"
                    )
                else:
                    logger.info(
                        f"ClearKey config validated: {len(valid_keys)}/{len(required_key_ids)} keys present "
                        f"(may limit available resolutions/tracks)"
                    )
                validated_configs.append(config)
            else:
                logger.error(
                    f"ClearKey config INVALID: no valid keys found. "
                    f"Required {len(required_key_ids)} key_ids but none match provided keys."
                )

        # If we have ClearKey configs but NONE are valid, return empty list
        # This prevents returning DRMSystem.NONE which would indicate unencrypted stream
        if any(c.system == DRMSystem.CLEARKEY for c in drm_configs) and not has_valid_clearkey:
            logger.error(
                "All ClearKey configs failed validation. Returning empty list "
                "(stream is encrypted but no valid keys available)."
            )
            return []

        return validated_configs

    def get_channel_drm_configs(self, provider_name: str, channel_id: str, **kwargs) -> List:
        """
        Get DRM configurations for a channel with two-phase plugin processing.

        Phase 0: Check if stream is encrypted (by examining manifest)
        Phase 1: GENERIC plugins (pre-provider) - can generate configs from PSSH
        Phase 2: System-specific plugins (post-provider) - transform provider configs
        """
        cache_key = f"{provider_name}:{channel_id}"
        manifest_content = None  # Store to avoid redundant fetches

        # Step 0: Get provider instance
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        # Step 0a: Fetch manifest and check if it's encrypted
        manifest_url = provider.get_manifest(channel_id, **kwargs)
        if manifest_url and manifest_url.startswith(('http://', 'https://')):
            try:
                from .network import HTTPManager

                # Use provider's HTTP manager if available
                http = provider.http_manager if hasattr(provider, 'http_manager') else HTTPManager()
                response = http.get(manifest_url, timeout=10, operation="api")
                response.raise_for_status()
                manifest_content = response.text

                # Check if manifest is encrypted
                if not self._is_manifest_encrypted(manifest_content):
                    logger.info(f"Stream '{channel_id}' is unencrypted (no DRM in manifest)")
                    return [DRMConfig(system=DRMSystem.NONE, priority=0)]

                logger.debug(f"Stream '{channel_id}' is encrypted, proceeding with DRM processing")

            except Exception as e:
                logger.warning(f"Failed to check manifest encryption for '{channel_id}': {e}")
                # Continue to provider DRM config on error
                manifest_content = None

        # Step 1: Check DRM config cache (ClearKey configs)
        cached_configs = self.drm_config_cache.get(cache_key)
        if cached_configs is not None:
            logger.info(f"Using cached DRM configs for '{channel_id}'")
            return cached_configs

        # Step 2: PHASE 1 - Try GENERIC plugins first (if registered)
        pssh_data_list = None  # Will be populated if PSSH extraction occurs

        if DRMSystem.GENERIC in self.drm_plugin_manager.plugins:
            logger.debug(f"Phase 1: Attempting GENERIC plugin processing for '{channel_id}'")

            generic_configs, pssh_data_list = self._try_generic_plugins(
                provider_name, channel_id, cache_key, manifest_content, **kwargs
            )

            # Only use generic configs if they contain actual DRM systems (not just NONE)
            if generic_configs and any(config.system != DRMSystem.NONE for config in generic_configs):
                logger.info(f"Phase 1: Generated {len(generic_configs)} configs via GENERIC plugin")

                # Validate ClearKey configs if PSSH data is available
                if pssh_data_list and self._has_clearkey_config(generic_configs):
                    validated = self._validate_clearkey_configs(generic_configs, pssh_data_list)

                    # If validation returned empty list, it means encrypted stream with no valid keys
                    # Don't cache and don't return - proceed to provider DRM (Phase 2)
                    if not validated:
                        logger.warning(
                            f"Phase 1: GENERIC plugins produced invalid ClearKey configs for '{channel_id}', "
                            f"falling back to provider DRM"
                        )
                    else:
                        logger.info(f"Phase 1: Validated {len(validated)} ClearKey configs")
                        if self._has_clearkey_config(validated):
                            self.drm_config_cache.set(cache_key, validated)
                        return validated
                else:
                    # No ClearKey configs to validate, return as-is
                    if self._has_clearkey_config(generic_configs):
                        self.drm_config_cache.set(cache_key, generic_configs)
                    return generic_configs
            else:
                logger.debug(f"Phase 1: No actual DRM configs from GENERIC plugin, proceeding to provider")

        # Step 3: Get provider's DRM configs (PHASE 2 entry point)
        drm_configs = provider.get_drm(channel_id, **kwargs)

        # Step 3a: Check for unencrypted streams (provider returned empty configs)
        # This is a secondary check if manifest check failed or was skipped
        if not drm_configs:
            logger.info(f"Stream '{channel_id}' is unencrypted (no DRM configs from provider)")
            return [DRMConfig(system=DRMSystem.NONE, priority=0)]

        # Step 4: PHASE 2 - Extract PSSH if needed for system-specific plugins
        # Reuse pssh_data_list from Phase 1 if already extracted
        if pssh_data_list is None and drm_configs and self.drm_plugin_manager.has_system_specific_plugins():
            if self._needs_pssh_extraction(drm_configs):
                # Try PSSH cache first
                pssh_data_list = self.pssh_cache.get(cache_key)

                if pssh_data_list is None:
                    # Try to extract from manifest_content if we already have it
                    if manifest_content:
                        logger.debug(f"Phase 2: Using cached manifest_content for PSSH extraction")
                        from .utils.manifest_parser import ManifestParser
                        pssh_data_list = ManifestParser._extract_from_manifest_content(manifest_content)

                        if pssh_data_list:
                            self.pssh_cache.set(cache_key, pssh_data_list)

                    # If still no PSSH, fetch manifest and extract
                    if not pssh_data_list:
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
            drm_configs, pssh_data_list if pssh_data_list else [], **kwargs
        )

        # Step 6: Validate ClearKey configs if PSSH data is available
        if pssh_data_list and self._has_clearkey_config(processed):
            processed = self._validate_clearkey_configs(processed, pssh_data_list)

        # If validation returned empty list, return it (encrypted stream with no valid keys)
        if not processed:
            logger.error(
                f"DRM processing failed for '{channel_id}': "
                f"stream is encrypted but no valid DRM configs available"
            )
            return []

        # Step 7: Cache if contains ClearKey config
        if self._has_clearkey_config(processed):
            logger.info(f"Caching validated ClearKey DRM configs for '{channel_id}'")
            self.drm_config_cache.set(cache_key, processed)

        logger.info(f"Processed DRM for '{channel_id}': {len(processed)} validated configs")
        return processed

    def _try_generic_plugins(
            self,
            provider_name: str,
            channel_id: str,
            cache_key: str,
            manifest_content: Optional[str] = None,
            **kwargs
    ) -> Tuple[Optional[List[DRMConfig]], Optional[List]]:
        """
        Try to generate configs using GENERIC plugins.
        Returns (configs, pssh_data_list) tuple. Both can be None.
        """
        # Get PSSH data (from cache or manifest)
        pssh_data_list = self.pssh_cache.get(cache_key)

        if pssh_data_list is None:
            # Try to extract from provided manifest_content first
            if manifest_content:
                logger.debug(f"GENERIC plugin: Using cached manifest_content for '{channel_id}'")
                from .utils.manifest_parser import ManifestParser
                pssh_data_list = ManifestParser._extract_from_manifest_content(manifest_content)

                if pssh_data_list:
                    self.pssh_cache.set(cache_key, pssh_data_list)

            # If still no PSSH, fetch manifest
            if not pssh_data_list:
                logger.debug(f"GENERIC plugin: Fetching PSSH for '{provider_name}' / '{channel_id}'")
                provider = self.registry.get_provider(provider_name)
                if not provider:
                    logger.warning(f"Provider '{provider_name}' not found for GENERIC plugin")
                    return None, None

                manifest_url = provider.get_manifest(channel_id, **kwargs)
                if manifest_url:
                    pssh_data_list = self._extract_pssh_from_manifest(manifest_url, provider_name)
                    if pssh_data_list:
                        self.pssh_cache.set(cache_key, pssh_data_list)

        if not pssh_data_list:
            logger.debug(f"GENERIC plugin: No PSSH data available for '{channel_id}'")
            return None, None

        # Create a dummy config to pass to GENERIC plugin
        dummy_configs = [DRMConfig(system=DRMSystem.NONE, priority=0)]

        # Let GENERIC plugins try to generate configs
        generic_configs = self.drm_plugin_manager.process_generic_plugins(
            dummy_configs, pssh_data_list, **kwargs
        )

        return generic_configs if generic_configs else None, pssh_data_list

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