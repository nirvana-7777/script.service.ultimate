# ============================================================================
# streaming_providers/base/drm_operations.py
"""
DRM-related operations with caching and optimized PSSH extraction.
Two-phase plugin processing: GENERIC plugins first, then system-specific.

Caching strategy:
- All DRM configs are cached uniformly regardless of DRM system type.
- Exception: if ClearKey configs have FULL key coverage, only the ClearKey
  configs are cached and returned (no need to involve upstream license servers).
- If ClearKey coverage is PARTIAL, all configs (ClearKey + others) are cached
  and returned so upstream can decide which system to use.
- Unencrypted streams (DRMSystem.NONE) are never cached.
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
    """
    Thread-safe cache for DRM configurations.

    Caches all DRM config types uniformly. The caller is responsible for
    deciding what to store (full ClearKey-only set vs. mixed set).
    Simple TTL expiry — no stale-while-revalidate complexity.
    """

    def __init__(self, ttl_seconds: int = 3600):
        self.cache: Dict[str, Tuple[List, float]] = {}
        self.ttl = ttl_seconds
        self.lock = Lock()

    def get(self, key: str) -> Optional[List]:
        """
        Get cached DRM configs if not expired.

        Returns:
            List of DRMConfig if found and within TTL, None otherwise.
        """
        with self.lock:
            if key in self.cache:
                drm_configs, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    logger.debug(f"DRM Config Cache HIT for {key}")
                    return drm_configs
                else:
                    logger.debug(f"DRM Config Cache EXPIRED for {key}")
                    del self.cache[key]
        return None

    def set(self, key: str, drm_configs: List):
        """Cache DRM configs"""
        with self.lock:
            self.cache[key] = (drm_configs, time.time())
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
        self.drm_config_cache = DRMConfigCache(ttl_seconds=cache_ttl)
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
        from .utils.drm_extractor import DRMExtractor
        pssh_list = DRMExtractor._extract_from_manifest_content(manifest_content)

        if pssh_list:
            # If we got PSSHData objects with valid DRM systems, it's encrypted!
            for pssh in pssh_list:
                if pssh.drm_system and pssh.drm_system != DRMSystem.NONE:
                    logger.debug(f"Detected DRM system: {pssh.drm_system.value} from PSSH data")
                    return True

        # Fallback: Check for ContentProtection elements with known DRM UUIDs
        cp_pattern = re.compile(
            r'<ContentProtection[^>]*schemeIdUri="urn:uuid:([^"]+)"[^>]*>',
            re.IGNORECASE
        )

        for match in cp_pattern.finditer(manifest_content):
            uuid = match.group(1).lower()
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
    def _check_clearkey_coverage(
            drm_configs: List[DRMConfig],
            pssh_data_list: List
    ) -> Tuple[List[DRMConfig], bool]:
        """
        Validate ClearKey configs against required KIDs from PSSH data and
        determine coverage level.

        Args:
            drm_configs: List of DRM configs to check
            pssh_data_list: PSSH data containing required KIDs

        Returns:
            Tuple of (validated_configs, has_full_coverage) where:
            - validated_configs: configs with invalid ClearKey entries removed.
              If ALL ClearKey configs are invalid, returns empty list.
            - has_full_coverage: True if at least one ClearKey config covers
              ALL required KIDs. False if coverage is partial or zero.

        Notes:
            - Non-ClearKey configs are always passed through unchanged.
            - A ClearKey config is considered valid if it covers at least one
              required KID (partial coverage is acceptable, but will not set
              has_full_coverage=True).
            - has_full_coverage=True means the caller may safely discard all
              non-ClearKey configs and rely solely on ClearKey decryption.
        """
        if not pssh_data_list:
            logger.warning("No PSSH data available for ClearKey validation")
            return drm_configs, False

        # Extract all required key_ids from PSSH (normalized)
        required_key_ids = set()
        for pssh_data in pssh_data_list:
            if pssh_data.key_ids:
                required_key_ids.update(
                    kid.lower().replace("-", "") for kid in pssh_data.key_ids
                )

        if not required_key_ids:
            logger.warning("No key_ids found in PSSH data")
            return drm_configs, False

        validated_configs = []
        has_valid_clearkey = False
        has_full_coverage = False

        for config in drm_configs:
            if config.system != DRMSystem.CLEARKEY:
                validated_configs.append(config)
                continue

            # Validate ClearKey config
            if not config.license or not config.license.keyids:
                logger.warning("ClearKey config missing license.keyids — skipping")
                continue

            # Normalize provided KIDs
            provided_kids = {
                kid.lower().replace("-", "")
                for kid in config.license.keyids.keys()
            }

            # Find intersection
            valid_keys = required_key_ids & provided_kids

            if valid_keys:
                has_valid_clearkey = True
                validated_configs.append(config)

                if valid_keys == required_key_ids:
                    has_full_coverage = True
                    logger.info(
                        f"ClearKey config: full coverage — "
                        f"all {len(required_key_ids)} required KIDs present"
                    )
                else:
                    logger.info(
                        f"ClearKey config: partial coverage — "
                        f"{len(valid_keys)}/{len(required_key_ids)} KIDs present "
                        f"(may limit available resolutions/tracks)"
                    )
            else:
                logger.error(
                    f"ClearKey config INVALID: none of the provided KIDs match "
                    f"the {len(required_key_ids)} required KIDs — discarding config"
                )

        # If all ClearKey configs were invalid, return empty list so the caller
        # knows the stream is encrypted but we have no usable keys.
        if any(c.system == DRMSystem.CLEARKEY for c in drm_configs) and not has_valid_clearkey:
            logger.error(
                "All ClearKey configs failed validation "
                "(stream is encrypted but no valid keys available) — returning empty list"
            )
            return [], False

        return validated_configs, has_full_coverage

    @staticmethod
    def _select_configs_for_cache_and_return(
            configs: List[DRMConfig],
            has_full_clearkey_coverage: bool
    ) -> List[DRMConfig]:
        """
        Apply the caching/return selection rule:

        - Full ClearKey coverage  → return only ClearKey configs (discard others)
        - Partial coverage or none → return all configs as-is

        Args:
            configs: Validated DRM configs
            has_full_clearkey_coverage: Result of _check_clearkey_coverage

        Returns:
            The list that should be both cached and returned upstream.
        """
        if has_full_clearkey_coverage:
            clearkey_only = [c for c in configs if c.system == DRMSystem.CLEARKEY]
            logger.info(
                f"Full ClearKey coverage: returning {len(clearkey_only)} ClearKey config(s) only "
                f"(discarding {len(configs) - len(clearkey_only)} other config(s))"
            )
            return clearkey_only

        return configs

    def get_content_drm_configs(self, provider_name: str, channel_id: str, **kwargs) -> List:
        """
        Get DRM configurations for a channel with two-phase plugin processing.

        Phase 0: Fetch manifest once, short-circuit if stream is unencrypted.
                 manifest_url, manifest_headers, and manifest_content are resolved
                 here and threaded through to all subsequent phases — no phase ever
                 calls get_manifest_with_headers() again unless Step 0a failed.
        Phase 1: GENERIC plugins (pre-provider) — can generate configs from PSSH.
                 If Phase 1 produces configs:
                   - Full ClearKey coverage  → cache ClearKey-only, return immediately.
                   - Partial ClearKey        → fall through to Phase 2 for a better result.
                   - No ClearKey / invalid   → fall through to Phase 2.
        Phase 2: Provider DRM configs + system-specific plugin processing.
                 Apply coverage check, cache, and return.

        Caching:
          All resulting configs are cached uniformly with a simple TTL.
          On cache hit the result is returned directly with no re-validation.
        """
        cache_key = f"{provider_name}:{channel_id}"
        manifest_content = None  # stored to avoid redundant fetches
        manifest_url = None      # resolved once in Step 0a and reused throughout
        manifest_headers = None  # resolved once in Step 0a and reused throughout

        # ------------------------------------------------------------------
        # Step 0: Resolve provider and inject proxy_config into kwargs
        # ------------------------------------------------------------------
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if "proxy_config" not in kwargs:
            http_mgr = getattr(provider, "http_manager", None)
            if http_mgr is not None:
                provider_proxy = getattr(getattr(http_mgr, "config", None), "proxy_config", None)
                if provider_proxy is not None:
                    kwargs["proxy_config"] = provider_proxy
                    logger.debug(
                        f"DRMOperations: Injected proxy_config from provider "
                        f"'{provider_name}' into plugin kwargs "
                        f"({provider_proxy.host}:{provider_proxy.port})"
                    )

        # ------------------------------------------------------------------
        # Step 0a: Fetch manifest once and short-circuit for unencrypted streams.
        # manifest_url, manifest_headers, and manifest_content are stored here
        # so that no later phase needs to call get_manifest_with_headers() again.
        # ------------------------------------------------------------------
        manifest_url, manifest_headers = provider.get_manifest_with_headers(channel_id, **kwargs)
        if manifest_url and manifest_url.startswith(('http://', 'https://')):
            try:
                from .network import HTTPManager
                http = provider.http_manager if hasattr(provider, 'http_manager') else HTTPManager()
                response = http.get(manifest_url, headers=manifest_headers, timeout=10, operation="api")
                response.raise_for_status()
                manifest_content = response.text

                if not self._is_manifest_encrypted(manifest_content):
                    logger.info(f"Stream '{channel_id}' is unencrypted (no DRM in manifest)")
                    return [DRMConfig(system=DRMSystem.NONE, priority=0)]

                logger.debug(f"Stream '{channel_id}' is encrypted, proceeding with DRM processing")

            except Exception as e:
                logger.warning(f"Failed to check manifest encryption for '{channel_id}': {e}")
                manifest_content = None

        # ------------------------------------------------------------------
        # Step 1: DRM config cache — simple TTL, no stale revalidation
        # ------------------------------------------------------------------
        cached_configs = self.drm_config_cache.get(cache_key)
        if cached_configs is not None:
            logger.info(f"Using cached DRM configs for '{cache_key}'")
            return cached_configs

        # ------------------------------------------------------------------
        # Step 2: PHASE 1 — Try GENERIC plugins first (if registered)
        # Pass the already-resolved manifest_url/headers so _try_generic_plugins
        # never needs to call get_manifest_with_headers() itself.
        # ------------------------------------------------------------------
        pssh_data_list = None  # reused across phases to avoid re-fetching

        if DRMSystem.GENERIC in self.drm_plugin_manager.plugins:
            logger.debug(f"Phase 1: Attempting GENERIC plugin processing for '{channel_id}'")

            generic_configs, pssh_data_list = self._try_generic_plugins(
                provider_name, channel_id, cache_key,
                manifest_content=manifest_content,
                manifest_url=manifest_url,
                manifest_headers=manifest_headers,
                **kwargs
            )

            # Only proceed with generic configs if they contain real DRM systems
            if generic_configs and any(c.system != DRMSystem.NONE for c in generic_configs):
                logger.info(f"Phase 1: Generated {len(generic_configs)} configs via GENERIC plugin")

                if pssh_data_list:
                    validated, has_full_coverage = self._check_clearkey_coverage(
                        generic_configs, pssh_data_list
                    )
                else:
                    validated = generic_configs
                    has_full_coverage = False

                if not validated:
                    # All ClearKey configs were invalid — fall through to Phase 2
                    logger.warning(
                        f"Phase 1: GENERIC plugins produced no valid ClearKey configs for "
                        f"'{channel_id}', falling back to provider DRM"
                    )
                elif has_full_coverage:
                    # Best case: we have all the keys we need — no need for Phase 2
                    result = self._select_configs_for_cache_and_return(validated, has_full_coverage)
                    self.drm_config_cache.set(cache_key, result)
                    return result
                else:
                    # Partial ClearKey coverage — fall through to Phase 2 to see if
                    # the provider can give us a better result.  Keep validated and
                    # pssh_data_list in scope so Phase 2 can merge if needed.
                    logger.info(
                        f"Phase 1: Partial ClearKey coverage for '{channel_id}', "
                        f"continuing to Phase 2 for potentially better coverage"
                    )
            else:
                logger.debug(f"Phase 1: No actual DRM configs from GENERIC plugin, proceeding to provider")
                generic_configs = None  # ensure clean state for Phase 2

        else:
            generic_configs = None

        # ------------------------------------------------------------------
        # Step 3: PHASE 2 — Get provider's DRM configs
        # ------------------------------------------------------------------
        provider_drm_configs = provider.get_drm(content_id=channel_id, **kwargs)

        # Secondary unencrypted check (in case manifest fetch failed earlier)
        if not provider_drm_configs:
            logger.info(f"Stream '{channel_id}' is unencrypted (no DRM configs from provider)")
            return [DRMConfig(system=DRMSystem.NONE, priority=0)]

        # ------------------------------------------------------------------
        # Step 4: PHASE 2 — Extract PSSH if needed for system-specific plugins.
        # Reuse pssh_data_list from Phase 1 if already extracted.
        # If a fresh fetch is needed, reuse the manifest_url/headers resolved
        # in Step 0a — never call get_manifest_with_headers() again.
        # ------------------------------------------------------------------
        if pssh_data_list is None and self.drm_plugin_manager.has_system_specific_plugins():
            if self._needs_pssh_extraction(provider_drm_configs):
                pssh_data_list = self.pssh_cache.get(cache_key)

                if pssh_data_list is None:
                    if manifest_content:
                        logger.debug(f"Phase 2: Using cached manifest_content for PSSH extraction")
                        from .utils.drm_extractor import DRMExtractor
                        pssh_data_list = DRMExtractor._extract_from_manifest_content(manifest_content)
                        if pssh_data_list:
                            self.pssh_cache.set(cache_key, pssh_data_list)

                    if not pssh_data_list:
                        # manifest_url/headers already resolved in Step 0a — reuse them
                        if manifest_url:
                            logger.debug(f"Phase 2: PSSH cache miss for {cache_key}, extracting from manifest")
                            pssh_data_list = self._extract_pssh_from_manifest(
                                manifest_url, manifest_headers, provider_name
                            )
                            if pssh_data_list:
                                self.pssh_cache.set(cache_key, pssh_data_list)
                        else:
                            logger.debug(f"Phase 2: No manifest URL available for PSSH extraction")
                else:
                    logger.debug(f"Phase 2: Using cached PSSH for {cache_key}")

        # ------------------------------------------------------------------
        # Step 5: PHASE 2 — Process through system-specific plugins.
        # Snapshot provider_drm_configs first so we can reinstate any configs
        # that a plugin replaced (e.g. PlayReady → ClearKey) if coverage turns
        # out to be only partial.
        # ------------------------------------------------------------------
        provider_configs_snapshot = list(provider_drm_configs)
        processed = self.drm_plugin_manager.process_system_specific_plugins(
            provider_drm_configs, pssh_data_list if pssh_data_list else [], **kwargs
        )

        # ------------------------------------------------------------------
        # Step 6: Merge Phase 1 partial ClearKey result (if any) with Phase 2
        # output.  Phase 1 configs whose DRM system is not already represented
        # in Phase 2 are appended so upstream has the full picture.
        # De-duplication is by DRM system to avoid two ClearKey entries.
        # ------------------------------------------------------------------
        if generic_configs:
            phase2_systems = {c.system for c in processed}
            extra = [c for c in generic_configs if c.system not in phase2_systems]
            if extra:
                logger.info(
                    f"Merging {len(extra)} Phase 1 config(s) into Phase 2 results"
                )
                processed = processed + extra

        # ------------------------------------------------------------------
        # Step 7: Validate ClearKey configs and determine coverage.
        # If coverage is only partial, reinstate any original provider configs
        # whose DRM system was replaced by a plugin but is no longer present
        # in the processed list.  This ensures upstream always has a complete
        # fallback (e.g. PlayReady) alongside a partial ClearKey config.
        # ------------------------------------------------------------------
        if pssh_data_list and any(c.system == DRMSystem.CLEARKEY for c in processed):
            processed, has_full_coverage = self._check_clearkey_coverage(processed, pssh_data_list)
        else:
            has_full_coverage = False

        if not has_full_coverage:
            # Find original provider systems that are no longer in processed
            # (a plugin replaced them) and reinstate them.
            processed_systems = {c.system for c in processed}
            reinstated = [
                c for c in provider_configs_snapshot
                if c.system not in processed_systems
            ]
            if reinstated:
                logger.info(
                    f"Partial/no ClearKey coverage: reinstating "
                    f"{len(reinstated)} replaced provider config(s): "
                    f"{[c.system.name for c in reinstated]}"
                )
                processed = processed + reinstated

        if not processed:
            logger.error(
                f"DRM processing failed for '{channel_id}': "
                f"stream is encrypted but no valid DRM configs available"
            )
            return []

        # ------------------------------------------------------------------
        # Step 8: Apply selection rule, cache, and return
        # ------------------------------------------------------------------
        result = self._select_configs_for_cache_and_return(processed, has_full_coverage)
        self.drm_config_cache.set(cache_key, result)
        logger.info(
            f"Processed DRM for '{channel_id}': returning {len(result)} config(s) "
            f"({'full ClearKey' if has_full_coverage else 'mixed/partial'})"
        )
        return result

    def _try_generic_plugins(
            self,
            provider_name: str,
            channel_id: str,
            cache_key: str,
            manifest_content: Optional[str] = None,
            manifest_url: Optional[str] = None,
            manifest_headers: Optional[dict] = None,
            **kwargs
    ) -> Tuple[Optional[List[DRMConfig]], Optional[List]]:
        """
        Try to generate configs using GENERIC plugins.
        Returns (configs, pssh_data_list) tuple. Both can be None.

        IMPORTANT: Ensures PSSH data is complete (with KIDs) before calling plugins.

        manifest_url and manifest_headers should be passed in from the caller
        (already resolved in Step 0a of get_content_drm_configs) to avoid any
        additional calls to get_manifest_with_headers(). A lazy fallback fetch
        is performed only when both are None (i.e. Step 0a failed entirely).
        """
        # Get PSSH data (from cache or manifest)
        pssh_data_list = self.pssh_cache.get(cache_key)

        if pssh_data_list is None:
            # Try to extract from provided manifest_content first
            if manifest_content:
                logger.debug(f"GENERIC plugin: Using cached manifest_content for '{channel_id}'")
                from .utils.drm_extractor import DRMExtractor
                pssh_data_list = DRMExtractor._extract_from_manifest_content(manifest_content)

                if pssh_data_list:
                    self.pssh_cache.set(cache_key, pssh_data_list)

            # If still no PSSH, use the manifest_url/headers passed in from the caller.
            # Only perform a lazy get_manifest_with_headers() call if they were not provided
            # (i.e. Step 0a failed entirely).
            if not pssh_data_list:
                if not manifest_url:
                    logger.debug(f"GENERIC plugin: No manifest URL provided, fetching for '{provider_name}' / '{channel_id}'")
                    provider = self.registry.get_provider(provider_name)
                    if not provider:
                        logger.warning(f"Provider '{provider_name}' not found for GENERIC plugin")
                        return None, None
                    manifest_url, manifest_headers = provider.get_manifest_with_headers(channel_id, **kwargs)
                else:
                    logger.debug(f"GENERIC plugin: Using pre-fetched manifest URL for '{channel_id}'")

                if manifest_url:
                    pssh_data_list = self._extract_pssh_from_manifest(manifest_url, manifest_headers, provider_name)
                    if pssh_data_list:
                        self.pssh_cache.set(cache_key, pssh_data_list)

        if not pssh_data_list:
            logger.debug(f"GENERIC plugin: No PSSH data available for '{channel_id}'")
            return None, None

        # CRITICAL: Check if PSSH is stub (no real data)
        if self._has_stub_pssh(pssh_data_list):
            logger.warning(
                f"GENERIC plugin: PSSH data is incomplete (no KIDs) - extracting from init segment"
            )

            # Reuse manifest_url/headers already in scope; they are guaranteed to be
            # populated at this point (either passed in or fetched in the block above).
            if not manifest_url:
                logger.error(f"GENERIC plugin: Cannot get manifest URL for init segment extraction")
                return None, pssh_data_list

            real_pssh = self._extract_pssh_from_manifest(manifest_url, manifest_headers, provider_name)

            if real_pssh and not self._has_stub_pssh(real_pssh):
                logger.info(
                    f"GENERIC plugin: Successfully extracted complete PSSH with "
                    f"{sum(len(p.key_ids) for p in real_pssh)} KIDs from init segment"
                )
                pssh_data_list = real_pssh
                self.pssh_cache.set(cache_key, pssh_data_list)
            else:
                logger.error(
                    f"GENERIC plugin: Failed to extract complete PSSH - "
                    f"Kid-Key plugin will not be called"
                )
                return None, pssh_data_list

        # Verify we now have complete PSSH
        total_kids = sum(len(p.key_ids) for p in pssh_data_list)
        if total_kids == 0:
            logger.warning(
                f"GENERIC plugin: PSSH has no KIDs even after extraction - "
                f"Kid-Key plugin will not be called"
            )
            return None, pssh_data_list

        logger.debug(f"GENERIC plugin: Processing with complete PSSH ({total_kids} KIDs)")

        # Create a dummy config to pass to GENERIC plugin
        dummy_configs = [DRMConfig(system=DRMSystem.NONE, priority=0)]

        # Let GENERIC plugins try to generate configs
        generic_configs = self.drm_plugin_manager.process_generic_plugins(
            dummy_configs, pssh_data_list, **kwargs
        )

        return generic_configs if generic_configs else None, pssh_data_list

    @staticmethod
    def _has_stub_pssh(pssh_data_list: List) -> bool:
        """
        Check if PSSH data is incomplete (stub).

        Stub PSSH occurs when manifest has ContentProtection tags but no actual PSSH boxes.
        Returns True if any PSSH is missing pssh_box or has no key_ids.
        """
        if not pssh_data_list:
            return True

        for pssh in pssh_data_list:
            if not pssh.pssh_box or not pssh.key_ids:
                return True

        return False

    def _needs_pssh_extraction(self, drm_configs) -> bool:
        """Check if PSSH extraction is needed for system-specific plugins."""
        config_systems = {config.system for config in drm_configs}
        # Exclude GENERIC from this check (it's handled separately)
        plugin_systems = {
            sys for sys in self.drm_plugin_manager.plugins.keys()
            if sys != DRMSystem.GENERIC
        }
        return bool(config_systems & plugin_systems)

    def _extract_pssh_from_manifest(self, manifest_url: str, manifest_headers: dict[str, str], provider_name: Optional[str] = None) -> List:
        """Extract PSSH data from manifest using the provider's HTTPManager."""
        from .utils.drm_extractor import DRMExtractor
        from .network import HTTPManager

        # 1. Validate the URL before attempting the request
        if not manifest_url or not manifest_url.startswith(('http://', 'https://')):
            logger.error(f"Invalid manifest URL provided: '{manifest_url}'. Cannot extract PSSH.")
            return []

        try:
            # 2. Resolve the correct HTTP manager
            http = None
            if provider_name:
                provider = self.registry.get_provider(provider_name)
                if provider:
                    http = provider.http_manager
                    logger.debug(f"Using configured HTTPManager for provider: {provider_name}")

            if not http:
                logger.debug("No provider manager found; using default HTTPManager")
                http = HTTPManager()

            # 3. Perform the request
            response = http.get(manifest_url, headers=manifest_headers, timeout=10, operation="api")
            response.raise_for_status()
            manifest_content = response.text

            # 4. Standard PSSH extraction logic
            pssh_list = DRMExtractor._extract_from_manifest_content(manifest_content)

            # Check if we need segment extraction
            needs_segment_extraction = not pssh_list or any(
                not p.pssh_box or not p.key_ids for p in pssh_list
            )

            if needs_segment_extraction:
                logger.debug("PSSH incomplete in manifest, extracting from init segment")
                from .utils import ManifestParser
                init_segment_url = ManifestParser.extract_single_init_segment_url(
                    manifest_content, manifest_url
                )

                if init_segment_url:
                    segment_pssh = DRMExtractor._extract_from_single_segment(
                        init_segment_url,
                        [p.system_id for p in pssh_list] if pssh_list else []
                    )

                    if segment_pssh:
                        return DRMExtractor._merge_pssh_data(pssh_list, segment_pssh)

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