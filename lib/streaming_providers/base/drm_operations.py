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
    def __init__(self, ttl_seconds: int = 3600):
        self.cache: Dict[str, Tuple[List, float]] = {}
        self.ttl = ttl_seconds
        self.lock = Lock()

    def get(self, key: str) -> Optional[List]:
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
        with self.lock:
            self.cache[key] = (drm_configs, time.time())
            logger.debug(f"DRM Config Cache SET for {key}")

    def clear(self):
        with self.lock:
            self.cache.clear()
            logger.debug("DRM Config Cache CLEARED")


class DRMOperations:
    def __init__(self, registry, cache_ttl: int = 3600):
        self.registry = registry
        self.drm_plugin_manager = DRMPluginManager()
        self.pssh_cache = PSSHCache(ttl_seconds=cache_ttl)
        self.drm_config_cache = DRMConfigCache(ttl_seconds=cache_ttl)
        logger.debug("DRMOperations: Initialized with two-phase plugin processing")

    @staticmethod
    def _is_manifest_encrypted(manifest_content: str) -> bool:
        import re
        from .utils.drm_extractor import DRMExtractor

        pssh_list = DRMExtractor._extract_from_manifest_content(manifest_content)
        if pssh_list:
            for pssh in pssh_list:
                if pssh.drm_system and pssh.drm_system != DRMSystem.NONE:
                    return True

        cp_pattern = re.compile(r'<ContentProtection[^>]*schemeIdUri="urn:uuid:([^"]+)"[^>]*>', re.IGNORECASE)
        for match in cp_pattern.finditer(manifest_content):
            uuid = match.group(1).lower()
            drm_system = DRMSystem.from_uuid(uuid)
            if drm_system:
                return True

        if re.search(r'(?:cenc:)?default_KID\s*=', manifest_content, re.IGNORECASE):
            return True
        if re.search(r'<(?:cenc:)?pssh[^>]*>', manifest_content, re.IGNORECASE):
            return True
        return False

    @staticmethod
    def _check_clearkey_coverage(drm_configs: List[DRMConfig], pssh_data_list: List) -> Tuple[List[DRMConfig], bool]:
        if not pssh_data_list:
            return drm_configs, False
        required_key_ids = set()
        for pssh_data in pssh_data_list:
            if pssh_data.key_ids:
                required_key_ids.update(kid.lower().replace("-", "") for kid in pssh_data.key_ids)
        if not required_key_ids:
            return drm_configs, False

        validated_configs = []
        has_valid_clearkey = False
        has_full_coverage = False

        for config in drm_configs:
            if config.system != DRMSystem.CLEARKEY:
                validated_configs.append(config)
                continue
            if not config.license or not config.license.keyids:
                continue
            provided_kids = {kid.lower().replace("-", "") for kid in config.license.keyids.keys()}
            valid_keys = required_key_ids & provided_kids
            if valid_keys:
                has_valid_clearkey = True
                validated_configs.append(config)
                if valid_keys == required_key_ids:
                    has_full_coverage = True
        if any(c.system == DRMSystem.CLEARKEY for c in drm_configs) and not has_valid_clearkey:
            return [], False
        return validated_configs, has_full_coverage

    @staticmethod
    def _select_configs_for_cache_and_return(configs: List[DRMConfig], has_full_clearkey_coverage: bool) -> List[
        DRMConfig]:
        if has_full_clearkey_coverage:
            return [c for c in configs if c.system == DRMSystem.CLEARKEY]
        return configs

    @staticmethod
    def _build_cache_key(provider_name: str, channel_id: str, **kwargs) -> str:
        VARIANT_KEYS = ("drm_variant", "preferred_quality", "preferred_format")
        parts = [provider_name, channel_id]
        for key in VARIANT_KEYS:
            value = kwargs.get(key)
            if value is not None:
                parts.append(f"{key}={str(value).lower()}")
        return ":".join(parts)

    def get_content_drm_configs(self, provider_name: str, channel_id: str, **kwargs) -> List:
        cache_key = self._build_cache_key(provider_name, channel_id, **kwargs)
        manifest_content = None
        manifest_url = None
        manifest_headers = None

        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if "proxy_config" not in kwargs:
            http_mgr = getattr(provider, "http_manager", None)
            if http_mgr is not None:
                provider_proxy = getattr(getattr(http_mgr, "config", None), "proxy_config", None)
                if provider_proxy is not None:
                    kwargs["proxy_config"] = provider_proxy

        cached_configs = self.drm_config_cache.get(cache_key)
        if cached_configs is not None:
            return cached_configs

        manifest_url, manifest_headers = provider.get_manifest_with_headers(channel_id, **kwargs)
        if manifest_url and manifest_url.startswith(('http://', 'https://')):
            try:
                from .network import HTTPManager
                http = provider.http_manager if hasattr(provider, 'http_manager') else HTTPManager()
                response = http.get(manifest_url, headers=manifest_headers, timeout=10, operation="api")
                response.raise_for_status()
                manifest_content = response.text
                if not self._is_manifest_encrypted(manifest_content):
                    return [DRMConfig(system=DRMSystem.NONE, priority=0)]
            except Exception:
                manifest_content = None

        pssh_data_list = None
        generic_configs = None

        if DRMSystem.GENERIC in self.drm_plugin_manager.plugins:
            generic_configs, pssh_data_list = self._try_generic_plugins(
                provider_name, channel_id, cache_key,
                manifest_content=manifest_content,
                manifest_url=manifest_url,
                manifest_headers=manifest_headers,
                **kwargs
            )
            if generic_configs and any(c.system != DRMSystem.NONE for c in generic_configs):
                if pssh_data_list:
                    validated, has_full_coverage = self._check_clearkey_coverage(generic_configs, pssh_data_list)
                else:
                    validated = generic_configs
                    has_full_coverage = False
                if not validated:
                    pass
                elif has_full_coverage:
                    result = self._select_configs_for_cache_and_return(validated, has_full_coverage)
                    self.drm_config_cache.set(cache_key, result)
                    return result
            else:
                generic_configs = None

        provider_drm_configs = provider.get_drm(content_id=channel_id, **kwargs)
        if not provider_drm_configs:
            return [DRMConfig(system=DRMSystem.NONE, priority=0)]

        if pssh_data_list is None and self.drm_plugin_manager.has_system_specific_plugins():
            if self._needs_pssh_extraction(provider_drm_configs):
                pssh_data_list = self.pssh_cache.get(cache_key)
                if pssh_data_list is None:
                    if manifest_content:
                        from .utils.drm_extractor import DRMExtractor
                        pssh_data_list = DRMExtractor._extract_from_manifest_content(manifest_content)
                        if pssh_data_list:
                            self.pssh_cache.set(cache_key, pssh_data_list)
                    if not pssh_data_list and manifest_url:
                        pssh_data_list = self._extract_pssh_from_manifest(
                            manifest_url, manifest_headers, provider_name,
                            channel_id=channel_id,
                            manifest_content=manifest_content,
                            **kwargs
                        )
                        if pssh_data_list:
                            self.pssh_cache.set(cache_key, pssh_data_list)

        provider_configs_snapshot = list(provider_drm_configs)
        sorted_systems = sorted(
            {c.system for c in provider_drm_configs},
            key=lambda s: min(c.priority for c in provider_drm_configs if c.system == s)
        )
        remaining = list(provider_drm_configs)

        for drm_system in sorted_systems:
            system_configs = [c for c in remaining if c.system == drm_system]
            if not system_configs:
                continue
            batch_result = self.drm_plugin_manager.process_system_specific_plugins(
                system_configs, pssh_data_list or [], **kwargs
            )
            remaining = [c for c in remaining if c.system != drm_system] + batch_result
            if pssh_data_list and any(c.system == DRMSystem.CLEARKEY for c in remaining):
                remaining, has_full_coverage = self._check_clearkey_coverage(remaining, pssh_data_list)
                if has_full_coverage:
                    break

        processed = remaining

        if generic_configs:
            phase2_systems = {c.system for c in processed}
            extra = [c for c in generic_configs if c.system not in phase2_systems]
            if extra:
                processed = processed + extra

        if pssh_data_list and any(c.system == DRMSystem.CLEARKEY for c in processed):
            processed, has_full_coverage = self._check_clearkey_coverage(processed, pssh_data_list)
        else:
            has_full_coverage = False

        if not has_full_coverage:
            processed_systems = {c.system for c in processed}
            reinstated = [c for c in provider_configs_snapshot if c.system not in processed_systems]
            if reinstated:
                processed = processed + reinstated

        if not processed:
            return []

        result = self._select_configs_for_cache_and_return(processed, has_full_coverage)
        self.drm_config_cache.set(cache_key, result)
        return result

    def _try_generic_plugins(
            self, provider_name: str, channel_id: str, cache_key: str,
            manifest_content: Optional[str] = None,
            manifest_url: Optional[str] = None,
            manifest_headers: Optional[dict] = None,
            **kwargs
    ) -> Tuple[Optional[List[DRMConfig]], Optional[List]]:
        pssh_data_list = self.pssh_cache.get(cache_key)

        if pssh_data_list is None:
            if manifest_content:
                from .utils.drm_extractor import DRMExtractor
                pssh_data_list = DRMExtractor._extract_from_manifest_content(manifest_content)
                if pssh_data_list:
                    self.pssh_cache.set(cache_key, pssh_data_list)

            if not pssh_data_list:
                if not manifest_url:
                    provider = self.registry.get_provider(provider_name)
                    if not provider: return None, None
                    manifest_url, manifest_headers = provider.get_manifest_with_headers(channel_id, **kwargs)

                if manifest_url:
                    pssh_data_list = self._extract_pssh_from_manifest(
                        manifest_url, manifest_headers, provider_name,
                        channel_id=channel_id,
                        manifest_content=manifest_content,
                        **kwargs
                    )
                    if pssh_data_list:
                        self.pssh_cache.set(cache_key, pssh_data_list)

        if not pssh_data_list:
            return None, None

        if self._has_stub_pssh(pssh_data_list):
            if not manifest_url:
                return None, pssh_data_list
            real_pssh = self._extract_pssh_from_manifest(
                manifest_url, manifest_headers, provider_name,
                channel_id=channel_id,
                manifest_content=manifest_content,
                **kwargs
            )
            if real_pssh and not self._has_stub_pssh(real_pssh):
                pssh_data_list = real_pssh
                self.pssh_cache.set(cache_key, pssh_data_list)
            else:
                return None, pssh_data_list

        total_kids = sum(len(p.key_ids) for p in pssh_data_list)
        if total_kids == 0:
            return None, pssh_data_list

        dummy_configs = [DRMConfig(system=DRMSystem.NONE, priority=0)]
        generic_configs = self.drm_plugin_manager.process_generic_plugins(
            dummy_configs, pssh_data_list, **kwargs
        )
        return generic_configs if generic_configs else None, pssh_data_list

    @staticmethod
    def _has_stub_pssh(pssh_data_list: List) -> bool:
        if not pssh_data_list:
            return True
        for pssh in pssh_data_list:
            if not pssh.pssh_box or not pssh.key_ids:
                return True
        return False

    def _needs_pssh_extraction(self, drm_configs) -> bool:
        config_systems = {config.system for config in drm_configs}
        plugin_systems = {
            sys for sys in self.drm_plugin_manager.plugins.keys()
            if sys != DRMSystem.GENERIC
        }
        return bool(config_systems & plugin_systems)

    def _extract_pssh_from_manifest(
            self, manifest_url: str, manifest_headers: Dict[str, str],
            provider_name: Optional[str] = None, channel_id: Optional[str] = None,
            manifest_content: Optional[str] = None, **kwargs
    ) -> List:
        """
        Extract PSSH data from manifest, falling back to the init segment.

        Passes `**kwargs` (which contain start_time/end_time for catchup)
        to `provider.get_segment_headers()` so that providers like MoveTV can
        return the correct catchup-scoped headers for init segment fetches.
        """
        from .utils.drm_extractor import DRMExtractor
        from .network import HTTPManager

        if not manifest_url or not manifest_url.startswith(('http://', 'https://')):
            return []

        try:
            http = None
            segment_headers = manifest_headers  # Default to manifest headers

            if provider_name:
                provider = self.registry.get_provider(provider_name)
                if provider:
                    http = provider.http_manager
                    if channel_id:
                        try:
                            # Call provider's segment headers with full context (start_time, end_time, etc.)
                            segment_headers = provider.get_segment_headers(channel_id, **kwargs)
                        except Exception:
                            pass  # Fallback to manifest_headers on error

            if not http:
                http = HTTPManager()

            if not manifest_content:
                response = http.get(manifest_url, headers=manifest_headers, timeout=10, operation="api")
                response.raise_for_status()
                manifest_content = response.text

            pssh_list = DRMExtractor._extract_from_manifest_content(manifest_content)

            needs_segment_extraction = not pssh_list or any(
                not p.pssh_box or not p.key_ids for p in pssh_list
            )

            if needs_segment_extraction:
                from .utils import ManifestParser
                init_segment_url = ManifestParser.extract_single_init_segment_url(
                    manifest_content, manifest_url
                )

                if init_segment_url:
                    segment_pssh = DRMExtractor._extract_from_single_segment(
                        init_segment_url,
                        [p.system_id for p in pssh_list] if pssh_list else [],
                        headers=segment_headers,
                        http_manager=http,
                    )

                    if segment_pssh:
                        return DRMExtractor._merge_pssh_data(pssh_list, segment_pssh)

            return pssh_list

        except Exception as e:
            logger.warning(f"Failed to extract PSSH: {e}")
            return []

    def get_catchup_content_drm_configs(
            self, provider_name: str, channel_id: str, catchup_manifest_url: str,
            catchup_manifest_headers: Dict[str, str], start_time: int, end_time: int,
            epg_id: Optional[str] = None, **kwargs,
    ) -> List:
        cache_key = self._build_catchup_cache_key(
            provider_name, channel_id, start_time, end_time, epg_id, **kwargs
        )
        manifest_content = None

        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if "proxy_config" not in kwargs:
            http_mgr = getattr(provider, "http_manager", None)
            if http_mgr is not None:
                provider_proxy = getattr(getattr(http_mgr, "config", None), "proxy_config", None)
                if provider_proxy is not None:
                    kwargs["proxy_config"] = provider_proxy

        cached_configs = self.drm_config_cache.get(cache_key)
        if cached_configs is not None:
            return cached_configs

        manifest_url = catchup_manifest_url
        manifest_headers = catchup_manifest_headers

        if manifest_url and manifest_url.startswith(("http://", "https://")):
            try:
                from .network import HTTPManager
                http = provider.http_manager if hasattr(provider, "http_manager") else HTTPManager()
                response = http.get(manifest_url, headers=manifest_headers, timeout=10, operation="api")
                response.raise_for_status()
                manifest_content = response.text

                if not self._is_manifest_encrypted(manifest_content):
                    return [DRMConfig(system=DRMSystem.NONE, priority=0)]
            except Exception:
                manifest_content = None
        else:
            return []

        # CRITICAL FIX: Explicitly construct catchup_kwargs to thread time context
        # down into _try_generic_plugins and _extract_pssh_from_manifest so that
        # provider.get_segment_headers() receives start_time/end_time.
        catchup_kwargs = {**kwargs, "start_time": start_time, "end_time": end_time}
        if epg_id:
            catchup_kwargs["epg_id"] = epg_id

        pssh_data_list = None
        generic_configs = None

        if DRMSystem.GENERIC in self.drm_plugin_manager.plugins:
            generic_configs, pssh_data_list = self._try_generic_plugins(
                provider_name, channel_id, cache_key,
                manifest_content=manifest_content,
                manifest_url=manifest_url,
                manifest_headers=manifest_headers,
                **catchup_kwargs,
            )
            if generic_configs and any(c.system != DRMSystem.NONE for c in generic_configs):
                if pssh_data_list:
                    validated, has_full_coverage = self._check_clearkey_coverage(generic_configs, pssh_data_list)
                else:
                    validated = generic_configs
                    has_full_coverage = False
                if not validated:
                    pass
                elif has_full_coverage:
                    result = self._select_configs_for_cache_and_return(validated, has_full_coverage)
                    self.drm_config_cache.set(cache_key, result)
                    return result
            else:
                generic_configs = None

        try:
            provider_drm_configs = provider.get_catchup_drm(
                content_id=channel_id, start_time=start_time, end_time=end_time,
                epg_id=epg_id, **kwargs,
            )
        except NotImplementedError:
            provider_drm_configs = []

        if not provider_drm_configs:
            if not generic_configs:
                return []
            provider_drm_configs = []

        if pssh_data_list is None and self.drm_plugin_manager.has_system_specific_plugins():
            if self._needs_pssh_extraction(provider_drm_configs):
                pssh_data_list = self.pssh_cache.get(cache_key)
                if pssh_data_list is None:
                    if manifest_content:
                        from .utils.drm_extractor import DRMExtractor
                        pssh_data_list = DRMExtractor._extract_from_manifest_content(manifest_content)
                        if pssh_data_list:
                            self.pssh_cache.set(cache_key, pssh_data_list)
                    if not pssh_data_list and manifest_url:
                        pssh_data_list = self._extract_pssh_from_manifest(
                            manifest_url, manifest_headers, provider_name,
                            channel_id=channel_id,
                            manifest_content=manifest_content,
                            **catchup_kwargs,
                        )
                        if pssh_data_list:
                            self.pssh_cache.set(cache_key, pssh_data_list)

        provider_configs_snapshot = list(provider_drm_configs)
        sorted_systems = sorted(
            {c.system for c in provider_drm_configs},
            key=lambda s: min(c.priority for c in provider_drm_configs if c.system == s),
        )
        remaining = list(provider_drm_configs)

        for drm_system in sorted_systems:
            system_configs = [c for c in remaining if c.system == drm_system]
            if not system_configs:
                continue
            batch_result = self.drm_plugin_manager.process_system_specific_plugins(
                system_configs, pssh_data_list or [], **catchup_kwargs
            )
            remaining = [c for c in remaining if c.system != drm_system] + batch_result
            if pssh_data_list and any(c.system == DRMSystem.CLEARKEY for c in remaining):
                remaining, has_full_coverage = self._check_clearkey_coverage(remaining, pssh_data_list)
                if has_full_coverage:
                    break

        processed = remaining

        if generic_configs:
            phase2_systems = {c.system for c in processed}
            extra = [c for c in generic_configs if c.system not in phase2_systems]
            if extra:
                processed = processed + extra

        if pssh_data_list and any(c.system == DRMSystem.CLEARKEY for c in processed):
            processed, has_full_coverage = self._check_clearkey_coverage(processed, pssh_data_list)
        else:
            has_full_coverage = False

        if not has_full_coverage:
            processed_systems = {c.system for c in processed}
            reinstated = [c for c in provider_configs_snapshot if c.system not in processed_systems]
            if reinstated:
                processed = processed + reinstated

        if not processed:
            return []

        result = self._select_configs_for_cache_and_return(processed, has_full_coverage)
        self.drm_config_cache.set(cache_key, result)
        return result

    @staticmethod
    def _build_catchup_cache_key(provider_name: str, channel_id: str, start_time: int, end_time: int,
                                 epg_id: Optional[str], **kwargs) -> str:
        VARIANT_KEYS = ("drm_variant", "preferred_quality", "preferred_format")
        parts = [provider_name, channel_id, "catchup", str(start_time), str(end_time)]
        if epg_id:
            parts.append(f"epg={epg_id}")
        for key in VARIANT_KEYS:
            value = kwargs.get(key)
            if value is not None:
                parts.append(f"{key}={str(value).lower()}")
        return ":".join(parts)

    def list_drm_plugins(self) -> Dict:
        return self.drm_plugin_manager.list_plugins()

    def clear_drm_plugins(self):
        self.drm_plugin_manager.clear_plugins()

    def clear_pssh_cache(self):
        self.pssh_cache.clear()

    def clear_drm_config_cache(self):
        self.drm_config_cache.clear()