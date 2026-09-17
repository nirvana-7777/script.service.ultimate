# ============================================================================
# streaming_providers/base/drm_operations.py
"""
DRM resolution pipeline with caching, single-flight deduplication and
parse-once manifest analysis.

Two-phase plugin processing: GENERIC plugins first, then system-specific.

Sentinel semantics (unified for live and catchup content):
- [DRMConfig(system=NONE)]  manifest verified as unencrypted → playable
                            without DRM. This result IS cached.
- []                        no DRM solution could be found. NOT cached, so
                            transient provider/extractor failures self-heal
                            on retry.

Pipeline (one implementation, two thin adapters — see get_content_drm_configs
and get_catchup_content_drm_configs):
1. cache check (double-checked under a per-key lock → single-flight)
2. fetch manifest, parse ONCE → (is_encrypted, pssh_list); analysis failures
   degrade gracefully rather than crashing the request
3. verified-clear short-circuit
4. generic plugin phase (with stub-PSSH upgrade via init segment)
5. provider DRM configs (generics become the base list if provider has none)
6. system-specific plugin loop with incremental ClearKey coverage checks
7. final composition: generic merge, ClearKey validation, reinstatement
8. cache (if non-empty) + return a copy

Cached DRM results are structurally invalidated when the plugin set changes
(`_plugin_epoch` is embedded in DRM-config cache keys). PSSH data is
manifest-derived and plugin-independent, so the PSSH cache deliberately does
NOT use the epoch.

Caching is centralised in `_resolve_content_drm`: `_compute_content_drm` is
pure with respect to the DRM-config cache and never writes to it directly.
"""

import re
import time
from collections import OrderedDict
from contextlib import contextmanager
from threading import Lock
from typing import Any, Callable, Dict, Iterator, List, NamedTuple, Optional, Tuple

from .drm import DRMPluginManager
from .models import DRMConfig, DRMSystem
from .network import HTTPManager
from .utils import ManifestParser
from .utils.drm_extractor import DRMExtractor
from .utils.logger import logger

_CONTENT_PROTECTION_RE = re.compile(
    r'<ContentProtection[^>]*schemeIdUri="urn:uuid:([^"]+)"[^>]*>', re.IGNORECASE
)
_DEFAULT_KID_RE = re.compile(r'(?:cenc:)?default_KID\s*=', re.IGNORECASE)
_PSSH_TAG_RE = re.compile(r'<(?:cenc:)?pssh[^>]*>', re.IGNORECASE)

# kwargs that produce distinct DRM results and therefore belong in cache keys
_VARIANT_KEYS = ("drm_variant", "preferred_quality", "preferred_format")


class TTLCache:
    """Thread-safe TTL cache with LRU eviction and a hard size bound.

    Replaces the previous PSSHCache/DRMConfigCache pair, which were identical
    except for log wording and unbounded: expired entries were only evicted
    when their specific key happened to be read again, so long-running
    processes accumulated stale entries indefinitely.
    """

    def __init__(self, ttl_seconds: int = 3600, max_size: int = 2048):
        self._data: "OrderedDict[str, Tuple[Any, float]]" = OrderedDict()
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._lock = Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            value, timestamp = entry
            if time.time() - timestamp >= self._ttl:
                del self._data[key]
                logger.debug(f"TTLCache: EXPIRED '{key}'")
                return None
            self._data.move_to_end(key)  # LRU touch
            logger.debug(f"TTLCache: HIT '{key}'")
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = (value, time.time())
            self._data.move_to_end(key)
            while len(self._data) > self._max_size:
                evicted, _ = self._data.popitem(last=False)
                logger.debug(f"TTLCache: EVICTED (size bound) '{evicted}'")
        logger.debug(f"TTLCache: SET '{key}'")

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
        logger.debug("TTLCache: CLEARED")

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


class _KeyedLocks:
    """Per-key locks giving single-flight semantics for cache misses.

    Cleanup is best-effort: a waiter that already grabbed a Lock reference
    keeps it, so at most one extra worker may be admitted right after the
    holder finishes. The computation is idempotent, so this is harmless.
    """

    def __init__(self):
        self._guard = Lock()
        self._locks: Dict[str, Lock] = {}

    @contextmanager
    def for_key(self, key: str) -> Iterator[None]:
        with self._guard:
            lock = self._locks.setdefault(key, Lock())
        with lock:
            yield
        with self._guard:
            if self._locks.get(key) is lock and not lock.locked():
                self._locks.pop(key, None)


class _ManifestContext(NamedTuple):
    """Everything the PSSH/DRM phases need to know about one manifest."""

    provider_name: str
    channel_id: str
    manifest_url: Optional[str]
    manifest_headers: Optional[Dict[str, str]]
    manifest_content: Optional[str]
    parsed_pssh: Optional[List]      # single manifest parse result; None = not analysed
    analysis_failed: bool = False    # parse raised; don't retry deterministically-failing work


class DRMOperations:
    """Resolves DRM configurations for live/VOD/event and catchup content.

    Both public entry points delegate to one shared pipeline; only manifest
    resolution and the provider-DRM fetch differ between them.
    """

    def __init__(self, registry, cache_ttl: int = 3600, cache_max_size: int = 2048):
        self.registry = registry
        self.drm_plugin_manager = DRMPluginManager()
        self.pssh_cache = TTLCache(ttl_seconds=cache_ttl, max_size=cache_max_size)
        self.drm_config_cache = TTLCache(ttl_seconds=cache_ttl, max_size=cache_max_size)
        self._keyed_locks = _KeyedLocks()
        # Bumped whenever the plugin set changes; embedded in DRM-config
        # cache keys so results computed under an old plugin set can never
        # be read again (stale entries age out via LRU eviction).
        self._plugin_epoch = 0
        logger.debug("DRMOperations: Initialized with unified two-phase pipeline")

    # ==========================================================================
    # PUBLIC API — thin adapters
    # ==========================================================================

    def get_content_drm_configs(
        self, provider_name: str, channel_id: str, **kwargs
    ) -> List[DRMConfig]:
        """Resolve DRM configs for live/VOD/event/recording content.

        kwargs are forwarded to the provider and DRM plugins; recognised
        cache-key variants are drm_variant, preferred_quality, preferred_format.
        """
        provider = self._get_provider(provider_name)
        kwargs = self._inject_provider_proxy(provider, kwargs)
        base_key = self._build_cache_key(provider_name, channel_id, **kwargs)

        def resolve_manifest() -> Tuple[Optional[str], Optional[Dict[str, str]]]:
            return provider.get_manifest_with_headers(channel_id, **kwargs)

        def get_provider_configs() -> List[DRMConfig]:
            return provider.get_drm(content_id=channel_id, **kwargs)

        return self._resolve_content_drm(
            provider, provider_name, channel_id, base_key,
            resolve_manifest, get_provider_configs, kwargs,
        )

    def get_catchup_content_drm_configs(
        self,
        provider_name: str,
        channel_id: str,
        catchup_manifest_url: str,
        catchup_manifest_headers: Dict[str, str],
        start_time: int,
        end_time: int,
        epg_id: Optional[str] = None,
        **kwargs,
    ) -> List[DRMConfig]:
        """Resolve DRM configs for a catchup/timeshift window."""
        provider = self._get_provider(provider_name)
        kwargs = self._inject_provider_proxy(provider, kwargs)
        base_key = self._build_catchup_cache_key(
            provider_name, channel_id, start_time, end_time, epg_id, **kwargs
        )

        # Thread the time context through the whole pipeline so
        # provider.get_segment_headers() receives start_time/end_time (needed
        # by providers whose catchup init segments require catchup-scoped
        # headers).
        pipeline_kwargs = {**kwargs, "start_time": start_time, "end_time": end_time}
        if epg_id:
            pipeline_kwargs["epg_id"] = epg_id

        def resolve_manifest() -> Tuple[Optional[str], Optional[Dict[str, str]]]:
            return catchup_manifest_url, catchup_manifest_headers

        def get_provider_configs() -> List[DRMConfig]:
            try:
                return provider.get_catchup_drm(
                    content_id=channel_id, start_time=start_time,
                    end_time=end_time, epg_id=epg_id, **kwargs,
                )
            except NotImplementedError:
                return []

        return self._resolve_content_drm(
            provider, provider_name, channel_id, base_key,
            resolve_manifest, get_provider_configs, pipeline_kwargs,
        )

    # ==========================================================================
    # THE PIPELINE
    # ==========================================================================

    def _resolve_content_drm(
        self,
        provider,
        provider_name: str,
        channel_id: str,
        base_cache_key: str,
        resolve_manifest: Callable[[], Tuple[Optional[str], Optional[Dict[str, str]]]],
        get_provider_configs: Callable[[], List[DRMConfig]],
        pipeline_kwargs: Dict[str, Any],
    ) -> List[DRMConfig]:
        cache_key = self._config_cache_key(base_cache_key)

        cached = self.drm_config_cache.get(cache_key)
        if cached is not None:
            return list(cached)

        # Single-flight: concurrent misses for the same key run the full
        # pipeline exactly once; the others wait and hit the cache.
        with self._keyed_locks.for_key(cache_key):
            cached = self.drm_config_cache.get(cache_key)  # double-check under lock
            if cached is not None:
                return list(cached)

            result = self._compute_content_drm(
                provider, provider_name, channel_id, base_cache_key,
                resolve_manifest, get_provider_configs, pipeline_kwargs,
            )

            # Caching policy — the ONLY place results are cached:
            # truthy results are answers (real configs, or verified-clear
            # [NONE]) and get cached; [] means "no solution found" and
            # deliberately does not, so transient provider/extractor
            # failures self-heal on retry.
            if result:
                self.drm_config_cache.set(cache_key, result)
            # Copy on every return: callers can sort/append/filter their list
            # without poisoning the cache. (Shallow — see DRMConfig note.)
            return list(result)

    def _compute_content_drm(
        self,
        provider,
        provider_name: str,
        channel_id: str,
        base_cache_key: str,
        resolve_manifest: Callable[[], Tuple[Optional[str], Optional[Dict[str, str]]]],
        get_provider_configs: Callable[[], List[DRMConfig]],
        pipeline_kwargs: Dict[str, Any],
    ) -> List[DRMConfig]:
        """Run the full resolution pipeline and return the result.

        Pure w.r.t. the DRM-config cache: caching and copy-on-return are owned
        by _resolve_content_drm. The PSSH cache is still populated here because
        PSSH resolution is an internal, multi-phase concern.
        """
        # -- 1. Manifest: fetch once, parse once --------------------------------
        manifest_url, manifest_headers = resolve_manifest()
        manifest_content: Optional[str] = None
        parsed_pssh: Optional[List] = None
        analysis_failed = False

        if manifest_url and manifest_url.startswith(("http://", "https://")):
            http = getattr(provider, "http_manager", None) or HTTPManager()
            manifest_content = self._fetch_manifest_text(http, manifest_url, manifest_headers)
            if manifest_content is not None:
                # Degrade, don't crash: extractor blowups on malformed content
                # must leave the pipeline free to resolve DRM from provider
                # configs and plugins (matches the previous behaviour, where
                # this ran inside the fetch's try/except and was swallowed).
                try:
                    is_encrypted, parsed_pssh = self._analyse_manifest(manifest_content)
                except Exception as e:
                    logger.warning(
                        f"DRMOperations: Manifest analysis failed for '{manifest_url}': {e}"
                    )
                    analysis_failed = True
                else:
                    # `is False` (not `not is_encrypted`): an UNKNOWN state
                    # must never short-circuit as "verified clear".
                    if is_encrypted is False:
                        return [DRMConfig(system=DRMSystem.NONE, priority=0)]

        # Non-http, unfetchable or unanalysable manifest: fall through —
        # provider configs and plugins may still resolve DRM. If nothing
        # produces a config, the pipeline returns [] (never claims 'clear'
        # unverified).

        ctx = _ManifestContext(
            provider_name=provider_name,
            channel_id=channel_id,
            manifest_url=manifest_url,
            manifest_headers=manifest_headers,
            manifest_content=manifest_content,
            parsed_pssh=parsed_pssh,
            analysis_failed=analysis_failed,
        )

        # -- 2. Generic plugin phase ---------------------------------------------
        generic_configs, pssh_list = self._run_generic_phase(ctx, base_cache_key, pipeline_kwargs)

        if generic_configs and any(c.system != DRMSystem.NONE for c in generic_configs):
            if pssh_list:
                validated, has_full_coverage = self._check_clearkey_coverage(generic_configs, pssh_list)
            else:
                validated, has_full_coverage = generic_configs, False
            if validated and has_full_coverage:
                # Generic plugins alone already cover every key ID.
                return self._select_configs_for_return(validated, True)
            # Partial or no coverage: keep generic_configs for the final merge.
        else:
            generic_configs = None

        # -- 3. Provider DRM configs ----------------------------------------------
        provider_configs = get_provider_configs()
        if not provider_configs:
            if generic_configs:
                # Provider has nothing, but generic plugins produced configs:
                # they become the base list for the system-specific phase.
                provider_configs = list(generic_configs)
                generic_configs = None
            else:
                return []  # no solution found — uncached by policy, self-heals

        # -- 4. PSSH resolution for the system-specific phase --------------------
        if pssh_list is None and self.drm_plugin_manager.has_system_specific_plugins():
            if self._needs_pssh_extraction(provider_configs):
                pssh_list = self._resolve_pssh_data(ctx, base_cache_key, pipeline_kwargs)

        # -- 5. System-specific plugin loop ---------------------------------------
        provider_snapshot = list(provider_configs)
        sorted_systems = sorted(
            {c.system for c in provider_configs},
            key=lambda s: min(c.priority for c in provider_configs if c.system == s),
        )
        remaining = list(provider_configs)

        for drm_system in sorted_systems:
            system_configs = [c for c in remaining if c.system == drm_system]
            if not system_configs:
                continue
            batch_result = self.drm_plugin_manager.process_system_specific_plugins(
                system_configs, pssh_list or [], **pipeline_kwargs
            )
            remaining = [c for c in remaining if c.system != drm_system] + batch_result
            if pssh_list and any(c.system == DRMSystem.CLEARKEY for c in remaining):
                remaining, has_full_coverage = self._check_clearkey_coverage(remaining, pssh_list)
                if has_full_coverage:
                    break

        # -- 6. Final composition ---------------------------------------------------
        processed, has_full_coverage = self._compose_final_result(
            remaining, generic_configs, provider_snapshot, pssh_list
        )
        if not processed:
            return []

        return self._select_configs_for_return(processed, has_full_coverage)

    # ==========================================================================
    # PIPELINE PHASES
    # ==========================================================================

    def _run_generic_phase(
        self, ctx: _ManifestContext, base_cache_key: str,
        pipeline_kwargs: Dict[str, Any],
    ) -> Tuple[Optional[List[DRMConfig]], Optional[List]]:
        """Run GENERIC plugins over PSSH data extracted from the manifest.

        Returns (generic_configs, pssh_list). generic_configs is None when no
        generic plugin is registered, no usable PSSH/key-ID data exists, or
        the plugins produce nothing. pssh_list may be non-None even then —
        the system-specific phase reuses it.
        """
        if DRMSystem.GENERIC not in self.drm_plugin_manager.plugins:
            return None, None

        pssh_list = self._resolve_pssh_data(ctx, base_cache_key, pipeline_kwargs)
        if not pssh_list:
            return None, None

        # Stub PSSH (no box / no key IDs): try to upgrade via the init segment.
        if self._has_stub_pssh(pssh_list):
            if not ctx.manifest_url:
                return None, pssh_list
            upgraded = self._extract_pssh_from_manifest(
                ctx.manifest_url, ctx.manifest_headers, ctx.provider_name,
                channel_id=ctx.channel_id,
                manifest_content=ctx.manifest_content,
                pssh_list=pssh_list,
                **pipeline_kwargs,
            )
            if upgraded and not self._has_stub_pssh(upgraded):
                pssh_list = upgraded
                self.pssh_cache.set(base_cache_key, pssh_list)
            else:
                return None, pssh_list

        total_kids = sum(len(p.key_ids) for p in pssh_list)
        if total_kids == 0:
            return None, pssh_list

        dummy_configs = [DRMConfig(system=DRMSystem.NONE, priority=0)]
        generic_configs = self.drm_plugin_manager.process_generic_plugins(
            dummy_configs, pssh_list, **pipeline_kwargs
        )
        return (generic_configs or None), pssh_list

    def _resolve_pssh_data(
        self, ctx: _ManifestContext, base_cache_key: str,
        pipeline_kwargs: Dict[str, Any],
    ) -> Optional[List]:
        """Resolve PSSH data, in priority order:

        1. PSSH TTL cache (may hold a previous init-segment-upgraded result —
           still valid even if THIS call's parse failed)
        2. The list parsed during manifest analysis (populates the cache)
        3. Full extraction: manifest (re-)fetch + init-segment fallback

        Note: the cache key includes catchup start/end times, so each timeshift
        window gets its own entry even though PSSH is likely identical per
        channel. The cache size bound caps this; keying by provider:channel is
        a possible future optimisation if KIDs prove stable across windows.
        """
        pssh_list = self.pssh_cache.get(base_cache_key)
        if pssh_list is not None:
            return pssh_list

        if ctx.analysis_failed:
            # Parsing this manifest already raised once and is deterministic —
            # retrying would just re-raise (caught) and re-log in every phase.
            return None

        if ctx.parsed_pssh:
            self.pssh_cache.set(base_cache_key, ctx.parsed_pssh)
            return ctx.parsed_pssh

        if ctx.manifest_url:
            pssh_list = self._extract_pssh_from_manifest(
                ctx.manifest_url, ctx.manifest_headers, ctx.provider_name,
                channel_id=ctx.channel_id,
                manifest_content=ctx.manifest_content,
                # None → full parse inside; [] → skip the re-parse and go
                # straight to init-segment extraction.
                pssh_list=ctx.parsed_pssh,
                **pipeline_kwargs,
            )
            if pssh_list:
                self.pssh_cache.set(base_cache_key, pssh_list)
            return pssh_list or None

        return None

    @staticmethod
    def _compose_final_result(
        processed: List[DRMConfig],
        generic_configs: Optional[List[DRMConfig]],
        provider_snapshot: List[DRMConfig],
        pssh_list: Optional[List],
    ) -> Tuple[List[DRMConfig], bool]:
        """Merge generic extras, validate ClearKey coverage, reinstate drops.

        Safety net: if ClearKey validation wipes the list (ClearKey present but
        invalid), the provider's original configs for every missing system are
        reinstated — the pipeline never returns fewer *systems* than the
        provider offered.
        """
        if generic_configs:
            phase2_systems = {c.system for c in processed}
            extra = [c for c in generic_configs if c.system not in phase2_systems]
            if extra:
                processed = processed + extra

        if pssh_list and any(c.system == DRMSystem.CLEARKEY for c in processed):
            processed, has_full_coverage = DRMOperations._check_clearkey_coverage(
                processed, pssh_list
            )
        else:
            has_full_coverage = False

        if not has_full_coverage:
            processed_systems = {c.system for c in processed}
            reinstated = [c for c in provider_snapshot if c.system not in processed_systems]
            if reinstated:
                processed = processed + reinstated

        return processed, has_full_coverage

    # ==========================================================================
    # MANIFEST ANALYSIS (parse once)
    # ==========================================================================

    @staticmethod
    def _analyse_manifest(manifest_content: str) -> Tuple[bool, List]:
        """Parse manifest content once → (is_encrypted, pssh_list).

        is_encrypted is False ONLY when the manifest is verifiably clear.
        """
        pssh_list = DRMExtractor._extract_from_manifest_content(manifest_content) or []

        if any(p.drm_system and p.drm_system != DRMSystem.NONE for p in pssh_list):
            return True, pssh_list

        for match in _CONTENT_PROTECTION_RE.finditer(manifest_content):
            drm_system = DRMSystem.from_uuid(match.group(1).lower())
            if drm_system:
                return True, pssh_list
        if _DEFAULT_KID_RE.search(manifest_content):
            return True, pssh_list
        if _PSSH_TAG_RE.search(manifest_content):
            return True, pssh_list
        return False, pssh_list

    @staticmethod
    def _is_manifest_encrypted(manifest_content: str) -> bool:
        """Back-compat wrapper around _analyse_manifest."""
        return DRMOperations._analyse_manifest(manifest_content)[0]

    @staticmethod
    def _fetch_manifest_text(
        http, manifest_url: str, manifest_headers: Optional[Dict[str, str]]
    ) -> Optional[str]:
        """Fetch manifest text; returns None (with a debug log) on failure."""
        try:
            response = http.get(manifest_url, headers=manifest_headers, timeout=10, operation="api")
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.debug(f"DRMOperations: Manifest fetch failed for '{manifest_url}': {e}")
            return None

    # ==========================================================================
    # PSSH EXTRACTION
    # ==========================================================================

    def _extract_pssh_from_manifest(
        self,
        manifest_url: str,
        manifest_headers: Optional[Dict[str, str]] = None,
        provider_name: Optional[str] = None,
        channel_id: Optional[str] = None,
        manifest_content: Optional[str] = None,
        pssh_list: Optional[List] = None,
        **kwargs,
    ) -> List:
        """Extract PSSH data from a manifest, falling back to the init segment.

        manifest_headers now defaults to None so the legacy facade call
        (which passes only the URL) works. pssh_list lets callers that already
        parsed the manifest skip the redundant re-parse and go straight to
        init-segment extraction (passing [] implies the manifest was already
        parsed and yielded nothing).

        **kwargs (which contain start_time/end_time for catchup) are passed to
        provider.get_segment_headers() so providers can return catchup-scoped
        headers for init segment fetches.
        """
        if not manifest_url or not manifest_url.startswith(("http://", "https://")):
            return []

        try:
            http = None
            segment_headers = manifest_headers  # default to manifest headers

            if provider_name:
                provider = self.registry.get_provider(provider_name)
                if provider:
                    http = getattr(provider, "http_manager", None)
                    if channel_id:
                        try:
                            # Full context (start_time, end_time, ...) for
                            # catchup-scoped segment headers.
                            segment_headers = provider.get_segment_headers(channel_id, **kwargs)
                        except Exception:
                            pass  # fall back to manifest headers on error

            if not http:
                http = HTTPManager()

            if pssh_list is None:
                if not manifest_content:
                    manifest_content = self._fetch_manifest_text(http, manifest_url, manifest_headers)
                if manifest_content:
                    pssh_list = DRMExtractor._extract_from_manifest_content(manifest_content) or []
                else:
                    return []  # manifest unobtainable

            needs_segment_extraction = not pssh_list or any(
                not p.pssh_box or not p.key_ids for p in pssh_list
            )

            if needs_segment_extraction:
                if not manifest_content:
                    # Content is needed to locate the init segment URL.
                    manifest_content = self._fetch_manifest_text(http, manifest_url, manifest_headers)
                if manifest_content:
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
            logger.warning(f"DRMOperations: Failed to extract PSSH: {e}")
            return []

    # ==========================================================================
    # VALIDATION / SELECTION HELPERS (unchanged semantics)
    # ==========================================================================

    @staticmethod
    def _check_clearkey_coverage(
        drm_configs: List[DRMConfig], pssh_data_list: List
    ) -> Tuple[List[DRMConfig], bool]:
        """Validate ClearKey configs against the key IDs required by the PSSH data.

        Returns (validated_configs, has_full_coverage). If ClearKey configs are
        present but none of their key IDs match, ALL configs are dropped
        ([], False) — the reinstatement step in _compose_final_result then
        restores the provider's original systems. Coverage is per-config: two
        ClearKey configs that together cover all key IDs do NOT count as full
        coverage.
        """
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
    def _select_configs_for_return(
        configs: List[DRMConfig], has_full_clearkey_coverage: bool
    ) -> List[DRMConfig]:
        """When ClearKey fully covers the content, return only ClearKey configs.

        (Renamed from _select_configs_for_cache_and_return — with caching
        centralised in _resolve_content_drm, this no longer caches anything
        and the old name would lie.)"""
        if has_full_clearkey_coverage:
            return [c for c in configs if c.system == DRMSystem.CLEARKEY]
        return configs

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
            system for system in self.drm_plugin_manager.plugins.keys()
            if system != DRMSystem.GENERIC
        }
        return bool(config_systems & plugin_systems)

    # ==========================================================================
    # CACHE KEYS & SMALL HELPERS
    # ==========================================================================

    def _config_cache_key(self, base_cache_key: str) -> str:
        """DRM-config cache keys embed the plugin epoch so that clearing or
        reloading plugins structurally invalidates all derived results."""
        return f"e{self._plugin_epoch}:{base_cache_key}"

    @staticmethod
    def _build_cache_key(provider_name: str, channel_id: str, **kwargs) -> str:
        parts = [provider_name, channel_id]
        for key in _VARIANT_KEYS:
            value = kwargs.get(key)
            if value is not None:
                parts.append(f"{key}={str(value).lower()}")
        return ":".join(parts)

    @staticmethod
    def _build_catchup_cache_key(
        provider_name: str, channel_id: str, start_time: int, end_time: int,
        epg_id: Optional[str], **kwargs
    ) -> str:
        parts = [provider_name, channel_id, "catchup", str(start_time), str(end_time)]
        if epg_id:
            parts.append(f"epg={epg_id}")
        for key in _VARIANT_KEYS:
            value = kwargs.get(key)
            if value is not None:
                parts.append(f"{key}={str(value).lower()}")
        return ":".join(parts)

    def _get_provider(self, provider_name: str):
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")
        return provider

    @staticmethod
    def _inject_provider_proxy(provider, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Return kwargs with the provider's proxy injected unless the caller
        supplied one explicitly. Returns a NEW dict — never mutates the
        caller's mapping."""
        if "proxy_config" in kwargs:
            return kwargs
        http_mgr = getattr(provider, "http_manager", None)
        if http_mgr is None:
            return kwargs
        provider_proxy = getattr(getattr(http_mgr, "config", None), "proxy_config", None)
        if provider_proxy is None:
            return kwargs
        return {**kwargs, "proxy_config": provider_proxy}

    # ==========================================================================
    # PLUGIN & CACHE MANAGEMENT
    # ==========================================================================

    def list_drm_plugins(self) -> Dict:
        return self.drm_plugin_manager.list_plugins()

    def clear_drm_plugins(self):
        """Clear all registered plugins and invalidate all cached DRM results.

        The epoch bump means results computed under the old plugin set can
        never be read again; stale entries age out via LRU eviction.
        """
        self.drm_plugin_manager.clear_plugins()
        self._plugin_epoch += 1
        logger.debug(f"DRMOperations: Plugins cleared (epoch -> {self._plugin_epoch})")

    def clear_pssh_cache(self):
        self.pssh_cache.clear()

    def clear_drm_config_cache(self):
        self.drm_config_cache.clear()