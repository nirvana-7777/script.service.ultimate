# ============================================================================
# streaming_providers/base/channel_operations.py
"""
Channel-related operations separated from core registry.
"""

import threading
import time
from typing import Any, Dict, Iterable, List, Optional

from .channel_cache import ChannelCache
from .models import StreamingChannel
from .utils.logger import logger


class ChannelOperations:
    """Handles all channel-related operations."""

    def __init__(self, registry, cache: Optional[ChannelCache] = None):
        self.registry = registry
        self.cache = cache or ChannelCache()
        self._refresher: Optional[threading.Thread] = None
        self._refresher_stop = threading.Event()
        logger.debug("ChannelOperations: Initialized")

    def get_channels(
        self, provider_name: str, fetch_manifests: bool = False, **kwargs
    ) -> List[StreamingChannel]:
        """
        Get channels from a specific provider (cached, see ChannelCache).

        `fetch_manifests` is accepted for compatibility but has no effect (the
        enrichment it controlled is disabled); it is deliberately NOT part of
        the cache key -- callers disagree on its default and would otherwise
        split one list into two cache entries.
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        # None-valued kwargs (e.g. country=None from the route) do not change the
        # result, so they must not split the cache key from the warm-up call.
        params = tuple(sorted((k, v) for k, v in kwargs.items() if v is not None))
        try:
            hash(params)
        except TypeError:
            return self._load(provider_name, provider, kwargs)  # uncacheable

        # A provider whose Channel objects embed expiring URLs/tokens can
        # shorten its cache with a class attribute CHANNEL_CACHE_TTL (seconds).
        ttl = getattr(provider, "CHANNEL_CACHE_TTL", None)
        channels = self.cache.get(
            provider_name,
            lambda: self._load(provider_name, provider, kwargs),
            params=params,
            ttl=ttl,
            owner=provider,
        )

#        if fetch_manifests and not provider.uses_dynamic_manifests:
#            enriched = []
#            for channel in channels:
#                enriched_channel = provider.enrich_channel_data(channel, **kwargs)
#                if enriched_channel:
#                    enriched.append(enriched_channel)
#            logger.info(f"Enriched {len(enriched)}/{len(channels)} channels")
#            return enriched

        return channels

    @staticmethod
    def _load(provider_name: str, provider, kwargs: Dict[str, Any]) -> List[StreamingChannel]:
        channels = provider.get_channels(**kwargs)
        logger.info(f"Retrieved {len(channels)} channels from '{provider_name}'")
        return channels

    # ------------------------------------------------------------------
    # Warm-up / cache state
    # ------------------------------------------------------------------
    def warm_up(self, provider_names: Optional[Iterable[str]] = None, max_parallel: int = 4) -> None:
        """
        Load channel lists into the cache in the background (returns at once).

        Goes through get_channels(), so auth + fetch happen exactly as for a
        client request and concurrent requests join the running load.
        """
        if provider_names is not None:
            names = list(provider_names)  # explicit request (new credentials, enabled): always
        else:
            # Startup: skip providers that opt out (WARMUP_ON_START = False), e.g. those
            # with an expensive or rate-limited login. They load on the first client request.
            names = [n for n in self.registry.list_providers() if self._warm_on_start(n)]
        if not names:
            return

        def run_all():
            gate = threading.Semaphore(max(1, max_parallel))

            def one(name: str):
                try:
                    self.get_channels(name)
                except Exception as exc:
                    logger.warning(f"ChannelOperations: warm-up of '{name}' failed: {exc}")
                finally:
                    gate.release()

            for name in names:
                gate.acquire()
                threading.Thread(
                    target=one, args=(name,), name=f"channel-warmup-{name}", daemon=True
                ).start()

        threading.Thread(target=run_all, name="channel-warmup", daemon=True).start()
        logger.info(f"ChannelOperations: warm-up started for {len(names)} providers")

    # ------------------------------------------------------------------
    # Automatic refresh: keeps the cache warm for every client, forever
    # ------------------------------------------------------------------
    def start_auto_refresh(
        self,
        check_interval: float = 900.0,
        refresh_fraction: float = 0.8,
        max_parallel: int = 4,
    ) -> None:
        """
        Background thread that, every `check_interval` seconds:
          * reloads lists that reached `refresh_fraction` of their TTL, so a
            client never meets a stale or cold list while the backend runs
          * loads providers that have NO list yet (idle), unless they opt out
            with WARMUP_ON_START = False
        Every attempt honours the cache's circuit breaker, so a failing login
        is not repeated every tick. A failed reload keeps the old list.
        Idempotent.
        """
        if self._refresher is not None and self._refresher.is_alive():
            return
        self._refresher_stop.clear()

        def loop():
            while not self._refresher_stop.wait(check_interval):
                try:
                    self.refresh_tick(refresh_fraction, max_parallel)
                except Exception as exc:
                    logger.warning(f"ChannelOperations: refresh tick failed: {exc}")

        self._refresher = threading.Thread(target=loop, name="channel-refresher", daemon=True)
        self._refresher.start()
        logger.info(f"ChannelOperations: auto refresh every {int(check_interval)}s")

    def stop_auto_refresh(self) -> None:
        self._refresher_stop.set()

    def refresh_tick(
        self,
        refresh_fraction: float,
        max_parallel: int = 4,
        join_timeout: float = 300.0,
    ) -> None:
        """
        One refresher pass (public so it can be tested without waiting).
        A hung provider cannot block the refresher beyond `join_timeout`; its
        load keeps running and is skipped by later ticks (single-flight).
        """
        targets: Dict[Any, Dict[str, Any]] = {}
        for name, params in self.cache.due(refresh_fraction):
            targets[(name, params)] = dict(params)
        for name in self.registry.list_providers():
            state = self.cache.status(name)["state"]
            if state not in ("idle", "error") or not self.cache.can_retry(name):
                continue
            if state == "idle" and not self._warm_on_start(name):
                continue
            targets[(name, ())] = {}
        if not targets:
            return

        gate = threading.Semaphore(max(1, max_parallel))
        threads = []

        def one(name: str, params, kwargs: Dict[str, Any]):
            try:
                provider = self.registry.get_provider(name)
                if provider is None:
                    return
                self.cache.refresh(
                    name,
                    lambda: self._load(name, provider, kwargs),
                    params=params,
                    ttl=getattr(provider, "CHANNEL_CACHE_TTL", None),
                    owner=provider,
                )
            except Exception as exc:
                logger.warning(f"ChannelOperations: refresh of '{name}' failed: {exc}")
            finally:
                gate.release()

        for (name, params), kwargs in targets.items():
            gate.acquire()
            t = threading.Thread(target=one, args=(name, params, kwargs), name=f"channel-refresh-{name}", daemon=True)
            t.start()
            threads.append(t)
        deadline = time.monotonic() + join_timeout
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))

    def _warm_on_start(self, name: str) -> bool:
        return getattr(self.registry.get_provider(name), "WARMUP_ON_START", True) is not False

    def get_channel_state(self, provider_name: str) -> Dict[str, Any]:
        """idle | warming | ready | error (+ count/age/stale for ready)."""
        return self.cache.status(provider_name)

    def invalidate_channels(self, provider_name: Optional[str] = None) -> None:
        self.cache.invalidate(provider_name)

    def get_channel_manifest(self, provider_name: str, channel_id: str, **kwargs) -> Optional[str]:
        """Get manifest URL for a specific channel."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        manifest_url = provider.get_manifest(content_id=channel_id, **kwargs)
        if manifest_url:
            logger.debug(f"Retrieved manifest for '{channel_id}' from '{provider_name}'")
        return manifest_url

    def get_all_channels(
        self, fetch_manifests: bool = True, **kwargs
    ) -> Dict[str, List[StreamingChannel]]:
        """Get channels from all enabled providers."""
        enabled = self.registry.get_enabled_providers()
        logger.info(f"Fetching channels from {len(enabled)} providers")

        result = {}
        total = 0

        for name in enabled:
            try:
                channels = self.get_channels(name, fetch_manifests, **kwargs)
                result[name] = channels
                total += len(channels)
            except Exception as e:
                logger.error(f"Failed to get channels from '{name}': {e}")
                result[name] = []

        logger.info(f"Retrieved {total} total channels")
        return result