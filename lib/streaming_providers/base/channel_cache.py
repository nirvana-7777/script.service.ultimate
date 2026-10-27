# streaming_providers/base/channel_cache.py
"""
In-memory channel-list cache for the provider layer.

What it gives the PVR client:
  * a warm cache: GET /api/providers/<p>/channels is answered from memory
  * single-flight: concurrent callers (warm-up, PVR, M3U generation) share ONE
    upstream load per (provider, params); nobody logs in twice in parallel
  * stale-while-revalidate: past the TTL the old list is served at once and
    refreshed in a background thread; only a cold miss blocks
  * a status per provider (idle / warming / ready / error) for /api/providers

Memory only, by design: channel objects are not serialised anywhere yet.
invalidate() must be called whenever the provider instance or its account
changes (credentials, reinitialize, enable/disable, rediscover). A load that
was already running when invalidate() was called is delivered to its waiters
but never stored (generation counter).
"""

import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Hashable, List, Optional, Tuple

from .utils.logger import logger

DEFAULT_TTL = 24 * 3600.0       # channel lists are stable: fresh for 24 h
DEFAULT_MAX_STALE = 7 * 24 * 3600.0  # serve stale (and refresh) up to 7 days; older = cold miss
EMPTY_RESULT_TTL = 30.0         # an empty list is probably a transient failure: retry soon
REFRESH_BACKOFF = 60.0          # after a failed background refresh, wait before the next one
ERROR_TTL = 60.0                # a failed COLD load is remembered: no upstream login per client retry

Key = Tuple[str, Hashable]

_URL_RE = re.compile(r"https?://\S+")


def _safe_error(exc: BaseException) -> str:
    """Error text for the API: no URLs (they may carry tokens), max 200 chars."""
    return _URL_RE.sub("<url>", f"{type(exc).__name__}: {exc}")[:200]


@dataclass
class _Entry:
    channels: List[Any]
    fetched_at: float
    ttl: float
    retry_after: float = 0.0
    owner: Any = None  # the provider instance this list came from


class _Flight:
    __slots__ = ("done", "result", "error", "gen", "owner")

    def __init__(self, gen: int, owner: Any = None):
        self.owner = owner
        self.done = threading.Event()
        self.result: Optional[List[Any]] = None
        self.error: Optional[BaseException] = None
        self.gen = gen


class ChannelCache:
    def __init__(
        self,
        ttl: float = DEFAULT_TTL,
        max_stale: float = DEFAULT_MAX_STALE,
        empty_ttl: float = EMPTY_RESULT_TTL,
        refresh_backoff: float = REFRESH_BACKOFF,
        error_ttl: float = ERROR_TTL,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._ttl = ttl
        self._max_stale = max_stale
        self._empty_ttl = empty_ttl
        self._backoff = refresh_backoff
        self._error_ttl = error_ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: Dict[Key, _Entry] = {}
        self._flights: Dict[Key, _Flight] = {}
        self._generation: Dict[str, int] = {}
        self._last_error: Dict[str, str] = {}
        self._failures: Dict[Key, Tuple[BaseException, float, Any]] = {}

    # ------------------------------------------------------------------
    def get(
        self,
        provider: str,
        loader: Callable[[], List[Any]],
        *,
        params: Hashable = (),
        ttl: Optional[float] = None,
        owner: Any = None,
    ) -> List[Any]:
        """
        Return the channel list, loading it through `loader` when needed.

        `owner` is the provider instance. A list (or failure, or running load)
        that belongs to a DIFFERENT instance is never served: replacing an
        instance invalidates its cache by identity, whatever code path did it.
        """
        key: Key = (provider, params)
        ttl = self._ttl if ttl is None else ttl
        now = self._clock()

        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and owner is not None and entry.owner is not owner:
                del self._entries[key]
                entry = None
            if entry is not None:
                age = now - entry.fetched_at
                if age < entry.ttl:
                    return list(entry.channels)
                if age < self._max_stale:
                    stale = list(entry.channels)
                    if now >= entry.retry_after:
                        flight, created = self._flight_locked(key, owner)
                        if created:
                            self._spawn_refresh(key, provider, loader, flight, ttl)
                    return stale
            if key not in self._flights:
                failure = self._failures.get(key)
                if failure is not None:
                    if owner is not None and failure[2] is not owner:
                        del self._failures[key]
                    elif now - failure[1] < self._error_ttl:
                        # Same answer as the failed load, without asking the upstream again.
                        raise failure[0].with_traceback(None)
                    else:
                        del self._failures[key]
            flight, created = self._flight_locked(key, owner)

        if created:
            self._run(key, provider, loader, flight, ttl)
        else:
            flight.done.wait()
        if flight.error is not None:
            raise flight.error
        return list(flight.result or [])

    def refresh(
        self,
        provider: str,
        loader: Callable[[], List[Any]],
        *,
        params: Hashable = (),
        ttl: Optional[float] = None,
        owner: Any = None,
    ) -> bool:
        """
        Reload now, in the calling thread, even if the entry is still fresh.

        Single-flight like get(): returns False (and does nothing) when a load
        for this key is already running. On failure the old list is kept and
        the exception propagates (used by the background refresher).
        """
        key: Key = (provider, params)
        with self._lock:
            flight, created = self._flight_locked(key, owner)
        if not created:
            return False
        self._run(key, provider, loader, flight, self._ttl if ttl is None else ttl)
        return True

    def due(self, fraction: float) -> List[Key]:
        """Keys whose age reached `fraction` of their TTL and are not in backoff."""
        now = self._clock()
        with self._lock:
            return [
                key
                for key, e in self._entries.items()
                if now - e.fetched_at >= e.ttl * fraction and now >= e.retry_after
            ]

    def invalidate(self, provider: Optional[str] = None) -> None:
        """Drop cached lists (one provider, or all) and discard loads in flight."""
        with self._lock:
            if provider is None:
                names = (
                    set(self._generation)
                    | {k[0] for k in self._entries}
                    | {k[0] for k in self._flights}
                )
                self._entries.clear()
                self._last_error.clear()
                self._failures.clear()
            else:
                names = {provider}
                for key in [k for k in self._entries if k[0] == provider]:
                    del self._entries[key]
                self._last_error.pop(provider, None)
                for key in [k for k in self._failures if k[0] == provider]:
                    del self._failures[key]
            for name in names:
                self._generation[name] = self._generation.get(name, 0) + 1

    def status(self, provider: str) -> Dict[str, Any]:
        """Snapshot for the API: state is idle | warming | ready | error."""
        now = self._clock()
        with self._lock:
            entries = [e for k, e in self._entries.items() if k[0] == provider]
            loading = any(k[0] == provider for k in self._flights)
            error = self._last_error.get(provider)
        if entries:
            newest = max(entries, key=lambda e: e.fetched_at)
            age = now - newest.fetched_at
            return {
                "state": "ready",
                "channel_count": len(newest.channels),
                "age_seconds": int(age),
                "stale": age >= newest.ttl,
                "refreshing": loading,
                "error": error,
            }
        if loading:
            return {"state": "warming", "error": error}
        if error:
            return {"state": "error", "error": error}
        return {"state": "idle"}

    # ------------------------------------------------------------------
    def _flight_locked(self, key: Key, owner: Any = None) -> Tuple[_Flight, bool]:
        flight = self._flights.get(key)
        if flight is not None:
            if owner is None or flight.owner is owner:
                return flight, False
            # Running load belongs to a replaced instance: discard its result, start anew.
            self._generation[key[0]] = self._generation.get(key[0], 0) + 1
        flight = _Flight(self._generation.get(key[0], 0), owner)
        self._flights[key] = flight
        return flight, True

    def _spawn_refresh(self, key, provider, loader, flight, ttl) -> None:
        def work():
            try:
                self._run(key, provider, loader, flight, ttl)
            except Exception as exc:  # already recorded in _last_error
                logger.warning(f"ChannelCache: background refresh of '{provider}' failed: {exc}")

        threading.Thread(target=work, name=f"channel-refresh-{provider}", daemon=True).start()

    def _run(self, key: Key, provider: str, loader, flight: _Flight, ttl: float) -> None:
        try:
            channels = list(loader())
        except Exception as exc:
            flight.error = exc
            with self._lock:
                if self._generation.get(provider, 0) == flight.gen:
                    self._last_error[provider] = _safe_error(exc)
                    self._failures[key] = (exc, self._clock(), flight.owner)
                    entry = self._entries.get(key)
                    if entry is not None:  # keep serving stale, but do not hammer upstream
                        entry.retry_after = self._clock() + self._backoff
            raise
        else:
            flight.result = channels
            with self._lock:
                if self._generation.get(provider, 0) == flight.gen:
                    self._entries[key] = _Entry(
                        channels,
                        self._clock(),
                        ttl if channels else min(ttl, self._empty_ttl),
                        owner=flight.owner,
                    )
                    self._last_error.pop(provider, None)
                    self._failures.pop(key, None)
        finally:
            with self._lock:
                if self._flights.get(key) is flight:
                    del self._flights[key]
            if flight.result is None and flight.error is None:
                flight.error = RuntimeError("channel load aborted")
            flight.done.set()