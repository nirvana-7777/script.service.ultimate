# streaming_providers/base/channel_cache.py
"""
In-memory channel-list cache with single-flight loading, stale-while-
revalidate and a per-provider circuit breaker.

What it gives the PVR client:
  * a warm cache: GET /api/providers/<p>/channels is answered from memory
  * single-flight: concurrent callers (warm-up, PVR, M3U generation) share ONE
    upstream load per (provider, params); nobody logs in twice in parallel
  * stale-while-revalidate: past the TTL the old list is served at once and
    refreshed in a background thread; only a cold miss blocks
  * a status per provider for /api/providers (see status())

Circuit breaker (never changes configuration, only controls RETRYING):
  A load counts as failed when it raises OR returns no channels (many
  providers log the error and return []). Consecutive failures back off:

      kind        delays (s)                          why
      transient   60, 300, 900, 3600, 10800, 21600    timeouts, 5xx, ...
      empty       900, 3600, 10800, 21600             swallowed error / no channels
      rate_limit  3600, 10800, 43200 (>= Retry-After) HTTP 429 / RateLimitError
      auth        21600, 86400                        401/403, AuthError, ...
      geo         86400                               GeoBlockError

  Both the lazy request path and the background refresher honour the delay,
  so a failing login is never repeated by client retries or refresh ticks.
  A list that was loaded successfully is NEVER replaced by a failed or empty
  reload. invalidate() (credentials changed, reinitialize, enable/disable,
  rediscover) resets the breaker of that provider.

Memory only, by design: channel objects are not serialised anywhere yet.
A load that was already running when invalidate() was called is delivered to
its waiters but never stored (generation counter); a list, failure or running
load that belongs to a replaced provider INSTANCE is never served (owner).
"""

import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Hashable, List, Optional, Tuple

from .utils.logger import logger

DEFAULT_TTL = 24 * 3600.0            # channel lists are stable: fresh for 24 h
DEFAULT_MAX_STALE = 7 * 24 * 3600.0  # serve stale (and refresh) up to 7 days; older = cold miss
EMPTY_TTL = 30.0                     # an empty list is shown as stale at once (its retry is governed by the breaker)

BACKOFF: Dict[str, Tuple[float, ...]] = {
    "transient": (60, 300, 900, 3600, 10800, 21600),
    "empty": (900, 3600, 10800, 21600),
    "rate_limit": (3600, 10800, 43200),
    "auth": (21600, 86400),
    "geo": (86400,),
}

Key = Tuple[str, Hashable]

_URL_RE = re.compile(r"https?://\S+")


def _safe_error(exc: BaseException) -> str:
    """Error text for the API: no URLs (they may carry tokens), max 200 chars."""
    return _URL_RE.sub("<url>", f"{type(exc).__name__}: {exc}")[:200]


def classify_error(exc: BaseException) -> str:
    """
    transient | rate_limit | auth | geo. By class NAME and HTTP status so that
    providers still raising raw requests.HTTPError (not yet migrated to
    base.errors) are classified too.
    """
    names = {cls.__name__ for cls in type(exc).__mro__}
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if "RateLimitError" in names or status == 429:
        return "rate_limit"
    if names & {"AuthError", "InvalidCredentialsError", "EntitlementError"} or status in (401, 403):
        return "auth"
    if "GeoBlockError" in names:
        return "geo"
    return "transient"


def _retry_after(exc: Optional[BaseException]) -> float:
    headers = getattr(getattr(exc, "response", None), "headers", None)
    try:
        value = float(headers.get("Retry-After")) if headers else 0.0
    except (TypeError, ValueError, AttributeError):
        return 0.0
    return value if 0 < value <= 86400 else 0.0


@dataclass
class _Entry:
    channels: List[Any]
    fetched_at: float
    ttl: float
    retry_after: float = 0.0
    owner: Any = None  # the provider instance this list came from


@dataclass
class _Health:
    failures: int
    next_retry: float
    kind: str


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
        empty_ttl: float = EMPTY_TTL,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._ttl = ttl
        self._max_stale = max_stale
        self._empty_ttl = empty_ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: Dict[Key, _Entry] = {}
        self._flights: Dict[Key, _Flight] = {}
        self._generation: Dict[str, int] = {}
        self._last_error: Dict[str, str] = {}
        self._health: Dict[str, _Health] = {}
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
        that belongs to a DIFFERENT instance is never served.
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
                    if (owner is not None and failure[2] is not owner) or now >= failure[1]:
                        del self._failures[key]
                    else:
                        # Same answer as the failed load, without asking the upstream again.
                        raise failure[0].with_traceback(None)
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

    def can_retry(self, provider: str) -> bool:
        """False while the provider's circuit breaker is in a backoff window."""
        with self._lock:
            health = self._health.get(provider)
            return health is None or self._clock() >= health.next_retry

    def invalidate(self, provider: Optional[str] = None) -> None:
        """Drop cached lists (one provider, or all), reset the breaker, discard loads in flight."""
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
                self._health.clear()
            else:
                names = {provider}
                for key in [k for k in self._entries if k[0] == provider]:
                    del self._entries[key]
                self._last_error.pop(provider, None)
                self._health.pop(provider, None)
                for key in [k for k in self._failures if k[0] == provider]:
                    del self._failures[key]
            for name in names:
                self._generation[name] = self._generation.get(name, 0) + 1

    def status(self, provider: str) -> Dict[str, Any]:
        """
        Snapshot for the API.

        state:        idle | warming | ready | error
        ready:        channel_count, age_seconds, stale (True = list is old; THIS is
                      the signal for "old", not `state`), refreshing
        any state:    error (sanitised text), error_kind, failures, retry_in
                      (seconds until the next automatic attempt)
        """
        now = self._clock()
        with self._lock:
            entries = [e for k, e in self._entries.items() if k[0] == provider]
            loading = any(k[0] == provider for k in self._flights)
            error = self._last_error.get(provider)
            health = self._health.get(provider)
        extra: Dict[str, Any] = {"error": error}
        if health is not None:
            extra.update(
                error_kind=health.kind,
                failures=health.failures,
                retry_in=max(0, int(health.next_retry - now)),
            )
        if entries:
            newest = max(entries, key=lambda e: e.fetched_at)
            age = now - newest.fetched_at
            return {
                "state": "ready",
                "channel_count": len(newest.channels),
                "age_seconds": int(age),
                "stale": age >= newest.ttl,
                "refreshing": loading,
                **extra,
            }
        if loading:
            return {"state": "warming", **extra}
        if error:
            return {"state": "error", **extra}
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

    def _record_failure_locked(self, provider: str, kind: str, exc: Optional[BaseException]) -> _Health:
        previous = self._health.get(provider)
        count = (previous.failures if previous else 0) + 1
        table = BACKOFF[kind]
        delay = table[min(count, len(table)) - 1]
        if kind == "rate_limit":
            delay = max(delay, _retry_after(exc))
        health = _Health(count, self._clock() + delay, kind)
        self._health[provider] = health
        logger.info(
            f"ChannelCache: '{provider}' {kind} failure #{count}, next automatic attempt in {int(delay)}s"
        )
        return health

    def _spawn_refresh(self, key, provider, loader, flight, ttl) -> None:
        def work():
            try:
                self._run(key, provider, loader, flight, ttl)
            except Exception as exc:  # already recorded in the breaker
                logger.warning(f"ChannelCache: background refresh of '{provider}' failed: {exc}")

        threading.Thread(target=work, name=f"channel-refresh-{provider}", daemon=True).start()

    def _run(self, key: Key, provider: str, loader, flight: _Flight, ttl: float) -> None:
        try:
            channels = list(loader())
        except Exception as exc:
            flight.error = exc
            with self._lock:
                if self._generation.get(provider, 0) == flight.gen:
                    health = self._record_failure_locked(provider, classify_error(exc), exc)
                    self._last_error[provider] = _safe_error(exc)
                    self._failures[key] = (exc, health.next_retry, flight.owner)
                    entry = self._entries.get(key)
                    if entry is not None:  # keep serving the old list, retry later
                        entry.retry_after = health.next_retry
            raise
        else:
            flight.result = channels
            with self._lock:
                if self._generation.get(provider, 0) == flight.gen:
                    now = self._clock()
                    if channels:
                        self._entries[key] = _Entry(channels, now, ttl, owner=flight.owner)
                        self._health.pop(provider, None)
                        self._last_error.pop(provider, None)
                        self._failures.pop(key, None)
                    else:
                        health = self._record_failure_locked(provider, "empty", None)
                        self._last_error[provider] = "no channels returned"
                        old = self._entries.get(key)
                        if old is not None and old.channels and (flight.owner is None or old.owner is flight.owner):
                            old.retry_after = health.next_retry  # never replace a good list by an empty one
                        else:
                            self._entries[key] = _Entry(
                                [], now, min(ttl, self._empty_ttl),
                                retry_after=health.next_retry, owner=flight.owner,
                            )
        finally:
            with self._lock:
                if self._flights.get(key) is flight:
                    del self._flights[key]
            if flight.result is None and flight.error is None:
                flight.error = RuntimeError("channel load aborted")
            flight.done.set()