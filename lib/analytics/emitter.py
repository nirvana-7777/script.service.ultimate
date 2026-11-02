"""
Asynchronous, best-effort event emitter.

Design goal: the request thread pays for ONE deque.append and nothing else.

  - emit() is a length check + deque.append. No lock, no condition-variable
    notify, no I/O, no logging, no allocation beyond the dict the caller built.
    It cannot block and does not wake the consumer thread.
  - The consumer thread polls every `flush_interval` seconds (Event.wait), so
    there is no per-event cross-thread signalling. Anonymisation, JSON encoding
    and HTTP all happen there.
  - Overflow drops the NEWEST event and counts it; the consumer logs the drop
    count (rate-limited). Nothing is ever logged from a request thread.
  - A failing sink drops the batch (no retry queue) and backs off exponentially
    up to `max_backoff`, so a dead endpoint is not hammered.
  - Counters are intentionally lock-free. `dropped` is incremented from request
    threads and may under-count under heavy contention; it is a health signal,
    not an audit log.
"""
from __future__ import annotations

import atexit
import collections
import os
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Mapping, Optional

import requests

from streaming_providers.base.utils import logger
from .events import finalize
from .privacy import make_anonymizer

Sink = Callable[[List[Dict[str, Any]]], None]
Transform = Callable[[Dict[str, Any]], Dict[str, Any]]


class HttpSink:
    """Batched JSON POST: {"events": [...]}. Raises on non-2xx."""

    def __init__(self, url: str, *, timeout: float = 5.0, auth_token: Optional[str] = None):
        self._url = url
        self._timeout = (min(3.05, timeout), timeout)  # (connect, read)
        self._session = requests.Session()  # only ever used from the consumer thread
        self._session.headers["User-Agent"] = "ultimate-backend-analytics/1"
        if auth_token:
            self._session.headers["Authorization"] = f"Bearer {auth_token}"

    def __call__(self, batch: List[Dict[str, Any]]) -> None:
        resp = self._session.post(self._url, json={"events": batch}, timeout=self._timeout)
        resp.raise_for_status()

    def close(self) -> None:
        self._session.close()


class AnalyticsEmitter:
    def __init__(
        self,
        sink: Sink,
        *,
        transform: Optional[Transform] = None,
        max_queue: int = 10_000,
        batch_size: int = 100,
        flush_interval: float = 1.0,
        max_backoff: float = 30.0,
        warn_interval: float = 60.0,
        report_interval: float = 300.0,
    ):
        self._sink = sink
        self._transform = transform or finalize
        self._max_queue = max_queue
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_backoff = max_backoff
        self._warn_interval = warn_interval
        self._report_interval = report_interval

        self._q: Deque[Dict[str, Any]] = collections.deque()
        self._dropped = 0          # queue overflow (approximate, see module docstring)
        self._dropped_logged = 0
        self._shipped = 0
        self._failed_batches = 0
        self._failed_events = 0    # lost to sink failure or a malformed event

        self._last_warn: Dict[str, float] = {}
        self._last_report = time.monotonic()
        self._report_snapshot = (0, 0, 0)

        self._drain_deadline = 0.0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="analytics-emitter", daemon=True)
        self._thread.start()

    # -- public API (request threads) ------------------------------------

    def emit(self, raw: Dict[str, Any]) -> None:
        """Non-blocking, lock-free, never raises. Drops the event if the queue is full."""
        if len(self._q) >= self._max_queue:
            self._dropped += 1
            return
        self._q.append(raw)

    # -- public API (anywhere) --------------------------------------------

    def stats(self) -> Dict[str, int]:
        return {
            "queue_depth": len(self._q),
            "dropped": self._dropped,
            "shipped": self._shipped,
            "failed_batches": self._failed_batches,
            "failed_events": self._failed_events,
        }

    def shutdown(self, timeout: float = 5.0) -> None:
        """Flush what is queued (bounded by `timeout`), then stop. Idempotent."""
        if self._stop.is_set():
            return
        self._drain_deadline = time.monotonic() + timeout
        self._stop.set()
        self._thread.join(timeout=timeout + 1.0)
        close = getattr(self._sink, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001
                pass

    # -- consumer thread ---------------------------------------------------

    def _warn(self, key: str, message: str) -> None:
        now = time.monotonic()
        if now - self._last_warn.get(key, -1e9) >= self._warn_interval:
            self._last_warn[key] = now
            logger.warning(message)

    def _take(self) -> List[Dict[str, Any]]:
        batch: List[Dict[str, Any]] = []
        pop = self._q.popleft
        while len(batch) < self._batch_size:
            try:
                batch.append(pop())
            except IndexError:
                break
        return batch

    def _ship(self, raw_batch: List[Dict[str, Any]]) -> bool:
        wire: List[Dict[str, Any]] = []
        for raw in raw_batch:
            try:
                wire.append(self._transform(raw))
            except Exception:  # noqa: BLE001 — one malformed event must not sink the batch
                self._failed_events += 1
        if not wire:
            return True
        try:
            self._sink(wire)
        except Exception as err:  # noqa: BLE001 — sink is pluggable
            self._failed_batches += 1
            self._failed_events += len(wire)
            self._warn("ship", f"Analytics ship failed, dropped {len(wire)} events: {err}")
            return False
        self._shipped += len(wire)
        return True

    def _report(self) -> None:
        dropped = self._dropped
        if dropped > self._dropped_logged:
            self._warn(
                "drop",
                f"Analytics queue full: {dropped - self._dropped_logged} events dropped "
                f"(total {dropped}). Analytics is best-effort and does not affect playback.",
            )
            self._dropped_logged = dropped
        now = time.monotonic()
        if now - self._last_report >= self._report_interval:
            self._last_report = now
            snapshot = (self._shipped, self._dropped, self._failed_events)
            if snapshot != self._report_snapshot:  # stay quiet when idle
                self._report_snapshot = snapshot
                logger.info(f"Analytics stats: {self.stats()}")

    def _run(self) -> None:
        backoff = 0.0
        while not self._stop.is_set():
            wait = self._flush_interval
            batch = self._take()
            if batch:
                if self._ship(batch):
                    backoff = 0.0
                    if len(self._q) >= self._batch_size:
                        wait = 0.0  # backlog: keep draining without sleeping
                else:
                    backoff = min(max(backoff * 2, 1.0), self._max_backoff)
                    wait = backoff
            self._report()
            self._stop.wait(wait)
        self._final_flush()

    def _final_flush(self) -> None:
        while self._q and time.monotonic() < self._drain_deadline:
            if not self._ship(self._take()):
                break
        if self._q:
            logger.warning(f"Analytics shutdown: {len(self._q)} queued events discarded")


# -- process-wide singleton -------------------------------------------------

_emitter: Optional[AnalyticsEmitter] = None
_lock = threading.Lock()


def _env_num(env: Mapping[str, str], name: str, default, cast, minimum):
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = cast(raw)
    except ValueError:
        logger.warning(f"Ignoring invalid {name}={raw!r}; using {default}")
        return default
    return value if value >= minimum else default


def configure_from_env(environ: Optional[Mapping[str, str]] = None) -> Optional[AnalyticsEmitter]:
    """
    Create the process-wide emitter from ANALYTICS_* variables. Idempotent.
    Never raises. Returns None (analytics fully off, zero overhead) when
    ANALYTICS_ENDPOINT_URL is unset or invalid.

      ANALYTICS_ENDPOINT_URL      full URL batches are POSTed to (unset = disabled)
      ANALYTICS_AUTH_TOKEN        optional bearer token
      ANALYTICS_MAX_QUEUE         default 10000
      ANALYTICS_BATCH_SIZE        default 100
      ANALYTICS_FLUSH_INTERVAL    seconds, default 1.0
      ANALYTICS_TIMEOUT           HTTP read timeout in seconds, default 5.0
      ANALYTICS_ANONYMIZE         off | truncate | hash   (default off)
      ANALYTICS_HASH_SALT         required for hash mode
    """
    global _emitter
    env = os.environ if environ is None else environ
    try:
        with _lock:
            if _emitter is not None:
                return _emitter
            url = (env.get("ANALYTICS_ENDPOINT_URL") or "").strip()
            if not url:
                logger.info("Analytics disabled (ANALYTICS_ENDPOINT_URL not set)")
                return None
            if not url.lower().startswith(("http://", "https://")):
                logger.warning(f"Analytics disabled: ANALYTICS_ENDPOINT_URL must be http(s), got {url!r}")
                return None

            token = (env.get("ANALYTICS_AUTH_TOKEN") or "").strip() or None
            if token and url.lower().startswith("http://"):
                logger.warning("Analytics auth token is sent over plain HTTP; use HTTPS")
            timeout = _env_num(env, "ANALYTICS_TIMEOUT", 5.0, float, 0.1)

            anonymize = make_anonymizer(
                env.get("ANALYTICS_ANONYMIZE", "off"), (env.get("ANALYTICS_HASH_SALT") or "")
            )
            _emitter = AnalyticsEmitter(
                HttpSink(url, timeout=timeout, auth_token=token),
                transform=lambda raw: finalize(anonymize(raw)),
                max_queue=_env_num(env, "ANALYTICS_MAX_QUEUE", 10_000, int, 1),
                batch_size=_env_num(env, "ANALYTICS_BATCH_SIZE", 100, int, 1),
                flush_interval=_env_num(env, "ANALYTICS_FLUSH_INTERVAL", 1.0, float, 0.05),
            )
            atexit.register(shutdown_emitter)
            logger.info(f"Analytics enabled -> {url.split('?')[0]}")
            return _emitter
    except Exception as err:  # noqa: BLE001 — analytics must never stop the service
        logger.warning(f"Analytics could not be initialised: {err}")
        return None


def get_emitter() -> Optional[AnalyticsEmitter]:
    return _emitter


def shutdown_emitter(timeout: float = 5.0) -> None:
    """Flush and stop the emitter. Safe to call repeatedly or when disabled."""
    global _emitter
    with _lock:
        emitter, _emitter = _emitter, None
    if emitter is not None:
        try:
            emitter.shutdown(timeout)
        except Exception:  # noqa: BLE001
            pass