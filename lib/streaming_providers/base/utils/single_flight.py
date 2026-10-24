# streaming_providers/base/utils/single_flight.py
"""
Single-flight: concurrent callers asking for the same key share ONE execution.

Used for HLS playlist refreshes: N viewers polling the same live playlist at
the same moment cause one upstream fetch + rewrite, not N. The first caller
for a key (the leader) runs `fn`; callers arriving while it runs wait for its
result (or exception). Nothing is cached here — the entry disappears as soon
as the leader finishes; caching is the caller's job.
"""

import threading
from typing import Callable, Dict, Hashable, TypeVar

T = TypeVar("T")


class _Call:
    __slots__ = ("event", "result", "error")

    def __init__(self):
        self.event = threading.Event()
        self.result = None
        self.error = None


class SingleFlight:
    def __init__(self, wait_timeout: float = 60.0):
        self._lock = threading.Lock()
        self._calls: Dict[Hashable, _Call] = {}
        self._wait_timeout = wait_timeout

    def do(self, key: Hashable, fn: Callable[[], T]) -> T:
        with self._lock:
            call = self._calls.get(key)
            leader = call is None
            if leader:
                call = self._calls[key] = _Call()

        if leader:
            try:
                call.result = fn()
            except BaseException as exc:  # shared with followers, re-raised below
                call.error = exc
            finally:
                with self._lock:
                    self._calls.pop(key, None)
                call.event.set()
        elif not call.event.wait(self._wait_timeout):
            raise TimeoutError(f"single-flight wait for {key!r} timed out")

        if call.error is not None:
            raise call.error
        return call.result
