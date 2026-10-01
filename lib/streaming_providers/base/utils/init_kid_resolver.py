# streaming_providers/base/utils/init_kid_resolver.py
"""
Resolves the default KID of an AdaptationSet from its init segment (tenc box).

Used by MPDRewriter when the MPD carries neither cenc:default_KID nor a
PSSH with KIDs and multiple keys are configured: without the KID the rewriter
cannot pick the right key for a segment.

Design notes
------------
* The rewriter stays free of network I/O: it receives this resolver as an
  injected callable (init_url -> KID or None).
* Results are cached per init-segment path (scheme + host + path). The query
  string is ignored on purpose: signed URLs change on every manifest refresh,
  the KID of a given init segment does not.
* Failures (fetch error, no tenc) are cached too, but only briefly, so a live
  MPD that refreshes every few seconds does not trigger a download per refresh
  while a transient error still heals quickly.
"""

import threading
import time
from collections import OrderedDict
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit

from .logger import logger
from .mp4_pssh_extractor import MP4PSSHExtractor

# The tenc box lives in moov at the start of the file; for single-file
# (SegmentBase) manifests this avoids downloading the whole MP4.
_PROBE_BYTES = 100 * 1024

_MISS = object()


class InitSegmentKidResolver:
    """Thread-safe, cached init-segment -> KID lookup."""

    def __init__(
            self,
            ttl_seconds: int = 3600,
            failure_ttl_seconds: int = 60,
            max_size: int = 1024,
    ) -> None:
        self._ttl = ttl_seconds
        self._failure_ttl = failure_ttl_seconds
        self._max_size = max_size
        self._entries: "OrderedDict[str, Tuple[Optional[str], float]]" = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _cache_key(init_url: str) -> str:
        parts = urlsplit(init_url)
        return f"{parts.scheme}://{parts.netloc}{parts.path}"

    def _get(self, key: str):
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return _MISS
            kid, expires = entry
            if expires <= time.monotonic():
                del self._entries[key]
                return _MISS
            self._entries.move_to_end(key)
            return kid

    def _set(self, key: str, kid: Optional[str]) -> None:
        ttl = self._ttl if kid else self._failure_ttl
        with self._lock:
            self._entries[key] = (kid, time.monotonic() + ttl)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_size:
                self._entries.popitem(last=False)

    def resolve(
            self,
            init_url: str,
            headers: Optional[Dict[str, str]] = None,
            http_manager=None,
    ) -> Optional[str]:
        """
        Return the KID (32 lowercase hex chars) of the init segment, or None.

        Args:
            init_url: Direct CDN URL of the init segment (not the proxied one).
            headers: Segment auth headers (StreamingProvider.get_segment_headers()).
            http_manager: Provider's HTTP manager, if any.
        """
        key = self._cache_key(init_url)
        cached = self._get(key)
        if cached is not _MISS:
            return cached

        request_headers = {
            **(headers or {}),
            "Range": f"bytes=0-{_PROBE_BYTES - 1}",
        }
        kids = MP4PSSHExtractor.extract_tenc_kids_from_url(
            init_url, headers=request_headers, http_manager=http_manager
        )
        kid = kids[0] if kids else None

        if len(kids) > 1:
            logger.debug(f"Init segment has {len(kids)} tenc KIDs, using the first: {key}")

        self._set(key, kid)
        return kid


_instance: Optional[InitSegmentKidResolver] = None
_instance_lock = threading.Lock()


def get_init_kid_resolver() -> InitSegmentKidResolver:
    """Process-wide resolver so the cache survives across per-request rewriters."""
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = InitSegmentKidResolver()
        return _instance