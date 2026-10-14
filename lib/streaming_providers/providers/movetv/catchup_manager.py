# streaming_providers/providers/movetv/catchup_manager.py
"""
move.tv catchup manager.

The catchup source is requested per programme ("epgId"), so the manager
resolves the programme from the EPG (`epg_id` if the caller has it, else the
programme at `start_time`). It needs three collaborators besides the four
standard ones: the channel manager (channel records / per-channel window), the
EPG manager and the provider-owned SourceCache.

  * `end_time` is accepted and ignored (the API never takes an end bound).
  * get_catchup_manifest returns None for "no catchup" (unknown channel, outside
    the channel's window, no programme found, source refused); it NEVER falls
    back to the live URL.
  * catchup streams are clear: get_catchup_drm keeps the ABC default `[]`, which
    ManagedProvider turns into NotImplementedError ("extract the PSSH from the
    manifest") -- the legacy contract.
"""

import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ...base.errors import NotFoundError
from ...base.managers import CatchupManager
from ...base.models.epg_models import EPGEntry
from ...base.utils.logger import logger
from .api import SourceCache, SourceInfo, api_post, fetch_source, is_fresh  # noqa: F401
from .channel_manager import MoveTvChannelManager
from .constants import MoveTVConfig
from .ids import parse_live_id

_PROVIDER = MoveTVConfig.PROVIDER_LABEL


class MoveTvCatchupManager(CatchupManager):
    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
        channels: MoveTvChannelManager,
        epg: Any,
        source_cache: SourceCache,
    ):
        super().__init__(http_manager=http_manager, auth=auth, country=country, config=config)
        self._channels = channels
        self._epg = epg
        self._source_cache = source_cache
        # EPG lookups used to resolve epg_id (rapid manifest polls): content_id -> (entries, expires_at)
        self._epg_lookup: Dict[str, Tuple[List[EPGEntry], float]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Capability
    # ------------------------------------------------------------------
    @property
    def catchup_window_hours(self) -> int:
        """Provider-wide MAXIMUM (constant; must cover every channel)."""
        return self.config.CATCHUP_WINDOW_HOURS

    def catchup_window_for_channel(self, content_id: str) -> int:
        record = self._channels.record(content_id)
        return record.catchup_hours if record is not None else self.catchup_window_hours

    def clear(self) -> None:
        with self._lock:
            self._epg_lookup = {}

    # ------------------------------------------------------------------
    # EPG resolution
    # ------------------------------------------------------------------
    def _epg_entries(self, content_id: str, start_time: int) -> List[EPGEntry]:
        now = time.time()
        with self._lock:
            cached = self._epg_lookup.get(content_id)
        if cached:
            entries, expires_at = cached
            if now < expires_at and entries:
                min_start = min(e.start for e in entries)
                max_end = max(e.end for e in entries)
                tolerance = self.config.CATCHUP_EPG_TOLERANCE_SECONDS
                if min_start - tolerance <= start_time <= max_end + tolerance:
                    return entries
        entries = self._epg.get_epg(
            content_id,
            start_time=datetime.fromtimestamp(start_time, tz=timezone.utc),
            backwards=self.config.CATCHUP_EPG_BACK_HOURS,
            forwards=self.config.CATCHUP_EPG_FORWARD_HOURS,
        )
        with self._lock:
            self._epg_lookup[content_id] = (entries, now + self.config.EPG_LOOKUP_CACHE_TTL)
        return entries

    def _resolve_epg_id(self, content_id: str, start_time: int) -> Optional[str]:
        entries = self._epg_entries(content_id, start_time)
        if not entries:
            return None
        closest: Optional[EPGEntry] = None
        closest_diff = float("inf")
        for entry in entries:
            if entry.start <= start_time < entry.end:
                return str(entry.program_id)
            diff = abs(entry.start - start_time)
            if diff < closest_diff:
                closest, closest_diff = entry, diff
        if closest is not None and closest_diff < self.config.CATCHUP_EPG_TOLERANCE_SECONDS:
            return str(closest.program_id)
        logger.warning(f"{_PROVIDER}: no suitable EPG entry for {content_id} at {start_time}")
        return None

    # ------------------------------------------------------------------
    # Source
    # ------------------------------------------------------------------
    def _catchup_source(
        self, content_id: str, start_time: int, epg_id: Optional[str]
    ) -> Optional[SourceInfo]:
        channel_id = parse_live_id(content_id)                     # BadRequestError if malformed
        record = self._channels.record(content_id, rebuild=True)
        if record is None:
            return None
        # Per-channel window, enforced here (the backend only knows the global one).
        if record.catchup_hours <= 0 or time.time() - start_time > record.catchup_hours * 3600:
            return None

        resolved = epg_id or self._resolve_epg_id(content_id, start_time)
        if not resolved:
            return None
        try:
            epg_id_int = int(resolved)
        except ValueError:
            logger.error(f"{_PROVIDER}: invalid epg id {resolved!r} for {content_id}")
            return None

        return fetch_source(
            http_manager=self.http_manager,
            session=self.auth,
            cache=self._source_cache,
            url=self.config.epg_source_url(),
            build_payload=lambda: {"epgId": epg_id_int, "contentId": channel_id},
            cache_key=f"{content_id}:{resolved}",
            operation="catchup_manifest",
            what=f"catchup source for {content_id}:{resolved}",
        )

    # ------------------------------------------------------------------
    # Manifest / headers
    # ------------------------------------------------------------------
    def get_catchup_manifest(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> Optional[str]:
        source = self._catchup_source(content_id, int(start_time), epg_id)
        return source[0] if source else None

    def get_catchup_manifest_headers(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> Dict[str, str]:
        url = kw.get("url") or kw.get("manifest_url") or kw.get("segment_url")
        if url:
            cached = self._source_cache.get(url)
            if is_fresh(cached):
                return self.config.stream_headers(cached[1])
        source = self._catchup_source(content_id, int(start_time), epg_id)
        if source is None:
            # Never fall back to live headers (wrong token); fail loudly instead.
            raise NotFoundError(
                f"{_PROVIDER}: no catchup source for {content_id} at {start_time}"
            )
        return self.config.stream_headers(source[1])