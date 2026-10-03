# streaming_providers/providers/simplitv/epg_manager.py
"""
simpliTV EPG manager.

Two endpoints, both anonymous (no token -- the existing addon sends
none):

  * /v1/EpgTile/FilterProgramTiles -- every channel's programmes in a
    [from, to] window. The response's `programs` is a dict:
    {channel codename: [programme, ...]}.
  * /v2/Tile/GetTiles -- tile details for a programme id (cast, genres,
    images).

One request therefore serves the whole grid, so get_epg_grid is
overridden natively and get_epg is just a one-channel view of the same
data. Windows are fetched in day-sized chunks (as the addon does) and
cached briefly, so per-channel callers don't re-download the grid.

Window: -7..+7 days around "now", matching the addon's TV-Guide.
"""

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ...base.errors import ServerError
from ...base.managers import EpgManager
from ...base.models.epg_models import EPGEntry, EPGProgramDetails
from ...base.utils.logger import logger

from .constants import SimpliTVDefaults
from .helpers import transport_errors


class SimpliTVEpgManager(EpgManager):
    """EPG for simpliTV."""

    def __init__(self, *, http_manager, auth, country, config):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        # (from_iso, to_iso) -> (expires_at, {codename: [programme]})
        self._window_cache: Dict[
            Tuple[str, str], Tuple[float, Dict[str, List[dict]]]
        ] = {}
        self._cache_lock = threading.Lock()

    @property
    def epg_window(self) -> Tuple[int, int]:
        return (
            SimpliTVDefaults.EPG_PAST_DAYS,
            SimpliTVDefaults.EPG_FUTURE_DAYS,
        )

    # ------------------------------------------------------------------
    # get_epg / get_epg_grid
    # ------------------------------------------------------------------

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw,
    ) -> List[EPGEntry]:
        """
        Programmes for `channel_id` in [start_time, end_time].

        channel_id may carry a live: or catchup: prefix (and @<ts>
        suffix); EPG is keyed on the channel codename.
        """
        codename = _strip_live_prefix(channel_id)
        programs = self._fetch_programs(start_time, end_time)
        return _entries_for(codename, programs.get(codename, []))

    def get_epg_grid(
        self,
        channel_ids: List[str],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw,
    ) -> Dict[str, List[EPGEntry]]:
        """Native batch: one fetch serves every requested channel."""
        programs = self._fetch_programs(start_time, end_time)
        grid: Dict[str, List[EPGEntry]] = {}
        for channel_id in channel_ids:
            codename = _strip_live_prefix(channel_id)
            grid[channel_id] = _entries_for(
                codename, programs.get(codename, [])
            )
        return grid

    # ------------------------------------------------------------------
    # get_program_details
    # ------------------------------------------------------------------

    def get_program_details(
        self, program_id: str, **kw
    ) -> Optional[EPGProgramDetails]:
        """
        Extended details for one tile id (EPGEntry.program_id).

        Returns None when the tile is not found.
        """
        body = {
            "platformCodename": self.config.platform_codename,
            "requestedTiles": [{"id": program_id}],
        }
        with transport_errors(f"GetTiles for {program_id!r}"):
            resp = self.http_manager.post(
                self.config.tile_details_url(),
                json=body,
                headers=self.config.get_api_headers(),
            )
            tiles = resp.json().get("tiles") or []
        if not tiles:
            return None
        return _tile_to_program_details(tiles[0])

    # ------------------------------------------------------------------
    # Fetching
    # ------------------------------------------------------------------

    def _fetch_programs(
        self, start_time: Optional[datetime], end_time: Optional[datetime]
    ) -> Dict[str, List[dict]]:
        """Merge day-sized windows into {codename: [programme]}."""
        start, end = _normalise_window(start_time, end_time)
        merged: Dict[str, Dict[str, dict]] = {}
        for w_start, w_end in _chunks(start, end):
            chunk = self._fetch_window(_iso(w_start), _iso(w_end))
            for codename, items in chunk.items():
                bucket = merged.setdefault(codename, {})
                for programme in items:
                    # A programme straddling a boundary appears in both
                    # windows; the id dedupes it.
                    key = programme.get("id") or (
                        f"{programme.get('codename')}:{programme.get('start')}"
                    )
                    bucket[key] = programme
        return {c: list(b.values()) for c, b in merged.items()}

    def _fetch_window(
        self, from_iso: str, to_iso: str
    ) -> Dict[str, List[dict]]:
        key = (from_iso, to_iso)
        now = time.monotonic()
        with self._cache_lock:
            hit = self._window_cache.get(key)
            if hit and hit[0] > now:
                return hit[1]

        body = {
            "platformCodename": self.config.platform_codename,
            "from": from_iso,
            "to": to_iso,
        }
        with transport_errors(f"FilterProgramTiles {from_iso}..{to_iso}"):
            resp = self.http_manager.post(
                self.config.program_tiles_url(),
                json=body,
                headers=self.config.get_api_headers(),
            )
            programs = resp.json().get("programs")
        if not isinstance(programs, dict):
            raise ServerError(
                "simpliTV: FilterProgramTiles `programs` is not a "
                "channel-keyed object"
            )

        with self._cache_lock:
            if len(self._window_cache) >= SimpliTVDefaults.EPG_CACHE_MAX:
                self._window_cache = {
                    k: v for k, v in self._window_cache.items()
                    if v[0] > now
                }
                if len(self._window_cache) >= SimpliTVDefaults.EPG_CACHE_MAX:
                    self._window_cache.clear()
            self._window_cache[key] = (
                now + SimpliTVDefaults.EPG_CACHE_TTL, programs,
            )
        return programs


# ----------------------------------------------------------------------
# Module-private helpers
# ----------------------------------------------------------------------

def _strip_live_prefix(channel_id: str) -> str:
    for prefix in (
        SimpliTVDefaults.LIVE_PREFIX,
        SimpliTVDefaults.CATCHUP_PREFIX,
    ):
        if channel_id.startswith(prefix):
            rest = channel_id[len(prefix):]
            return rest.split(SimpliTVDefaults.CATCHUP_TS_SEPARATOR, 1)[0]
    return channel_id


def _normalise_window(
    start_time: Optional[datetime], end_time: Optional[datetime]
) -> Tuple[datetime, datetime]:
    """UTC-aware [start, end]; missing bounds mean "now" / +1 minute."""
    def aware(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    start = aware(start_time) if start_time else datetime.now(timezone.utc)
    end = aware(end_time) if end_time else start + timedelta(minutes=1)
    if end <= start:
        end = start + timedelta(minutes=1)
    return start, end


def _chunks(
    start: datetime, end: datetime
) -> Iterator[Tuple[datetime, datetime]]:
    step = timedelta(hours=SimpliTVDefaults.EPG_CHUNK_HOURS)
    cursor = start
    while cursor < end:
        yield cursor, min(cursor + step, end)
        cursor += step


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_iso_to_unix(s: Optional[str]) -> Optional[int]:
    """
    ISO-8601 (Z or offset) -> Unix seconds, or None if missing/malformed.

    A timestamp without offset is read as UTC (as the addon does), never
    as the server's local time.
    """
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _entries_for(
    channel_codename: str, programmes: List[dict]
) -> List[EPGEntry]:
    entries = []
    for programme in programmes:
        entry = _programme_to_entry(channel_codename, programme)
        if entry is not None:
            entries.append(entry)
    entries.sort(key=lambda e: e.start)
    return entries


def _programme_to_entry(
    channel_codename: str, programme: Dict[str, Any]
) -> Optional[EPGEntry]:
    """
    Map a programme tile to EPGEntry; None if it has no usable times
    (an entry without times would collide on its broadcast id).

    broadcast_id embeds the programme codename as its last segment --
    that is what the catchup manager takes as epg_id for replay.
    program_id is the tile id GetTiles needs.
    """
    start = _parse_iso_to_unix(programme.get("start"))
    end = _parse_iso_to_unix(programme.get("stop"))
    if start is None or end is None:
        logger.debug(
            f"simpliTV: skipping programme without times: "
            f"{programme.get('id')!r}"
        )
        return None

    images = programme.get("images") or []
    icon = images[0].get("url") if images else None

    return EPGEntry(
        broadcast_id=(
            f"{SimpliTVDefaults.BROADCAST_ID_PREFIX}{channel_codename}:"
            f"{start}:{programme.get('codename', '')}"
        ),
        title=programme.get("title", ""),
        description=programme.get("description", ""),
        start=start,
        end=end,
        icon=icon,
        program_id=programme.get("id"),
    )


def _tile_to_program_details(tile: Dict[str, Any]) -> EPGProgramDetails:
    """
    Map a /v2/Tile/GetTiles tile to the shared EPGProgramDetails shape.

    Season/episode numbers, countries and genres are on the tile but not
    in the shared shape; extend EPGProgramDetails first (template rule)
    rather than inventing kwargs here.
    """
    images = tile.get("images") or []
    icon = images[0].get("url") if images else None

    people = tile.get("people") or []
    cast = [p.get("fullName", "") for p in people if p.get("fullName")]

    return EPGProgramDetails(
        program_id=tile.get("id", ""),
        description=tile.get("description", ""),
        episode_name=tile.get("subTitle", ""),
        year=tile.get("date") or None,
        icon=icon,
        cast=cast,
    )
