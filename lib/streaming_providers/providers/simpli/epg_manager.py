# streaming_providers/providers/simpli/epg_manager.py
"""
simpliTV EPG manager.

Endpoints:

  * GET /v1/EpgTile/FilterProgramTiles -- every channel's programmes in
    a [from, to] window. The response's `programs` is a dict:
    {channel codename: [programme, ...]}. Programme tiles carry
    `from` / `to` and have NO title, description or images.

  * POST /v2/Tile/GetTiles -- tile details by id. Called in batches to
    enrich the programmes FilterProgramTiles returned. Only a compact
    summary (title, description, icon) is cached per id, and the cache
    is size-bounded. Ids the server did not return are cached as empty
    so they are not re-requested on every call. The summaries used for
    one request are collected locally, so cache eviction can never
    blank titles in the response being built.

  * POST /v1/EpgTile/GetAvailableDays -- the server's EPG window. Used
    only to expose epg_window; the fetch windows themselves follow the
    caller's [start, end].

If GetTiles fails, the grid is still returned: titles fall back to the
programme codename (and a warning is logged) instead of failing the
whole EPG request.

Windows are fetched in day-sized chunks (as the addon does) and cached
briefly, so per-channel callers don't re-download the grid.
"""

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote

from ...base.errors import ServerError
from ...base.managers import EpgManager
from ...base.models.epg_models import (
    EPGEntry,
    EPGFlags,
    EPGGenre,
    EPGProgramDetails,
)
from ...base.utils.logger import logger

from .constants import SimpliTVDefaults
from .helpers import parse_iso, transport_errors

# GetTiles ids per request.
_TILE_BATCH = 500
# Upper bound on cached tile summaries; the oldest half is dropped when
# exceeded.
_TILE_CACHE_MAX = 50000


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
        # programme id -> {"title", "description", "icon"} ({} = unknown)
        self._tile_cache: Dict[str, dict] = {}
        self._available_window: Optional[Tuple[int, int]] = None
        self._available_window_expires: float = 0.0
        self._cache_lock = threading.Lock()

    @property
    def epg_window(self) -> Tuple[int, int]:
        """
        Server-advertised EPG window as (past_days, future_days).

        Informational: it does NOT bound the fetch windows, which
        follow the caller's [start, end].
        """
        return self._fetch_available_window()

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
        programs, tiles = self._fetch_programs(start_time, end_time)
        return _entries_for(codename, programs.get(codename, []), tiles)

    def get_epg_grid(
        self,
        channel_ids: List[str],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw,
    ) -> Dict[str, List[EPGEntry]]:
        """Native batch: one fetch serves every requested channel."""
        programs, tiles = self._fetch_programs(start_time, end_time)
        grid: Dict[str, List[EPGEntry]] = {}
        for channel_id in channel_ids:
            codename = _strip_live_prefix(channel_id)
            grid[channel_id] = _entries_for(
                codename, programs.get(codename, []), tiles
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

        Always fetches the full tile (cast, subtitle, year are not in
        the cached summary), so every call makes one small request.
        Returns None when the tile is not found.
        """
        tile = self._fetch_tiles([program_id]).get(program_id)
        if not tile:
            return None
        return _tile_to_program_details(tile)

    # ------------------------------------------------------------------
    # Available-days window
    # ------------------------------------------------------------------

    def _fetch_available_window(self) -> Tuple[int, int]:
        """
        Return (past_days, future_days) advertised by the server.

        Cached for EPG_CACHE_TTL seconds; falls back to the constants
        on any error or unusable answer, logged at info because being
        permanently on the fallback is worth noticing.
        """
        now = time.monotonic()
        with self._cache_lock:
            if (
                self._available_window is not None
                and self._available_window_expires > now
            ):
                return self._available_window

        try:
            resp = self.http_manager.post(
                self.config.epg_available_days_url(),
                json={},
                headers=self.config.get_api_headers(),
            )
            data = resp.json()
            window = _days_from_window(data.get("from"), data.get("to"))
            if window is not None:
                with self._cache_lock:
                    self._available_window = window
                    self._available_window_expires = (
                        now + SimpliTVDefaults.EPG_CACHE_TTL
                    )
                return window
            logger.info(
                "simpliTV: GetAvailableDays returned no usable from/to; "
                "using defaults for epg_window"
            )
        except Exception as e:
            logger.info(
                f"simpliTV: GetAvailableDays failed ({e}); using "
                f"defaults for epg_window"
            )

        fallback = (
            SimpliTVDefaults.EPG_PAST_DAYS,
            SimpliTVDefaults.EPG_FUTURE_DAYS,
        )
        with self._cache_lock:
            self._available_window = fallback
            self._available_window_expires = now + 60
        return fallback

    # ------------------------------------------------------------------
    # Fetching
    # ------------------------------------------------------------------

    def _fetch_programs(
        self, start_time: Optional[datetime], end_time: Optional[datetime]
    ) -> Tuple[Dict[str, List[dict]], Dict[str, dict]]:
        """
        Merge day-sized windows into {codename: [programme]} and
        return it together with {programme id: tile summary} for every
        programme in it.

        The summaries are gathered into a local dict (from the cache
        for known ids, from GetTiles for the rest) rather than re-read
        from the shared cache afterwards, so eviction during a large
        fetch cannot drop titles from this response.
        """
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
                        f"{programme.get('codename')}:"
                        f"{programme.get('from')}"
                    )
                    bucket[key] = programme

        all_ids = list(dict.fromkeys(
            programme["id"]
            for bucket in merged.values()
            for programme in bucket.values()
            if programme.get("id")
        ))

        tiles: Dict[str, dict] = {}
        missing: List[str] = []
        with self._cache_lock:
            for pid in all_ids:
                if pid in self._tile_cache:
                    tiles[pid] = self._tile_cache[pid]
                else:
                    missing.append(pid)

        for i in range(0, len(missing), _TILE_BATCH):
            batch = missing[i:i + _TILE_BATCH]
            try:
                fresh = self._fetch_tiles(batch)
            except Exception as e:
                # Degrade to codename titles rather than fail the EPG.
                logger.warning(
                    f"simpliTV: GetTiles failed ({e}); programme titles "
                    f"fall back to codenames"
                )
                break
            for pid in batch:
                tile = fresh.get(pid)
                tiles[pid] = _summarise_tile(tile) if tile else {}

        return {c: list(b.values()) for c, b in merged.items()}, tiles

    def _fetch_window(
        self, from_iso: str, to_iso: str
    ) -> Dict[str, List[dict]]:
        key = (from_iso, to_iso)
        now = time.monotonic()
        with self._cache_lock:
            hit = self._window_cache.get(key)
            if hit and hit[0] > now:
                return hit[1]

        # FilterProgramTiles is a GET with query-string parameters.
        # `from` and `to` MUST be percent-encoded (colons, dots).
        url = (
            f"{self.config.program_tiles_url()}"
            f"&platformCodename={quote(self.config.platform_codename)}"
            f"&from={quote(from_iso)}"
            f"&to={quote(to_iso)}"
        )
        with transport_errors(f"FilterProgramTiles {from_iso}..{to_iso}"):
            resp = self.http_manager.get(
                url, headers=self.config.get_api_headers()
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

    # ------------------------------------------------------------------
    # Tile details (batched, cached as compact summaries)
    # ------------------------------------------------------------------

    def _fetch_tiles(self, program_ids: List[str]) -> Dict[str, dict]:
        """
        POST /v2/Tile/GetTiles for the given ids.

        Returns {id: full tile} for the ids the server returned, and
        records a compact summary for every requested id in the cache
        (an empty summary for ids the server did not return). Raises
        ServerError on transport failure; callers decide how to
        degrade.
        """
        if not program_ids:
            return {}

        body = {
            "platformCodename": self.config.platform_codename,
            "requestedTiles": [{"id": pid} for pid in program_ids],
        }
        with transport_errors(f"GetTiles for {len(program_ids)} tiles"):
            resp = self.http_manager.post(
                self.config.tile_details_url(),
                json=body,
                headers=self.config.get_api_headers(),
            )
            tiles = resp.json().get("tiles") or []

        fresh: Dict[str, dict] = {}
        for tile in tiles:
            if not isinstance(tile, dict):
                continue
            tid = tile.get("id")
            if tid:
                fresh[tid] = tile

        with self._cache_lock:
            for pid in program_ids:
                tile = fresh.get(pid)
                self._tile_cache[pid] = (
                    _summarise_tile(tile) if tile else {}
                )
            if len(self._tile_cache) > _TILE_CACHE_MAX:
                # dicts keep insertion order: drop the oldest half.
                for old in list(self._tile_cache)[: len(self._tile_cache) // 2]:
                    del self._tile_cache[old]
        return fresh


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
    """ISO-8601 -> Unix seconds, or None if missing / malformed."""
    dt = parse_iso(s)
    return int(dt.timestamp()) if dt is not None else None


def _days_from_window(
    from_iso: Optional[str], to_iso: Optional[str]
) -> Optional[Tuple[int, int]]:
    """
    Convert GetAvailableDays's from/to to (past_days, future_days)
    relative to now. None if either bound is missing or unparseable.
    """
    frm = parse_iso(from_iso)
    to = parse_iso(to_iso)
    if frm is None or to is None:
        return None
    now = datetime.now(timezone.utc)
    past = max(0, int((now - frm).total_seconds() // 86400))
    future = max(0, int((to - now).total_seconds() // 86400))
    return past, future


def _first_image_url(images: Any) -> Optional[str]:
    """
    URL of the first image, tolerating an unverified response shape:
    a list of {"url": ...} objects, a list of plain strings, or
    anything else (-> None).
    """
    if not isinstance(images, list) or not images:
        return None
    first = images[0]
    if isinstance(first, dict):
        return first.get("url") or None
    if isinstance(first, str):
        return first or None
    return None


def _as_int(value: Any) -> Optional[int]:
    """int(value) or None; never raises."""
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _positive_int(value: Any) -> Optional[int]:
    """Season/episode style numbers: EPGEntry wants >= 1 or None."""
    n = _as_int(value)
    return n if n is not None and n > 0 else None


def _year_from(value: Any) -> Optional[int]:
    """
    Production year from tile["date"], which may be a plain year or a
    full ISO date (shape unverified). EPGEntry.year is an int, so a
    string must never leak through.
    """
    n = _as_int(value)
    if n is not None:
        return n if 1800 <= n <= 2100 else None
    if isinstance(value, str):
        dt = parse_iso(value.strip())
        if dt is not None and 1800 <= dt.year <= 2100:
            return dt.year
    return None


def _genre_names(categories: Any) -> List[str]:
    """
    Names of the tile's genre / subcategory categories, main genre
    first, de-duplicated. Same typeCodename values the old EPG parser
    used ("genre", "subcategory"); other category types are ignored.
    """
    if not isinstance(categories, list):
        return []
    names: List[str] = []
    for wanted in ("genre", "subcategory"):
        for cat in categories:
            if not isinstance(cat, dict):
                continue
            name = cat.get("name")
            if cat.get("typeCodename") == wanted and name and name not in names:
                names.append(name)
    return names


def _people_by_role(people: Any) -> Tuple[List[str], List[str]]:
    """
    Split tile["people"] into (cast, directors).

    The name key is unverified: this code reads `fullName` while the
    old EPG parser read `name`, so both are accepted. `role` (old
    parser) is used to pull directors out when present; anything that
    is not a director counts as cast.
    """
    cast: List[str] = []
    directors: List[str] = []
    for p in people if isinstance(people, list) else []:
        if not isinstance(p, dict):
            continue
        name = (p.get("fullName") or p.get("name") or "").strip()
        if not name:
            continue
        role = str(p.get("role") or "").lower()
        (directors if "director" in role else cast).append(name)
    return cast, directors


def _summarise_tile(tile: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compact per-programme summary kept in the tile cache. Everything
    the grid needs from GetTiles is taken here, so no extra requests
    are made for genre / season / subtitle.
    """
    return {
        "title": tile.get("title") or "",
        "description": tile.get("description") or "",
        "icon": _first_image_url(tile.get("images")),
        "episode_name": tile.get("subTitle") or "",
        "genres": _genre_names(tile.get("categories")),
        "season_number": _positive_int(tile.get("seasonNumber")),
        "is_series": bool(tile.get("seriesId")),
    }


def _entries_for(
    channel_codename: str,
    programmes: List[dict],
    tiles: Dict[str, dict],
) -> List[EPGEntry]:
    entries = []
    for programme in programmes:
        entry = _programme_to_entry(
            channel_codename,
            programme,
            tiles.get(programme.get("id") or "") or {},
        )
        if entry is not None:
            entries.append(entry)
    entries.sort(key=lambda e: e.start)
    return entries


def _programme_to_entry(
    channel_codename: str,
    programme: Dict[str, Any],
    tile: Dict[str, Any],
) -> Optional[EPGEntry]:
    """
    Map a FilterProgramTiles programme (plus its tile summary, if any)
    to EPGEntry.

    FilterProgramTiles emits `from` / `to` (not `start` / `stop`) and
    carries no title, description or images; those come from `tile`.
    When no title is available the programme codename is used, so the
    grid is never blank.

    broadcast_id is the shared int encoding (provider hash + event
    hash), NOT a string: EPGEntry validates it as an int and the
    catchup path recovers the provider from it.

    EPGEntry validates on construction (end after start, ...). One bad
    programme must not take the whole channel's EPG down, so a failed
    construction skips that programme.
    """
    start = _parse_iso_to_unix(
        programme.get("from") or programme.get("start")
    )
    end = _parse_iso_to_unix(
        programme.get("to") or programme.get("stop")
    )
    if start is None or end is None:
        logger.debug(
            f"simpliTV: skipping programme without times: "
            f"{programme.get('id')!r}"
        )
        return None

    title = (
        tile.get("title")
        or programme.get("title")
        or programme.get("codename")
        or "(no title)"
    )

    genres = tile.get("genres") or None
    flags = EPGFlags.IS_SERIES if tile.get("is_series") else None

    try:
        return EPGEntry(
            broadcast_id=EPGEntry.encode_broadcast_id(
                SimpliTVDefaults.PROVIDER_NAME, channel_codename, start
            ),
            title=title,
            description=tile.get("description") or "",
            start=start,
            end=end,
            icon=tile.get("icon"),
            program_id=programme.get("id"),
            episode_name=tile.get("episode_name") or None,
            genres=genres,
            # Kodi shows genre_description when genre is USE_STRING; no
            # DVB-SI mapping exists for simpliTV's category names yet.
            genre=EPGGenre.USE_STRING if genres else None,
            genre_description=", ".join(genres) if genres else None,
            season_number=tile.get("season_number"),
            flags=flags,
        )
    except (ValueError, TypeError) as e:
        logger.debug(
            f"simpliTV: skipping invalid programme "
            f"{programme.get('id')!r}: {e}"
        )
        return None


def _tile_to_program_details(tile: Dict[str, Any]) -> EPGProgramDetails:
    """
    Map a /v2/Tile/GetTiles tile to the shared EPGProgramDetails shape.

    EPGProgramDetails already carries genres, season/episode numbers,
    country_of_origin and series_id, so no base-model change is needed
    for those.

    Left out until verified against a raw tile: episode_number (the old
    parser stored `episodeId` as the number, but the name suggests an
    id), poster / backdrop (need the image `role` values), and
    cast_details.
    """
    cast, directors = _people_by_role(tile.get("people"))

    countries = tile.get("countries")
    country_of_origin = [
        c["name"]
        for c in (countries if isinstance(countries, list) else [])
        if isinstance(c, dict) and c.get("name")
    ]
    series_id = tile.get("seriesId")

    return EPGProgramDetails(
        program_id=tile.get("id", ""),
        description=tile.get("description", ""),
        episode_name=tile.get("subTitle", ""),
        year=_year_from(tile.get("date")),
        icon=_first_image_url(tile.get("images")),
        cast=cast or None,
        directors=directors or None,
        genres=_genre_names(tile.get("categories")) or None,
        season_number=_positive_int(tile.get("seasonNumber")),
        country_of_origin=country_of_origin or None,
        series_id=str(series_id) if series_id else None,
    )