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
    summary (title, description, icon, subtitle, genres, season/episode,
    ratings, credits) is cached per id, and the cache
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

import html
import re
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
    PersonData,
)
from ...base.utils.logger import logger

from .constants import SimpliTVDefaults
from .helpers import parse_iso, transport_errors

# GetTiles ids per request.
_TILE_BATCH = 500
# Upper bound on cached tile summaries; the oldest half is dropped when
# exceeded.
_TILE_CACHE_MAX = 50000
# Credits per role kept in the cached grid summary (get_program_details
# returns everyone). Keeps the cache compact for large ensemble casts.
_MAX_GRID_PEOPLE = 15

# seriesType "time-based" tiles (news, magazines, ...) carry the YEAR as
# seasonNumber and a running broadcast counter as episodeNumber (e.g.
# S2026 / E602). Kodi would render that literally, so by default such
# numbering is dropped. Set True to pass the raw values through.
KEEP_TIME_BASED_NUMBERING = False

# "04.10.2026 16:00." -- the API's placeholder subTitle for programmes
# that have no episode title.
_SUBTITLE_PLACEHOLDER = re.compile(
    r"^\d{1,2}\.\d{1,2}\.\d{4}(?: \d{1,2}:\d{2}(?::\d{2})?)?\.?$"
)
_TAG_RE = re.compile(r"<[^>]+>")

# tile["people"][i]["roleCodename"] -> credit bucket. "actor", "writer"
# and "creator" are verified against real tiles; the others are the
# expected codenames and are unverified. Unknown roles end up in
# "contributors" rather than being mislabelled as cast.
_ROLE_BUCKET = {
    "actor": "cast",
    "writer": "writers",
    "director": "directors",
    "producer": "producers",
    "presenter": "presenter",
    "composer": "composers",
    "creator": "contributors",
}


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

    @property
    def implements_epg(self) -> bool:
        """
        Always True. The ABC derives this from epg_window != (0, 0), but
        epg_window here is a (cached) GetAvailableDays request, and the
        flag is read on every get_epg call and in the registry listing.
        The window is informational and never (0, 0) (it falls back to
        the EPG_PAST_DAYS / EPG_FUTURE_DAYS constants).
        """
        return True

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
        return _tile_to_program_details(tile, program_id)

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


def _pick_image(images: Any, role: str) -> Optional[str]:
    """
    URL of the best image with the given `role` ("photo", "poster",
    "photo-details", "still"). A tile repeats the same photo in several
    sizes; prefer the entry flagged isMain, then type "large".
    """
    if not isinstance(images, list):
        return None
    cands = [
        i for i in images
        if isinstance(i, dict) and i.get("role") == role and i.get("url")
    ]
    if not cands:
        return None
    best = (
        next((i for i in cands if i.get("isMain")), None)
        or next((i for i in cands if i.get("type") == "large"), None)
        or cands[0]
    )
    return best["url"]


def _season_episode(tile: Dict[str, Any]) -> Tuple[Optional[int], Optional[int]]:
    """
    (season, episode) as 1-based ints, or (None, None).

    Time-based tiles (and tiles whose season equals the production
    year) carry year / broadcast-counter values, not real numbering;
    see KEEP_TIME_BASED_NUMBERING.
    """
    season = _positive_int(tile.get("seasonNumber"))
    episode = _positive_int(tile.get("episodeNumber"))
    if not KEEP_TIME_BASED_NUMBERING:
        if tile.get("seriesType") == "time-based":
            return None, None
        year = _year_from(tile.get("date"))
        if season is not None and year is not None and season == year:
            return None, None
    return season, episode


def _episode_name(tile: Dict[str, Any]) -> Optional[str]:
    """subTitle, unless it is the API's date/time placeholder."""
    name = str(tile.get("subTitle") or tile.get("subtitle") or "").strip()
    if not name or _SUBTITLE_PLACEHOLDER.match(name):
        return None
    return name


def _paragraphs(text: Any) -> List[str]:
    """Plain-text paragraphs of an HTML-ish description, de-duplicated."""
    raw = re.sub(r"<br\s*/?>", "\n", str(text or ""), flags=re.IGNORECASE)
    raw = html.unescape(_TAG_RE.sub("", raw))
    seen = set()
    out: List[str] = []
    for para in (x.strip() for x in raw.split("\n")):
        if para and para not in seen:
            seen.add(para)
            out.append(para)
    return out


def _descriptions(tile: Dict[str, Any]) -> Tuple[str, str]:
    """
    (description, plot_outline). `description` is a long text of the
    form "<episode synopsis><br /><br /><series blurb>" and sometimes
    repeats the same paragraph twice; tags are stripped and repeats
    dropped. The outline is shortDescription, left empty when it adds
    nothing over the description.
    """
    short = (
        " ".join(_paragraphs(tile.get("shortDescription")))
        or " ".join(_paragraphs(tile.get("tinyDescription")))
    )
    description = "\n\n".join(_paragraphs(tile.get("description"))) or short
    return description, ("" if short == description else short)


def _star_rating(value: Any) -> Optional[int]:
    """imdbRating (0-10 float) -> EPGEntry.star_rating (0-10 int)."""
    if isinstance(value, bool):
        return None
    try:
        rating = float(value)
    except (TypeError, ValueError):
        return None
    if not 0 < rating <= 10:
        return None
    return int(rating + 0.5)


def _person_name(p: Dict[str, Any]) -> str:
    """fullName (may have a leading space), else first + last name."""
    name = str(p.get("fullName") or "").strip()
    if not name:
        name = (
            f"{p.get('firstName') or ''} {p.get('lastName') or ''}"
        ).strip()
    return name or str(p.get("name") or "").strip()


def _split_people(people: Any) -> Dict[str, List[Dict[str, str]]]:
    """
    Group tile["people"] by credit bucket (see _ROLE_BUCKET), keeping
    API order and dropping repeats. Each item is {"id", "name", "role"}
    where `role` is functionDescription (empty when the API has none).
    """
    out: Dict[str, List[Dict[str, str]]] = {}
    seen = set()
    for p in people if isinstance(people, list) else []:
        if not isinstance(p, dict):
            continue
        name = _person_name(p)
        if not name:
            continue
        role = str(p.get("roleCodename") or p.get("role") or "").lower()
        bucket = _ROLE_BUCKET.get(role)
        if bucket is None:
            bucket = "directors" if "director" in role else "contributors"
        if (bucket, name) in seen:
            continue
        seen.add((bucket, name))
        out.setdefault(bucket, []).append({
            "id": str(p.get("id") or p.get("codename") or name),
            "name": name,
            "role": str(p.get("functionDescription") or "").strip(),
        })
    return out


def _names(
    buckets: Dict[str, List[Dict[str, str]]], bucket: str
) -> Optional[List[str]]:
    return [x["name"] for x in buckets.get(bucket, [])] or None


def _person_data(
    buckets: Dict[str, List[Dict[str, str]]], bucket: str
) -> Optional[List[PersonData]]:
    return [
        PersonData(
            id=x["id"],
            name=x["name"],
            roles=[x["role"]] if x["role"] else None,
        )
        for x in buckets.get(bucket, [])
    ] or None


def _summarise_tile(tile: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compact per-programme summary kept in the tile cache. Everything
    the grid needs from GetTiles is taken here, so no extra requests
    are made for genre / season / subtitle / credits.
    """
    description, outline = _descriptions(tile)
    season, episode = _season_episode(tile)
    title = str(tile.get("title") or "").strip()
    original = str(
        tile.get("orginalTitle")  # sic: the API's spelling
        or tile.get("originalTitle")
        or ""
    ).strip()

    buckets = _split_people(tile.get("people"))
    people: Dict[str, List[str]] = {}
    for bucket in ("cast", "directors", "writers", "producers"):
        names = _names(buckets, bucket)
        if names:
            people[bucket] = names[:_MAX_GRID_PEOPLE]

    return {
        "title": title,
        "original_title": original if original and original != title else "",
        "description": description,
        "plot_outline": outline,
        "icon": _pick_image(tile.get("images"), "photo")
        or _first_image_url(tile.get("images")),
        "episode_name": _episode_name(tile) or "",
        "genres": _genre_names(tile.get("categories")),
        "year": _year_from(tile.get("date")),
        "season_number": season,
        "episode_number": episode,
        "parental_rating": _as_int(tile.get("ageRating")),
        "star_rating": _star_rating(tile.get("imdbRating")),
        "is_series": bool(tile.get("seriesId")),
        "is_live": bool(tile.get("isLive") or tile.get("isLiveEvent")),
        "people": people,
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
    flags = EPGFlags.UNDEFINED
    if tile.get("is_series"):
        flags |= EPGFlags.IS_SERIES
    if tile.get("is_live"):
        flags |= EPGFlags.IS_LIVE
    people = tile.get("people") or {}

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
            plot_outline=tile.get("plot_outline") or None,
            episode_name=tile.get("episode_name") or None,
            original_title=tile.get("original_title") or None,
            year=tile.get("year"),
            cast=people.get("cast") or None,
            directors=people.get("directors") or None,
            writers=people.get("writers") or None,
            producers=people.get("producers") or None,
            genres=genres,
            # Kodi shows genre_description when genre is USE_STRING; no
            # DVB-SI mapping exists for simpliTV's category names yet.
            genre=EPGGenre.USE_STRING if genres else None,
            genre_description=", ".join(genres) if genres else None,
            season_number=tile.get("season_number"),
            episode_number=tile.get("episode_number"),
            star_rating=tile.get("star_rating"),
            parental_rating=tile.get("parental_rating"),
            flags=flags or None,
        )
    except (ValueError, TypeError) as e:
        logger.debug(
            f"simpliTV: skipping invalid programme "
            f"{programme.get('id')!r}: {e}"
        )
        return None


def _tile_to_program_details(
    tile: Dict[str, Any], program_id: Optional[str] = None
) -> EPGProgramDetails:
    """
    Map a /v2/Tile/GetTiles tile to the shared EPGProgramDetails shape.

    Absent values are None, never "": merge_content() overlays every
    non-None field onto the grid entry, so an empty string would wipe
    a value the entry already has (and an empty program_id would fail
    its mismatch check).

    Not mapped (no verified source in the tile): imdb_number,
    release_date (`date` is only a year), trailer, provider_vod_id.
    `backdrop` is taken from the "photo-details" image: the role is
    verified, its use as a backdrop is an assumption.
    """
    description, _ = _descriptions(tile)
    season, episode = _season_episode(tile)
    buckets = _split_people(tile.get("people"))

    countries = tile.get("countries")
    country_of_origin = [
        c["name"]
        for c in (countries if isinstance(countries, list) else [])
        if isinstance(c, dict) and c.get("name")
    ]
    series_id = tile.get("seriesId")
    images = tile.get("images")

    return EPGProgramDetails(
        program_id=str(tile.get("id") or program_id or ""),
        description=description or None,
        episode_name=_episode_name(tile),
        year=_year_from(tile.get("date")),
        icon=_pick_image(images, "photo") or _first_image_url(images),
        poster=_pick_image(images, "poster"),
        backdrop=_pick_image(images, "photo-details"),
        cast=_names(buckets, "cast"),
        directors=_names(buckets, "directors"),
        writers=_names(buckets, "writers"),
        producers=_names(buckets, "producers"),
        presenter=_names(buckets, "presenter"),
        composers=_names(buckets, "composers"),
        contributors=_names(buckets, "contributors"),
        cast_details=_person_data(buckets, "cast"),
        directors_details=_person_data(buckets, "directors"),
        writers_details=_person_data(buckets, "writers"),
        producers_details=_person_data(buckets, "producers"),
        presenter_details=_person_data(buckets, "presenter"),
        series_id=str(series_id) if series_id else None,
        genres=_genre_names(tile.get("categories")) or None,
        parental_rating=_as_int(tile.get("ageRating")),
        duration=_as_int(tile.get("durationSeconds")),
        season_number=season,
        episode_number=episode,
        country_of_origin=country_of_origin or None,
    )