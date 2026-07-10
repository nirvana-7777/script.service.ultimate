# streaming_providers/providers/magentaeu/epg_manager.py
# -*- coding: utf-8 -*-
"""
EPG manager for all Magenta EU countries (AT, PL, HR, ME, HU).

Design notes
------------
* Self-contained — no dependency on epg_parser project classes
  (YoDigitalFetcher / YoDigitalParser / Channel / Programme are NOT used here).
* Reuses the provider's shared ``http_manager`` for all HTTP traffic so that
  proxy settings, retries, and connection pooling are all inherited.
* EPG is guest-access only (no bearer token required). Device/session IDs are
  read lazily from the authenticator token so they are always fresh after the
  first authentication.
* Returns ``List[Dict]`` from ``get_channel_epg()`` — the same raw-dict contract
  used by other native-EPG providers and expected by EPGOperations.
* ``get_channel_epg_batch()`` fetches schedule data once per calendar day and
  extracts all requested channels in a single pass.  For N channels over D days
  the cost is 4*D HTTP requests rather than 4*D*N.  Each day still requires 4
  sequential 6-hour chunks with a 1-second sleep between them; callers should
  budget ~4 seconds of wall-clock time per calendar day in the window.
* Programme details (description, credits, image) are fetched per-programme and
  cached in-memory via ``_ProgramDetailsCache`` to avoid hammering the API.
* Credit labels are localised per country because the bifrost API returns
  role names in the content language, sometimes ALL-CAPS (HR, ME).
"""

from __future__ import annotations

import time
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Any, Dict, List, Optional, Set, Tuple

from .utils import build_guest_headers
from ...base.utils.logger import logger
from ...base.models.epg_models import EPGEntry, EPGProgramDetails, EPGFlags
from .constants import (
    DEFAULT_REQUEST_TIMEOUT,
    SUPPORTED_COUNTRIES,
    get_app_key,
    get_bifrost_url,
    get_language,
    get_natco_key,
)

_VIENNA_TZ = ZoneInfo("Europe/Vienna")


# ---------------------------------------------------------------------------
# Lightweight in-memory programme details cache
# ---------------------------------------------------------------------------

class _ProgramDetailsCache:
    """
    Simple in-memory cache for programme detail dicts.

    Keyed by (natco_code, program_id).  Lives for the lifetime of the
    provider process — no disk I/O, no external dependency.
    """

    def __init__(self) -> None:
        self._store: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def get(self, natco_code: str, program_id: str) -> Optional[Dict[str, Any]]:
        return self._store.get((natco_code, program_id))

    def put(self, natco_code: str, program_id: str, data: Dict[str, Any]) -> None:
        self._store[(natco_code, program_id)] = data


# ---------------------------------------------------------------------------
# Localised credit-role labels
# ---------------------------------------------------------------------------
# The bifrost API returns role_name in the content language, not English.
# Each mapping translates the localised label → canonical credit bucket.
# Verified against actual epg_parser provider implementations.
# Note: HR uses ALL-CAPS labels as returned by the API.

_ROLES_DE: Dict[str, str] = {
    "Besetzung": "cast",
    "Regie": "directors",
    "Produktion": "producers",
    "Drehbuch": "writers",
    "Moderation": "presenter",
    "Musik": "composers",
    "songs": "composers",       # songwriter credit (English label used across AT content)
    "Mitarbeiter": "contributors",
    "Technik": "contributors",  # technical crew
}

_ROLES_PL: Dict[str, str] = {
    "Aktor": "cast",
    "Reżyser": "directors",
    "Producent": "producers",
    "Scenarzysta": "writers",
    "Prezenter": "presenter",
}

_ROLES_HR: Dict[str, str] = {
    # ALL-CAPS as returned by the bifrost API for HR
    "GLUMI": "cast",
    "REŽIJA": "directors",
    "PRODUKCIJA": "producers",
    "SCENARIJ": "writers",
    "AUTOR": "writers",       # second writer label — both map to the same bucket
    "VODITELJ": "presenter",
}

_ROLES_ME: Dict[str, str] = {
    "Glumi": "cast",
    "Režija": "directors",
    "Producent": "producers",
    "Scenarista": "writers",
    "Voditelj": "presenter",
}

_ROLES_HU: Dict[str, str] = {
    "Színész": "cast",
    "Rendező": "directors",
    "Producer": "producers",
    "Író": "writers",
    "Forgatókönyvíró": "writers",   # screenwriter — also maps to writers
    "Műsorvezető": "presenter",
    "Stáb": "contributors",
}

_ROLE_MAPS: Dict[str, Dict[str, str]] = {
    "at": _ROLES_DE,
    "hu": _ROLES_HU,
    "hr": _ROLES_HR,
    "me": _ROLES_ME,
    "pl": _ROLES_PL,
}


# ---------------------------------------------------------------------------
# MagentaEUEpgManager
# ---------------------------------------------------------------------------

class MagentaEUEpgManager:
    """
    Fetches and normalises EPG data from the Magenta EU bifrost API.

    Returns programme dicts with the following fields:

    Identifiers:
        channel_id (station_id), program_id

    Title & description:
        title, description, episode_name (sub-title)

    Episode info:
        season_number, episode_number

    Time (Unix timestamps — int):
        start, end

    Genre:
        genre_description

    Credits:
        cast, directors, producers, writers, presenter, composers, contributors
        (each a List[str] or None)

    Metadata:
        year, image (poster URL)
    """

    def __init__(
            self,
            country: str,
            http_manager: Any,
            authenticator: Any,
            cache: Optional[_ProgramDetailsCache] = None,
            fetch_details: bool = False,
    ) -> None:
        """
        Parameters
        ----------
        country:       Two-letter country code (at / pl / hr / me / hu).
        http_manager:  Provider's shared HTTPManager instance.
        authenticator: MagentaAuthenticator — used only to read device_id /
                       session_id from the current token (no auth calls made).
        cache:         Optional shared _ProgramDetailsCache.  A default in-memory
                       instance is created if omitted.
        fetch_details: If True, fetch full programme details (description, credits,
                       images). If False, only use schedule data (faster, fewer API calls).
        """
        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"MagentaEUEpgManager: unsupported country '{country}'")

        self._country = country
        self._http = http_manager
        self._auth = authenticator
        self._cache = cache or _ProgramDetailsCache()
        self._fetch_details = fetch_details
        self._role_map = _ROLE_MAPS.get(country, _ROLES_DE)
        self._bifrost_url = get_bifrost_url(country)
        self._natco_key = get_natco_key(country)
        self._app_language = get_language(country)
        self._app_key = get_app_key(country)

        logger.info(
            f"[MagentaEUEpgManager] Initialised for country={country}, "
            f"fetch_details={fetch_details}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_channel_epg(
            self,
            channel_id: str,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **_kwargs: Any,
    ) -> List[EPGEntry]:
        date_from, date_to = self._resolve_window(start_time, end_time)

        # Collect the calendar dates spanned by the window in UTC
        dates: List[datetime] = []
        current = date_from.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        utc_to = date_to.astimezone(timezone.utc)
        while current.date() <= utc_to.date():
            dates.append(current)
            current = current + timedelta(days=1)

        programmes: List[EPGEntry] = []
        ts_from = int(date_from.timestamp())
        ts_to = int(date_to.timestamp())

        for date in dates:
            # ✅ PASS THE TIME PARAMETERS!
            raw_blocks = self._fetch_day_schedules(date, start_time, end_time)
            if not raw_blocks:
                continue
            day_items = self._extract_channel_items(raw_blocks, channel_id)
            for item in day_items:
                entry = self._parse_item_to_entry(item, channel_id)
                if entry is None:
                    continue
                # Keep only programmes that overlap the requested window
                if entry.end <= ts_from:
                    continue
                if entry.start >= ts_to:
                    continue
                programmes.append(entry)

        programmes.sort(key=lambda p: p.start)
        logger.info(
            f"[MagentaEUEpgManager/{self._country}] "
            f"{len(programmes)} programmes for channel {channel_id}"
        )
        return programmes

    def get_channel_epg_batch(
            self,
            channel_ids: List[str],
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **_kwargs: Any,
    ) -> Dict[str, List[EPGEntry]]:
        if not channel_ids:
            return {}

        date_from, date_to = self._resolve_window(start_time, end_time)

        # Collect the calendar dates spanned by the window in UTC
        dates: List[datetime] = []
        current = date_from.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        utc_to = date_to.astimezone(timezone.utc)
        while current.date() <= utc_to.date():
            dates.append(current)
            current = current + timedelta(days=1)

        # Fetch ALL schedule data once per date (4 requests per day)
        all_schedule_blocks: Dict[str, Any] = {}
        for date in dates:
            # ✅ PASS THE TIME PARAMETERS!
            blocks = self._fetch_day_schedules(date, start_time, end_time)
            if blocks:
                all_schedule_blocks.update(blocks)

        if not all_schedule_blocks:
            return {channel_id: [] for channel_id in channel_ids}

        # Extract and parse items for all requested channels
        ts_from = int(date_from.timestamp())
        ts_to = int(date_to.timestamp())

        result: Dict[str, List[EPGEntry]] = {
            channel_id: [] for channel_id in channel_ids
        }

        for channel_id in channel_ids:
            items = self._extract_channel_items(all_schedule_blocks, channel_id)
            for item in items:
                entry = self._parse_item_to_entry(item, channel_id)
                if entry is None:
                    continue
                if entry.end <= ts_from:
                    continue
                if entry.start >= ts_to:
                    continue
                result[channel_id].append(entry)

        # Sort each channel's programmes by start time
        for channel_id in result:
            result[channel_id].sort(key=lambda p: p.start)

        logger.info(
            f"[MagentaEUEpgManager/{self._country}] "
            f"Batch EPG: {sum(len(v) for v in result.values())} programmes "
            f"across {len(channel_ids)} channels"
        )

        return result

    def get_program_details(self, program_id: str) -> Optional[EPGProgramDetails]:
        """
        Fetch detailed metadata for a single programme.

        Fetches the raw bifrost detail response (with in-memory caching) and
        maps it to an EPGProgramDetails instance.  Returns None if the
        programme is not found or the request fails.

        Parameters
        ----------
        program_id: Programme identifier as returned by the schedule API.
        """
        raw = self._fetch_program_details(program_id)
        if not raw:
            return None

        credit_map = self._parse_credits(raw)

        # Description lives under raw["details"]["description"]
        details_block = (raw.get("details") or {})
        description = details_block.get("description") or None

        # Release year
        year_raw = raw.get("release_year")
        try:
            year = int(year_raw) if year_raw else None
        except (ValueError, TypeError):
            year = None

        # Genres: details.metadata carries a GENRES-typed entry with a
        # comma-separated text value (e.g. "Serija, Telenovela"). This is
        # distinct from the schedule item's own `genres` list of
        # {id, name} dicts, which _parse_item_to_entry reads separately
        # into genre_description.
        genres = None
        for meta_entry in (details_block.get("metadata") or []):
            if meta_entry.get("type") == "GENRES" and meta_entry.get("value"):
                genres = [
                    g.strip() for g in meta_entry["value"].split(",") if g.strip()
                ] or None
                break

        # Parental rating: `ratings` is a numeric-looking string (e.g.
        # "12", "0"). Coerced to int when possible; left unset if
        # missing/non-numeric rather than fabricating a 0 rating.
        # NOTE: not yet confirmed whether "0" from the API means "no
        # restriction" or "no rating provided" - treated as a real 0
        # for now, flag if that turns out to be wrong.
        parental_rating = None
        ratings_raw = raw.get("ratings")
        if ratings_raw is not None:
            try:
                parental_rating = int(ratings_raw)
            except (ValueError, TypeError):
                parental_rating = None

        return EPGProgramDetails(
            program_id=program_id,
            description=description,
            episode_name=raw.get("episode_name") or None,
            year=year,
            icon=raw.get("poster_image_url") or None,
            cast=credit_map.get("cast"),
            directors=credit_map.get("directors"),
            writers=credit_map.get("writers"),
            producers=credit_map.get("producers"),
            presenter=credit_map.get("presenter"),
            composers=credit_map.get("composers"),
            contributors=credit_map.get("contributors"),
            genres=genres,
            parental_rating=parental_rating,
            duration=raw.get("runtime_seconds"),
            country_of_origin=raw.get("country_of_origin") or None,
            trailer=raw.get("trailer") or None,
        )

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _current_ids(self) -> Tuple[str, str]:
        """Return (device_id, session_id) for guest EPG requests.

        Sourced from the authenticator's guest session (get_guest_session_ids),
        which is validated and refreshed on its own TTL -- not read directly
        off current_token, since those values could otherwise go stale
        without ever being re-checked for the lifetime of the process.
        """
        if hasattr(self._auth, "get_guest_session_ids"):
            return self._auth.get_guest_session_ids()

        # Fallback for authenticators that don't implement guest sessions
        token = getattr(self._auth, "current_token", None)
        device_id = getattr(token, "device_id", "") or ""
        session_id = getattr(token, "session_id", "") or ""
        return device_id, session_id

    def _guest_headers(self, flow: str, step: str) -> Dict[str, str]:
        device_id, session_id = self._current_ids()
        return build_guest_headers(
            self._country, device_id, session_id, flow=flow, step=step
        )

    @staticmethod
    def _ensure_tz(dt: datetime) -> datetime:
        """Ensure datetime is timezone-aware (attach UTC if naive)."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    def _fetch_day_schedules(self, date: datetime, start_time: Optional[datetime] = None,
                             end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """Fetch only the 3-hour blocks that overlap with the requested time window.

        `date` and the window bounds are UTC-aware (per _resolve_window). The
        bifrost API's `date` / `hour_offset` params are plain UTC — confirmed
        empirically: hour_offset=N on a given date returns the UTC block
        [N:00, N+hour_range:00) of that UTC calendar day, with programs that
        overlap the block boundary returned in full (not clipped). No Vienna
        conversion belongs here; do not reintroduce it.
        """
        merged: Dict[str, Any] = {}

        utc_date = self._ensure_tz(date).astimezone(timezone.utc)
        formatted = utc_date.strftime("%Y-%m-%d")

        start_hour = 0
        end_hour = 24

        if start_time:
            utc_start = self._ensure_tz(start_time).astimezone(timezone.utc)
            if utc_start.date() == utc_date.date():
                start_hour = (utc_start.hour // 3) * 3
                logger.debug(
                    f"start_time UTC={utc_start}, hour_offset={start_hour}"
                )

        if end_time:
            utc_end = self._ensure_tz(end_time).astimezone(timezone.utc)
            if utc_end.date() == utc_date.date():
                # Calculate which block the end time falls into
                end_block = utc_end.hour // 3
                # If end time is EXACTLY at a block boundary, we don't need that block
                # If it's inside a block (even at the very start), we need it
                if utc_end.hour % 3 == 0 and utc_end.minute == 0 and utc_end.second == 0:
                    # Exactly at boundary (e.g., 15:00:00) → don't need the block
                    end_hour = end_block * 3
                else:
                    # Inside the block → need it
                    end_hour = (end_block + 1) * 3

        logger.debug(
            f"[MagentaEUEpgManager/{self._country}] "
            f"Fetching {formatted} hours {start_hour}-{end_hour} (UTC)"
        )

        for hour_offset in range(start_hour, end_hour, 3):
            url = (
                f"{self._bifrost_url}/epg/channel/schedules"
                f"?natco_key={self._natco_key}"
                f"&date={formatted}"
                f"&hour_offset={hour_offset}"
                f"&hour_range=3"
                f"&channelMap_id="
                f"&filler=true"
                f"&includeSyntheticChannels=false"
                f"&app_language={self._app_language}"
                f"&natco_code={self._country}"
            )
            # Add retry logic
            max_retries = 3
            block_success = False
            for attempt in range(max_retries):
                # Build a fresh, internally-consistent header set for every
                # single request (including retries). x-txn-id is a hash of
                # tracking-id + call-time, so all three must be regenerated
                # together — patching only tracking-id (as before) left
                # x-txn-id bound to a stale/mismatched tracking-id on every
                # request after the first, which upstream's edge (Akamai)
                # appears to reject as malformed/replayed.
                headers = self._guest_headers(flow="EPG", step="EPG_SCHEDULES")

                logger.debug(
                    f"[MagentaEUEpgManager/{self._country}] "
                    f"EPG request headers (offset={hour_offset}, attempt={attempt + 1}): {headers}"
                )

                try:
                    response = self._http.get(
                        url,
                        operation=f"epg_schedules_offset_{hour_offset}",
                        headers=headers,
                        timeout=DEFAULT_REQUEST_TIMEOUT,
                    )
                    response.raise_for_status()
                    merged[url] = response.json()
                    block_success = True
                    break  # Success, exit retry loop
                except Exception as exc:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt  # 1, 2, 4 seconds
                        logger.warning(
                            f"[MagentaEUEpgManager/{self._country}] "
                            f"schedule fetch offset={hour_offset} attempt {attempt + 1} failed, "
                            f"retrying in {wait_time}s: {exc}"
                        )
                        time.sleep(wait_time)
                    else:
                        logger.error(
                            f"[MagentaEUEpgManager/{self._country}] "
                            f"schedule fetch offset={hour_offset} failed after {max_retries} attempts: {exc}"
                        )

            # If the block failed after all retries, skip it and move to the next block
            if not block_success:
                logger.warning(
                    f"[MagentaEUEpgManager/{self._country}] "
                    f"Skipping block offset={hour_offset} due to server 500/503 errors."
                )
                continue

        return merged

    def _fetch_program_details(self, program_id: str) -> Dict[str, Any]:
        """Fetch detailed metadata for a single programme (with in-memory cache)."""
        if not program_id:
            return {}

        cached = self._cache.get(self._country, program_id)
        if cached is not None:
            return cached

        # program_id is always episode-scoped, even for series
        # (e.g. "HRT1-SH4506209-S4E236"), so a single endpoint handles
        # both movies and series episodes. The previous "-SH" in
        # program_id branch routed series episodes to
        # /details/series/{program_id}, which is not a valid endpoint
        # shape for an episode-scoped ID (only for the bare series ID)
        # and returned empty description/genres/ratings as a result.
        endpoint = f"/details/program/{program_id}"
        flow = "SINGLE_PROGRAM_DETAIL"
        step = "PROGRAM_METADATA"

        url = (
            f"{self._bifrost_url}{endpoint}"
            f"?natco_key={self._natco_key}"
            f"&interacted_with_nPVR=false"
            f"&app_language={self._app_language}"
            f"&natco_code={self._country}"
        )
        headers = self._guest_headers(flow=flow, step=step)

        try:
            response = self._http.get(
                url,
                operation="epg_program_details",
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            details = response.json()
            if details:
                self._cache.put(self._country, program_id, details)
                logger.debug(
                    f"[{self._country}] Found details for {program_id} "
                    f"using {endpoint} endpoint"
                )
                # TEMP DEBUG: dump raw response to confirm season_number/
                # episode_number key names for /details/program/ before
                # mapping them in get_program_details(). Remove once confirmed.
                logger.info(
                    f"[{self._country}] TEMP DEBUG raw /details/program/ response "
                    f"for {program_id}: {json.dumps(details, ensure_ascii=False)}"
                )
            return details
        except Exception as exc:
            logger.error(
                f"[{self._country}] Program details fetch failed for {program_id}: {exc}"
            )
            return {}

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_channel_items(
        schedule_blocks: Dict[str, Any], channel_id: str
    ) -> List[Dict[str, Any]]:
        """
        Collect all schedule items for *channel_id* across all fetched blocks
        and return them sorted by start_time string.
        """
        items: List[Dict[str, Any]] = []
        for data in schedule_blocks.values():
            channels_map = (data or {}).get("channels", {})
            items.extend(channels_map.get(channel_id, []))
        items.sort(key=lambda x: x.get("start_time", ""))
        return items

    def _parse_credits(
        self, details: Dict[str, Any]
    ) -> Dict[str, Optional[List[str]]]:
        """
        Parse the ``roles`` list from programme details into credit buckets.

        Returns a dict with keys: cast, directors, producers, writers,
        presenter, composers, contributors — each a sorted List[str] or None.
        """
        buckets: Dict[str, Set[str]] = {
            k: set() for k in
            ["cast", "directors", "producers", "writers",
             "presenter", "composers", "contributors"]
        }

        for role in (details.get("roles") or []):
            role_name = role.get("role_name")
            person_name = role.get("person_name")
            if not role_name or not person_name:
                continue
            bucket = self._role_map.get(role_name)
            if bucket:
                buckets[bucket].add(person_name)
            else:
                logger.debug(
                    f"[MagentaEUEpgManager/{self._country}] "
                    f"unmapped role '{role_name}' for '{person_name}'"
                )

        return {k: sorted(v) if v else None for k, v in buckets.items()}

    @staticmethod
    def _parse_episode_number(value: Any, max_valid: Optional[int] = None) -> Optional[int]:
        """
        Parse a season or episode number from the API response.

        The bifrost/Gracenote API always returns these as strings. When a show
        has no real season structure Gracenote encodes a year-based placeholder
        (e.g. "20230000", "39170000"). Pass max_valid to discard values above a
        threshold (season numbers only — episode numbers have no upper bound).
        """
        if value is None:
            return None
        try:
            n = int(value)
            if n <= 0:
                return None
            if max_valid is not None and n > max_valid:
                return None
            return n
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_timestamp(iso_str: Optional[str]) -> Optional[int]:
        """Parse an ISO-8601 datetime string to a Unix timestamp (int seconds)."""
        if not iso_str:
            return None
        try:
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            return int(dt.timestamp())
        except (ValueError, AttributeError):
            return None

    def _parse_item_to_entry(
            self, item: Dict[str, Any], channel_id: str
    ) -> Optional[EPGEntry]:
        """
        Convert a single bifrost schedule item into an EPGEntry object.
        """
        # Parse time range - required fields
        start = self._parse_timestamp(item.get("start_time"))
        end = self._parse_timestamp(item.get("end_time"))
        if start is None or end is None or end <= start:
            return None

        # Get the original program_id from the API
        program_id = item.get("program_id")

        # Generate broadcast_id (integer for Kodi)
        if program_id:
            try:
                # If program_id is numeric, use it directly
                broadcast_id = int(program_id)
            except (ValueError, TypeError):
                # Otherwise encode deterministically with provider info
                broadcast_id = EPGEntry.encode_broadcast_id(
                    self._country,  # provider name
                    channel_id,  # channel ID
                    start  # start timestamp
                )
        else:
            # No program_id - encode from channel + start
            broadcast_id = EPGEntry.encode_broadcast_id(
                self._country,
                channel_id,
                start
            )

        # Fetch programme details if enabled
        details = {}
        credit_map = {
            "cast": None,
            "directors": None,
            "producers": None,
            "writers": None,
            "presenter": None,
            "composers": None,
            "contributors": None,
        }

        if self._fetch_details and program_id:
            details = self._fetch_program_details(program_id)
            credit_map = self._parse_credits(details)

        # Genre: take the first genre name if present
        genres = item.get("genres") or []
        genre_description = genres[0].get("name") if genres else None

        # Release year — prefer schedule item, fall back to details (if fetched)
        year = item.get("release_year")
        if not year and details:
            year = details.get("release_year")
        try:
            year = int(year) if year else None
        except (ValueError, TypeError):
            year = None

        # Season / episode
        season_number = self._parse_episode_number(
            item.get("season_number"), max_valid=9998
        )
        episode_number = self._parse_episode_number(
            item.get("episode_number"), max_valid=None
        )

        # Flags — only derivable when details were fetched
        flags = None
        if details:
            flag_bits = []
            if details.get("is_live"):
                flag_bits.append(EPGFlags.IS_LIVE)
            if details.get("show_type") == "TVShow":
                flag_bits.append(EPGFlags.IS_SERIES)
            if flag_bits:
                flags = EPGFlags.combine(*flag_bits)

        # Build EPGEntry with both IDs
        return EPGEntry(
            # Required fields
            broadcast_id=broadcast_id,  # Integer for Kodi
            title=item.get("description") or item.get("title") or "Unknown",
            start=start,
            end=end,

            # API identifier (stored but not sent to Kodi)
            program_id=program_id,  # Original string from API

            # Optional fields - Programme Information
            description=(details.get("details") or {}).get("description") if details else None,
            plot_outline=None,  # Not available from bifrost API
            episode_name=item.get("episode_name"),
            original_title=None,  # Not available from bifrost API

            # Optional fields - Media Metadata
            year=year,
            icon=details.get("poster_image_url") if details else None,

            # Optional fields - People
            cast=credit_map["cast"],
            directors=credit_map["directors"],
            writers=credit_map["writers"],
            producers=credit_map["producers"],

            # Optional fields - Genre/Category
            genre=None,  # Not using numeric DVB-SI genres
            genre_sub_type=None,
            genre_description=genre_description,

            # Optional fields - Episode Information
            season_number=season_number,
            episode_number=episode_number,
            episode_part_number=None,  # Not available from bifrost API

            # Optional fields - Ratings
            star_rating=None,  # Not available from bifrost API
            parental_rating=None,  # Not using numeric rating
            parental_rating_code=item.get("ratings"),

            # Optional fields - Additional Metadata
            first_aired=None,  # Not available from bifrost API
            imdb_number=None,  # Not available from bifrost API
            series_link=None,  # Not available from bifrost API
            flags=flags, # Could be set based on programme properties if needed
        )

    # ------------------------------------------------------------------
    # Window resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_window(
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> Tuple[datetime, datetime]:
        """
        Normalise start/end to UTC-aware datetimes.

        Defaults: start → today 00:00 UTC, end → today 23:59:59 UTC.
        """
        def _to_utc(dt: datetime) -> datetime:
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)

        now_utc = datetime.now(tz=timezone.utc)

        if start_time is None and end_time is None:
            date_from = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
            date_to = now_utc.replace(hour=23, minute=59, second=59, microsecond=0)
        elif start_time is not None and end_time is None:
            date_from = _to_utc(start_time)
            date_to = date_from.replace(hour=23, minute=59, second=59, microsecond=0)
        elif start_time is None and end_time is not None:
            date_to = _to_utc(end_time)
            date_from = date_to.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            date_from = _to_utc(start_time)
            date_to = _to_utc(end_time)

        if date_to <= date_from:
            logger.warning(
                "[MagentaEUEpgManager] end_time is not after start_time — "
                "extending to end of start day"
            )
            date_to = date_from.replace(hour=23, minute=59, second=59, microsecond=0)

        return date_from, date_to