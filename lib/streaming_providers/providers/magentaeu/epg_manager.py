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
* Programme details (description, credits, image) are fetched per-programme and
  cached in-memory via ``_ProgramDetailsCache`` to avoid hammering the API.
* Credit labels are localised per country because the bifrost API returns
  role names in the content language, sometimes ALL-CAPS (HR, ME).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ...base.utils.logger import logger
from .constants import (
    DEFAULT_REQUEST_TIMEOUT,
    SUPPORTED_COUNTRIES,
    get_app_key,
    get_bifrost_url,
    get_guest_headers,
    get_language,
    get_natco_key,
)


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
        """
        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"MagentaEUEpgManager: unsupported country '{country}'")

        self._country = country
        self._http = http_manager
        self._auth = authenticator
        self._cache = cache or _ProgramDetailsCache()
        self._role_map = _ROLE_MAPS.get(country, _ROLES_DE)
        self._bifrost_url = get_bifrost_url(country)
        self._natco_key = get_natco_key(country)
        self._app_language = get_language(country)
        self._app_key = get_app_key(country)

        logger.info(f"[MagentaEUEpgManager] Initialised for country={country}")

    # ------------------------------------------------------------------
    # Public API  (called by provider.get_epg)
    # ------------------------------------------------------------------

    def get_channel_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **_kwargs: Any,
    ) -> List[Dict[str, Any]]:
        """
        Fetch and normalise EPG for a single channel on the days covered by
        the requested window.

        Parameters
        ----------
        channel_id:  Station ID (theplatform Station URI) — identical to the
                     content_id stored on StreamingChannel / used as the key
                     in the bifrost schedules response.
        start_time:  Window start (datetime, aware or naive-UTC, or None → today).
        end_time:    Window end   (datetime, aware or naive-UTC, or None → today).

        Returns
        -------
        List of normalised programme dicts, filtered to the requested window,
        sorted by start time.  Empty list on any error.
        """
        date_from, date_to = self._resolve_window(start_time, end_time)

        # Collect the calendar dates spanned by the window
        dates: List[datetime] = []
        current = date_from.replace(hour=0, minute=0, second=0, microsecond=0)
        while current.date() <= date_to.date():
            dates.append(current)
            current = current + timedelta(days=1)

        programmes: List[Dict[str, Any]] = []

        for date in dates:
            raw_blocks = self._fetch_day_schedules(date)
            if not raw_blocks:
                continue
            day_items = self._extract_channel_items(raw_blocks, channel_id)
            for item in day_items:
                prog = self._parse_item(item, channel_id)
                if prog is None:
                    continue
                # Keep only programmes that overlap the requested window
                if prog["end"] <= int(date_from.timestamp()):
                    continue
                if prog["start"] >= int(date_to.timestamp()):
                    continue
                programmes.append(prog)

        programmes.sort(key=lambda p: p["start"])
        logger.info(
            f"[MagentaEUEpgManager/{self._country}] "
            f"{len(programmes)} programmes for channel {channel_id}"
        )
        return programmes

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _current_ids(self) -> Tuple[str, str]:
        """Return (device_id, session_id) from the authenticator token."""
        token = getattr(self._auth, "current_token", None)
        device_id = getattr(token, "device_id", "") or ""
        session_id = getattr(token, "session_id", "") or ""
        return device_id, session_id

    def _guest_headers(self, flow: str, step: str) -> Dict[str, str]:
        """Build request headers for a guest (unauthenticated) bifrost call."""
        device_id, session_id = self._current_ids()
        headers = get_guest_headers(self._country, device_id, session_id)
        headers.update(
            {
                "x-tv-flow": flow,
                "x-tv-step": step,
                "x-call-type": "GUEST_USER",
                "x-request-tracking-id": str(uuid.uuid4()),
            }
        )
        return headers

    def _fetch_day_schedules(self, date: datetime) -> Dict[str, Any]:
        """Fetch all 6-hour schedule blocks for *date*."""
        merged: Dict[str, Any] = {}
        headers = self._guest_headers(flow="EPG", step="EPG_SCHEDULES")
        formatted = date.strftime("%Y-%m-%d")

        # Change: 6-hour chunks (0, 6, 12, 18)
        for hour_offset in range(0, 24, 6):
            url = (
                f"{self._bifrost_url}/epg/channel/schedules"
                f"?date={formatted}"
                f"&hour_offset={hour_offset}"
                f"&hour_range=6"  # Changed from 3 to 6
                f"&channelMap_id="
                f"&filler=true"
                f"&app_language={self._app_language}"
                f"&natco_code={self._country}"
            )
            headers["x-request-tracking-id"] = str(uuid.uuid4())
            try:
                response = self._http.get(
                    url,
                    operation=f"epg_schedules_offset_{hour_offset}",
                    headers=headers,
                    timeout=DEFAULT_REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                merged[url] = response.json()
            except Exception as exc:
                logger.error(
                    f"[MagentaEUEpgManager/{self._country}] "
                    f"schedule fetch offset={hour_offset} date={formatted} failed: {exc}"
                )

        return merged

    def _fetch_program_details(self, program_id: str) -> Dict[str, Any]:
        """Fetch detailed metadata for a single programme (with in-memory cache)."""
        if not program_id:
            return {}

        cached = self._cache.get(self._country, program_id)
        if cached is not None:
            return cached

        url = (
            f"{self._bifrost_url}/details/program/{program_id}"
            f"?natco_key={self._natco_key}"
            f"&interacted_with_nPVR=false"
            f"&app_language={self._app_language}"
            f"&natco_code={self._country}"
        )
        headers = self._guest_headers(
            flow="SINGLE_PROGRAM_DETAIL", step="PROGRAM_METADATA"
        )
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
            return details
        except Exception as exc:
            logger.error(
                f"[MagentaEUEpgManager/{self._country}] "
                f"program details fetch failed for {program_id}: {exc}"
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

    def _parse_item(
        self, item: Dict[str, Any], channel_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Convert a single bifrost schedule item + its programme details into
        a normalised programme dict.

        Returns None if start/end cannot be parsed (programme is unusable).
        """
        start = self._parse_timestamp(item.get("start_time"))
        end = self._parse_timestamp(item.get("end_time"))
        if start is None or end is None or end <= start:
            return None

        program_id = item.get("program_id")
        details = self._fetch_program_details(program_id) if program_id else {}
        credit_map = self._parse_credits(details)

        # Genre: take the first genre name if present
        genres = item.get("genres") or []
        genre_description = genres[0].get("name") if genres else None

        # Release year — prefer schedule item, fall back to details
        year = item.get("release_year") or details.get("release_year")
        try:
            year = int(year) if year else None
        except (ValueError, TypeError):
            year = None

        # Season / episode — the API returns strings, and Gracenote encodes
        # "no real season" as a large placeholder (e.g. "20230000", "39170000").
        # Any value >= 9999 is treated as absent to avoid nonsense data.
        # Season: values >= 9999 are Gracenote year-encoded placeholders (e.g.
        # "20230000") meaning the show has no real season structure → treat as None.
        # Episode: no upper bound — long-running daily shows can have 2000+ episodes.
        season_number = self._parse_episode_number(item.get("season_number"), max_valid=9998)
        episode_number = self._parse_episode_number(item.get("episode_number"), max_valid=None)

        return {
            # Identifiers
            "channel_id": channel_id,
            "program_id": program_id,

            # Title & description
            "title": item.get("description") or item.get("title") or "Unknown",
            "description": (details.get("details") or {}).get("description"),
            "episode_name": item.get("episode_name"),

            # Episode info
            "season_number": season_number,
            "episode_number": episode_number,

            # Time (Unix timestamps)
            "start": start,
            "end": end,

            # Genre
            "genre_description": genre_description,

            # Credits
            "cast": credit_map["cast"],
            "directors": credit_map["directors"],
            "producers": credit_map["producers"],
            "writers": credit_map["writers"],
            "presenter": credit_map["presenter"],
            "composers": credit_map["composers"],
            "contributors": credit_map["contributors"],

            # Metadata
            "year": year,
            "image": details.get("poster_image_url"),
            "language": self._app_language,

            # Parental rating — schedule item returns a raw value (e.g. "12", "FSK 16").
            # Stored as-is in parental_rating_code; numeric extraction left to the consumer.
            "parental_rating_code": item.get("ratings") or None,
        }

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