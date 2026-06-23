# streaming_providers/providers/magenta2/epg_manager.py
# -*- coding: utf-8 -*-
"""
EPG manager for the Magenta2 provider.

Uses the ThePlatform API:
- Schedule: mdeprod-all-channel-schedules
- Details:  mdeprod-all-programs

Design:
- Single-shot window fetching for schedules (byListingTime=ISO~ISO)
- No in-memory caching (stateless)
- No authentication required (guest access) — only device/session IDs
"""

from __future__ import annotations

import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ...base.models.epg_models import EPGEntry, EPGProgramDetails
from ...base.utils.logger import logger
from .constants import DEFAULT_REQUEST_TIMEOUT


class Magenta2EpgManager:
    """
    Fetches and normalises EPG grid + programme-details data from the
    Magenta2 ThePlatform API.
    """

    # HTTP statuses that should never be retried
    _NO_RETRY_STATUSES: Set[int] = {400, 401, 403, 404}

    # Pattern to extract the numeric station ID from a stationId URI
    # e.g. "http://data.entertainment.tv.theplatform.eu/entertainment/data/Station/265809960047"
    # -> "265809960047"
    _STATION_ID_PATTERN = re.compile(r"/Station/(\d+)$")

    # Pattern to parse credit role from credit ID
    # e.g. "telekom.de-030d1565-director-gnp_1022271" -> "director"
    _CREDIT_ROLE_PATTERN = re.compile(r"-[a-z]+-([a-z]+)-")

    # Map credit role strings to bucket names
    _ROLE_MAP = {
        "director": "directors",
        "scriptwriter": "writers",
        "writer": "writers",
        "producer": "producers",
        "cast": "cast",
        "actor": "cast",
        "presenter": "presenter",
        "host": "presenter",
    }

    def __init__(
        self,
        endpoint_manager: Any,
        provider_config: Any,
        http_manager: Any,
        authenticator: Any,
        fetch_details: bool = True,
        default_past_days: int = 7,
        default_future_days: int = 13,
    ) -> None:
        self._endpoint_manager = endpoint_manager
        self._provider_config = provider_config
        self._http = http_manager
        self._auth = authenticator
        self._fetch_details = fetch_details
        self._default_past_days = default_past_days
        self._default_future_days = default_future_days

        self._schedule_feed_url = self._resolve_feed_url("allChannelSchedulesFeed")
        self._programs_feed_url = self._resolve_feed_url("allProgramsFeedUrl")
        self._location_id = self._get_location_id()

        logger.info(
            f"[Magenta2EpgManager] Initialised: "
            f"schedule_feed={self._schedule_feed_url is not None}, "
            f"programs_feed={self._programs_feed_url is not None}, "
            f"location_id={self._location_id is not None}, "
            f"fetch_details={fetch_details}"
        )

    # ------------------------------------------------------------------
    # URL resolution helpers
    # ------------------------------------------------------------------

    def _resolve_feed_url(self, feed_name: str) -> Optional[str]:
        if not self._provider_config or not self._provider_config.manifest:
            return None

        feed_template = self._provider_config.manifest.mpx.feeds.get(feed_name)
        if not feed_template:
            return None

        account_pid = self._provider_config.manifest.mpx.account_pid
        if not account_pid:
            return None

        return feed_template.replace("{MpxAccountPid}", account_pid)

    def _get_location_id(self) -> Optional[str]:
        if not self._provider_config or not self._provider_config.manifest:
            return None
        return self._provider_config.manifest.mpx.location_id_uri

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _current_ids(self) -> Tuple[str, str]:
        token = getattr(self._auth, "current_token", None)
        device_id = getattr(token, "device_id", "") or ""
        session_id = getattr(token, "session_id", "") or ""
        return device_id, session_id

    def _guest_headers(self) -> Dict[str, str]:
        device_id, session_id = self._current_ids()
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-dt-session-id": session_id,
            "x-dt-call-id": str(uuid.uuid4()),
        }
        if device_id:
            headers["x-dt-device-id"] = device_id
        return headers

    def _get_with_retry(self, url: str, operation: str) -> Optional[Dict[str, Any]]:
        headers = self._guest_headers()
        max_retries = 3

        for attempt in range(max_retries):
            headers["x-dt-call-id"] = str(uuid.uuid4())
            try:
                response = self._http.get(
                    url,
                    operation=operation,
                    headers=headers,
                    timeout=DEFAULT_REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                return response.json()
            except Exception as exc:
                status = getattr(getattr(exc, "response", None), "status_code", None)

                if status in self._NO_RETRY_STATUSES:
                    logger.warning(
                        f"[Magenta2EpgManager] {operation} failed with non-retryable "
                        f"status {status}, giving up: {exc}"
                    )
                    return None

                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.warning(
                        f"[Magenta2EpgManager] {operation} attempt {attempt + 1} "
                        f"failed, retrying in {wait_time}s: {exc}"
                    )
                    time.sleep(wait_time)
                else:
                    logger.error(
                        f"[Magenta2EpgManager] {operation} failed after "
                        f"{max_retries} attempts: {exc}"
                    )

        return None

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ensure_tz(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    @staticmethod
    def _parse_timestamp(ts: Optional[Any]) -> Optional[int]:
        if ts is None:
            return None
        try:
            return int(ts) // 1000
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_episode_number(value: Any) -> Optional[int]:
        if value is None:
            return None
        try:
            n = int(value)
            return n if n > 0 else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _extract_station_id(station_uri: str) -> Optional[str]:
        """Extract numeric station ID from a stationId URI."""
        if not station_uri:
            return None
        match = Magenta2EpgManager._STATION_ID_PATTERN.search(station_uri)
        return match.group(1) if match else None

    def _resolve_entry_channel_id(self, entry: Dict[str, Any]) -> Optional[str]:
        """Resolve the channel/station identifier from the entry's first listing."""
        listings = entry.get("listings", [])
        if not listings:
            return None

        # All listings in an entry share the same stationId
        first_listing = listings[0]
        station_id_uri = first_listing.get("stationId")
        if not station_id_uri:
            return None

        return self._extract_station_id(station_id_uri)

    # ------------------------------------------------------------------
    # Credit parsing from credit IDs
    # ------------------------------------------------------------------

    @classmethod
    def _parse_credit_role(cls, credit_id: str) -> Optional[str]:
        if not credit_id:
            return None
        match = cls._CREDIT_ROLE_PATTERN.search(credit_id)
        return match.group(1) if match else None

    @classmethod
    def _parse_credit_names_from_ids(
        cls, credit_ids: List[str]
    ) -> Dict[str, Optional[List[str]]]:
        """
        Parse credit IDs into role buckets.

        Credit IDs contain the role in their name pattern, but not the
        actual person's name. For now, we store the credit ID itself
        as a placeholder.
        """
        buckets: Dict[str, Set[str]] = {
            "cast": set(),
            "directors": set(),
            "producers": set(),
            "writers": set(),
            "presenter": set(),
        }

        for credit_id in credit_ids or []:
            role = cls._parse_credit_role(credit_id)
            if not role:
                continue

            bucket = cls._ROLE_MAP.get(role)
            if bucket:
                buckets[bucket].add(credit_id)

        return {
            key: sorted(values) if values else None
            for key, values in buckets.items()
        }

    # ------------------------------------------------------------------
    # Programme details fetching
    # ------------------------------------------------------------------

    def _fetch_program_details(self, program_guid: str) -> Dict[str, Any]:
        if not program_guid or not self._programs_feed_url:
            return {}

        # Don't restrict fields - get everything available
        url = (
            f"{self._programs_feed_url}"
            f"?byGuid={program_guid}"
            f"&cid={uuid.uuid4()}"
        )

        data = self._get_with_retry(url, operation="epg_program_details")
        if not data:
            return {}

        entries = data.get("entries", [])
        return entries[0] if entries else {}

    # ------------------------------------------------------------------
    # Schedule fetching
    # ------------------------------------------------------------------

    def _fetch_schedule(
        self,
        date_from: datetime,
        date_to: datetime,
    ) -> Dict[str, Any]:
        """
        Fetch the full schedule grid for the [date_from, date_to] window in
        a single ThePlatform API call using byListingTime=ISO~ISO.

        Returns the raw decoded JSON (with an "entries" list) or an empty
        dict on failure / missing config.
        """
        if not self._schedule_feed_url or not self._location_id:
            return {}

        utc_from = self._ensure_tz(date_from).astimezone(timezone.utc)
        utc_to = self._ensure_tz(date_to).astimezone(timezone.utc)

        # ThePlatform expects: YYYY-MM-DDTHH:MM:SS.000Z~YYYY-MM-DDTHH:MM:SS.000Z
        start_iso = utc_from.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_iso = utc_to.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        logger.debug(
            f"[Magenta2EpgManager] Fetching schedule window "
            f"{start_iso} ~ {end_iso} (UTC)"
        )

        # Schedule only needs: time, title, guid, stationId.
        # Everything else is fetched via get_program_details() on demand.
        fields = (
            "listings.stationId,"
            "listings.program.guid,listings.program.title,"
            "listings.startTime,listings.endTime"
        )

        url = (
            f"{self._schedule_feed_url}"
            f"?byListingTime={start_iso}~{end_iso}"
            f"&byLocationId={self._location_id}"
            f"&fields={fields}"
            f"&cid={uuid.uuid4()}"
        )

        data = self._get_with_retry(url, operation="epg_schedule_window")
        if data and data.get("entries"):
            return data
        return {}

    # ------------------------------------------------------------------
    # Listing -> EPGEntry
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_icon(thumbnails: Dict[str, Any]) -> Optional[str]:
        for preferred in ("posterWideNoTitle", "mainWide", "HighResLandscape"):
            entry = thumbnails.get(preferred)
            if entry:
                url = entry.get("url")
                if url:
                    return url
        return None

    @staticmethod
    def _extract_genre(tags: List[Dict[str, Any]]) -> Optional[str]:
        for tag in tags or []:
            scheme = tag.get("scheme", "")
            if scheme in ("genre-primary", "category"):
                title = tag.get("title")
                if title:
                    return title
        return None

    def _parse_item_to_entry(
            self,
            item: Dict[str, Any],
            channel_id: str,
            start: int,
            end: int,
            program: Dict[str, Any],
    ) -> Optional[EPGEntry]:
        program_guid = program.get("guid", "")
        title = program.get("title", "Unknown")

        broadcast_id = EPGEntry.encode_broadcast_id("magenta2", channel_id, start)

        # Only fetch details if enabled (should be False for grid)
        details: Dict[str, Any] = {}
        credit_map = {
            "cast": None,
            "directors": None,
            "producers": None,
            "writers": None,
            "presenter": None,
        }

        if self._fetch_details and program_guid:
            details = self._fetch_program_details(program_guid)
            credit_ids = details.get("dt$creditIds", [])
            if credit_ids:
                credit_map = self._parse_credit_names_from_ids(credit_ids)

        # Use details only if fetched, otherwise use schedule data
        title = details.get("title") or title
        description = details.get("description")
        original_title = details.get("secondaryTitle")
        year = details.get("year")
        if year is not None:
            try:
                year = int(year)
            except (ValueError, TypeError):
                year = None

        season_number = self._parse_episode_number(details.get("tvSeasonNumber"))
        episode_number = self._parse_episode_number(details.get("tvSeasonEpisodeNumber"))

        thumbnails = details.get("thumbnails", {}) or {}
        icon = self._extract_icon(thumbnails)

        tags = details.get("tags", [])
        genre_description = self._extract_genre(tags)

        return EPGEntry(
            broadcast_id=broadcast_id,
            title=title,
            start=start,
            end=end,
            program_id=program_guid,
            description=description,
            plot_outline=None,
            episode_name=None,
            original_title=original_title,
            year=year,
            icon=icon,
            cast=credit_map["cast"],
            directors=credit_map["directors"],
            writers=credit_map["writers"],
            genre=None,
            genre_sub_type=None,
            genre_description=genre_description,
            season_number=season_number,
            episode_number=episode_number,
            episode_part_number=None,
            star_rating=None,
            parental_rating=None,
            parental_rating_code=None,
            first_aired=None,
            imdb_number=None,
            series_link=None,
            flags=None,
        )

    # ------------------------------------------------------------------
    # Window resolution
    # ------------------------------------------------------------------

    def _resolve_window(
        self,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> Tuple[datetime, datetime]:
        def _to_utc(dt: datetime) -> datetime:
            return self._ensure_tz(dt).astimezone(timezone.utc)

        now_utc = datetime.now(tz=timezone.utc)

        if start_time is None and end_time is None:
            date_from = (now_utc - timedelta(days=self._default_past_days)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            date_to = (now_utc + timedelta(days=self._default_future_days)).replace(
                hour=23, minute=59, second=59, microsecond=0
            )
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
                "[Magenta2EpgManager] end_time is not after start_time — "
                "extending to end of start day"
            )
            date_to = date_from.replace(hour=23, minute=59, second=59, microsecond=0)

        return date_from, date_to

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_epg_grid(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        channel_ids: Optional[List[str]] = None,
        **_kwargs: Any,
    ) -> Dict[str, List[EPGEntry]]:
        """
        Build the EPG grid for the given window.

        Performs a single ThePlatform schedule request with
        byListingTime=start~end, then buckets listings per channel and
        filters by the resolved window + requested channel_ids.
        """
        date_from, date_to = self._resolve_window(start_time, end_time)
        ts_from, ts_to = int(date_from.timestamp()), int(date_to.timestamp())

        schedule_data = self._fetch_schedule(date_from, date_to)

        wanted = set(channel_ids) if channel_ids else None

        if not schedule_data:
            return {cid: [] for cid in wanted} if wanted else {}

        grid: Dict[str, List[EPGEntry]] = {}

        for entry in schedule_data.get("entries", []):
            channel_id = self._resolve_entry_channel_id(entry)
            if channel_id is None:
                continue
            if wanted is not None and channel_id not in wanted:
                continue

            bucket = grid.setdefault(channel_id, [])
            for item in entry.get("listings", []):
                start = self._parse_timestamp(item.get("startTime"))
                end = self._parse_timestamp(item.get("endTime"))
                if start is None or end is None or end <= start:
                    continue
                if end <= ts_from or start >= ts_to:
                    continue

                program = item.get("program", {}) or {}
                parsed = self._parse_item_to_entry(item, channel_id, start, end, program)
                if parsed:
                    bucket.append(parsed)

        for entries in grid.values():
            entries.sort(key=lambda p: p.start)

        if wanted is not None:
            for cid in wanted:
                grid.setdefault(cid, [])

        logger.info(
            f"[Magenta2EpgManager] Grid EPG: "
            f"{sum(len(v) for v in grid.values())} programmes across "
            f"{len(grid)} channels"
        )
        return grid

    def get_channel_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **_kwargs: Any,
    ) -> List[EPGEntry]:
        """Get EPG for a single channel (delegates to grid)."""
        result = self.get_epg_grid(
            start_time=start_time,
            end_time=end_time,
            channel_ids=[channel_id],
            **_kwargs,
        )
        return result.get(channel_id, [])

    def get_program_details(self, program_id: str) -> Optional[EPGProgramDetails]:
        if not program_id:
            return None

        raw = self._fetch_program_details(program_id)
        if not raw:
            return None

        credit_ids = raw.get("dt$creditIds", [])
        credit_map = {
            "cast": None,
            "directors": None,
            "producers": None,
            "writers": None,
            "presenter": None,
        }
        if credit_ids:
            credit_map = self._parse_credit_names_from_ids(credit_ids)

        year = raw.get("year")
        try:
            year = int(year) if year is not None else None
        except (ValueError, TypeError):
            year = None

        return EPGProgramDetails(
            program_id=program_id,
            description=raw.get("description"),
            episode_name=raw.get("secondaryTitle"),
            year=year,
            icon=self._extract_icon(raw.get("thumbnails", {}) or {}),
            cast=credit_map["cast"],
            directors=credit_map["directors"],
            writers=credit_map["writers"],
            producers=credit_map["producers"],
            presenter=credit_map["presenter"],
            composers=None,
            contributors=None,
        )