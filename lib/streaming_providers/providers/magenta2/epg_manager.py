# streaming_providers/providers/magenta2/epg_manager.py
# -*- coding: utf-8 -*-
"""
EPG manager for the Magenta2 provider.

Uses the ThePlatform API:
- Schedule: mdeprod-all-channel-schedules
- Details:  mdeprod-all-programs
- Person Details: tvHubUrls.personDetailsUrl

Design:
- Single-shot window fetching for schedules (byListingTime=ISO~ISO)
- No authentication required (guest access) — only device/session IDs
- Bounded LRU caching for person name lookups
"""

from __future__ import annotations

import re
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ...base.models.epg_models import EPGEntry, EPGProgramDetails, PersonData
from ...base.utils.logger import logger
from ..lib_theplatform import paginate_feed, PaginationError
from .constants import DEFAULT_REQUEST_TIMEOUT


class Magenta2EpgManager:
    """
    Fetches and normalises EPG grid + programme-details data from the
    Magenta2 ThePlatform API.
    """

    _NO_RETRY_STATUSES: Set[int] = {400, 401, 403, 404}

    _STATION_ID_PATTERN = re.compile(r"/Station/(\d+)$")
    _CREDIT_ROLE_PATTERN = re.compile(r"-[a-z0-9]+-([a-z0-9]+)-")
    _PERSON_ID_PATTERN = re.compile(r"(gnp_\d+)$")

    _ROLE_MAP = {
        # Text role names (from dt$creditIds role segment and credits[].creditType)
        "director": "directors",
        "scriptwriter": "writers",
        "writer": "writers",
        "producer": "producers",
        "cast": "cast",
        "actor": "cast",
        "presenter": "presenter",
        "host": "presenter",
        "composer": "composers",
        "contributor": "contributors",
        # ThePlatform AD-series numeric credit type codes (lowercase)
        # Appear both as creditType in credits[] and as the role segment in dt$creditIds
        "ad1": "cast",        # Cast Member
        "ad2": "directors",   # Director
        "ad3": "producers",   # Producer
        "ad4": "writers",     # Writer / Scriptwriter
        "ad5": "composers",   # Composer
        "ad6": "presenter",   # Host / Moderator / Quizmaster
        "ad7": "cast",        # Guest (treated as cast)
    }

    _CACHE_MAX_SIZE = 1000

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

        self._person_details_template = self._resolve_person_details_template()
        self._person_cache: OrderedDict[str, Optional[PersonData]] = OrderedDict()

        logger.info(
            f"[Magenta2EpgManager] Initialised: "
            f"schedule_feed={self._schedule_feed_url is not None}, "
            f"programs_feed={self._programs_feed_url is not None}, "
            f"location_id={self._location_id is not None}, "
            f"person_details={self._person_details_template is not None}, "
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

    def _resolve_person_details_template(self) -> Optional[str]:
        if not self._provider_config or not self._provider_config.manifest:
            return None

        person_details_url = self._provider_config.manifest.tv_hubs.base_urls.get("personDetailsUrl")
        if not person_details_url:
            logger.debug("[Magenta2EpgManager] personDetailsUrl not found in tvHubUrls")
            return None

        if "{clientModel}" not in person_details_url or "{id}" not in person_details_url:
            logger.warning(
                f"[Magenta2EpgManager] personDetailsUrl template missing placeholders: {person_details_url}"
            )
            return None

        return person_details_url

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

                if status == 429:
                    retry_after_val = None
                    exc_response = getattr(exc, "response", None)
                    if exc_response and hasattr(exc_response, "headers"):
                        retry_after_val = exc_response.headers.get("Retry-After")

                    # Explicit type check for the type checker
                    if isinstance(retry_after_val, str) and retry_after_val.isdigit():
                        wait_time = int(retry_after_val)
                    else:
                        wait_time = 2 ** attempt

                    logger.warning(
                        f"[Magenta2EpgManager] {operation} rate limited (429), "
                        f"retrying in {wait_time}s: {exc}"
                    )
                    time.sleep(wait_time)
                elif attempt < max_retries - 1:
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
        if isinstance(ts, (int, str, float)):
            try:
                return int(ts) // 1000
            except (ValueError, TypeError):
                return None
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
        if not station_uri:
            return None
        match = Magenta2EpgManager._STATION_ID_PATTERN.search(station_uri)
        return match.group(1) if match else None

    @staticmethod
    def _extract_person_id_from_credit(credit_id: str) -> Optional[str]:
        if not credit_id:
            return None
        match = Magenta2EpgManager._PERSON_ID_PATTERN.search(credit_id)
        return match.group(1) if match else None

    def _resolve_entry_channel_id(self, entry: Dict[str, Any]) -> Optional[str]:
        listings = entry.get("listings", [])
        if not listings:
            return None

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

    def _get_client_model(self) -> Optional[str]:
        if not self._provider_config or not self._provider_config.bootstrap:
            return None
        return self._provider_config.bootstrap.client_model

    def _fetch_person_details(self, person_id: str) -> Optional[Dict[str, Any]]:
        if not person_id or not self._person_details_template:
            return None

        client_model = self._get_client_model()
        if not client_model:
            logger.warning("[Magenta2EpgManager] Cannot fetch person details: no client_model")
            return None

        url = self._person_details_template.replace("{clientModel}", client_model).replace("{id}", person_id)
        url = f"{url}?cid={uuid.uuid4()}"

        data = self._get_with_retry(url, operation="person_details")
        if not data:
            return None

        return data.get("content", {})

    def _get_person_data(self, person_id: str) -> Optional[PersonData]:
        """
        Resolve a person ID to a PersonData object, with bounded LRU caching.
        Caches None results to prevent repeated failures.
        """
        if person_id in self._person_cache:
            self._person_cache.move_to_end(person_id)
            return self._person_cache[person_id]

        details = self._fetch_person_details(person_id)
        person_data = None
        if details:
            image_url = None
            image_data = details.get("image")
            if image_data and isinstance(image_data, dict):
                image_url = image_data.get("href")

            person_data = PersonData(
                id=person_id,
                name=details.get("fullName", person_id),
                image=image_url,
                roles=details.get("roles")
            )

        self._person_cache[person_id] = person_data
        if len(self._person_cache) > self._CACHE_MAX_SIZE:
            self._person_cache.popitem(last=False)

        return person_data

    def _resolve_credits_from_list(
            self, credits: List[Dict[str, Any]]
    ) -> Tuple[Dict[str, Optional[List[str]]], Dict[str, Optional[List[PersonData]]]]:
        """Parse the ``credits`` array that ThePlatform includes on detail responses.

        This is the preferred path over ``_resolve_credit_names`` because:
        - ``personName`` is already resolved — no person-details API call needed.
        - ``creditType`` is a clean string (e.g. ``"AD6"``), not a regex-parsed segment.
        - ``personId`` is available for optional enrichment via ``_get_person_data``.

        Falls back to ``_get_person_data`` (person details API + LRU cache) only when
        ``personName`` is absent, so the person-details API is still used when useful.
        """
        string_buckets: Dict[str, Set[str]] = {
            "cast": set(), "directors": set(), "producers": set(),
            "writers": set(), "presenter": set(),
            "composers": set(), "contributors": set(),
        }
        detail_buckets: Dict[str, List[PersonData]] = {
            "cast": [], "directors": [], "producers": [],
            "writers": [], "presenter": [],
            "composers": [], "contributors": [],
        }

        for credit in credits or []:
            credit_type = credit.get("creditType", "").lower()
            bucket = self._ROLE_MAP.get(credit_type)
            if not bucket:
                continue

            person_name = credit.get("personName", "").strip()
            person_id_uri = credit.get("personId", "")
            person_id = self._extract_person_id_from_credit(person_id_uri) if person_id_uri else None

            if not person_name and person_id:
                # Name missing — try the person details API (cached)
                person_data = self._get_person_data(person_id)
                if person_data:
                    string_buckets[bucket].add(person_data.name)
                    detail_buckets[bucket].append(person_data)
                continue

            if not person_name:
                continue

            string_buckets[bucket].add(person_name)

            # Build PersonData: enrich from cache/API only if already cached to
            # avoid an extra API round-trip per person on every detail request.
            if person_id and person_id in self._person_cache:
                cached = self._person_cache[person_id]
                self._person_cache.move_to_end(person_id)
                if cached:
                    detail_buckets[bucket].append(cached)
                    continue

            detail_buckets[bucket].append(PersonData(
                id=person_id or person_name,
                name=person_name,
            ))

        final_strings = {
            key: sorted(values) if values else None
            for key, values in string_buckets.items()
        }
        final_details = {
            key: values if values else None
            for key, values in detail_buckets.items()
        }
        return final_strings, final_details

    def _resolve_credit_names(
            self, credit_ids: List[str]
    ) -> Tuple[Dict[str, Optional[List[str]]], Dict[str, Optional[List[PersonData]]]]:
        """
        Parse credit IDs into role buckets, resolving person names via API.
        Returns a tuple of: (string_buckets, person_data_buckets)
        """
        string_buckets: Dict[str, Set[str]] = {
            "cast": set(), "directors": set(), "producers": set(),
            "writers": set(), "presenter": set(),
            "composers": set(), "contributors": set(),
        }
        detail_buckets: Dict[str, List[PersonData]] = {
            "cast": [], "directors": [], "producers": [],
            "writers": [], "presenter": [],
            "composers": [], "contributors": [],
        }

        for credit_id in credit_ids or []:
            role = self._parse_credit_role(credit_id)
            if not role:
                continue

            bucket = self._ROLE_MAP.get(role)
            if bucket:
                person_id = self._extract_person_id_from_credit(credit_id)
                if person_id:
                    person_data = self._get_person_data(person_id)
                    if person_data:
                        string_buckets[bucket].add(person_data.name)
                        detail_buckets[bucket].append(person_data)
                    else:
                        string_buckets[bucket].add(credit_id)
                else:
                    string_buckets[bucket].add(credit_id)

        final_strings = {
            key: sorted(values) if values else None
            for key, values in string_buckets.items()
        }
        final_details = {
            key: values if values else None
            for key, values in detail_buckets.items()
        }

        return final_strings, final_details

    # ------------------------------------------------------------------
    # Programme details fetching
    # ------------------------------------------------------------------

    def _fetch_program_details(self, program_guid: str) -> Dict[str, Any]:
        if not program_guid or not self._programs_feed_url:
            return {}

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

    def _fetch_schedule(self, date_from: datetime, date_to: datetime) -> Dict[str, Any]:
        if not self._schedule_feed_url or not self._location_id:
            return {}

        utc_from = self._ensure_tz(date_from).astimezone(timezone.utc)
        utc_to = self._ensure_tz(date_to).astimezone(timezone.utc)
        start_iso = utc_from.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_iso = utc_to.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        logger.debug(f"[Magenta2EpgManager] Fetching schedule window {start_iso} ~ {end_iso} (UTC)")

        fields = (
            "listings.stationId,"
            "listings.program.guid,listings.program.title,"
            "listings.startTime,listings.endTime"
        )

        def _fetch_page(start_index: int, page_size: int) -> Optional[Dict[str, Any]]:
            url = (
                f"{self._schedule_feed_url}"
                f"?byListingTime={start_iso}~{end_iso}"
                f"&byLocationId={self._location_id}"
                f"&fields={fields}"
                f"&range={start_index}-{start_index + page_size - 1}"
                f"&cid={uuid.uuid4()}"
            )
            return self._get_with_retry(url, operation="epg_schedule_window")

        try:
            entries = paginate_feed(
                _fetch_page, items_per_page=200, max_pages=10, feed_name="epg_schedule_window"
            )
        except PaginationError as exc:
            logger.error(
                f"[Magenta2EpgManager] {exc} — EPG grid will be INCOMPLETE "
                f"({len(exc.partial_entries)} stations fetched before failure)"
            )
            entries = exc.partial_entries

        return {"entries": entries} if entries else {}

    # ------------------------------------------------------------------
    # Listing -> EPGEntry
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_icon(thumbnails: Dict[str, Any]) -> Optional[str]:
        """Return the best available poster/icon URL from a thumbnails dict.

        The API appends dimension suffixes to keys (e.g. ``posterWideNoTitle-0x0``),
        so we match by prefix rather than exact key equality.
        """
        for preferred in ("posterWideNoTitle", "mainWide", "HighResLandscape"):
            for key, entry in thumbnails.items():
                if key.startswith(preferred) and isinstance(entry, dict):
                    url = entry.get("url")
                    if url:
                        return url
        return None

    @staticmethod
    def _extract_backdrop(thumbnails: Dict[str, Any]) -> Optional[str]:
        """Return a wide/landscape backdrop URL from a thumbnails dict.

        Prefers the production-still variant over the generic landscape image.
        Keys have dimension suffixes, so we match by prefix.
        """
        for preferred in ("HighResLandscape", "HighResLandscapeProductionStill"):
            for key, entry in thumbnails.items():
                if key.startswith(preferred) and isinstance(entry, dict):
                    url = entry.get("url")
                    if url:
                        return url
        return None

    @staticmethod
    def _extract_genre(tags: List[Dict[str, Any]]) -> Optional[str]:
        """Return the first primary genre string (used by EPGEntry grid path)."""
        for tag in tags or []:
            scheme = tag.get("scheme", "")
            if scheme in ("genre-primary", "category"):
                title = tag.get("title")
                if title:
                    return title
        return None

    @staticmethod
    def _extract_genres(tags: List[Dict[str, Any]]) -> Optional[List[str]]:
        """Return all unique genre strings from primary and secondary genre tags.

        Used by the detail path to populate ``EPGProgramDetails.genres``.
        """
        seen: Dict[str, None] = {}  # ordered-set via insertion-order dict
        for tag in tags or []:
            scheme = tag.get("scheme", "")
            if scheme in ("genre-primary", "genre-secondary", "category"):
                title = tag.get("title")
                if title and title not in seen:
                    seen[title] = None
        return list(seen) if seen else None

    @staticmethod
    def _parse_parental_rating(ratings: List[Dict[str, Any]]) -> Optional[int]:
        """Extract a numeric parental rating from the ratings array.

        The API sends string values like ``"FSK12"`` or ``"UNKNOWN"``;
        we extract the trailing integer when present and return None otherwise.
        """
        for rating_obj in ratings or []:
            raw = rating_obj.get("rating", "")
            if not raw or raw.upper() == "UNKNOWN":
                continue
            digits = "".join(ch for ch in raw if ch.isdigit())
            if digits:
                return int(digits)
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

        details: Dict[str, Any] = {}
        credit_map: Dict[str, Optional[List[str]]] = {
            "cast": None, "directors": None, "producers": None,
            "writers": None, "presenter": None,
        }

        if self._fetch_details and program_guid:
            details = self._fetch_program_details(program_guid)
            # Prefer the credits[] array (names already resolved, clean creditType).
            # Fall back to dt$creditIds regex parsing only when credits[] is absent.
            credits_list = details.get("credits") or []
            if credits_list:
                credit_map, _ = self._resolve_credits_from_list(credits_list)
            else:
                credit_ids = details.get("dt$creditIds", [])
                if credit_ids:
                    credit_map, _ = self._resolve_credit_names(credit_ids)

        title = details.get("title") or title
        description = details.get("description")
        # secondaryTitle is the episode subtitle/guest line, not an alternate language title
        episode_name = details.get("secondaryTitle") or None
        year_raw = details.get("year")
        year = None
        if isinstance(year_raw, (int, str, float)):
            try:
                year = int(year_raw)
            except (ValueError, TypeError):
                year = None

        season_number = self._parse_episode_number(details.get("tvSeasonNumber"))
        episode_number = self._parse_episode_number(details.get("tvSeasonEpisodeNumber"))

        thumbnails = details.get("thumbnails", {}) or {}
        icon = self._extract_icon(thumbnails)

        tags = details.get("tags", []) or []
        genre_description = self._extract_genre(tags)

        parental_rating = self._parse_parental_rating(details.get("ratings") or [])

        return EPGEntry(
            broadcast_id=broadcast_id,
            title=title,
            start=start,
            end=end,
            program_id=program_guid,
            description=description,
            plot_outline=None,
            episode_name=episode_name,
            original_title=None,
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
            parental_rating=parental_rating,
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
            assert start_time is not None
            assert end_time is not None
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

        # Prefer credits[] (names pre-resolved, clean creditType).
        # Fall back to dt$creditIds + person API only when credits[] is absent.
        credits_list = raw.get("credits") or []
        if credits_list:
            credit_map, credit_details = self._resolve_credits_from_list(credits_list)
        else:
            credit_ids = raw.get("dt$creditIds", [])
            credit_map, credit_details = (
                self._resolve_credit_names(credit_ids) if credit_ids
                else (
                    {"cast": None, "directors": None, "producers": None,
                     "writers": None, "presenter": None,
                     "composers": None, "contributors": None},
                    {"cast": None, "directors": None, "producers": None,
                     "writers": None, "presenter": None,
                     "composers": None, "contributors": None},
                )
            )

        year_raw = raw.get("year")
        year = None
        if isinstance(year_raw, (int, str, float)):
            try:
                year = int(year_raw)
            except (ValueError, TypeError):
                year = None

        thumbnails = raw.get("thumbnails", {}) or {}
        tags = raw.get("tags", []) or []

        runtime_raw = raw.get("runtime")
        duration: Optional[int] = None
        if isinstance(runtime_raw, (int, float)):
            duration = int(runtime_raw)
        elif isinstance(runtime_raw, str):
            try:
                duration = int(float(runtime_raw))
            except (ValueError, TypeError):
                pass

        return EPGProgramDetails(
            program_id=program_id,
            description=raw.get("description"),
            episode_name=raw.get("secondaryTitle") or None,
            year=year,
            icon=self._extract_icon(thumbnails),
            backdrop=self._extract_backdrop(thumbnails),
            cast=credit_map["cast"],
            directors=credit_map["directors"],
            writers=credit_map["writers"],
            producers=credit_map["producers"],
            presenter=credit_map["presenter"],
            composers=credit_map["composers"],
            contributors=credit_map["contributors"],
            cast_details=credit_details["cast"],
            directors_details=credit_details["directors"],
            writers_details=credit_details["writers"],
            producers_details=credit_details["producers"],
            presenter_details=credit_details["presenter"],
            season_number=self._parse_episode_number(raw.get("tvSeasonNumber")),
            episode_number=self._parse_episode_number(raw.get("tvSeasonEpisodeNumber")),
            genres=self._extract_genres(tags),
            parental_rating=self._parse_parental_rating(raw.get("ratings") or []),
            duration=duration,
        )