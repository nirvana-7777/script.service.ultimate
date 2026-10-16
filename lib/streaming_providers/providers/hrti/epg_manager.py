# streaming_providers/providers/hrti/epg_manager.py
"""
HRTi EPG Manager - Electronic Program Guide operations (v2).

Native endpoints (both web API, both POST):
    GetProgramme    one call covers 1..N channels - the web client sends all
                    ~23 ChannelReferenceIds in a single request, so
                    get_epg_grid() overrides the ABC's per-channel loop with
                    ONE native batch call.
    GetEpgDetails   per-programme enrichment (description, categories,
                    credits, production countries) -> EPGProgramDetails; also
                    carries the catchup / start-over stream URLs (FileName*)
                    which the catchup manager reads through get_epg_details().

Collaborators: exactly the four of the manager contract. ``auth`` is the HRTi
session (AuthProtocol plus device_id / ip_address / refresh - see api.api_post);
``config`` is the shared HRTiConfig with the lazily loaded endpoints.

Error contract (README §8):
    * transport / HTTP errors raise typed errors (via api.api_post); a 401 is
      answered there with ONE session refresh and exactly ONE retry
    * ErrorCode != 0 on either endpoint -> [] / None with a warning: for EPG
      "nothing there" is a valid answer and must not take the backend down
      (v1 warned and returned empty results as well)
    * a malformed single programme is skipped with a warning and never fails
      the whole channel

``limit`` / ``country`` arrive in **kw from the backend and are ignored on
purpose: the API has no server-side paging and HRTi is single-country ("HR").
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from ...base.managers.epg import EpgManager
from ...base.models.epg_models import (
    EPGEntry,
    EPGFlags,
    EPGGenre,
    EPGProgramDetails,
)
from ...base.utils.logger import logger
from .api import api_post
from .constants import HRTiConfig, HRTiDefaults


class HRTiEpgManager(EpgManager):
    """Manages HRTi EPG operations (GetProgramme / GetEpgDetails)."""

    # EPG window (v1 values, kept): 2 days back, 7 days forward
    PAST_DAYS = 2
    FUTURE_DAYS = 7

    # referer the web client uses on both EPG endpoints (v1 used "/tv")
    EPG_REFERER_PATH = "/live/programme"

    # WCF JSON date format "/Date(<milliseconds>)/"
    _DATE_RE = re.compile(r"/Date\((\d+)\)/")

    # Size guard for the programme -> channel hint map. Entries are two short
    # strings; cleared wholesale when exceeded - it is only a hint that every
    # grid fetch re-populates.
    _CHANNEL_HINT_CAP = 20000

    # HRTi category label -> DVB-SI genre (ETSI EN 300 468); labels are
    # upper-cased before the lookup. Same map as v1.
    _CATEGORY_GENRES = {
        "VIJESTI": EPGGenre.NEWSCURRENTAFFAIRS,
        "SPORT": EPGGenre.SPORTS,
        "GLAZBA": EPGGenre.MUSICBALLETDANCE,
        "IGRANI PROGRAM": EPGGenre.MOVIEDRAMA,
        "UMJETNOST I KULTURA": EPGGenre.ARTSCULTURE,
        "ZABAVA": EPGGenre.SHOW,
        "RELIGIJA": EPGGenre.SOCIALPOLITICALECONOMICS,
        "OBRAZOVANJE": EPGGenre.EDUCATIONALSCIENCE,
        "ZNANOST": EPGGenre.EDUCATIONALSCIENCE,
        "DRUGI INFORMATIVNI SADRŽAJI": EPGGenre.NEWSCURRENTAFFAIRS,
        "PROMOCIJA": EPGGenre.SHOW,
        "KOMERCIJALNI PROGRAMI": EPGGenre.SHOW,
    }

    def __init__(self, *, http_manager: Any, auth: Any, country: str,
                 config: HRTiConfig) -> None:
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        # EPG ReferenceID -> channel ReferenceID. GetEpgDetails wants BOTH ids
        # while the ABC hands get_program_details() only the programme id, so
        # the mapping is remembered while parsing grids (and from the
        # ChannelReferenceID of every details answer). Advisory only: a lost
        # update under concurrent grid fetches costs nothing but the empty
        # ChannelReferenceId fallback.
        self._channel_by_epg_id: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Capability (ABC)
    # ------------------------------------------------------------------

    @property
    def epg_window(self) -> Tuple[int, int]:
        """(past_days, future_days) - v1 window, kept unchanged."""
        return self.PAST_DAYS, self.FUTURE_DAYS

    # handles_channel_id(): the ABC default (True) is correct - every HRTi
    # channel, TV and radio alike, carries an EpgList.

    # ------------------------------------------------------------------
    # Schedule (ABC)
    # ------------------------------------------------------------------

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw: Any,
    ) -> List[EPGEntry]:
        """
        EPG for one channel (one GetProgramme call with a single id).

        ``channel_id`` is the Channel.content_id == the HRTi channel
        ReferenceID (e.g. "40013"). ``start_time``/``end_time`` are the
        timezone-aware UTC datetimes the backend hands down, already clamped
        to epg_window; called directly without times, the default window
        applies (2 days back / 7 days forward).

        **kw: ``limit`` and ``country`` arrive from the backend and are
        ignored on purpose (no server-side paging, single country).

        Returns [] when the channel has no programmes in the window ("nothing
        there" is not an error); transport/auth failures raise typed errors.
        """
        grid = self._fetch_programmes([channel_id], start_time, end_time)
        return grid.get(str(channel_id), [])

    def get_epg_grid(
        self,
        channel_ids: List[str],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw: Any,
    ) -> Dict[str, List[EPGEntry]]:
        """
        Native batch override: GetProgramme takes 1..N ChannelReferenceIds in
        one POST (the web client sends all ~23 at once), so the grid is ONE
        request, not the ABC's per-channel loop.

        Every requested channel id is present in the result (with [] when the
        API returns nothing for it). An empty ``channel_ids`` returns {} - the
        provider layer fills the ids from get_channels() when the backend
        passes none.

        One request for all channels also means one failure for all channels:
        there is no per-channel isolation here (ISOLATE_GRID_FAILURES only
        affects the default loop, which we do not use).
        """
        if not channel_ids:
            return {}
        return self._fetch_programmes(list(channel_ids), start_time, end_time)

    # ------------------------------------------------------------------
    # Programme details (ABC + HRTi-specific raw access)
    # ------------------------------------------------------------------

    def get_program_details(
        self, program_id: str, **kw: Any
    ) -> Optional[EPGProgramDetails]:
        """
        Enrichment for one programme (GetEpgDetails) -> EPGProgramDetails.

        ``program_id`` is the EPG ReferenceID - the value this manager puts
        into EPGEntry.program_id while parsing grids. The API also wants the
        channel id: it is remembered from grid parses (and from every details
        answer); an unknown programme falls back to an empty
        ChannelReferenceId (the v1 request shape), and a failing lookup
        simply yields None.
        """
        channel_id = self._channel_by_epg_id.get(program_id, "")
        raw = self.get_epg_details(channel_id, program_id)
        if not raw:
            return None
        return self._parse_program_details(raw, program_id)

    def get_epg_details(
        self, channel_id: str, reference_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Raw GetEpgDetails Result for one programme.

        HRTi-specific surface next to the ABC (NOT a delegated capability):
        the catchup manager reads FileName / FileNameStartOver (and the
        StartOver / PauseLiveTV / Npvr flags) from here - fields with no place
        on EPGProgramDetails. Intended flow for EPG-based catchup: the
        catchup manager takes this manager as a keyword-only ``epg=`` extra,
        asks get_epg() for the programme at start_time, takes its
        EPGEntry.program_id and calls this method.

        ``channel_id`` may be empty when unknown (see get_program_details).
        Returns None when the API has no details for the programme
        (ErrorCode != 0 - an optional endpoint).
        """
        payload = {
            "ChannelReferenceId": channel_id or "",
            "ReferenceId": reference_id,
        }
        return api_post(
            http_manager=self.http_manager,
            session=self.auth,
            config=self.config,
            endpoint_key="epg_details",
            payload=payload,
            referer_path=self.EPG_REFERER_PATH,
            required=False,
        )

    # ------------------------------------------------------------------
    # Core fetch
    # ------------------------------------------------------------------

    def _fetch_programmes(
        self,
        channel_ids: List[str],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> Dict[str, List[EPGEntry]]:
        """ONE GetProgramme call; every requested id is present in the dict."""
        ids = [str(cid) for cid in channel_ids if cid]
        start_time, end_time = self._resolve_range(start_time, end_time)
        payload = {
            "ChannelReferenceIds": ids,
            "StartTime": f"/Date({int(start_time.timestamp() * 1000)})/",
            "EndTime": f"/Date({int(end_time.timestamp() * 1000)})/",
        }

        logger.debug(
            f"HRTi EPG: GetProgramme for {len(ids)} channel(s), "
            f"{start_time.isoformat()} .. {end_time.isoformat()}"
        )

        # required=False: ErrorCode != 0 (or a missing Result) is "no EPG for
        # this request", not a failure - v1 warned and returned [] as well.
        result = api_post(
            http_manager=self.http_manager,
            session=self.auth,
            config=self.config,
            endpoint_key="programme",
            payload=payload,
            referer_path=self.EPG_REFERER_PATH,
            required=False,
        )

        grid: Dict[str, List[EPGEntry]] = {cid: [] for cid in ids}
        if result is None:
            logger.warning(
                "HRTi EPG: GetProgramme returned no result (ErrorCode != 0?)"
            )
            return grid
        if not result:
            return grid

        total = 0
        for channel_data in result:
            channel_id = channel_data.get("ReferenceID")
            if not channel_id:
                continue
            entries = []
            for item in channel_data.get("EpgList") or []:
                entry = self._parse_epg_item(item, str(channel_id))
                if entry is not None:
                    entries.append(entry)
            entries.sort(key=lambda e: e.start)
            grid[str(channel_id)] = entries
            total += len(entries)

        logger.debug(f"HRTi EPG: {total} programme(s) on {len(result)} channel(s)")
        return grid

    def _resolve_range(
        self, start_time: Optional[datetime], end_time: Optional[datetime]
    ) -> Tuple[datetime, datetime]:
        """
        Default window when called without times (the backend always hands
        clamped, timezone-aware datetimes - defaults only matter for direct
        calls). UTC "now" keeps the window correct regardless of the host's
        local timezone.
        """
        now = datetime.now(timezone.utc)
        if start_time is None:
            start_time = now - timedelta(days=self.PAST_DAYS)
        if end_time is None:
            end_time = now + timedelta(days=self.FUTURE_DAYS)
        return start_time, end_time

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_epg_item(
        self, item: Dict[str, Any], channel_id: str
    ) -> Optional[EPGEntry]:
        """
        One EpgList item -> EPGEntry (or None, skipped with a warning).

        Observed shape (GetProgramme):
            {"AdultContent": false, "CategoryReferenceId": "GLAZBA",
             "ContentRating": "", "ImagePath": "https://...",
             "ReferenceID": "2230531584",
             "TimeEnd": "/Date(1792094400000)/", "TimeEndUnixEpoch": 1792094400,
             "TimeStart": "/Date(1792087200000)/", "TimeStartUnixEpoch": 1792087200,
             "Title": "Mozart za spavalice"}

        Programme ids are per broadcast slot (channel + time), so ReferenceID
        becomes EPGEntry.program_id - the id get_program_details() expects.
        Grid items carry no description; that arrives via details (and
        EPGEntry.merge_details / merge_content on the caller side).
        """
        reference_id = item.get("ReferenceID")
        if reference_id is not None:
            self._remember_channel(str(reference_id), channel_id)

        title = str(item.get("Title") or "").strip()
        start = self._epoch_seconds(item.get("TimeStartUnixEpoch"), item.get("TimeStart"))
        end = self._epoch_seconds(item.get("TimeEndUnixEpoch"), item.get("TimeEnd"))

        if not title:
            logger.warning(f"HRTi EPG: skipping programme without title on channel {channel_id}")
            return None
        if not start or not end or end <= start:
            logger.warning(
                f"HRTi EPG: skipping programme '{title}' with invalid times ({reference_id})"
            )
            return None

        category = str(item.get("CategoryReferenceId") or "").strip() or None

        try:
            return EPGEntry(
                broadcast_id=EPGEntry.encode_broadcast_id(
                    HRTiDefaults.PROVIDER_NAME, channel_id, start
                ),
                title=title,
                start=start,
                end=end,
                program_id=str(reference_id) if reference_id is not None else None,
                description=item.get("DescriptionShort")
                or item.get("DescriptionLong")
                or None,
                icon=item.get("ImagePath") or None,
                genre=self._map_category_to_genre(category),
                genre_description=category,
                genres=[category] if category else None,
                parental_rating=self._parse_parental_rating(item.get("ContentRating")),
                flags=EPGFlags.IS_SERIES if item.get("IsSeries") else EPGFlags.UNDEFINED,
            )
        except ValueError as exc:  # EPGEntry post-init validation
            logger.warning(
                f"HRTi EPG: skipping invalid programme '{title}' on {channel_id}: {exc}"
            )
            return None

    def _parse_program_details(
        self, raw: Dict[str, Any], program_id: str
    ) -> EPGProgramDetails:
        """
        Map a GetEpgDetails Result onto EPGProgramDetails.

        Not mapped (no field on the model): OriginalTitle, ChannelName /
        ChannelIcon (channel manager data), ThumbnailsDefinitionURL,
        EpgRatingAverage, Price / IsPPVEvent, EnabledStreaming and the
        FileName* stream URLs (catchup manager, via get_epg_details()).
        """
        # self-healing hint map: details answers carry the channel id
        channel_ref = raw.get("ChannelReferenceID")
        if channel_ref:
            self._remember_channel(program_id, str(channel_ref))

        genres: List[str] = []
        for category in [raw.get("Category")] + list(raw.get("AdditionalCategories") or []):
            if category and category not in genres:
                genres.append(category)

        credits = self._parse_credits(raw.get("Credits"))

        # "Duration" is minutes (verified against the schedule: Duration == 11
        # for an 11-minute event) -> seconds, the unit the rest of the
        # codebase uses. Re-check on a longer programme during the device test.
        duration = None
        if isinstance(raw.get("Duration"), (int, float)):
            duration = int(raw["Duration"]) * 60

        countries = [c for c in (raw.get("ProductionCountries") or []) if c]

        return EPGProgramDetails(
            program_id=str(raw.get("ReferenceID") or program_id),
            description=raw.get("DescriptionLong") or raw.get("DescriptionShort") or None,
            icon=raw.get("ImagePath") or None,
            genres=genres or None,
            parental_rating=self._parse_parental_rating(raw.get("ContentRating")),
            duration=duration,
            country_of_origin=countries or None,
            **credits,
        )

    @staticmethod
    def _parse_credits(credits: Any) -> Dict[str, List[str]]:
        """
        Best-effort split of the Credits list into cast / directors / writers.

        Every observed response carries an empty list, so the item shape is
        INFERRED (name + role fields with Croatian or English role labels, or
        plain strings -> cast). Unknown shapes are skipped; credits must never
        fail the details parse. Verify on a programme with credits during the
        device test.
        """
        split: Dict[str, List[str]] = {}
        if not isinstance(credits, list):
            return split
        for credit in credits:
            if isinstance(credit, str):
                name, role = credit.strip(), ""
            elif isinstance(credit, dict):
                name = str(credit.get("Name") or credit.get("name") or "").strip()
                role = str(
                    credit.get("Role") or credit.get("role") or credit.get("RoleName") or ""
                ).strip().lower()
            else:
                continue
            if not name:
                continue
            if "redat" in role or "direct" in role:            # redatelj / director
                split.setdefault("directors", []).append(name)
            elif "scenar" in role or "writ" in role or "autor" in role:
                split.setdefault("writers", []).append(name)   # scenarist / writer
            else:                                              # glumac / rest
                split.setdefault("cast", []).append(name)
        return split

    @classmethod
    def _epoch_seconds(cls, epoch: Any, date_string: Any) -> Optional[int]:
        """
        Unix SECONDS from the API's double encoding: the *UnixEpoch field
        (already seconds) with the /Date(milliseconds)/ string as fallback.
        The conversion lives here because EPGEntry's coercion understands
        ints and ISO strings but not the WCF /Date()/ format.
        """
        if isinstance(epoch, (int, float)) and epoch > 0:
            return int(epoch)
        if isinstance(date_string, str):
            match = cls._DATE_RE.search(date_string)
            if match:
                return int(match.group(1)) // 1000
        return None

    @classmethod
    def _map_category_to_genre(cls, category: Optional[str]) -> Optional[int]:
        """HRTi category label -> DVB-SI genre type (ETSI EN 300 468)."""
        if not category:
            return None
        return cls._CATEGORY_GENRES.get(category.strip().upper(), EPGGenre.UNDEFINED)

    @staticmethod
    def _parse_parental_rating(rating: Any) -> Optional[int]:
        """Numeric age out of ContentRating ('', '12', 'FSK 12', '12+', 12)."""
        if rating is None:
            return None
        if isinstance(rating, (int, float)):
            value = int(rating)
            return value if value > 0 else None
        match = re.search(r"(\d+)", str(rating))
        return int(match.group(1)) if match else None

    def _remember_channel(self, epg_reference_id: str, channel_id: str) -> None:
        """Programme -> channel hint for GetEpgDetails (advisory, see __init__)."""
        if len(self._channel_by_epg_id) >= self._CHANNEL_HINT_CAP:
            self._channel_by_epg_id.clear()
        self._channel_by_epg_id[epg_reference_id] = channel_id