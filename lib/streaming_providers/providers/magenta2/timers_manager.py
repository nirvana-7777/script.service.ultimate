# streaming_providers/providers/magenta2/timers_manager.py
"""
Magenta2 Timers Manager

Handles nPVR timer (scheduled recording) CRUD for the Magenta2 provider
using the Audience nPVR API.

API overview
------------
Base URL:
    Same as RecordingsManager — discovered from manifest["mpx"]["pvrBaseUrl"]:
        https://audience.npvr.eu.theplatform.com/npvr-audience/2709353023

List timers (SCHEDULED recordings):
    GET  {pvr_base_url}/get-recordings
    Query params:  limit, offset, byRecordingStatus=SCHEDULED
    Authorization: Basic {persona_token}
    Accept:        application/json; v=2; charset=utf-8

Schedule a new timer  (confirmed via live capture):
    POST {pvr_base_url}/schedule-recording-for-listing/{listing_guid}?cid={cid}
    Body:          {"stationReferences": ["das_erste_hd"],
                    "startOffsetSeconds": 60, "endOffsetSeconds": 300}
    Authorization: Basic {persona_token}
    Content-Type:  application/json;v=3
    Response:      202 Accepted (asynchronous — no recording object is
                   guaranteed in the body)

Delete a timer  (confirmed via live capture):
    DELETE {pvr_base_url}/delete-recording-for-listing/{listing_guid}?cid={cid}
    Authorization: Basic {persona_token}
    Response:      202 Accepted

    Deletion is addressed by LISTING GUID, not by recording id.

Update an existing timer:
    No dedicated endpoint has been captured.  update_timer() is implemented
    as delete + re-schedule using the two confirmed endpoints above.

The ``cid`` query parameter
---------------------------
Format ``{session_uuid}::{call_uuid}`` (two UUIDv1).  In the captures the
first part is identical across requests of one session, the second part
changes per request.  It is sent URL-encoded (``%3A%3A``).  If the provider
already has a CID generator (e.g. for the concurrency unlock), pass it as
``cid_callback`` so both share the same session id.

Public interface
----------------
    timers_manager.get_timers(**kwargs) -> List[Timer]

    timers_manager.add_timer(timer: Timer) -> Timer

    timers_manager.update_timer(timer: Timer) -> Timer

    timers_manager.delete_timer(client_index: int,
                                force_delete: bool = False) -> None

    timers_manager.get_timer_types() -> List[TimerType]

client_index vs. listing GUID
-----------------------------
The PVR contract needs an int ``client_index``; the nPVR recording id is a hex
string, so ``client_index`` is a lossy hash of it and cannot be turned back
into an id.  Because the delete endpoint works on the listing GUID, this
manager keeps a ``client_index -> listing_guid`` map that is filled by
get_timers() / add_timer() and refreshed on demand.

Relationship to RecordingsManager
----------------------------------
Both managers talk to the same nPVR base URL and use the same auth scheme.
Shared HTTP/auth plumbing lives in PvrHttpMixin (pvr_helpers.py).
Shared parsing utilities live in PvrHelpers (pvr_helpers.py).

Timers are SCHEDULED recordings that have not yet been captured.  After the
broadcast window passes the backend transitions them to RECORDING → GENERATED,
at which point RecordingsManager takes ownership of the object.
"""

import copy
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional
from urllib.parse import quote

from ...base.models.timer import Timer, TimerState
from ...base.models.timer_type import TimerType, TimerTypeAttribute
from ...base.utils.logger import logger

from .constants import (
    PVR_DEFAULT_PAGE_LIMIT,
    PVR_MAX_PAGE_LIMIT,
    PVR_GET_RECORDINGS_PATH,
    PVR_TIMER_TYPE_EPG_ONE_SHOT,
    PVR_RECORDING_STATUSES_TIMERS,
)
from .pvr_helpers import PvrHelpers, PvrHttpMixin

# TODO: move into constants.py alongside PVR_GET_RECORDINGS_PATH once stable.
# Both confirmed via live network capture: schedule and delete are addressed
# by listing GUID, not by recording id.
PVR_SCHEDULE_RECORDING_PATH = "/schedule-recording-for-listing"
PVR_DELETE_RECORDING_PATH   = "/delete-recording-for-listing"

# Content-Type observed on the schedule request.  NOTE: PvrHttpMixin._post()
# must send this (the old docs said "v=2; charset=utf-8").
PVR_TIMER_CONTENT_TYPE = "application/json;v=3"

# Safety cap when paging through all timers to refresh the index map.
_MAX_REFRESH_PAGES = 20

# Listing GUIDs are formed as "{stationReference}_{8-hex-char program id}",
# e.g. "das_erste_hd_033182e7" -> stationReference "das_erste_hd".
_LISTING_GUID_STATION_RE = re.compile(r"^(?P<station_ref>.+)_[0-9a-f]{8}$")


class TimersManager(PvrHttpMixin):
    """
    Manages Magenta2 nPVR timer CRUD.

    Constructor mirrors RecordingsManager for symmetry — both are created by
    the parent provider and share the same http_manager + auth callback.

    Args:
        http_manager:          HTTPManager instance from the parent provider.
        provider_name:         Provider identifier string (e.g. ``"magenta2"``).
        provider_config:       ProviderConfig; supplies ``pvr_base_url``.
        auth_headers_callback: ``() -> Dict[str, str]`` returning per-request
                               headers with ``Authorization: Basic {persona}``.
        cid_callback:          Optional ``() -> str`` returning a fresh
                               ``{session}::{call}`` correlation id.  When
                               omitted, a per-instance session UUID and a
                               per-request call UUID are generated.
    """

    def __init__(
        self,
        http_manager,
        provider_name: str,
        provider_config=None,
        auth_headers_callback=None,
        cid_callback: Optional[Callable[[], str]] = None,
    ):
        self._http                  = http_manager
        self._provider              = provider_name
        self._provider_config       = provider_config
        self._auth_headers_callback = auth_headers_callback
        self._cid_callback          = cid_callback

        self._session_id            = str(uuid.uuid1())
        self._index_lock            = threading.Lock()
        self._listing_by_index: Dict[int, str] = {}

    # =========================================================================
    # Timer types
    # =========================================================================

    @staticmethod
    def get_timer_types() -> List[TimerType]:
        """
        Return the timer types supported by Magenta2.

        Currently Magenta2 supports EPG-based one-shot timers only.  The
        listing GUID is required at creation time (REQUIRES_EPG_TAG_ON_CREATE)
        because it is part of the schedule-recording-for-listing URL.

        Extend this list when the API confirms support for manual or
        recurring timers.
        """
        return [
            TimerType(
                type_id=PVR_TIMER_TYPE_EPG_ONE_SHOT,
                description="EPG-based one-time recording",
                attributes=(
                    TimerTypeAttribute.IS_EPG_BASED
                    | TimerTypeAttribute.SUPPORTS_CHANNELS
                    | TimerTypeAttribute.SUPPORTS_START_TIME
                    | TimerTypeAttribute.SUPPORTS_END_TIME
                    | TimerTypeAttribute.SUPPORTS_PADDING
                    | TimerTypeAttribute.REQUIRES_EPG_TAG_ON_CREATE
                ),
            )
        ]

    # =========================================================================
    # Public API
    # =========================================================================

    def get_timers(
        self,
        *,
        limit: int = PVR_DEFAULT_PAGE_LIMIT,
        offset: int = 1,
    ) -> List[Timer]:
        """
        Fetch SCHEDULED timers from the nPVR API (one page).

        The API is paginated (same as get-recordings).  Call again with an
        incremented ``offset`` to page through all results.

        Also refreshes the ``client_index -> listing_guid`` map used by
        delete_timer() / update_timer().

        Args:
            limit:  Maximum timers per request. Capped at PVR_MAX_PAGE_LIMIT.
            offset: 1-based page offset.

        Returns:
            List of :class:`Timer` objects ordered as returned by the API.

        Raises:
            RuntimeError: When auth_headers_callback is missing or the API
                          returns a non-200 status.
        """
        pvr_base_url = self._get_pvr_base_url()
        url = f"{pvr_base_url}{PVR_GET_RECORDINGS_PATH}"

        params = {
            "limit": min(limit, PVR_MAX_PAGE_LIMIT),
            "offset": offset,
            "byRecordingStatus": "|".join(PVR_RECORDING_STATUSES_TIMERS),
        }

        data = self._get(url, params)
        if not data:
            return []

        raw_recordings = data.get("recordings", [])
        timers = [
            self._map_timer(r)
            for r in raw_recordings
            if r
        ]

        self._remember_timers(timers)

        logger.info(
            f"{self._provider}: Retrieved {len(timers)} timers "
            f"(offset={offset})"
        )
        return timers

    def add_timer(self, timer: Timer) -> Timer:
        """
        Schedule a new timer on the nPVR backend.

        The timer must be EPG-based: ``timer.epg_event_id`` must be set to the
        listing GUID (e.g. ``"das_erste_hd_033182e7"``).  This is the
        ``listing.guid`` field present on every recording/timer returned by
        the get-recordings endpoint.

        The API answers ``202 Accepted`` and does not necessarily return the
        created recording.  Success is therefore judged by the absence of an
        error, not by the response body.  The created timer is looked up in the
        timer list afterwards; if it is not visible yet (asynchronous
        processing), a provisional SCHEDULED copy of ``timer`` is returned and
        the real ``client_index`` appears on the next get_timers().

        Args:
            timer: Timer to create.  ``client_index`` is ignored.

        Returns:
            The saved Timer (or a provisional copy, see above).

        Raises:
            ValueError:   If ``timer.epg_event_id`` is not set or is not a
                          valid listing GUID.
            RuntimeError: If the API rejects the request (e.g. scheduling
                          conflict, listing not found).
        """
        if not timer.epg_event_id:
            raise ValueError(
                f"{self._provider}: add_timer() requires timer.epg_event_id "
                "(listing GUID, e.g. 'das_erste_hd_033182e7')"
            )

        pvr_base_url = self._get_pvr_base_url()
        url = self._with_cid(
            f"{pvr_base_url}{PVR_SCHEDULE_RECORDING_PATH}/{timer.epg_event_id}"
        )

        payload = self._build_create_payload(timer)

        # Errors are expected to raise (RuntimeError) inside _post(); an empty
        # body on 202 is a success, so the return value is NOT checked.
        data = self._post(url, payload)

        logger.info(
            f"{self._provider}: Timer scheduled for listing "
            f"'{timer.epg_event_id}' (202 accepted)"
        )

        # 1) Body already contains a recording object (not expected, but cheap).
        if isinstance(data, dict) and data.get("id"):
            created = self._map_timer(data)
            self._remember_timers([created])
            return created

        # 2) Look the new timer up in the timer list.
        found = self._find_timer_by_listing(timer.epg_event_id)
        if found is not None:
            return found

        # 3) Not visible yet — return a provisional copy.
        logger.debug(
            f"{self._provider}: Timer for '{timer.epg_event_id}' not yet "
            "listed; returning provisional timer"
        )
        provisional = copy.copy(timer)
        provisional.state = TimerState.SCHEDULED
        return provisional

    def update_timer(self, timer: Timer) -> Timer:
        """
        Update an existing timer (padding, etc.).

        No update endpoint has been captured, so this is implemented as
        delete + re-schedule of the same listing.  Because both calls are
        asynchronous (202), the re-schedule may race with the delete; treat
        this method as UNVERIFIED until tested against the live API.

        Args:
            timer: Timer with updated fields; ``client_index`` must identify an
                   existing timer.

        Returns:
            The re-created Timer (see add_timer() for provisional behaviour).

        Raises:
            ValueError: If ``timer.client_index`` is 0 (not yet saved).
            KeyError:   If no timer with that client_index exists.
            RuntimeError: If the API rejects delete or schedule.
        """
        if not timer.client_index:
            raise ValueError(
                f"{self._provider}: update_timer() requires a non-zero "
                "timer.client_index"
            )

        listing_guid = self._resolve_listing_guid(timer.client_index)

        self._delete_listing(listing_guid)

        replacement = copy.copy(timer)
        replacement.epg_event_id = listing_guid
        updated = self.add_timer(replacement)

        logger.info(
            f"{self._provider}: Timer updated (delete + schedule) — "
            f"listing='{listing_guid}' client_index={updated.client_index}"
        )
        return updated

    def delete_timer(
        self,
        client_index: int,
        force_delete: bool = False,
        **kwargs,
    ) -> None:
        """
        Cancel a timer on the nPVR backend.

        The API deletes by listing GUID (``delete-recording-for-listing``).
        The GUID is resolved from ``client_index`` via the internal map,
        refreshing the timer list once if the index is unknown.

        Args:
            client_index: ``Timer.client_index`` of a previously listed timer.
            force_delete: Unused for SCHEDULED timers; included for interface
                          parity with the base provider contract.  When a timer
                          is already in RECORDING state this flag would abort
                          the active capture — implement if/when needed.

        Raises:
            KeyError:     If no timer with that client_index exists.
            RuntimeError: If the API refuses deletion.
        """
        listing_guid = self._resolve_listing_guid(client_index)
        self._delete_listing(listing_guid)

        with self._index_lock:
            self._listing_by_index.pop(client_index, None)

    # =========================================================================
    # Private helpers – requests
    # =========================================================================

    def _delete_listing(self, listing_guid: str) -> None:
        pvr_base_url = self._get_pvr_base_url()
        url = self._with_cid(
            f"{pvr_base_url}{PVR_DELETE_RECORDING_PATH}/{listing_guid}"
        )
        status_code = self._delete(url)
        logger.info(
            f"{self._provider}: Timer for listing '{listing_guid}' "
            f"cancelled [HTTP {status_code}]"
        )

    def _next_cid(self) -> str:
        """Return a fresh ``{session}::{call}`` correlation id."""
        if self._cid_callback is not None:
            return self._cid_callback()
        return f"{self._session_id}::{uuid.uuid1()}"

    def _with_cid(self, url: str) -> str:
        """Append the URL-encoded ``cid`` query parameter (``::`` -> %3A%3A)."""
        return f"{url}?cid={quote(self._next_cid(), safe='')}"

    # =========================================================================
    # Private helpers – client_index <-> listing GUID
    # =========================================================================

    def _remember_timers(self, timers: List[Timer]) -> None:
        with self._index_lock:
            for t in timers:
                if t.client_index and t.epg_event_id:
                    self._listing_by_index[t.client_index] = t.epg_event_id

    def _refresh_index(self) -> None:
        """Page through all SCHEDULED timers to rebuild the index map."""
        limit = min(PVR_DEFAULT_PAGE_LIMIT, PVR_MAX_PAGE_LIMIT)
        for page in range(1, _MAX_REFRESH_PAGES + 1):
            batch = self.get_timers(limit=limit, offset=page)
            if len(batch) < limit:
                break

    def _resolve_listing_guid(self, client_index: int) -> str:
        with self._index_lock:
            guid = self._listing_by_index.get(client_index)
        if guid:
            return guid

        self._refresh_index()

        with self._index_lock:
            guid = self._listing_by_index.get(client_index)
        if not guid:
            raise KeyError(
                f"{self._provider}: no timer with client_index={client_index}"
            )
        return guid

    def _find_timer_by_listing(self, listing_guid: str) -> Optional[Timer]:
        """Best-effort lookup of a just-created timer; never raises."""
        try:
            limit = min(PVR_DEFAULT_PAGE_LIMIT, PVR_MAX_PAGE_LIMIT)
            for page in range(1, _MAX_REFRESH_PAGES + 1):
                batch = self.get_timers(limit=limit, offset=page)
                for t in batch:
                    if t.epg_event_id == listing_guid:
                        return t
                if len(batch) < limit:
                    break
        except Exception as exc:  # the timer WAS created; don't fail the add
            logger.warning(
                f"{self._provider}: timer lookup after schedule failed: {exc}"
            )
        return None

    # =========================================================================
    # Private helpers – request building
    # =========================================================================

    @staticmethod
    def _station_reference_from_listing_guid(listing_guid: str) -> str:
        """
        Derive the ``stationReferences`` value the nPVR API expects from a
        listing GUID, e.g. ``"das_erste_hd_033182e7"`` -> ``"das_erste_hd"``.

        Confirmed via live network capture. If a proper station reference is
        already cached elsewhere on the channel model, prefer that over this
        regex-derived value — it's inferred from sample data, not documented.

        Raises:
            ValueError: If the GUID does not have the expected shape.
        """
        match = _LISTING_GUID_STATION_RE.match(listing_guid or "")
        if not match:
            raise ValueError(
                f"Unexpected listing GUID format: {listing_guid!r} "
                "(expected '<station_ref>_<8 hex chars>')"
            )
        return match.group("station_ref")

    @classmethod
    def _build_create_payload(cls, timer: Timer) -> Dict:
        """
        Build the POST body for ``schedule-recording-for-listing/{guid}``.

        Confirmed via live network capture:
            {"stationReferences": ["<station_ref>"],
             "startOffsetSeconds": N, "endOffsetSeconds": N}

        The listing GUID itself goes in the URL path, not the body — do not
        add "listingId" here.  Both offsets are always sent (0 when unset) so
        the backend never falls back to its own default padding.
        """
        return {
            "stationReferences": [
                cls._station_reference_from_listing_guid(timer.epg_event_id)
            ],
            # Timer model uses minutes, API uses seconds
            "startOffsetSeconds": int(timer.margin_start or 0) * 60,
            "endOffsetSeconds": int(timer.margin_end or 0) * 60,
        }

    # =========================================================================
    # Private helpers – response mapping
    # =========================================================================

    def _map_timer(self, raw: Dict) -> Timer:
        """
        Map a raw nPVR API recording dict (status=SCHEDULED) to a :class:`Timer`.

        Field mapping:
            id                              → client_index (cast to int via hash)
            recordingStatus                 → state
            listing.guid                    → epg_event_id
            listing.stationId               → client_channel_uid (numeric tail)
            program.title / series.title    → title
            program.description             → description
            startDateTime                   → start_time
            endDateTime                     → end_time
            startOffsetSeconds              → margin_start (seconds → minutes)
            endOffsetSeconds                → margin_end   (seconds → minutes)
            program.tags[genre-primary]     → (description field only)
            program.thumbnails              → (not carried on Timer — no Content)
        """
        recording_id: str = raw.get("id", "")

        # client_index must be an int per the PVR contract.
        # The nPVR IDs are hex strings — use a stable numeric hash.  The hash is
        # NOT reversible; delete/update therefore go through the listing GUID
        # (epg_event_id) via the client_index -> listing_guid map.
        client_index: int = _hex_id_to_int(recording_id)

        # ── State ────────────────────────────────────────────────────────
        state = _map_timer_state(raw.get("recordingStatus", "SCHEDULED"))

        # ── Title ────────────────────────────────────────────────────────
        program: Dict = raw.get("program") or {}
        series:  Dict = raw.get("series")  or {}
        title: str = (
            program.get("title")
            or series.get("title")
            or raw.get("title")
            or f"Timer {recording_id[:8]}"
        ).strip()

        # ── Description ──────────────────────────────────────────────────
        description: Optional[str] = (
            program.get("shortDescription")
            or program.get("description")
            or None
        )

        # ── Channel ──────────────────────────────────────────────────────
        listing: Dict       = raw.get("listing") or {}
        station_id_uri      = listing.get("stationId")
        client_channel_uid  = PvrHelpers.extract_numeric_tail(station_id_uri) or -1

        # ── EPG linkage ───────────────────────────────────────────────────
        # listing.guid identifies the timer for scheduling AND deletion.
        listing_guid: Optional[str] = listing.get("guid")  # e.g. "das_erste_hd_033182e7"

        # The original nPVR recording id is kept in series_link for
        # diagnostics (client_index is a lossy int hash of it).
        series_link: Optional[str] = recording_id or None

        # ── Timing ───────────────────────────────────────────────────────
        start_time = PvrHelpers.parse_datetime(raw.get("startDateTime"))
        end_time   = PvrHelpers.parse_datetime(raw.get("endDateTime"))

        # ── Padding (API stores seconds; Timer model uses minutes) ────────
        margin_start = _seconds_to_minutes(raw.get("startOffsetSeconds", 0))
        margin_end   = _seconds_to_minutes(raw.get("endOffsetSeconds", 0))

        return Timer(
            client_index=client_index,
            state=state,
            timer_type_id=PVR_TIMER_TYPE_EPG_ONE_SHOT,
            title=title,
            provider=self._provider,
            # channel
            client_channel_uid=client_channel_uid,
            # timing
            start_time=start_time,
            end_time=end_time,
            # padding
            margin_start=margin_start,
            margin_end=margin_end,
            # EPG linkage
            epg_event_id=listing_guid,
            series_link=series_link,
            # metadata
            description=description,
            last_updated=datetime.now(tz=timezone.utc),
        )


# ---------------------------------------------------------------------------
# Module-level helpers (pure functions; no access to manager state)
# ---------------------------------------------------------------------------

def _map_timer_state(status_str: str) -> TimerState:
    """Map nPVR recordingStatus to TimerState."""
    _map = {
        "SCHEDULED": TimerState.SCHEDULED,
        "RECORDING": TimerState.RECORDING,
        "RECORDED":  TimerState.COMPLETED,
        "GENERATED": TimerState.COMPLETED,
        "FAILED":    TimerState.ERROR,
        "TO_DELETE": TimerState.CANCELLED,
        "DELETED":   TimerState.CANCELLED,
    }
    return _map.get(status_str.upper(), TimerState.SCHEDULED)


def _hex_id_to_int(hex_str: str) -> int:
    """
    Convert an nPVR hex recording ID to a stable positive integer.

    The PVR contract requires client_index to be an unsigned int.  We use the
    lower 31 bits of the hex value to stay safely within signed-int range on
    all platforms.  Collisions are astronomically unlikely for the number of
    timers a single user would have.  The mapping is lossy and NOT reversible.
    """
    if not hex_str:
        return 0
    try:
        return int(hex_str, 16) & 0x7FFF_FFFF
    except ValueError:
        return hash(hex_str) & 0x7FFF_FFFF


def _seconds_to_minutes(seconds) -> int:
    """Convert seconds (int or None) to whole minutes, minimum 0."""
    try:
        return max(0, int(seconds) // 60)
    except (TypeError, ValueError):
        return 0