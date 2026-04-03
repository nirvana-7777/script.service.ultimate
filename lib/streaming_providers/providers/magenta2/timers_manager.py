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

Schedule a new timer:
    POST {pvr_base_url}/recordings
    Body:          {"listingId": "<listing_guid>", "startOffsetSeconds": N,
                    "endOffsetSeconds": N}
    Authorization: Basic {persona_token}
    Content-Type:  application/json; v=2; charset=utf-8

    NOTE: The exact request body shape must be confirmed against the live API.
    The listing GUID is derived from Timer.epg_event_id (the listing.guid field
    in the get-recordings response, e.g. "3sat_hd_02fe69d5").

Update an existing timer:
    PUT  {pvr_base_url}/recordings/{recording_id}
    Body:          same shape as POST, partial updates accepted
    Authorization: Basic {persona_token}

Delete a timer (cancel before it fires):
    DELETE {pvr_base_url}/recordings/{recording_id}
    Authorization: Basic {persona_token}
    — identical to recording deletion; the backend differentiates by status

Public interface
----------------
    timers_manager.get_timers(**kwargs) -> List[Timer]

    timers_manager.add_timer(timer: Timer) -> Timer

    timers_manager.update_timer(timer: Timer) -> Timer

    timers_manager.delete_timer(client_index: int,
                                force_delete: bool = False) -> None

    timers_manager.get_timer_types() -> List[TimerType]

Relationship to RecordingsManager
----------------------------------
Both managers talk to the same nPVR base URL and use the same auth scheme.
Shared HTTP/auth plumbing lives in PvrHttpMixin (pvr_helpers.py).
Shared parsing utilities live in PvrHelpers (pvr_helpers.py).

Timers are SCHEDULED recordings that have not yet been captured.  After the
broadcast window passes the backend transitions them to RECORDING → GENERATED,
at which point RecordingsManager takes ownership of the object.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from ...base.models.timer import Timer, TimerState
from ...base.models.timer_type import TimerType, TimerTypeAttribute
from ...base.utils.logger import logger

from .constants import (
    PVR_DEFAULT_PAGE_LIMIT,
    PVR_MAX_PAGE_LIMIT,
    PVR_GET_RECORDINGS_PATH,
    PVR_RECORDINGS_PATH,
    PVR_TIMER_TYPE_EPG_ONE_SHOT,
    PVR_RECORDING_STATUSES_TIMERS,
)
from .pvr_helpers import PvrHelpers, PvrHttpMixin



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
    """

    def __init__(
        self,
        http_manager,
        provider_name: str,
        provider_config=None,
        auth_headers_callback=None,
    ):
        self._http                  = http_manager
        self._provider              = provider_name
        self._provider_config       = provider_config
        self._auth_headers_callback = auth_headers_callback

    # =========================================================================
    # Timer types
    # =========================================================================

    @staticmethod
    def get_timer_types() -> List[TimerType]:
        """
        Return the timer types supported by Magenta2.

        Currently Magenta2 supports EPG-based one-shot timers only.  The
        listing GUID is required at creation time (REQUIRES_EPG_TAG_ON_CREATE)
        since the nPVR POST endpoint expects a listingId.

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
        Fetch all SCHEDULED timers from the nPVR API.

        The API is paginated (same as get-recordings).  Call again with an
        incremented ``offset`` to page through all results.

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

        logger.info(
            f"{self._provider}: Retrieved {len(timers)} timers "
            f"(offset={offset})"
        )
        return timers

    def add_timer(self, timer: Timer) -> Timer:
        """
        Schedule a new timer on the nPVR backend.

        The timer must be EPG-based: ``timer.epg_event_id`` must be set to the
        listing GUID (e.g. ``"3sat_hd_02fe69d5"``).  This is the ``listing.guid``
        field present on every recording/timer returned by the get-recordings
        endpoint.

        Args:
            timer: Timer to create.  ``client_index`` is ignored — the backend
                   assigns and returns it on the created object.

        Returns:
            The saved Timer with ``client_index`` populated from the API
            response.

        Raises:
            ValueError:   If ``timer.epg_event_id`` is not set.
            RuntimeError: If the API rejects the request (e.g. scheduling
                          conflict, listing not found).
        """
        if not timer.epg_event_id:
            raise ValueError(
                f"{self._provider}: add_timer() requires timer.epg_event_id "
                "(listing GUID, e.g. '3sat_hd_02fe69d5')"
            )

        pvr_base_url = self._get_pvr_base_url()
        url = f"{pvr_base_url}{PVR_RECORDINGS_PATH}"

        payload = self._build_create_payload(timer)
        data = self._post(url, payload)

        if not data:
            raise RuntimeError(
                f"{self._provider}: add_timer() — no response from nPVR API "
                f"for listing '{timer.epg_event_id}'"
            )

        created = self._map_timer(data)
        logger.info(
            f"{self._provider}: Timer created — "
            f"client_index={created.client_index} title='{created.title}'"
        )
        return created

    def update_timer(self, timer: Timer) -> Timer:
        """
        Update an existing timer on the nPVR backend.

        ``timer.client_index`` must be set to the ``id`` returned when the
        timer was first fetched or created (the short hex nPVR recording ID).

        Args:
            timer: Timer with updated fields.

        Returns:
            The updated Timer as confirmed by the API.

        Raises:
            KeyError:     If no timer with that client_index exists (404).
            ValueError:   If ``timer.client_index`` is 0 (not yet saved).
            RuntimeError: If the API rejects the update.
        """
        if not timer.client_index:
            raise ValueError(
                f"{self._provider}: update_timer() requires a non-zero "
                "timer.client_index"
            )

        pvr_base_url = self._get_pvr_base_url()
        url = f"{pvr_base_url}{PVR_RECORDINGS_PATH}/{timer.client_index}"

        payload = self._build_create_payload(timer)
        data = self._put(url, payload)

        if not data:
            raise RuntimeError(
                f"{self._provider}: update_timer() — no response from nPVR API "
                f"for timer '{timer.client_index}'"
            )

        updated = self._map_timer(data)
        logger.info(
            f"{self._provider}: Timer updated — "
            f"client_index={updated.client_index} title='{updated.title}'"
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

        Uses the same DELETE endpoint as RecordingsManager.delete_recording()
        because the backend distinguishes timers from recordings only by their
        current status.

        Args:
            client_index: The nPVR recording ID (== Timer.client_index for
                          saved timers).
            force_delete: Unused for SCHEDULED timers; included for interface
                          parity with the base provider contract.  When a timer
                          is already in RECORDING state this flag would abort
                          the active capture — implement if/when needed.

        Raises:
            KeyError:     If no timer with that ID exists (404).
            RuntimeError: If the API refuses deletion.
        """
        pvr_base_url = self._get_pvr_base_url()
        url = f"{pvr_base_url}{PVR_RECORDINGS_PATH}/{client_index}"

        status_code = self._delete(url)
        logger.info(
            f"{self._provider}: Timer '{client_index}' cancelled "
            f"[HTTP {status_code}]"
        )

    # =========================================================================
    # Private helpers – request building
    # =========================================================================

    @staticmethod
    def _build_create_payload(timer: Timer) -> Dict:
        """
        Build the POST/PUT request body for the nPVR recordings endpoint.

        The Magenta2 nPVR API expects the listing GUID (timer.epg_event_id)
        as ``listingId``, plus optional pre/post padding offsets in seconds.

        NOTE: Confirm the exact field names against the live API spec.
              ``startOffsetSeconds`` / ``endOffsetSeconds`` are inferred from
              the sample JSON data (recordings carry these fields).
        """
        payload: Dict = {
            "listingId": timer.epg_event_id,
        }

        # Pre/post padding — convert from minutes (Timer model) to seconds (API)
        if timer.margin_start:
            payload["startOffsetSeconds"] = timer.margin_start * 60
        if timer.margin_end:
            payload["endOffsetSeconds"] = timer.margin_end * 60

        return payload

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
        # The nPVR IDs are hex strings — use a stable numeric hash.
        # We also store the original string in epg_event_id / series_link
        # so that update/delete calls can reconstruct the URL path.
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
        # listing.guid is the stable identifier used to re-create / update
        # the timer (passed back as listingId in the POST body).
        listing_guid: Optional[str] = listing.get("guid")  # e.g. "3sat_hd_02fe69d5"

        # The nPVR recording ID is used for DELETE/PUT URL construction;
        # store it in series_link so it survives a round-trip through Timer.
        # (client_index is an int and cannot hold the hex string directly.)
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
    timers a single user would have.
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