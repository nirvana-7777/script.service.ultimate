# streaming_providers/providers/magenta2/recordings_manager.py
"""
Magenta2 Recordings Manager

Handles nPVR recording catalogue retrieval and deletion for the Magenta2
provider using the Audience nPVR API.

API overview
------------
Base URL:
    Discovered dynamically from the manifest response:
        manifest["mpx"]["pvrBaseUrl"]
    e.g. https://audience.npvr.eu.theplatform.com/npvr-audience/2709353023

List recordings:
    GET {pvr_base_url}/get-recordings
    Query params:  limit, offset, byRecordingStatus (pipe-separated list)
    Authorization: Basic {persona_token}
    Accept:        application/json; v=2; charset=utf-8

Delete a recording:
    DELETE {pvr_base_url}/recordings/{recording_id}
    Authorization: Basic {persona_token}

Public interface
----------------
    recordings_manager.get_recordings(
        *,
        include_deleted: bool = False,
        limit: int = PVR_DEFAULT_PAGE_LIMIT,
        offset: int = 1,          # nPVR API is 1-based
    ) -> List[Recording]

    recordings_manager.delete_recording(recording_id: str) -> None

    recordings_manager.get_recording_manifest(recording_id: str) -> Optional[str]
"""

from datetime import datetime
from typing import Dict, List, Optional

from ...base.models.recording import Recording, RecordingStatus
from ...base.utils.logger import logger

from .constants import (
    PVR_DEFAULT_PAGE_LIMIT,
    PVR_GET_RECORDINGS_PATH,
    PVR_MAX_PAGE_LIMIT,
    PVR_RECORDINGS_PATH,
    PVR_RECORDING_STATUSES_ACTIVE,
    PVR_RECORDING_STATUSES_ALL,
)
from .pvr_helpers import PvrHelpers, PvrHttpMixin


class RecordingsManager(PvrHttpMixin):
    """
    Manages Magenta2 nPVR recording catalogue retrieval and deletion.

    Args:
        http_manager:   An HTTPManager instance (from the parent provider).
        provider_name:  Provider identifier string (e.g. ``"magenta2"``).
        provider_config: ProviderConfig; supplies ``pvr_base_url`` and all
                         platform-scoped device identity values.
        auth_headers_callback:
                        Callable ``() -> Dict[str, str]`` returning the current
                        per-request headers (Authorization: Basic {persona},
                        user-agent, etc.).  Must be supplied for authenticated
                        endpoints — ``get_recordings`` and ``delete_recording``
                        will raise ``RuntimeError`` if it is ``None``.
    """

    def __init__(
        self,
        http_manager,
        provider_name: str,
        provider_config=None,
        auth_headers_callback=None,
    ):
        self._http = http_manager
        self._provider = provider_name
        self._provider_config = provider_config
        self._auth_headers_callback = auth_headers_callback

    # =========================================================================
    # Public API
    # =========================================================================

    def get_recordings(
        self,
        *,
        include_deleted: bool = False,
        limit: int = PVR_DEFAULT_PAGE_LIMIT,
        offset: int = 1,
    ) -> List[Recording]:
        """
        Fetch recordings from the nPVR API and return them as Recording objects.

        The API is paginated; this method performs a single request.  Call
        again with an incremented ``offset`` to page through all results.

        Args:
            include_deleted: When True, include recordings whose status is
                             DELETED or TO_DELETE.  Defaults to False.
            limit:           Maximum recordings to return per request.
                             Capped at PVR_MAX_PAGE_LIMIT.
            offset:          1-based page offset (first page = 1).

        Returns:
            List of :class:`Recording` objects ordered as returned by the API.

        Raises:
            RuntimeError: When ``auth_headers_callback`` is not configured or
                          the API returns a non-200 status.
        """
        pvr_base_url = self._get_pvr_base_url()
        url = f"{pvr_base_url}{PVR_GET_RECORDINGS_PATH}"

        statuses = PVR_RECORDING_STATUSES_ALL if include_deleted else PVR_RECORDING_STATUSES_ACTIVE
        params = {
            "limit": min(limit, PVR_MAX_PAGE_LIMIT),
            "offset": offset,
            "byRecordingStatus": "|".join(statuses),
        }

        data = self._get(url, params)
        if not data:
            return []

        raw_recordings = data.get("recordings", [])
        recordings = [
            self._map_recording(r)
            for r in raw_recordings
            if r  # skip any null/empty entries
        ]

        logger.info(
            f"{self._provider}: Retrieved {len(recordings)} recordings "
            f"(offset={offset}, include_deleted={include_deleted})"
        )
        return recordings

    def delete_recording(self, recording_id: str) -> None:
        """
        Permanently delete a recording on the nPVR backend.

        Args:
            recording_id: The recording's ``id`` field (not externalRecordingId).

        Raises:
            RuntimeError: When the API returns a non-200/204 status or the
                          ``auth_headers_callback`` is not configured.
            KeyError:     When the recording does not exist (404).
        """
        pvr_base_url = self._get_pvr_base_url()
        url = f"{pvr_base_url}{PVR_RECORDINGS_PATH}/{recording_id}"

        status_code = self._delete(url)
        logger.info(
            f"{self._provider}: Deleted recording '{recording_id}' "
            f"[HTTP {status_code}]"
        )

    def get_recording_manifest(self, recording_id: str) -> Optional[str]:
        """
        Return the playback URL for a recording.

        The nPVR API embeds ``playbackUrl`` directly on each recording object.
        Because the manifest URL format is the same as for live channels and
        VOD (link.theplatform.eu/s/mdeprod/media/{guid}), it can be resolved
        directly by the existing ``provider.get_manifest(content_id)`` path
        once the recording's playbackUrl is stored as ``manifest_script``.

        This method is provided for convenience — direct look-up of the URL by
        recording ID requires a fresh API call since this manager does not
        maintain a local cache of recording objects.

        Args:
            recording_id: The recording's ``id`` field.

        Returns:
            The ``playbackUrl`` string from the API, or ``None`` when not
            available (e.g. recording is PENDING or FAILED).
        """
        pvr_base_url = self._get_pvr_base_url()
        url = f"{pvr_base_url}{PVR_RECORDINGS_PATH}/{recording_id}"

        data = self._get(url, {})
        if not data:
            return None

        playback_url: Optional[str] = data.get("playbackUrl")
        if playback_url:
            logger.debug(
                f"{self._provider}: Recording '{recording_id}' → "
                f"playbackUrl={playback_url}"
            )
        return playback_url

    # =========================================================================
    # Private helpers – response mapping
    # =========================================================================

    def _map_recording(self, raw: Dict) -> Recording:
        """
        Map a raw nPVR API recording dict to a :class:`Recording` model.

        Field mapping:
            id                              → content_id / recording_id
            program.title                   → name
            program.description             → description (plot)
            program.shortDescription        → plot_outline
            program.longDescription         → plot
            program.year                    → release_year
            program.runtime                 → duration_seconds (float, seconds)
            program.programType             → (used to determine is_movie etc.)
            program.tags[scheme=genre-primary].title → genre_description
            program.thumbnails.mainWide-*   → thumbnail_url
            program.thumbnails.posterWide*  → fanart_url
            listing.stationId               → channel_uid (numeric tail)
            recordingStatus                 → status (mapped to RecordingStatus)
            startDateTime                   → recording_time
            recordingDuration               → duration_seconds (ISO 8601 duration)
            expirationDateTime              → lifetime (days from now)
            playbackUrl                     → manifest_script
        """
        recording_id: str = raw.get("id", "")
        status_str: str = raw.get("recordingStatus", "GENERATED")
        status = _map_status(status_str)

        program: Dict = raw.get("program") or {}
        listing: Dict = raw.get("listing") or {}

        # ── Name ──────────────────────────────────────────────────────────
        title: str = (program.get("title") or raw.get("title") or "").strip()
        if not title:
            title = f"Recording {recording_id[:8]}"

        # ── Descriptions ──────────────────────────────────────────────────
        description: Optional[str] = (
            program.get("shortDescription")
            or program.get("description")
            or None
        )
        plot: Optional[str] = program.get("longDescription") or program.get("description")
        plot_outline: Optional[str] = program.get("shortDescription")

        # ── Duration ──────────────────────────────────────────────────────
        # Prefer recordingDuration (ISO 8601) for the actual captured length.
        # Fall back to program.runtime which is the broadcast length in seconds.
        duration_seconds: Optional[int] = None
        recording_duration_str: Optional[str] = raw.get("recordingDuration")
        if recording_duration_str:
            duration_seconds = PvrHelpers.parse_iso8601_duration(recording_duration_str)
        if duration_seconds is None:
            runtime_raw = program.get("runtime")
            if runtime_raw is not None:
                try:
                    duration_seconds = int(float(runtime_raw))
                except (ValueError, TypeError):
                    pass

        # ── Timing ────────────────────────────────────────────────────────
        recording_time: Optional[datetime] = PvrHelpers.parse_datetime(
            raw.get("startDateTime")
        )

        # ── Lifetime (days until expiry) ──────────────────────────────────
        lifetime: Optional[int] = PvrHelpers.compute_lifetime_days(
            raw.get("expirationDateTime")
        )

        # ── Release year ──────────────────────────────────────────────────
        release_year: Optional[int] = None
        year_raw = program.get("year")
        if year_raw:
            try:
                release_year = int(year_raw)
            except (ValueError, TypeError):
                pass

        # ── Genre ─────────────────────────────────────────────────────────
        genre_description: Optional[str] = PvrHelpers.extract_primary_genre(
            program.get("tags") or []
        )

        # ── Thumbnails ────────────────────────────────────────────────────
        thumbnails: Dict = program.get("thumbnails") or {}
        thumbnail_url: Optional[str] = PvrHelpers.pick_thumbnail(thumbnails, "mainWide")
        fanart_url: Optional[str] = PvrHelpers.pick_thumbnail(
            thumbnails, "posterWideNoTitle", fallback_key="HighResLandscapeProductionStill"
        )

        # ── Channel info ──────────────────────────────────────────────────
        # stationId is a theplatform URI; extract the numeric tail as channel_uid.
        station_id_uri: Optional[str] = listing.get("stationId")
        channel_uid: Optional[int] = PvrHelpers.extract_numeric_tail(station_id_uri)

        # ── Playback / manifest ───────────────────────────────────────────
        # playbackUrl is a theplatform selector URL in the same format used
        # by live channels and VOD:
        #   http://link.theplatform.eu/s/mdeprod/media/{guid}
        #
        # The GUID (e.g. "gze0sD559dZ7u6TWviDNXw") is the MPX media ID that
        # the SMIL/selector path in provider.get_manifest() needs.  We extract
        # it directly here so no extra resolution step is required at playback
        # time — unlike VOD which must walk VodDetails → productInformation →
        # VodPlayer to discover the same value.
        playback_url: Optional[str] = raw.get("playbackUrl")
        mpx_guid: Optional[str] = PvrHelpers.extract_mpx_guid(playback_url)

        # Use the MPX GUID as content_id when available so downstream manifest
        # and DRM calls resolve correctly.  Fall back to the nPVR recording ID
        # only when the playbackUrl is absent (e.g. PENDING / FAILED recordings).
        effective_content_id: str = mpx_guid if mpx_guid else recording_id
        manifest_script: Optional[str] = playback_url
        session_manifest: bool = manifest_script is not None

        return Recording(
            content_id=effective_content_id,
            name=title,
            provider=self._provider,
            # descriptions
            description=description,
            plot=plot,
            plot_outline=plot_outline,
            # timing
            recording_time=recording_time,
            duration_seconds=duration_seconds,
            # year / genre
            release_year=release_year,
            genre_description=genre_description,
            # thumbnails
            thumbnail_url=thumbnail_url,
            fanart_url=fanart_url,
            # channel
            channel_uid=channel_uid,
            # management
            lifetime=lifetime,
            # playback
            manifest_script=manifest_script,
            session_manifest=session_manifest,
            # status
            status=status,
        )


# ---------------------------------------------------------------------------
# Module-level helpers (pure functions; no access to manager state)
# ---------------------------------------------------------------------------

def _map_status(status_str: str) -> RecordingStatus:
    """Map nPVR API recordingStatus string to RecordingStatus enum."""
    _map = {
        "SCHEDULED": RecordingStatus.PENDING,
        "RECORDING": RecordingStatus.RECORDING,
        "RECORDED":  RecordingStatus.COMPLETED,
        "GENERATED": RecordingStatus.COMPLETED,
        "FAILED":    RecordingStatus.FAILED,
        "TO_DELETE": RecordingStatus.DELETED,
        "DELETED":   RecordingStatus.DELETED,
    }
    return _map.get(status_str.upper(), RecordingStatus.COMPLETED)