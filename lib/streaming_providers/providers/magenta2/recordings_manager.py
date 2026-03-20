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

from datetime import datetime, timezone
from typing import Dict, List, Optional

from ...base.models.recording import Recording, RecordingStatus
from ...base.utils.logger import logger

from .constants import (
    PVR_DEFAULT_PAGE_LIMIT,
    PVR_MAX_PAGE_LIMIT,
    PVR_RECORDING_STATUSES_ACTIVE,
    PVR_RECORDING_STATUSES_ALL,
)


class RecordingsManager:
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
        url = f"{pvr_base_url}/get-recordings"

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
        url = f"{pvr_base_url}/recordings/{recording_id}"

        headers = self._build_auth_headers()
        try:
            response = self._http.delete(url, headers=headers)
        except Exception as exc:
            raise RuntimeError(
                f"{self._provider}: DELETE request failed for recording "
                f"'{recording_id}': {exc}"
            ) from exc

        if response is None:
            raise RuntimeError(
                f"{self._provider}: No response received when deleting "
                f"recording '{recording_id}'"
            )

        if response.status_code == 404:
            raise KeyError(
                f"{self._provider}: Recording '{recording_id}' not found on provider"
            )

        if response.status_code not in (200, 204):
            raise RuntimeError(
                f"{self._provider}: Failed to delete recording '{recording_id}' "
                f"[HTTP {response.status_code}]: {response.text[:200]}"
            )

        logger.info(
            f"{self._provider}: Deleted recording '{recording_id}' "
            f"[HTTP {response.status_code}]"
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
        url = f"{pvr_base_url}/recordings/{recording_id}"

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
    # Private helpers – HTTP layer
    # =========================================================================

    def _get_pvr_base_url(self) -> str:
        """
        Resolve the nPVR base URL from the discovered manifest config.

        Resolution order:
          1. ``provider_config.manifest.mpx.pvr_base_url``   (dynamic, preferred)
          2. Raises ``RuntimeError``                          (no hardcoded fallback)

        The URL is intentionally not hardcoded.  It is always present in the
        manifest response under ``mpx.pvrBaseUrl`` and must be discovered
        before the RecordingsManager is used.
        """
        if self._provider_config is not None:
            try:
                pvr_url = self._provider_config.manifest.mpx.pvr_base_url
                if pvr_url:
                    return pvr_url.rstrip("/")
            except AttributeError:
                pass

        raise RuntimeError(
            f"{self._provider}: PVR base URL not available — "
            "provider configuration must be fully discovered before "
            "using RecordingsManager."
        )

    def _build_auth_headers(self) -> Dict[str, str]:
        """
        Build authentication headers for nPVR requests.

        The nPVR API uses ``Authorization: Basic {persona_token}``, which is
        distinct from the Bearer tokens used by VOD endpoints.  The
        auth_headers_callback is expected to return headers that already
        include a Basic Authorization value.

        Raises:
            RuntimeError: When auth_headers_callback is not configured.
        """
        if self._auth_headers_callback is None:
            raise RuntimeError(
                f"{self._provider}: auth_headers_callback not configured — "
                "cannot make authenticated nPVR requests."
            )
        try:
            return self._auth_headers_callback()
        except Exception as exc:
            raise RuntimeError(
                f"{self._provider}: auth_headers_callback raised an exception: {exc}"
            ) from exc

    def _get(self, url: str, params: Dict) -> Optional[Dict]:
        """
        Perform an authenticated GET request against the nPVR API.

        Accept header is set to the nPVR-required value:
            application/json; v=2; charset=utf-8

        Returns:
            Parsed JSON body, or ``None`` on error.
        """
        headers = self._build_auth_headers()
        # nPVR API requires a versioned Accept header — different from standard JSON.
        headers["Accept"] = "application/json; v=2; charset=utf-8"

        try:
            response = self._http.get(url, params=params, headers=headers)
            if response and response.status_code == 200:
                return response.json()
            logger.warning(
                f"{self._provider}: nPVR request failed "
                f"[{response.status_code if response else 'no response'}] {url}"
            )
        except Exception as exc:
            logger.error(
                f"{self._provider}: nPVR request exception for {url}: {exc}"
            )
        return None

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
        status = self._map_status(status_str)

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
            duration_seconds = self._parse_iso8601_duration(recording_duration_str)
        if duration_seconds is None:
            runtime_raw = program.get("runtime")
            if runtime_raw is not None:
                try:
                    duration_seconds = int(float(runtime_raw))
                except (ValueError, TypeError):
                    pass

        # ── Timing ────────────────────────────────────────────────────────
        recording_time: Optional[datetime] = self._parse_datetime(raw.get("startDateTime"))

        # ── Lifetime (days until expiry) ──────────────────────────────────
        lifetime: Optional[int] = self._compute_lifetime_days(raw.get("expirationDateTime"))

        # ── Release year ──────────────────────────────────────────────────
        release_year: Optional[int] = None
        year_raw = program.get("year")
        if year_raw:
            try:
                release_year = int(year_raw)
            except (ValueError, TypeError):
                pass

        # ── Genre ─────────────────────────────────────────────────────────
        genre_description: Optional[str] = self._extract_primary_genre(
            program.get("tags") or []
        )

        # ── Thumbnails ────────────────────────────────────────────────────
        thumbnails: Dict = program.get("thumbnails") or {}
        thumbnail_url: Optional[str] = self._pick_thumbnail(thumbnails, "mainWide")
        fanart_url: Optional[str] = self._pick_thumbnail(
            thumbnails, "posterWideNoTitle", fallback_key="HighResLandscapeProductionStill"
        )

        # ── Channel info ──────────────────────────────────────────────────
        # stationId is a theplatform URI; extract the numeric tail as channel_uid.
        station_id_uri: Optional[str] = listing.get("stationId")
        channel_uid: Optional[int] = self._extract_numeric_tail(station_id_uri)

        # ── Playback / manifest ───────────────────────────────────────────
        # playbackUrl is already a theplatform selector URL — same format as
        # live channels (link.theplatform.eu/s/mdeprod/media/{guid}).
        # Store it as manifest_script so provider.get_manifest() can resolve
        # it through the existing SMIL/selector path.
        playback_url: Optional[str] = raw.get("playbackUrl")
        manifest_script: Optional[str] = playback_url if playback_url else None
        session_manifest: bool = manifest_script is not None

        return Recording(
            content_id=recording_id,
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

    @staticmethod
    def _map_status(status_str: str) -> RecordingStatus:
        """Map nPVR API recordingStatus string to RecordingStatus enum."""
        _map = {
            "SCHEDULED": RecordingStatus.PENDING,
            "RECORDING": RecordingStatus.RECORDING,
            "RECORDED": RecordingStatus.COMPLETED,
            "GENERATED": RecordingStatus.COMPLETED,
            "FAILED": RecordingStatus.FAILED,
            "TO_DELETE": RecordingStatus.DELETED,
            "DELETED": RecordingStatus.DELETED,
        }
        return _map.get(status_str.upper(), RecordingStatus.COMPLETED)

    @staticmethod
    def _parse_iso8601_duration(duration_str: str) -> Optional[int]:
        """
        Parse an ISO 8601 duration string and return total seconds.

        Supported formats:  PT2H44M5S,  PT26M19S,  PT45S,  P1DT2H

        Returns:
            Total duration in whole seconds, or None on parse failure.
        """
        import re
        pattern = re.compile(
            r"P(?:(?P<days>\d+)D)?"
            r"(?:T"
            r"(?:(?P<hours>\d+)H)?"
            r"(?:(?P<minutes>\d+)M)?"
            r"(?:(?P<seconds>\d+(?:\.\d+)?)S)?"
            r")?",
            re.IGNORECASE,
        )
        match = pattern.fullmatch(duration_str.strip())
        if not match:
            return None
        days = int(match.group("days") or 0)
        hours = int(match.group("hours") or 0)
        minutes = int(match.group("minutes") or 0)
        seconds = float(match.group("seconds") or 0)
        total = days * 86400 + hours * 3600 + minutes * 60 + int(seconds)
        return total if total > 0 else None

    @staticmethod
    def _parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
        """Parse an ISO 8601 datetime string to a timezone-aware datetime."""
        if not dt_str:
            return None
        try:
            # Python 3.7+ handles the Z suffix via fromisoformat after replacement
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _compute_lifetime_days(expiration_str: Optional[str]) -> Optional[int]:
        """
        Compute days remaining until expiry from an ISO 8601 datetime string.

        Returns:
            Whole days remaining (minimum 0), or None when not available.
        """
        if not expiration_str:
            return None
        try:
            expiry = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
            now = datetime.now(tz=timezone.utc)
            delta = expiry - now
            return max(0, delta.days)
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _extract_primary_genre(tags: List[Dict]) -> Optional[str]:
        """
        Extract the primary genre title from a program tags list.

        Looks for the first tag with scheme == ``"genre-primary"``.
        Falls back to the first tag with scheme == ``"genre-secondary"`` if
        no primary genre is present.
        """
        primary: Optional[str] = None
        secondary: Optional[str] = None
        for tag in tags:
            scheme = tag.get("scheme", "")
            title = tag.get("title", "").strip()
            if not title:
                continue
            if scheme == "genre-primary" and primary is None:
                primary = title
            elif scheme == "genre-secondary" and secondary is None:
                secondary = title
        return primary or secondary

    @staticmethod
    def _pick_thumbnail(
        thumbnails: Dict,
        preferred_key: str,
        fallback_key: Optional[str] = None,
    ) -> Optional[str]:
        """
        Pick a thumbnail URL from the program thumbnails dict.

        Looks for a key that starts with ``preferred_key`` (e.g. ``"mainWide"``
        matches ``"mainWide-0x0"``).  Falls back to ``fallback_key`` and then
        to the first available URL.
        """
        for key, value in thumbnails.items():
            if key.startswith(preferred_key):
                return (value or {}).get("url")
        if fallback_key:
            for key, value in thumbnails.items():
                if key.startswith(fallback_key):
                    return (value or {}).get("url")
        # Last resort: first available thumbnail
        for value in thumbnails.values():
            url = (value or {}).get("url")
            if url:
                return url
        return None

    @staticmethod
    def _extract_numeric_tail(uri: Optional[str]) -> Optional[int]:
        """
        Extract the numeric ID from the tail of a theplatform URI.

        e.g. ``"http://data.entertainment.tv.theplatform.eu/.../Station/265809448374"``
             → ``265809448374``
        """
        if not uri:
            return None
        tail = uri.rstrip("/").rsplit("/", 1)[-1]
        try:
            return int(tail)
        except (ValueError, TypeError):
            return None