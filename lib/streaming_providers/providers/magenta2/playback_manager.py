# streaming_providers/providers/magenta2/playback_manager.py
# -*- coding: utf-8 -*-
"""
Routes manifest and DRM requests for the Magenta2 provider.

Responsibilities
----------------
- Serve live-channel manifests directly from the ChannelManager cache
  (avoiding a SMIL round-trip for channels already fetched by get_channels).
- Build Widevine licence URLs directly for live channels using lib_theplatform.
- Delegate VOD and recording manifest/DRM requests to SmilManager.
- Serve catchup manifests by appending ``dvr_window_length`` to the cached
  live manifest URL — no separate SMIL fetch required.
- Inject ``smil_base_url`` from the recording-URL cache so callers (e.g.
  DRMOperations) only need to pass a ``content_id``.

The class holds NO state of its own beyond references to the managers and
callbacks passed at construction time.  All caches belong to ChannelManager.

Catchup routing
---------------
Magenta2 catchup is DVR-based: the live DASH manifest URL is reused with a
``dvr_window_length`` query parameter (in seconds) that tells the CDN how far
back the sliding window should reach.  Example:

    Live:    https://svc45.…/zdf_hd/DASH/index.mpd?AppVersion=…
    Catchup: https://svc45.…/zdf_hd/DASH/index.mpd?AppVersion=…&dvr_window_length=14400

The window length is derived from the provider's ``catchup_window`` property
(hours) and is passed in as ``dvr_window_seconds`` from the caller, or falls
back to ``DVR_WINDOW_SECONDS_DEFAULT`` (4 h = 14 400 s).

DRM for catchup is identical to live — the same Widevine licence URL applies —
so ``get_drm`` routes catchup requests through the same fast-path as live.

If the live manifest URL is not yet cached when a catchup request arrives,
``_ensure_live_cache()`` is called to populate it before building the URL.
SmilManager is NOT used for catchup on this provider.
"""
import base64
from typing import Callable, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from ...base.models import DRMConfig
from ...base.utils.logger import logger
from .constants import CONTENT_TYPE_LIVE, MAGENTA2_FALLBACK_ACCOUNT_URI
from .endpoint_manager import EndpointManager
from .config_models import ProviderConfig
from .smil_manager import SmilManager
from .channel_manager import ChannelManager
from ..lib_theplatform import (
    extract_persona_jwt,
    build_licence_url,
    build_widevine_drm_config,
)

# Default DVR window: 4 hours in seconds.  Matches provider.catchup_window = 4.
DVR_WINDOW_SECONDS_DEFAULT: int = 4 * 3600  # 14 400
DVR_WINDOW_PARAM: str = "dvr_window_length"


class PlaybackManager:
    """
    Routes manifest and DRM requests for Magenta2 content.

    Parameters
    ----------
    channel_manager:
        The provider's ChannelManager instance (owns live-manifest/pid caches).
    smil_manager:
        The provider's SmilManager instance (handles VOD / recording SMIL).
    endpoint_manager:
        Populated EndpointManager after discovery.
    provider_config:
        ProviderConfig after discovery.
    platform_config:
        Platform-specific dict from MAGENTA2_PLATFORMS (user_agent, etc.).
    auth_callback:
        Callable[[], str] — returns a valid persona token (Basic-auth value).
    recording_url_cache:
        Shared dict (owned by the provider) mapping content_id → manifest_script
        for recordings fetched via RecordingsManager.
    """

    def __init__(
        self,
        channel_manager: ChannelManager,
        smil_manager: Optional[SmilManager],
        endpoint_manager: Optional[EndpointManager],
        provider_config: Optional[ProviderConfig],
        platform_config: Dict,
        auth_callback: Callable[[], str],
        recording_url_cache: Dict[str, str],
    ):
        self._channel_manager = channel_manager
        self._smil_manager = smil_manager
        self._endpoint_manager = endpoint_manager
        self._provider_config = provider_config
        self._platform_config = platform_config
        self._ensure_authenticated = auth_callback
        self._recording_url_cache = recording_url_cache

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def get_manifest(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs
    ) -> Optional[str]:
        """
        Return the MPD manifest URL for *content_id*.

        Routing logic
        ~~~~~~~~~~~~~
        1. **Catchup** (``start_time`` + ``end_time`` present in kwargs):
           Appends ``dvr_window_length`` to the cached live manifest URL.
           No SMIL round-trip.  The live cache is populated on demand if empty.
        2. **Live** (``content_type == CONTENT_TYPE_LIVE``, no time window):
           Served directly from the ChannelManager cache when available.
        3. **VOD / recordings**: Fall through to ``SmilManager.get_manifest``.
        """
        if self._is_catchup_request(kwargs):
            return self._get_catchup_manifest(content_id, kwargs)

        if content_type == CONTENT_TYPE_LIVE:
            self._ensure_live_cache()
            if content_id in self._channel_manager._live_manifest_cache:
                logger.debug(f"get_manifest: cache hit for live channel {content_id}")
                return self._channel_manager._live_manifest_cache[content_id]

        if not self._smil_manager:
            raise RuntimeError("SmilManager not available")
        self._inject_smil_base_url(content_id, kwargs)
        return self._smil_manager.get_manifest(content_id, content_type, **kwargs)

    def get_drm(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs
    ) -> List[DRMConfig]:
        """
        Return DRM configuration for *content_id*.

        Routing logic
        ~~~~~~~~~~~~~
        1. **Catchup** (``start_time`` + ``end_time`` present in kwargs):
           DRM is identical to live — same Widevine licence URL applies to the
           DVR window.  Routes through the live fast-path using the pid cache.
           Falls back to SmilManager if the pid is not cached.
        2. **Live** (``content_type == CONTENT_TYPE_LIVE``, no time window):
           For live channels whose releasePid is cached, the Widevine licence
           URL is built directly using lib_theplatform — no SMIL fetch needed.
        3. **VOD / recordings**: Fall through to ``SmilManager.get_drm``.
        """
        if self._is_catchup_request(kwargs):
            # Catchup uses the same Widevine licence as live — reuse the fast-path.
            self._ensure_live_cache()
            if content_id in self._channel_manager._live_pid_cache:
                logger.debug(
                    f"get_drm: catchup request for {content_id} — reusing live DRM fast-path"
                )
                return self._build_live_drm(content_id)
            # pid not cached yet — fall through to SmilManager as a best-effort.
            logger.warning(
                f"get_drm: catchup for {content_id} but pid not in live cache; "
                "falling back to SmilManager"
            )
            if not self._smil_manager:
                raise RuntimeError("SmilManager not available")
            self._inject_smil_base_url(content_id, kwargs)
            return self._smil_manager.get_drm(content_id, content_type, **kwargs)

        if content_type == CONTENT_TYPE_LIVE:
            self._ensure_live_cache()
            if content_id in self._channel_manager._live_pid_cache:
                return self._build_live_drm(content_id)

        if not self._smil_manager:
            raise RuntimeError("SmilManager not available")
        self._inject_smil_base_url(content_id, kwargs)
        return self._smil_manager.get_drm(content_id, content_type, **kwargs)

    def get_catchup_manifest(
        self, content_id: str, start_time: int, end_time: int, drm_variant: Optional[str] = "auto", **kwargs
    ) -> Optional[str]:
        """
        Return a catchup manifest URL for *channel_id*.

        Builds the DVR URL from the cached live manifest by appending
        ``dvr_window_length``.  ``start_time`` and ``end_time`` are accepted
        for interface compatibility but are not used — Magenta2 catchup is a
        sliding DVR window, not a fixed time-range VOD asset.

        Parameters
        ----------
        channel_id:
            The live channel content_id (same key used in the live cache).
        start_time:
            Unix timestamp (seconds) of the catchup window start.  Accepted
            for API compatibility; not forwarded to the CDN.
        end_time:
            Unix timestamp (seconds) of the catchup window end.  Accepted
            for API compatibility; not forwarded to the CDN.
        dvr_window_seconds:
            Optional override (via kwargs) for the DVR window length in
            seconds.  Defaults to ``DVR_WINDOW_SECONDS_DEFAULT`` (14 400).
        """
        dvr_seconds: int = kwargs.get("dvr_window_seconds", DVR_WINDOW_SECONDS_DEFAULT)
        return self._build_dvr_manifest_url(content_id, dvr_seconds)

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_catchup_request(kwargs: Dict) -> bool:
        """
        Return True when *kwargs* carries both ``start_time`` and ``end_time``,
        indicating a time-shifted / catchup playback request.
        """
        return (
            kwargs.get("start_time") is not None
            and kwargs.get("end_time") is not None
        )

    def _get_catchup_manifest(self, content_id: str, kwargs: Dict) -> Optional[str]:
        """
        Build a DVR manifest URL for a catchup request arriving via
        ``get_manifest``.

        Extracts an optional ``dvr_window_seconds`` override from kwargs;
        otherwise derives the window from ``end_time - start_time`` when both
        are present, capped at ``DVR_WINDOW_SECONDS_DEFAULT``.
        """
        # Prefer an explicit override; otherwise derive from the requested
        # time window so the DVR slider covers at least the requested range.
        if "dvr_window_seconds" in kwargs:
            dvr_seconds: int = kwargs["dvr_window_seconds"]
        else:
            start_time: int = kwargs["start_time"]
            end_time: int = kwargs["end_time"]
            requested_window = end_time - start_time
            # Never request a window smaller than the requested range, but
            # cap at the provider default to avoid oversized requests.
            dvr_seconds = max(
                min(requested_window, DVR_WINDOW_SECONDS_DEFAULT),
                DVR_WINDOW_SECONDS_DEFAULT,
            )

        logger.debug(
            f"get_manifest: catchup request for {content_id} "
            f"(start={kwargs['start_time']}, end={kwargs['end_time']}, "
            f"dvr_window_seconds={dvr_seconds})"
        )
        return self._build_dvr_manifest_url(content_id, dvr_seconds)

    def _build_dvr_manifest_url(self, content_id: str, dvr_seconds: int) -> Optional[str]:
        """
        Retrieve the cached live manifest URL for *content_id* and append
        (or replace) the ``dvr_window_length`` query parameter.

        Returns ``None`` if the channel is not found in the live cache even
        after attempting to populate it.
        """
        self._ensure_live_cache()

        live_url = self._channel_manager._live_manifest_cache.get(content_id)
        if not live_url:
            logger.error(
                f"_build_dvr_manifest_url: no live manifest cached for {content_id}; "
                "cannot build catchup URL"
            )
            return None

        dvr_url = self._append_dvr_param(live_url, dvr_seconds)
        logger.debug(
            f"_build_dvr_manifest_url: {content_id} → {dvr_url}"
        )
        return dvr_url

    @staticmethod
    def _append_dvr_param(url: str, dvr_seconds: int) -> str:
        """
        Return *url* with ``dvr_window_length=<dvr_seconds>`` set in the query
        string.  Any pre-existing ``dvr_window_length`` value is replaced so
        that repeated calls are idempotent.
        """
        parsed = urlparse(url)
        # Parse existing query parameters, preserving all existing keys.
        # parse_qs returns lists; rebuild as a flat dict for urlencode.
        existing: Dict[str, List[str]] = parse_qs(parsed.query, keep_blank_values=True)
        # Replace (or add) the DVR param — overwrite any existing value.
        existing[DVR_WINDOW_PARAM] = [str(dvr_seconds)]
        new_query = urlencode(
            {k: v[0] for k, v in existing.items()},
            safe="",
        )
        return urlunparse(parsed._replace(query=new_query))

    def _ensure_live_cache(self) -> None:
        """
        Bootstrap the live-manifest / live-pid caches on demand by calling
        ChannelManager.get_channels() if they are empty.
        """
        if not self._channel_manager._live_manifest_cache:
            logger.debug("Live channel cache is empty — auto-populating via get_channels()")
            self._channel_manager.get_channels()

    def _build_live_drm(self, content_id: str) -> List[DRMConfig]:
        """
        Build a Widevine DRMConfig directly for a live channel, bypassing SMIL.
        """
        release_pid = content_id
        logger.debug(
            f"get_drm: building licence directly for live channel (releasePid: {release_pid})"
        )
        try:
            persona_token = self._ensure_authenticated()
            raw_jwt = extract_persona_jwt(persona_token)
            if not raw_jwt:
                logger.error("get_drm: failed to extract persona JWT")
                return []

            widevine_endpoint = (
                self._endpoint_manager.get_endpoint("widevine_license")
                if self._endpoint_manager
                else None
            )
            if not widevine_endpoint:
                logger.error("get_drm: no widevine_license endpoint available")
                return []

            account_uri = (
                self._provider_config.manifest.mpx.get_account_uri()
                if self._provider_config and self._provider_config.manifest
                else None
            ) or MAGENTA2_FALLBACK_ACCOUNT_URI

            licence_url = build_licence_url(
                widevine_endpoint=widevine_endpoint,
                release_pid=release_pid,
                persona_jwt=raw_jwt,
                account_uri=account_uri,
            )
            return [
                build_widevine_drm_config(
                    licence_url=licence_url,
                    user_agent=self._platform_config["user_agent"],
                )
            ]
        except Exception as exc:
            logger.error(f"get_drm: direct licence build failed for {content_id}: {exc}")
            return []

    def _inject_smil_base_url(self, content_id: str, kwargs: Dict) -> None:
        """
        If a recording manifest_script URL is cached for *content_id*, inject it
        as ``smil_base_url`` into *kwargs* so SmilManager can use it without the
        caller needing to know about it.
        """
        if "smil_base_url" not in kwargs and content_id in self._recording_url_cache:
            kwargs["smil_base_url"] = self._recording_url_cache[content_id]
            logger.debug(f"Injected smil_base_url from recording cache for {content_id}")

    @staticmethod
    def extract_persona_jwt_from_token(persona_token: str) -> Optional[str]:
        """
        Decode a Base64-encoded persona token and extract the raw JWT portion.

        The persona token format is: ``Base64(account_uri + ":" + persona_jwt)``.
        """
        try:
            decoded = base64.b64decode(persona_token).decode("utf-8")
            last_colon_index = decoded.rfind(":")
            if last_colon_index == -1:
                logger.error("No colon found in decoded persona token")
                return None
            persona_jwt = decoded[last_colon_index + 1:]
            if not persona_jwt.startswith("eyJ"):
                logger.error("Extracted token doesn't look like a JWT")
                return None
            return persona_jwt
        except Exception as e:
            logger.error(f"Error extracting persona JWT token: {e}")
            return None