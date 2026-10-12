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
- Serve catchup manifests by appending ``begin``/``end`` to the cached live
  manifest URL — no separate SMIL fetch required.
- Inject ``smil_base_url`` from the recording-URL cache so callers (e.g.
  DRMOperations) only need to pass a ``content_id``.

The class holds NO state of its own beyond references to the managers and
callbacks passed at construction time.  All caches belong to ChannelManager.

Catchup routing
---------------
Magenta2 catchup reuses the live DASH manifest URL with ``begin``/``end``
query parameters (basic-ISO UTC) bounding the requested programme window.  The
Broadpeak origin then serves a static, programme-bounded manifest
(mediaPresentationDuration == programme length), so no manifest rewriting is
needed.  ``end`` is clamped to now so a running programme never requests beyond
the live edge.  Example:

    Live:    https://svc45.…/zdf_hd/DASH/index.mpd?AppVersion=…
    Catchup: https://svc45.…/zdf_hd/DASH/index.mpd?AppVersion=…&begin=20261011T104300&end=20261011T111500

DRM for catchup is identical to live — the same Widevine licence URL applies —
so ``get_drm`` routes catchup requests through the same fast-path as live.

If the live manifest URL is not yet cached when a catchup request arrives,
``_ensure_live_cache()`` is called to populate it before building the URL.
SmilManager is NOT used for catchup on this provider.
"""
import base64
import time
from typing import Callable, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from ...base.models import DRMConfig
from ...base.utils.logger import logger
from ...base.utils.timestamp_converter import TimestampConverter
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
        Platform-specific dict from MAGENTA2_PLATFORMS. Kept for any fields
        not covered by user_agent_subscriber (subscriber_type, etc.) — no
        longer used for platform_config["user_agent"], which doesn't exist
        anymore; use user_agent_subscriber instead.
    user_agent_subscriber:
        Rendered UA (with subscriber_type suffix) — used for the live-DRM
        fast path in get_drm(), matching what SmilManager uses for its own
        (SMIL/VOD) DRM path.
    session_id / call_id_callback:
        Needed so the live-DRM fast path can send a CID header
        ("{session_id}::{call_id}"), matching the SMIL DRM path (see
        smil_manager.get_drm) and confirmed against a real ATV widevine
        capture, which shows only CID — no separate session-id header.
        call_id_callback is optional — if omitted, CID is left off entirely
        (better than sending a malformed header).
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
        user_agent_subscriber: Optional[str] = None,
        session_id: Optional[str] = None,
        call_id_callback: Optional[Callable[[], str]] = None,
    ):
        self._channel_manager = channel_manager
        self._smil_manager = smil_manager
        self._endpoint_manager = endpoint_manager
        self._provider_config = provider_config
        self._platform_config = platform_config
        self._ensure_authenticated = auth_callback
        self._recording_url_cache = recording_url_cache
        self._ua_subscriber = user_agent_subscriber
        self._session_id = session_id
        self._call_id = call_id_callback

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
           Appends ``begin``/``end`` to the cached live manifest URL.
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
        Return a catchup manifest URL for *content_id*.

        Appends ``begin``/``end`` (the requested programme window) to the cached
        live manifest URL. The Broadpeak origin then serves a static, programme-
        bounded manifest (mediaPresentationDuration == programme length), so no
        client- or backend-side manifest rewriting is needed. ``end`` is clamped
        to now so a still-running programme does not request beyond the live edge.

        Parameters
        ----------
        content_id:
            The live channel content_id (same key used in the live cache).
        start_time:
            Unix timestamp (seconds) of the catchup window start.
        end_time:
            Unix timestamp (seconds) of the catchup window end.
        """
        return self._build_begin_end_manifest_url(content_id, start_time, end_time)

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
        Build a programme-bounded catchup manifest URL for a catchup request
        arriving via ``get_manifest`` (``start_time``/``end_time`` in kwargs).
        """
        start_time: int = kwargs["start_time"]
        end_time: int = kwargs["end_time"]
        logger.debug(
            f"get_manifest: catchup request for {content_id} "
            f"(start={start_time}, end={end_time})"
        )
        return self._build_begin_end_manifest_url(content_id, start_time, end_time)

    def _build_begin_end_manifest_url(
        self, content_id: str, start_time: int, end_time: int
    ) -> Optional[str]:
        """
        Retrieve the cached live manifest URL for *content_id* and append the
        ``begin``/``end`` programme window (basic-ISO UTC). ``end`` is clamped to
        now so a running programme never requests beyond the live edge.

        Returns ``None`` if the channel is not found in the live cache even after
        attempting to populate it.
        """
        self._ensure_live_cache()

        live_url = self._channel_manager._live_manifest_cache.get(content_id)
        if not live_url:
            logger.error(
                f"_build_begin_end_manifest_url: no live manifest cached for {content_id}; "
                "cannot build catchup URL"
            )
            return None

        end_time = min(int(end_time), int(time.time()))
        begin_iso = TimestampConverter.epoch_to_iso(
            int(start_time), format_type="basic", as_utc=True
        )
        end_iso = TimestampConverter.epoch_to_iso(end_time, format_type="basic", as_utc=True)

        parsed = urlparse(live_url)
        existing: Dict[str, List[str]] = parse_qs(parsed.query, keep_blank_values=True)
        existing["begin"] = [begin_iso]
        existing["end"] = [end_iso]
        new_query = urlencode({k: v[0] for k, v in existing.items()}, safe="")
        catchup_url = urlunparse(parsed._replace(query=new_query))
        logger.debug(f"_build_begin_end_manifest_url: {content_id} → {catchup_url}")
        return catchup_url

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
            call_id = self._call_id() if self._call_id else None
            return [
                build_widevine_drm_config(
                    licence_url=licence_url,
                    # Subscriber-suffixed UA — matches what SmilManager.get_drm
                    # sends for the SMIL/VOD DRM path.
                    user_agent=self._ua_subscriber,
                    session_id=self._session_id,
                    call_id=call_id,
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