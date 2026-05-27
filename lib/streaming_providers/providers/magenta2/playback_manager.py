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
- Inject ``smil_base_url`` from the recording-URL cache so callers (e.g.
  DRMOperations) only need to pass a ``content_id``.
- Provide ``get_catchup_manifest`` via SmilManager.

The class holds NO state of its own beyond references to the managers and
callbacks passed at construction time.  All caches belong to ChannelManager.
"""
import base64
from typing import Callable, Dict, List, Optional

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

        Live channels whose manifest was already fetched by get_channels() are
        served directly from the ChannelManager cache — no SMIL round-trip.
        VOD and recordings fall through to SmilManager.
        """
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

        For live channels whose releasePid is cached, the Widevine licence URL
        is built directly using lib_theplatform — no SMIL fetch needed.
        VOD and recordings fall through to SmilManager.
        """
        if content_type == CONTENT_TYPE_LIVE:
            self._ensure_live_cache()
            if content_id in self._channel_manager._live_pid_cache:
                return self._build_live_drm(content_id)

        if not self._smil_manager:
            raise RuntimeError("SmilManager not available")
        self._inject_smil_base_url(content_id, kwargs)
        return self._smil_manager.get_drm(content_id, content_type, **kwargs)

    def get_catchup_manifest(
        self, channel_id: str, start_time: int, end_time: int, **kwargs
    ) -> Optional[str]:
        """Return a catchup manifest URL via SmilManager."""
        if not self._smil_manager:
            raise RuntimeError("SmilManager not available")
        return self._smil_manager.get_catchup_manifest(
            channel_id, start_time, end_time, **kwargs
        )

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

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