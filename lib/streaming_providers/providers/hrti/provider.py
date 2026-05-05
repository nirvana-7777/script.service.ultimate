# streaming_providers/providers/hrti/provider.py
import json
import datetime
import traceback
from urllib.parse import urlparse
from typing import ClassVar, Dict, List, Optional, Union

import requests

from ...base.models import DRMConfig, StreamingChannel, Event
from ...base.models.proxy_models import ProxyConfig
from ...base.provider import AuthType, StreamingProvider
from ...base.utils import logger
from ..lib_drmtoday import create_drmtoday_widevine_config
from .auth import HRTiAuthenticator
from .constants import HRTiConfig, HRTiDefaults
from .vod_manager import HRTiVodManager

# Navigation-only prefixes — these content_ids are category/series containers.
# They are never directly playable and must never be sent to get_manifest/get_drm.
_NAV_PREFIXES = ("catalogue_", "series_", "special_")

# Playable VOD prefix — "details_{ref_id}" is an explicit single-item request.
_DETAILS_PREFIX = "details_"


class HRTiProvider(StreamingProvider):
    """
    HRTi (Croatian Radio Television Internet) provider implementation.
    """

    # ============================================================================
    # STATIC METADATA
    # ============================================================================
    PROVIDER_LABEL: ClassVar[str] = "HRTi"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = [
        "client_credentials",
        "user_credentials",
    ]
    PROVIDER_LOGO: ClassVar[str] = HRTiDefaults.PROVIDER_LOGO
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["HR"]

    def __init__(
        self,
        country: str = "HR",
        config: Optional[Dict] = None,
        proxy_config: Optional[ProxyConfig] = None,
    ):
        super().__init__(country)

        # Initialize configuration with overrides
        self.hrti_config = HRTiConfig(config)
        self.channels_cache = None

        # Short-lived session cache: {channel_id: session_data}.
        # Populated by _get_live_manifest so that a subsequent _get_live_drm
        # call for the same channel (same playback request) can reuse the
        # already-authorized session instead of making a second round trip.
        self._session_cache: Dict[str, dict] = {}

        # Setup HTTP manager using abstraction
        self.http_manager = self._setup_http_manager(
            provider_name="hrti",
            proxy_config=proxy_config,
            user_agent=self.hrti_config.user_agent,
            timeout=self.hrti_config.timeout,
        )

        # Initialize authenticator and share HTTP manager
        self.authenticator = HRTiAuthenticator(
            proxy_config=proxy_config, http_manager=self.http_manager
        )

        # Share HTTP manager
        self.http_manager = self._share_http_manager_with_authenticator(self.authenticator)

        # Initialize VOD manager
        self._vod_manager = HRTiVodManager(self)

        try:
            self.authenticator.get_bearer_token()
            logger.debug("HRTi authentication successful during initialization")
        except Exception as e:
            logger.warning(f"HRTi could not authenticate during initialization: {e}")

    # ============================================================================
    # Provider properties
    # ============================================================================

    @property
    def provider_name(self) -> str:
        return "hrti"

    @property
    def provider_label(self) -> str:
        return self.get_static_label(self.country)

    @property
    def provider_logo(self) -> str:
        return self.hrti_config.logo or self.PROVIDER_LOGO

    @property
    def uses_dynamic_manifests(self) -> bool:
        return True

    @property
    def implements_epg(self) -> bool:
        return False

    @property
    def implements_vod(self) -> bool:
        return True

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

    # ============================================================================
    # Internal helpers
    # ============================================================================

    def _get_hrti_authenticated_headers(self) -> Dict[str, str]:
        """Build authenticated headers for HRTi API requests."""
        return self._build_provider_headers(
            auth_type=AuthType.CLIENT,
            token_key="authorization",  # HRTi uses lowercase
            provider_headers={
                "deviceid": self.authenticator.get_device_id(),
                "devicetypeid": self.hrti_config.device_reference_id,
                "ipaddress": self.authenticator.get_ip_address(),
                "operatorreferenceid": self.hrti_config.operator_reference_id,
                "origin": self.hrti_config.base_website,
                "referer": f"{self.hrti_config.base_website}/login",
            },
        )

    @staticmethod
    def _is_nav_node(content_id: str) -> bool:
        """Return True for navigation-only ids (category/series/season/special).
        These are never playable and must not be passed to get_manifest/get_drm."""
        return any(content_id.startswith(p) for p in _NAV_PREFIXES)

    @staticmethod
    def _is_playable_vod(content_id: str) -> bool:
        """Return True for ids that represent a playable VOD item.

        Two forms are playable:
          - ``details:{ref_id}``  — explicit single-item request
          - bare ref-id (no prefix) — raw ReferenceId from catalogue listing
            (UUIDs like "85b273d1-..." or legacy ids like "1870699590_delin")

        Live channel ids are also bare numeric strings (e.g. "40013") so this
        method alone does not distinguish VOD from live — callers must first
        exclude nav nodes, then check against the live channel list.
        """
        if any(content_id.startswith(p) for p in _NAV_PREFIXES):
            return False
        # "details_" prefix is an explicit VOD request
        if content_id.startswith(_DETAILS_PREFIX):
            return True
        # Bare id — could be VOD or live; live ids are short numerics.
        # We treat any non-numeric bare id as VOD; live channel lookup
        # will confirm or deny for numeric ids.
        return not content_id.isdigit()

    @staticmethod
    def _derive_content_drm_id(streaming_url: str) -> Optional[str]:
        """
        Derive the content DRM ID from a streaming URL.

        HRTi expects the first two path segments joined by '_'.
        Example: /cdn1oiv/hrtliveorigin/... → "cdn1oiv_hrtliveorigin"
        """
        parts = urlparse(streaming_url).path.strip("/").split("/")
        if len(parts) >= 2:
            return f"{parts[0]}_{parts[1]}"
        return None

    def _find_channel(self, content_id: str) -> Optional[StreamingChannel]:
        """Return the cached channel for *content_id*, fetching if needed."""
        channels = self.channels if (hasattr(self, "channels") and self.channels) else self.get_channels()
        for ch in channels:
            # StreamingChannel is constructed with content_id= kwarg; some base-class
            # versions also alias it as channel_id — check both to be safe.
            ch_id = getattr(ch, "content_id", None) or getattr(ch, "channel_id", None)
            if ch_id == content_id:
                return ch
        return None

    def _authorize_live_session(self, content_id: str) -> Optional[dict]:
        """
        Authorize a live playback session for *content_id*.

        Looks up the channel to determine the correct content_type
        (``rlive`` for radio, ``tlive`` for TV) and derives the DRM ID
        from the streaming URL.  Reports the session-start event on
        success and stores the result in ``_session_cache``.

        Returns the raw session dict, or None on failure.
        """
        channel = self._find_channel(content_id)
        if not channel:
            logger.error(f"Channel {content_id} not found for session authorization")
            return None

        content_type = "rlive" if channel.content_type == "AUDIO" else "tlive"
        content_drm_id = self._derive_content_drm_id(channel.manifest_script or "")

        logger.debug(
            f"Authorizing session — channel: {content_id}, "
            f"content_type: {content_type}, drm_id: {content_drm_id}"
        )

        session_data = self.authenticator.authorize_session(
            content_type=content_type,
            content_ref_id=content_id,
            content_drm_id=content_drm_id,
            video_store_ids=None,
            channel_id=content_id,
            start_time=None,
            end_time=None,
        )

        if not session_data or not session_data.get("Authorized", False):
            logger.error(f"Session authorization failed for channel {content_id}")
            return None

        logger.debug(f"Session authorized for channel {content_id}")

        session_id = session_data.get("SessionId")
        if session_id:
            self.authenticator.report_session_event(session_id, content_id)

        # Cache so a same-request get_drm() call can skip a second auth round trip
        self._session_cache[content_id] = session_data
        return session_data

    def _build_widevine_drm_config(
        self,
        session_data: dict,
        content_id: str,
        referer_path: str,
    ) -> List[DRMConfig]:
        """
        Build a Widevine DRMConfig list from an already-authorized session.

        Args:
            session_data:  Authorized session dict containing at least ``DrmId``.
            content_id:    Used only for log messages.
            referer_path:  Appended to base_website for the Referer header
                           (e.g. ``"/"`` for live, ``"/videostore"`` for VOD).
        """
        drm_id = session_data.get("DrmId")
        if not drm_id:
            logger.error(f"No DrmId in session data for {content_id}")
            return []

        license_data = self.authenticator.get_license_data(drm_id)
        if not license_data:
            logger.error(f"Failed to generate license data for {content_id}")
            return []

        drm_config = create_drmtoday_widevine_config(
            upfront_token=license_data,
            origin=self.hrti_config.base_website,
            referer=f"{self.hrti_config.base_website}{referer_path}",
            user_agent=self.hrti_config.user_agent,
            auth_header_name="dt-custom-data",
        )

        if not drm_config:
            logger.error(f"create_drmtoday_widevine_config returned nothing for {content_id}")
            return []

        logger.debug(f"Created Widevine DRM config for {content_id}")
        return [drm_config]

    # ============================================================================
    # Channel fetching
    # ============================================================================

    def _fetch_channels_once(self) -> List[StreamingChannel]:
        """Single attempt to fetch and parse the channel list."""
        headers = self._get_hrti_authenticated_headers()
        logger.debug(
            "Fetching HRTi channels with authorization: "
            f"{'Client ...' if 'authorization' in headers else 'NO AUTHORIZATION'}"
        )

        response = self.http_manager.post(
            self.hrti_config.api_endpoints["channels"],
            operation="api",
            headers=headers,
            data=json.dumps({}),
        )
        response.raise_for_status()

        channels_data = response.json()
        if not channels_data.get("Result"):
            logger.warning("No channels found in HRTi response")
            logger.debug(f"HRTi channels response: {channels_data}")
            return []

        channels = []
        for raw in channels_data["Result"]:
            ch = self._parse_channel_data(raw)
            if ch:
                channels.append(ch)

        self.channels = channels
        return channels

    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """Fetch channels from HRTi API, with one auth-refresh retry on failure."""
        try:
            channels = self._fetch_channels_once()
            logger.info(f"Successfully fetched {len(channels)} channels from HRTi")
            return channels
        except requests.RequestException as e:
            logger.error(f"Error fetching HRTi channels: {e}")
            logger.info("Attempting to refresh authentication and retry...")
            self.authenticator.invalidate_token()
            try:
                channels = self._fetch_channels_once()
                logger.info(f"Successfully fetched {len(channels)} channels from HRTi on retry")
                return channels
            except Exception as retry_e:
                logger.error(f"Retry failed: {retry_e}")
                return []
        except Exception as e:
            logger.error(f"Error parsing HRTi channels: {e}")
            return []

    def get_events(
        self,
        start_time: Optional[datetime.datetime] = None,
        end_time: Optional[datetime.datetime] = None,
        **kwargs,
    ) -> List[Event]:
        return []

    def _parse_channel_data(self, channel_data: Dict) -> Optional[StreamingChannel]:
        """Parse a raw HRTi channel dict into a StreamingChannel."""
        try:
            name = channel_data.get("Name", "")
            # API returns 'ReferenceID' (capital ID), not 'ReferenceId'
            channel_id = channel_data.get("ReferenceID", "")
            streaming_url = channel_data.get("StreamingURL", "")
            is_radio = channel_data.get("Radio", False)
            icon_url = channel_data.get("Icon", "")

            if not name or not channel_id:
                logger.debug(f"Skipping channel — missing name or ID: {channel_data}")
                return None

            channel = StreamingChannel(
                name=name,
                content_id=channel_id,
                provider=self.provider_name,
                logo_url=icon_url,
                mode="live",
                session_manifest=True,
                manifest=None,
                manifest_script=streaming_url,
                content_type="AUDIO" if is_radio else "LIVE",
                country=self.country,
                is_radio=is_radio,
                language="hr",
            )
            channel.use_cdm = True
            channel.cdm_type = "widevine"

            logger.debug(f"Parsed HRTi channel: {name} ({channel_id}) — radio: {is_radio}")
            return channel

        except Exception as e:
            logger.error(f"Error parsing channel {channel_data}: {e}")
            return None

    # ============================================================================
    # VOD
    # ============================================================================

    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kwargs,
    ) -> Union[List, Dict]:
        """
        Get VOD category children. Delegates to HRTiVodManager.

        Args:
            content_id: Opaque node identifier (see HRTiVodManager docstring)
            cursor:     Pagination cursor
            page_size:  Items per page

        Returns:
            Dict with ``entries``, ``next_cursor``, ``total`` keys.
        """
        result = self._vod_manager.get_category(content_id, cursor, page_size)

        if isinstance(result, dict):
            return result
        if isinstance(result, list):
            return {"entries": result, "next_cursor": None, "total": None}
        return {"entries": [], "next_cursor": None, "total": None}

    # ============================================================================
    # Manifest
    # ============================================================================

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        """
        Return the playback manifest URL for *content_id*.

        Routing:
          - Navigation nodes (catalogue:/series:/season:/special:) → error, not playable
          - details_{ref} or bare non-numeric id → VOD
          - bare numeric id → live channel
        """
        if self._is_nav_node(content_id):
            logger.error(
                f"get_manifest called with navigation node '{content_id}' — "
                f"this is a category/series/season container, not a playable item"
            )
            return None

        # Strip "details_" prefix before passing to VOD manager
        vod_ref = content_id[len(_DETAILS_PREFIX):] if content_id.startswith(_DETAILS_PREFIX) else content_id

        if self._is_playable_vod(content_id):
            return self._vod_manager.get_vod_streaming_url(vod_ref)

        return self._get_live_manifest(content_id, **kwargs)

    def _get_live_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        """Authorize a session and return the streaming URL for a live channel."""
        try:
            session_data = self._authorize_live_session(content_id)
            if not session_data:
                return None

            channel = self._find_channel(content_id)
            if channel and channel.manifest_script:
                return channel.manifest_script

            logger.warning(f"No streaming URL found for channel {content_id}")
            return None

        except Exception as e:
            logger.error(f"Error getting manifest for channel {content_id}: {e}")
            return None

    # ============================================================================
    # DRM
    # ============================================================================

    def get_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """
        Return Widevine DRM config(s) for *content_id*.

        Routing mirrors get_manifest() — nav nodes are rejected, playable VOD
        goes to _get_vod_drm, live channels go to _get_live_drm.
        """
        if self._is_nav_node(content_id):
            logger.error(
                f"get_drm called with navigation node '{content_id}' — "
                f"this is a category/series/season container, not a playable item"
            )
            return []

        vod_ref = content_id[len(_DETAILS_PREFIX):] if content_id.startswith(_DETAILS_PREFIX) else content_id

        if self._is_playable_vod(content_id):
            return self._get_vod_drm(vod_ref, **kwargs)
        return self._get_live_drm(content_id, **kwargs)

    def _get_live_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """Get Widevine DRM config for a live channel."""
        try:
            # Prefer session data passed explicitly by the caller, then the
            # cache populated by _get_live_manifest, then authorize fresh.
            session_data = (
                kwargs.get("session_data")
                or self._session_cache.get(content_id)
                or self._authorize_live_session(content_id)
            )

            if not session_data:
                return []

            return self._build_widevine_drm_config(
                session_data=session_data,
                content_id=content_id,
                referer_path="/",
            )

        except Exception as e:
            logger.error(f"Error getting DRM config for channel {content_id}: {e}")
            logger.error(traceback.format_exc())
            return []

    def _get_vod_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """Get Widevine DRM config for a VOD item."""
        try:
            session_data = self._vod_manager.get_vod_session_data(content_id)

            if not session_data or not session_data.get("Authorized", False):
                logger.error(f"Failed to authorize session for VOD DRM: {content_id}")
                return []

            return self._build_widevine_drm_config(
                session_data=session_data,
                content_id=content_id,
                referer_path="/videostore",
            )

        except Exception as e:
            logger.error(f"Error getting DRM for VOD {content_id}: {e}")
            logger.error(traceback.format_exc())
            return []

    # ============================================================================
    # EPG and ancillary methods
    # ============================================================================

    def get_epg(self, channel_id: str, **kwargs) -> List[Dict]:
        """Get EPG data for a channel."""
        try:
            headers = self._get_hrti_authenticated_headers()
            start_time = self.authenticator.get_time_offset(-4)
            end_time = self.authenticator.get_time_offset(4)

            payload = {
                "ChannelReferenceIds": [channel_id],
                "StartTime": f"/Date({start_time})/",
                "EndTime": f"/Date({end_time})/",
            }

            response = self.http_manager.post(
                self.hrti_config.api_endpoints["programme"],
                operation="api",
                headers=headers,
                data=json.dumps(payload),
            )
            response.raise_for_status()

            epg_data = response.json()
            if "Result" in epg_data:
                return [
                    {
                        "title": entry.get("Title", ""),
                        "description": entry.get("Description", ""),
                        "start": entry.get("StartTime", ""),
                        "end": entry.get("EndTime", ""),
                        "genre": entry.get("Genre", ""),
                    }
                    for entry in epg_data["Result"]
                ]
            return []

        except Exception as e:
            logger.error(f"Error getting EPG data for channel {channel_id}: {e}")
            return []

    def get_license_url(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        """Return the Widevine license server URL for *channel*."""
        drm_configs = self.get_drm(channel.channel_id, **kwargs)
        if drm_configs:
            return drm_configs[0].license.server_url
        return None

    @property
    def catchup_window(self) -> int:
        """HRTi does not support live-channel catchup."""
        return 0

    def get_epg_xmltv(self, **kwargs) -> Optional[str]:
        """HRTi does not provide XMLTV natively."""
        return None

    def get_dynamic_manifest_params(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        """Session authorization is handled inside get_manifest(); nothing extra needed here."""
        return None