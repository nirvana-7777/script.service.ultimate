# streaming_providers/providers/hrti/channel_manager.py
"""
HRTi live channel manager (live TV + radio).

Playback flow (unchanged from v1, now one shared authorised session):
  AuthorizeSession(rlive|tlive, channel id, drm id derived from the stream URL)
  -> report the session start -> manifest = the channel's StreamingURL
  -> DRM from the same session (DrmId -> DRMToday upfront token).
Manifest and DRM share ONE authorised session through the provider-owned
playout cache (5 s TTL), so a zap costs one AuthorizeSession, not two.

Return conventions (ChannelManager ABC):
  * handles_content_id is ids.is_live (digits only); anything else is not ours
  * unknown live id -> NotFoundError; session not authorised -> EntitlementError
  * transport / auth / server failures propagate typed (base.errors)
"""

import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from ...base.errors import EntitlementError, NotFoundError
from ...base.managers import ChannelManager
from ...base.models import Channel, DRMConfig
from ...base.utils.logger import logger
from . import ids
from .api import api_post
from .constants import HRTiDefaults
from .drm import build_widevine, derive_live_drm_id
from .models import LiveChannelInfo

_LIVE_REFERER = "/"


class HRTiChannelManager(ChannelManager):
    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
        playout_cache: Optional[Dict[str, Tuple[Dict, float]]] = None,
    ):
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        # Provider-owned dict, borrowed by reference (cleared on credential change).
        self._playout_cache = playout_cache if playout_cache is not None else {}
        # channel id -> API record (stream URL, radio flag); filled by get_channels()
        self._records: Dict[str, LiveChannelInfo] = {}
        self._records_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------
    def handles_content_id(self, content_id: str) -> bool:
        return ids.is_live(content_id)

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------
    def get_channels(self, **kw: Any) -> List[Channel]:
        result = api_post(
            http_manager=self.http_manager,
            session=self.auth,
            config=self.config,
            endpoint_key="channels",
            payload={},
            referer_path=_LIVE_REFERER,
        )
        if not result:
            logger.warning("HRTi: no channels in the GetChannels response")
            return []

        records: Dict[str, LiveChannelInfo] = {}
        channels: List[Channel] = []
        for raw in result:
            try:
                record = LiveChannelInfo.from_api_response(raw)
                channel = record.to_channel(HRTiDefaults.PROVIDER_NAME, self.country.upper())
            except (KeyError, TypeError, AttributeError, ValueError) as exc:
                logger.warning(f"HRTi: skipping malformed channel entry: {exc!r}")
                continue
            records[record.content_id] = record
            channels.append(channel)

        with self._records_lock:
            self._records = records
        logger.info(f"HRTi: {len(channels)} channels loaded")
        return channels

    def clear_caches(self) -> None:
        """Called by the provider when the credentials / session change."""
        self._playout_cache.clear()
        with self._records_lock:
            self._records = {}

    def _record_for(self, content_id: str) -> LiveChannelInfo:
        with self._records_lock:
            record = self._records.get(content_id)
        if record is None:
            self.get_channels()                       # fills self._records
            with self._records_lock:
                record = self._records.get(content_id)
        if record is None:
            raise NotFoundError(f"HRTi: channel {content_id} is not in the channel list")
        return record

    # ------------------------------------------------------------------
    # Authorised playback session (shared by manifest and DRM)
    # ------------------------------------------------------------------
    def _session(self, content_id: str) -> Dict[str, Any]:
        now = time.time()
        cached = self._playout_cache.get(content_id)
        if cached and (now - cached[1]) < HRTiDefaults.PLAYOUT_CACHE_TTL:
            return cached[0]

        record = self._record_for(content_id)
        content_type = "rlive" if record.is_radio else "tlive"
        session_data = self.auth.authorize_session(
            content_type=content_type,
            content_ref_id=content_id,
            content_drm_id=derive_live_drm_id(record.stream_url),
            video_store_ids=None,
            channel_id=content_id,
            start_time=None,
            end_time=None,
        )
        if not session_data.get("Authorized", False):
            raise EntitlementError(
                f"HRTi: session for channel {content_id} was not authorised"
            )
        session_id = session_data.get("SessionId")
        if session_id:
            self.auth.report_session_event(session_id, content_id)   # best effort
        self._playout_cache[content_id] = (session_data, now)
        return session_data

    # ------------------------------------------------------------------
    # Manifest / DRM
    # ------------------------------------------------------------------
    def get_channel_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        self._session(content_id)                 # authorise first (v1 behaviour)
        record = self._record_for(content_id)
        if not record.stream_url:
            logger.warning(f"HRTi: no streaming URL for channel {content_id}")
            return None
        return record.stream_url

    def get_channel_drm(self, content_id: str, **kw: Any) -> List[DRMConfig]:
        # The backend passes drm_variant / preferred_* kwargs: accepted, unused.
        session_data = self._session(content_id)
        return build_widevine(
            self.config,
            self.auth.user_id,
            session_data,
            content_id,
            referer_path=_LIVE_REFERER,
        )
