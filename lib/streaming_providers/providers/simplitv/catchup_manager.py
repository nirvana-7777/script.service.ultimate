# streaming_providers/providers/simplitv/catchup_manager.py
"""
simpliTV catchup manager.

simpliTV has no catchup endpoint. The existing addon does two things,
and this manager mirrors both:

1. Programme replay. An EPG programme (isCatchupEnabled) is played by
   passing the *programme's own codename* to AcquireContent -- a plain
   manifest, no time parameters. get_catchup_manifest does this when the
   caller supplies epg_id (the programme codename, an EPG broadcast_id,
   or a prog: id).

2. Restart from the beginning. The addon plays the *live* manifest, which
   carries a 3 hour DVR window, and seeks
   (window - age - margin) seconds into it. A manifest URL cannot express
   a seek, so this is exposed separately as get_restart_manifest(),
   returning (url, seek_seconds). get_catchup_manifest never answers a
   restart request with a bare live URL: the ABC can only hand back a
   URL, and the caller would silently play live.

Contract
--------
The router parses the @<ts> suffix of catchup:<channel>@<unix_ts> and
passes start_time. A malformed id raises BadRequestError (it is not
swallowed). end_time is ignored: the API has no end bound.
"""

import time
from typing import List, Optional, Tuple

from ...base.errors import BadRequestError, NotFoundError
from ...base.managers import CatchupManager
from ...base.models import DRMConfig

from .channel_manager import (
    parse_catchup_id,
    parse_live_id,
    programme_codename_from_epg_id,
)
from .constants import SimpliTVDefaults


class SimpliTVCatchupManager(CatchupManager):
    """Catchup for simpliTV."""

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        channels=None,  # SimpliTVChannelManager: AcquireContent, DRM
    ):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        self._channels = channels

    # ------------------------------------------------------------------
    # Capability
    # ------------------------------------------------------------------

    @property
    def catchup_window_hours(self) -> int:
        return SimpliTVDefaults.CATCHUP_WINDOW_HOURS

    # ------------------------------------------------------------------
    # Abstract method
    # ------------------------------------------------------------------

    def get_catchup_manifest(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw,
    ) -> Optional[str]:
        """
        Manifest for replaying a programme (epg_id given), else None.

        Returns None when there is no epg_id (use get_restart_manifest
        for restart-from-beginning) or when AcquireContent has no
        manifest for the programme. Raises BadRequestError for a
        malformed id.
        """
        _channel_and_ts(content_id)  # grammar check; raises on malformed

        if not epg_id or self._channels is None:
            return None

        programme = programme_codename_from_epg_id(epg_id)
        try:
            return self._channels.get_channel_manifest(
                f"{SimpliTVDefaults.PROGRAMME_PREFIX}{programme}"
            )
        except NotFoundError:
            return None

    # ------------------------------------------------------------------
    # Restart-from-beginning (live manifest + player-side seek)
    # ------------------------------------------------------------------

    def get_restart_manifest(
        self, content_id: str, start_time: int = 0
    ) -> Optional[Tuple[str, int]]:
        """
        Return (live manifest URL, seek_seconds) to restart a programme
        that began at start_time, or None.

        seek_seconds is the offset from the *start* of the DVR window:
        window - age - margin. The id's embedded @<ts> is used when
        start_time is not given. None when the start is in the future,
        outside the window (less the safety margin), or the channel has
        no manifest.
        """
        codename, embedded = _channel_and_ts(content_id)
        if start_time <= 0 and embedded:
            start_time = embedded
        if start_time <= 0 or self._channels is None:
            return None

        window = SimpliTVDefaults.CATCHUP_WINDOW_HOURS * 3600
        margin = SimpliTVDefaults.CATCHUP_SEEK_MARGIN_SECONDS
        age = int(time.time()) - start_time
        if age < 0 or age >= window - margin:
            return None

        try:
            url = self._channels.get_channel_manifest(
                f"{SimpliTVDefaults.LIVE_PREFIX}{codename}"
            )
        except NotFoundError:
            return None
        if not url:
            return None
        return url, window - age - margin

    # ------------------------------------------------------------------
    # Concrete overrides
    # ------------------------------------------------------------------

    def get_catchup_drm(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw,
    ) -> List[DRMConfig]:
        """
        DRM for catchup: the programme's own (epg_id) when replaying,
        otherwise the channel's live DRM (restart plays the live
        stream). Scheme selection stays in the channel manager.
        """
        codename, _ = _channel_and_ts(content_id)
        if self._channels is None:
            return []
        if epg_id:
            target = (
                f"{SimpliTVDefaults.PROGRAMME_PREFIX}"
                f"{programme_codename_from_epg_id(epg_id)}"
            )
        else:
            target = f"{SimpliTVDefaults.LIVE_PREFIX}{codename}"
        return self._channels.get_channel_drm(target)


def _channel_and_ts(content_id: str) -> Tuple[str, Optional[int]]:
    """(channel codename, embedded ts or None) for catchup: / live: ids."""
    if content_id.startswith(SimpliTVDefaults.CATCHUP_PREFIX):
        return parse_catchup_id(content_id)
    if content_id.startswith(SimpliTVDefaults.LIVE_PREFIX):
        return parse_live_id(content_id), None
    raise BadRequestError(
        f"simpliTV: not a catchup/live id: {content_id!r}"
    )
