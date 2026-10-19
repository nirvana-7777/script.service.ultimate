# streaming_providers/providers/eon/catchup_manager.py
"""
Eon catchup manager.

Catchup is the live URL plus a start time inside the encrypted payload
(`t=<start>000`) and the timeshift server list; it is minted per request
(fresh ctime and session id) by EonChannelManager.stream_url, which this
manager borrows as an explicit keyword-only extra (`channels=`).

* The API only takes a start time: `end_time` / `epg_id` are accepted for
  signature compatibility and IGNORED.
* Per-channel window = `cutvDelay` of v4/channels (168 h in all samples),
  enforced here: a start outside the window, in the future, or on a channel
  without `cutvEnabled` returns None ("no catchup"), never the live URL.
* Streams are clear HLS: get_catchup_drm stays [] (the backend then reads the
  manifest itself). Catchup is fetched from the CDN, so the headers are the
  same CDN headers as live (no token).
"""

import time
from typing import Any, Dict, Optional

from ...base.managers import CatchupManager
from .constants import EonConfig, EonDefaults


class EonCatchupManager(CatchupManager):
    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: EonConfig,
        channels: Any,
    ):
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        self._channels = channels

    @property
    def catchup_window_hours(self) -> int:
        # Provider-wide MAXIMUM, a constant on purpose: this property is read
        # without a channel and must not trigger network I/O.
        return EonDefaults.CATCHUP_WINDOW_HOURS

    def catchup_window_for_channel(self, content_id: str) -> int:
        record = self._channels.record(content_id)
        return record.catchup_hours if record else 0

    def get_catchup_manifest(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> Optional[str]:
        record = self._channels.record(content_id)
        if record is None or record.catchup_hours <= 0:
            return None
        now = int(time.time())
        if start_time <= 0 or start_time > now:
            return None
        if now - start_time > record.catchup_hours * 3600:
            return None
        return self._channels.stream_url(record, start_time=int(start_time))

    def get_catchup_manifest_headers(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> Dict[str, str]:
        return self.config.stream_headers()