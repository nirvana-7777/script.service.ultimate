# streaming_providers/providers/example/catchup_manager.py
"""
Catchup manager skeleton.

--- WIRING ---
from .catchup_manager import ExampleCatchupManager
def _build_catchup(self):
    if self.channels is None:        # built after channels; may borrow them
        return None
    return ExampleCatchupManager(http_manager=self.http_manager, auth=self.auth,
                                 country=self.country, config=self.provider_config,
                                 channels=self.channels)
--- END WIRING ---

Contract (CatchupManager ABC) and how the backend uses it
(CatchupOperations):
  * catchup_window_hours: the provider-wide MAXIMUM in hours (> 0 turns the
    capability on). The backend gates on it and validates request age with it
    WITHOUT knowing the channel. Per-channel windows go in
    catchup_window_for_channel(content_id); enforce them yourself (return
    None for a start outside the channel's window).
  * get_catchup_manifest(content_id, start_time, end_time=None, epg_id=None, **kw)
        times are UNIX SECONDS; end_time is Optional (pass None, never a
        sentinel); returns None when there is no catchup for that content --
        NEVER fall back to the live URL (the DRM pipeline would extract the
        live PSSH).
  * get_catchup_drm: [] means "no catchup-specific DRM". ManagedProvider
    turns [] into NotImplementedError, which the backend reads as "extract
    PSSH from the catchup manifest". Reusing the live DRM must be explicit:
    return it yourself, or set CATCHUP_DRM_FROM_LIVE = True on the provider.
  * Header hooks: if your catchup streams need the CDN headers, OVERRIDE
    get_catchup_manifest_headers / get_catchup_segment_headers (the ABC
    default is auth.build_headers() = API headers).
  * "Restart" (live manifest + player-side seek) cannot be a URL: expose it
    as a separate provider method (see simpli get_restart()).
  * catchup:<channel>@<ts>-style ids are provider grammar: parse them in
    the provider's get_manifest / get_drm override and hand the manager
    plain (content_id, start_time).
"""

from typing import Any, Optional

from ....base.managers import CatchupManager


class ExampleCatchupManager(CatchupManager):
    def __init__(self, *, http_manager, auth, country, config, channels=None):
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        self._channels = channels

    @property
    def catchup_window_hours(self) -> int:
        return 24            # TODO: the MAXIMUM across channels

    def get_catchup_manifest(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> Optional[str]:
        # TODO: resolve the catchup manifest; None when not available.
        return None
