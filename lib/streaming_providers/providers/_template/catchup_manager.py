# streaming_providers/providers/_template/catchup_manager.py
"""
{TODO: Provider name} catchup manager (optional).

Include this file only if the provider supports timeshift / restart.
Providers without catchup don't create a catchup manager -- the
provider's implements_catchup is False and calls to
get_catchup_manifest return None.

See ../_template/README.md for the contract.

Reference implementations
-------------------------
MoveTV's provider (providers/movetv/provider.py) implements catchup
by resolving an EPG entry, then POSTing to a catchup-source endpoint
that returns a URL + a play-auth header. The URL and header are
coupled, so the manager needs a reference to the EPG manager (to
resolve epg_id) and to the channel manager (for the channel's stream
uid).

Magenta EU's provider (providers/magentaeu/provider.py) implements
catchup by appending start/end query parameters to the live manifest
URL via build_catchup_url().

HRTi has no catchup -- its VOD and EPG are separate domains, and
authorize_session's session id is not reused for timeshift.

State sharing
-------------
The catchup step often shares state with the channel manager (the live
manifest URL) or the EPG manager (the epg_id for the requested window).
Pass those collaborators as explicit keyword-only arguments rather than
reaching back to the provider.

Do NOT fall back to the live manifest
-------------------------------------
If get_catchup_manifest cannot resolve catchup for the given window,
return None. Do not return the live manifest URL as a "catchup"
manifest -- the DRM pipeline would extract PSSH from the live stream,
which may differ from the catchup stream's encryption context.
"""

from typing import Any, Dict, List, Optional

from ...base.managers import CatchupManager
from ...base.models import DRMConfig
from ...base.utils.logger import logger


class YourCatchupManager(CatchupManager):
    """Catchup for {TODO: provider name}."""

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        channels=None,
        epg=None,
    ):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        # Common collaborators. Catchup often needs one or both.
        #   - channels: for resolving a channel's live manifest URL
        #     (Magenta) or its stream uid (MoveTV).
        #   - epg: for resolving an epg_id from a start_time
        #     (MoveTV).
        self._channels = channels
        self._epg = epg

    # ----- Capability -----

    @property
    def catchup_window_hours(self) -> int:
        """Return the catchup window in hours. 0 means no catchup."""
        return 0  # TODO: e.g. 168 for 7 days

    # ----- Abstract method -----

    def get_catchup_manifest(
        self,
        content_id: str,
        start_time: int,
        end_time: int,
        epg_id: Optional[str] = None,
        **kw,
    ) -> Optional[str]:
        """
        Return the catchup manifest URL, or None if not resolvable.

        Do NOT fall back to the live manifest URL here.
        """
        raise NotImplementedError("YourCatchupManager.get_catchup_manifest")

    # ----- Concrete methods (override when needed) -----

    # def get_catchup_drm(
    #     self,
    #     content_id: str,
    #     start_time: int,
    #     end_time: int,
    #     epg_id: Optional[str] = None,
    #     **kw,
    # ) -> List[DRMConfig]:
    #     """
    #     Override only if catchup uses a different DRM config from live.
    #     The default returns [] -- the caller falls back to live DRM.
    #     """
    #     return []