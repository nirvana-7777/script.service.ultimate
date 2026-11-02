# streaming_providers/base/managers/epg.py
"""
EpgManager ABC.

Public interface
----------------
    epg_window                              -> Tuple[int, int]               [concrete]
    implements_epg                          -> bool                          [concrete]
    handles_channel_id(channel_id)          -> bool                          [concrete]
    get_epg(channel_id, start_time, end_time, **kw)
                                            -> List[EPGEntry]                [abstract]
    get_epg_grid(channel_ids, start_time, end_time, **kw)
                                            -> Dict[str, List[EPGEntry]]     [concrete]
    get_program_details(program_id, **kw)   -> Optional[EPGProgramDetails]   [concrete]
    epg_capabilities                        -> EpgCapability                 [concrete]

Constructor contract
--------------------
Four required keyword-only collaborators. No **kwargs.

epg_window returns (past_days, future_days). (0, 0) means no EPG support.

Routing (read this before touching implements_epg)
--------------------------------------------------
EPGOperations routes every endpoint on its OWN capability, never on
implements_epg / epg_window:

    EpgCapability.CHANNEL  get_epg() is a working per-channel query
                           (Kodi PVR path). Without it the channel endpoint
                           is served from the system XMLTV source.
    EpgCapability.GRID     get_epg_grid() is a NATIVE batch implementation that
                           also accepts channel_ids=None (= all channels). With
                           only CHANNEL the backend resolves the channel list
                           itself and the default loop below is used.
    EpgCapability.DETAILS  get_program_details() returns real data. Without it
                           the details endpoint answers 404.

implements_epg / epg_window stay informational (status, listings).

Declaring: set the class attribute EPG_CAPABILITIES. Not declared (None) =
legacy behaviour, derived once from the old signals so nothing changes:
implements_epg False -> NONE, otherwise CHANNEL plus GRID / DETAILS if the
class overrides get_epg_grid / get_program_details.
"""

from __future__ import annotations

from abc import abstractmethod
from datetime import datetime
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from ..epg_capability import (  # noqa: F401  (re-exported)
    EPG_CAP_ALL,
    EpgCapability,
    derive_capabilities,
)
from ..errors import AuthError, GeoBlockError, ProviderError, RateLimitError
from ..models.epg_models import EPGEntry, EPGProgramDetails
from ..utils.logger import logger
from ._base import ManagerBase


class EpgManager(ManagerBase):
    """Abstract base for provider EPG managers."""

    # Explicit capability declaration. None = not declared yet: capabilities are
    # derived from the legacy signals (see module docstring), i.e. no behaviour
    # change. Declare it as a plain class attribute so it never needs a network
    # call (unlike a server-advertised epg_window).
    EPG_CAPABILITIES: ClassVar[Optional[EpgCapability]] = None

    # Opt-in (default False = the historical behaviour, unchanged).
    # False: get_epg_grid() lets any exception of ONE channel abort the grid.
    # True:  AuthError / RateLimitError / GeoBlockError still abort (they hit
    #        every channel alike); any other ProviderError of one channel yields
    #        [] for that channel plus a warning, so one bad channel cannot take
    #        the whole grid down. Only affects the DEFAULT get_epg_grid; a
    #        manager that overrides get_epg_grid is not touched.
    ISOLATE_GRID_FAILURES: ClassVar[bool] = False

    # ------------------------------------------------------------------
    # Capability
    # ------------------------------------------------------------------

    @property
    def epg_window(self) -> Tuple[int, int]:
        """(past_days, future_days). Default (0, 0) means no EPG."""
        return 0, 0

    @property
    def implements_epg(self) -> bool:
        """
        True when this manager provides EPG data. Informational: routing uses
        epg_capabilities. Follows an explicit EPG_CAPABILITIES declaration,
        otherwise the historical rule (epg_window != (0, 0)). A subclass may
        still override it (e.g. server-advertised window).
        """
        declared = self.EPG_CAPABILITIES
        if declared is not None:
            return declared != EpgCapability.NONE
        return self.epg_window != (0, 0)

    @property
    def epg_capabilities(self) -> EpgCapability:
        """Capabilities the backend routes on (see module docstring)."""
        declared = self.EPG_CAPABILITIES
        if declared is not None:
            return declared
        return self._derive_legacy_capabilities()

    @property
    def epg_capabilities_declared(self) -> bool:
        """False while this manager still relies on the derived (legacy) set."""
        return self.EPG_CAPABILITIES is not None

    def _derive_legacy_capabilities(self) -> EpgCapability:
        # Deliberately based on implements_epg (not epg_window): providers with
        # a server-advertised window override implements_epg and must keep EPG.
        return derive_capabilities(self, EpgManager, channel_implied=True)

    def handles_channel_id(self, channel_id: str) -> bool:
        """
        True if this manager provides EPG for the given channel.

        Default: True. Override when only a subset of channels has EPG
        (e.g. radio-only, or a whitelist). Used by the default
        get_epg_grid() to skip unhandled channels without a call.
        """
        return True

    # ------------------------------------------------------------------
    # Abstract
    # ------------------------------------------------------------------

    @abstractmethod
    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw: Any,
    ) -> List[EPGEntry]:
        """Return EPG entries for one channel, or [] if none."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Concrete
    # ------------------------------------------------------------------

    def get_epg_grid(
        self,
        channel_ids: List[str],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw: Any,
    ) -> Dict[str, List[EPGEntry]]:
        """
        Batch EPG for multiple channels.

        Default: loops get_epg per channel, skipping channels for which
        handles_channel_id() is False (returns [] for those without calling
        get_epg). Override when the provider has a native batch endpoint.

        With ISOLATE_GRID_FAILURES = True a failure of one channel (other than
        auth / rate-limit / geo) yields [] for that channel instead of
        aborting the grid. Default: False (unchanged behaviour).
        """
        result: Dict[str, List[EPGEntry]] = {}
        for cid in channel_ids:
            if not self.handles_channel_id(cid):
                result[cid] = []
                continue
            if not self.ISOLATE_GRID_FAILURES:
                result[cid] = self.get_epg(
                    cid, start_time=start_time, end_time=end_time, **kw
                )
                continue
            try:
                result[cid] = self.get_epg(
                    cid, start_time=start_time, end_time=end_time, **kw
                )
            except (AuthError, RateLimitError, GeoBlockError):
                raise
            except ProviderError as exc:
                logger.warning(
                    f"{self.__class__.__name__}: channel {cid} skipped in EPG grid: {exc}"
                )
                result[cid] = []
        return result

    def get_program_details(
        self, program_id: str, **kw: Any
    ) -> Optional[EPGProgramDetails]:
        """Rich metadata for one programme. Default: not supported."""
        return None