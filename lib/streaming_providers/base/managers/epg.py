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

Constructor contract
--------------------
Four required keyword-only collaborators. No **kwargs.

epg_window returns (past_days, future_days). (0, 0) means no EPG support.
"""

from __future__ import annotations

from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ..models.epg_models import EPGEntry, EPGProgramDetails
from ._base import ManagerBase


class EpgManager(ManagerBase):
    """Abstract base for provider EPG managers."""

    # ------------------------------------------------------------------
    # Capability
    # ------------------------------------------------------------------

    @property
    def epg_window(self) -> Tuple[int, int]:
        """(past_days, future_days). Default (0, 0) means no EPG."""
        return 0, 0

    @property
    def implements_epg(self) -> bool:
        """True when this manager actually provides EPG data."""
        return self.epg_window != (0, 0)

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
        """
        result: Dict[str, List[EPGEntry]] = {}
        for cid in channel_ids:
            if not self.handles_channel_id(cid):
                result[cid] = []
                continue
            result[cid] = self.get_epg(
                cid, start_time=start_time, end_time=end_time, **kw
            )
        return result

    def get_program_details(
        self, program_id: str, **kw: Any
    ) -> Optional[EPGProgramDetails]:
        """Rich metadata for one programme. Default: not supported."""
        return None