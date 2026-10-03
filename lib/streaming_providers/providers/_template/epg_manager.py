# streaming_providers/providers/_template/epg_manager.py
"""
{TODO: Provider name} EPG manager.

Subclasses base.managers.EpgManager. See ../_template/README.md.
"""

from datetime import datetime
from typing import Dict, List, Optional, Tuple

from ...base.managers import EpgManager
from ...base.models.epg_models import EPGEntry, EPGProgramDetails
from ...base.utils.logger import logger


class YourEpgManager(EpgManager):
    """EPG for {TODO: provider name}."""

    @property
    def epg_window(self) -> Tuple[int, int]:
        """(past_days, future_days). (0, 0) means no EPG support."""
        return 0, 0  # TODO: e.g. (2, 7)

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw,
    ) -> List[EPGEntry]:
        raise NotImplementedError("YourEpgManager.get_epg")

    # ----- Optional overrides -----

    # def get_epg_grid(
    #     self,
    #     channel_ids: List[str],
    #     start_time: Optional[datetime] = None,
    #     end_time: Optional[datetime] = None,
    #     **kw,
    # ) -> Dict[str, List[EPGEntry]]:
    #     # Override if the provider has a native batch endpoint.
    #     return super().get_epg_grid(
    #         channel_ids, start_time=start_time,
    #         end_time=end_time, **kw
    #     )