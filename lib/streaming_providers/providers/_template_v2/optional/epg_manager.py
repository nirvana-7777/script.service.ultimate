# streaming_providers/providers/example/epg_manager.py
"""
EPG manager skeleton.

--- WIRING ---
from .epg_manager import ExampleEpgManager
def _build_epg(self):
    return ExampleEpgManager(http_manager=self.http_manager, auth=self.auth,
                             country=self.country, config=self.provider_config)
--- END WIRING ---

Contract (EpgManager ABC):
  * epg_window -> (past_days, future_days); (0, 0) means "no EPG".
    The default is (0, 0): a provider WITHOUT EPG simply has no EPG manager.
  * implements_epg is derived from epg_window != (0, 0) and the backend uses
    it to choose between the native path (this manager) and the generic
    XMLTV path. If epg_window needs a network call (server-advertised
    window), OVERRIDE implements_epg to return True: it is read on every
    get_epg call and in the registry listing.
  * get_epg(channel_id, start_time, end_time, **kw) -> List[EPGEntry]
        - the backend hands timezone-aware UTC datetimes (already clamped to
          epg_window) plus limit= in **kw; EPGEntry.start/end are unix
          SECONDS (int). Never compare naive and aware datetimes.
        - channel_id == the Channel.content_id of get_channels() (strip your
          own prefixes if the id carries any).
  * get_epg_grid(channel_ids, ...) default loops get_epg; override with the
    native batch endpoint when there is one (one fetch serves all channels).
  * get_program_details(program_id) -> Optional[EPGProgramDetails]
  * handles_channel_id: override to skip channels without EPG.
"""

from datetime import datetime
from typing import Any, List, Optional, Tuple

from ....base.managers import EpgManager


class ExampleEpgManager(EpgManager):
    @property
    def epg_window(self) -> Tuple[int, int]:
        return 7, 7          # TODO: past days, future days

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw: Any,
    ) -> List:
        # TODO: build EPGEntry objects (see base/models/epg_models.py) for
        # the window [start_time, end_time]; [] when there is nothing.
        return []
