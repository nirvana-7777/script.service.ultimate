"""Provider EPG (electronic program guide) mixin."""

from datetime import datetime
from typing import Dict, List, Optional, Tuple

from ..models.epg_models import EPGEntry, EPGProgramDetails


class ProviderEpgMixin:
    @property
    def epg_window(self) -> Tuple[int, int]:
        """
        Return the EPG window as (past_days, future_days).

        Returns:
            Tuple[int, int]: (past_days, future_days)
            (0, 0) means no EPG support

        MUST be overridden by providers.
        """
        return 0, 0

    @property
    def implements_epg(self) -> bool:
        """Check if provider implements EPG."""
        return self.epg_window != (0, 0)

    # ============================================================================
    # EPG METHODS - Optional with sensible defaults
    # ============================================================================

    def get_epg(
            self,
            channel_id: str,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            country: Optional[str] = None,
            **kwargs,
    ) -> List["EPGEntry"]:
        """
        Get EPG data for a specific channel.

        Override if provider supports per-channel EPG.
        Default returns empty list (no EPG).
        """
        return []

    def get_epg_grid(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            channel_ids: Optional[List[str]] = None,
            country: Optional[str] = None,
            **kwargs,
    ) -> Dict[str, List["EPGEntry"]]:
        """
        Get EPG data for multiple channels in one operation.

        Override if provider supports batch EPG.
        Default returns empty dict (no batch EPG).

        Note: If provider only supports per-channel EPG,
        implement get_epg() and leave this as default.
        """
        return {}

    def get_program_details(self, program_id: str, **kwargs) -> Optional["EPGProgramDetails"]:
        """
        Get detailed metadata for a single program.

        Override if provider supports program details.
        Default returns None (no details).
        """
        return None

    def get_epg_xmltv(self, country: Optional[str] = None, **kwargs) -> Optional[str]:
        """
        Get complete EPG data in XMLTV format.

        Override if provider supports XMLTV export.
        Default returns None (no XMLTV).
        """
        return None