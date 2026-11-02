"""Provider EPG (electronic program guide) mixin."""

from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Tuple

from ..epg_capability import EpgCapability, derive_capabilities
from ..models.epg_models import EPGEntry, EPGProgramDetails


class ProviderEpgMixin:
    # Explicit capability declaration (see EpgManager). None = derived from
    # which of the methods below the provider actually overrides.
    EPG_CAPABILITIES: ClassVar[Optional[EpgCapability]] = None

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
        """Informational (status / listings); routing uses epg_capabilities."""
        declared = self.EPG_CAPABILITIES
        if declared is not None:
            return declared != EpgCapability.NONE
        return self.epg_window != (0, 0)

    @property
    def epg_capabilities(self) -> EpgCapability:
        """
        What the backend may route to this provider. Declared via
        EPG_CAPABILITIES, otherwise derived: an epg_window alone is not enough,
        a method must be overridden for its capability to count (the defaults
        below return nothing).
        """
        declared = self.EPG_CAPABILITIES
        if declared is not None:
            return declared
        return derive_capabilities(self, ProviderEpgMixin, channel_implied=False)

    @property
    def epg_capabilities_declared(self) -> bool:
        return self.EPG_CAPABILITIES is not None

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

        Override if provider supports batch EPG (and declare
        EpgCapability.GRID).

        Default: if provider only supports per-channel EPG, loop get_epg() over
        the given channel_ids. With channel_ids=None it returns {} (unchanged
        from before; ManagedProvider resolves "all channels" itself).
        """
        return {
            cid: self.get_epg(cid, start_time=start_time, end_time=end_time,
                              country=country, **kwargs)
            for cid in (channel_ids or [])
        }

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