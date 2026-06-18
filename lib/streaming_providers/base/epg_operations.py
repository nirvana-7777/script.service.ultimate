# ============================================================================
# streaming_providers/base/epg_operations.py
"""
EPG-related operations.
"""

from typing import Dict, List, Optional

from .epg import EPGManager
from .utils.logger import logger
from .models.epg_models import EPGEntry, EPGProgramDetails


class EPGOperations:
    """Handles all EPG-related operations.

    Design note: instantiate this class ONCE (e.g. at application / route
    setup time) and reuse the same instance for every request.  Creating a
    new instance per-request causes EPGManager, EPGCache, EPGMapping and
    their VFS helpers to be re-constructed (and re-logged) on every call.
    """

    def __init__(self, registry):
        self.registry = registry
        self.epg_manager = EPGManager()
        logger.debug("EPGOperations: Initialized")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_provider(self, provider_name: str):
        """Return the provider instance or raise ValueError."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")
        return provider

    # ------------------------------------------------------------------
    # Channel EPG
    # ------------------------------------------------------------------

    def get_channel_epg(
        self,
        provider_name: str,
        channel_id: str,
        start_time=None,
        end_time=None,
        limit: int = 100,
        country: Optional[str] = None,
    ) -> List[EPGEntry]:
        """Get EPG data for a specific channel.

        Args:
            provider_name: Registered provider identifier.
            channel_id:    Provider-scoped channel identifier.
            start_time:    Window start as a timezone-aware datetime (optional).
            end_time:      Window end   as a timezone-aware datetime (optional).
            limit:         Maximum number of programs to return (default 100).
            country:       Optional country filter forwarded to the provider.
        """
        provider = self._get_provider(provider_name)

        if provider.implements_epg:
            logger.debug(f"Using native EPG for '{provider_name}'")
            epg_data = provider.get_epg(
                channel_id,
                start_time=start_time,
                end_time=end_time,
                limit=limit,
                country=country,
            )
        else:
            logger.debug(f"Using generic EPG for '{provider_name}'")
            epg_data = self.epg_manager.get_epg(
                provider_name=provider_name,
                channel_id=channel_id,
                start_time=start_time,
                end_time=end_time,
                limit=limit,
                country=country,
            )

        # Guard against a provider returning None instead of an empty list.
        if epg_data is None:
            logger.warning(
                f"get_epg() returned None for channel '{channel_id}' "
                f"on provider '{provider_name}' — treating as empty result"
            )
            epg_data = []

        logger.debug(f"Retrieved {len(epg_data)} EPG entries for '{channel_id}'")
        return epg_data

    # ------------------------------------------------------------------
    # Multi-channel grid
    # ------------------------------------------------------------------

    def get_provider_epg_grid(
        self,
        provider_name: str,
        start_time=None,
        end_time=None,
        channel_ids: Optional[List[str]] = None,
        country: Optional[str] = None,
    ) -> Dict[str, List[EPGEntry]]:
        """Get a time-windowed EPG grid across multiple channels.

        Returns a dict keyed by channel_id, each value being a list of
        program dicts within the requested window.

        Args:
            provider_name: Registered provider identifier.
            start_time:    Window start as a timezone-aware datetime (optional).
            end_time:      Window end   as a timezone-aware datetime (optional).
            channel_ids:   Subset of channels to include; None means all.
            country:       Optional country filter forwarded to the provider.
        """
        provider = self._get_provider(provider_name)

        if provider.implements_epg:
            logger.debug(f"Using native EPG grid for '{provider_name}'")
            return provider.get_epg_grid(
                start_time=start_time,
                end_time=end_time,
                channel_ids=channel_ids,
                country=country,
            ) or {}

        # Fallback: fan out to the generic EPG manager per channel.
        logger.debug(f"Using generic EPG grid fallback for '{provider_name}'")
        channels = channel_ids or self.epg_manager.get_channel_ids(provider_name)
        grid: Dict[str, List[Dict]] = {}
        for cid in channels:
            entries = self.epg_manager.get_epg(
                provider_name=provider_name,
                channel_id=cid,
                start_time=start_time,
                end_time=end_time,
            ) or []
            grid[cid] = entries

        logger.debug(
            f"Grid for '{provider_name}': {len(grid)} channels, "
            f"window {start_time} – {end_time}"
        )
        return grid

    # ------------------------------------------------------------------
    # Program detail
    # ------------------------------------------------------------------

    def get_program_details(
        self,
        provider_name: str,
        program_id: str,
    ) -> Optional[EPGProgramDetails]:
        """Get full metadata for a single program.

        Args:
            provider_name: Registered provider identifier.
            program_id:    Provider-scoped program identifier.
        """
        provider = self._get_provider(provider_name)

        if provider.implements_epg:
            logger.debug(f"Using native program detail for '{provider_name}/{program_id}'")
            return provider.get_program_details(program_id)

        logger.debug(f"Using generic program detail for '{provider_name}/{program_id}'")
        # The generic EPGManager has no program-detail index; native providers
        # must implement get_program_details() to support this endpoint.
        return None

    # ------------------------------------------------------------------
    # XMLTV export
    # ------------------------------------------------------------------

    def get_provider_epg_xmltv(
        self,
        provider_name: str,
        country: Optional[str] = None,
    ) -> Optional[str]:
        """Get the complete EPG feed in XMLTV format.

        Args:
            provider_name: Registered provider identifier.
            country:       Optional country filter forwarded to the provider.
        """
        provider = self._get_provider(provider_name)

        if provider.implements_epg:
            return provider.get_epg_xmltv(country=country)

        logger.warning(f"Provider '{provider_name}' has no XMLTV EPG")
        return None

    # ------------------------------------------------------------------
    # Cache / mapping utilities
    # ------------------------------------------------------------------

    def clear_epg_cache(self) -> bool:
        """Clear the generic EPG cache."""
        return self.epg_manager.clear_cache()

    def reload_epg_mapping(self) -> bool:
        """Reload EPG channel mapping."""
        return self.epg_manager.reload_mapping()

    def get_epg_cache_info(self) -> Optional[Dict]:
        """Get EPG cache information."""
        return self.epg_manager.get_cache_info()

    def get_epg_mapping_stats(self) -> Dict:
        """Get EPG mapping statistics."""
        return self.epg_manager.get_mapping_stats()

    def has_epg_mapping(self, provider_name: str, channel_id: str) -> bool:
        """Check if an EPG mapping exists for the given channel."""
        return self.epg_manager.has_mapping_for_channel(provider_name, channel_id)