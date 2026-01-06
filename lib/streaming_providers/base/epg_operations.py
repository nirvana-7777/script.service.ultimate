# ============================================================================
# streaming_providers/base/epg_operations.py
"""
EPG-related operations.
"""

from typing import Dict, List, Optional

from .epg import EPGManager
from .utils.logger import logger


class EPGOperations:
    """Handles all EPG-related operations."""

    def __init__(self, registry):
        self.registry = registry
        self.epg_manager = EPGManager()
        logger.debug("EPGOperations: Initialized")

    def get_channel_epg(
        self, provider_name: str, channel_id: str, **kwargs
    ) -> List[Dict]:
        """Get EPG data for a specific channel."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if provider.implements_epg:
            logger.debug(f"Using native EPG for '{provider_name}'")
            epg_data = provider.get_epg(channel_id, **kwargs)
        else:
            logger.debug(f"Using generic EPG for '{provider_name}'")
            epg_data = self.epg_manager.get_epg(
                provider_name=provider_name,
                channel_id=channel_id,
                start_time=kwargs.get("start_time"),
                end_time=kwargs.get("end_time"),
            )

        logger.debug(f"Retrieved {len(epg_data)} EPG entries for '{channel_id}'")
        return epg_data

    def get_provider_epg_xmltv(self, provider_name: str, **kwargs) -> Optional[str]:
        """Get complete EPG data in XMLTV format."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if provider.implements_epg:
            return provider.get_epg_xmltv(**kwargs)

        logger.warning(f"Provider '{provider_name}' has no XMLTV EPG")
        return None

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
        """Check if EPG mapping exists."""
        return self.epg_manager.has_mapping_for_channel(provider_name, channel_id)
