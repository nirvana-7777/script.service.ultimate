# ============================================================================
# streaming_providers/base/channel_operations.py
"""
Channel-related operations separated from core registry.
"""

from typing import Dict, List, Optional

from .models import StreamingChannel
from .utils.logger import logger


class ChannelOperations:
    """Handles all channel-related operations."""

    def __init__(self, registry):
        self.registry = registry
        logger.debug("ChannelOperations: Initialized")

    def get_channels(
        self, provider_name: str, fetch_manifests: bool = False, **kwargs
    ) -> List[StreamingChannel]:
        """Get channels from a specific provider."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        channels = provider.get_channels(**kwargs)
        logger.info(f"Retrieved {len(channels)} channels from '{provider_name}'")

        if fetch_manifests and not provider.uses_dynamic_manifests:
            enriched = []
            for channel in channels:
                enriched_channel = provider.enrich_channel_data(channel, **kwargs)
                if enriched_channel:
                    enriched.append(enriched_channel)
            logger.info(f"Enriched {len(enriched)}/{len(channels)} channels")
            return enriched

        return channels

    def get_channel_manifest(
        self, provider_name: str, channel_id: str, **kwargs
    ) -> Optional[str]:
        """Get manifest URL for a specific channel."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        manifest_url = provider.get_manifest(channel_id, **kwargs)
        if manifest_url:
            logger.debug(
                f"Retrieved manifest for '{channel_id}' from '{provider_name}'"
            )
        return manifest_url

    def get_all_channels(
        self, fetch_manifests: bool = True, **kwargs
    ) -> Dict[str, List[StreamingChannel]]:
        """Get channels from all enabled providers."""
        enabled = self.registry.get_enabled_providers()
        logger.info(f"Fetching channels from {len(enabled)} providers")

        result = {}
        total = 0

        for name in enabled:
            try:
                channels = self.get_channels(name, fetch_manifests, **kwargs)
                result[name] = channels
                total += len(channels)
            except Exception as e:
                logger.error(f"Failed to get channels from '{name}': {e}")
                result[name] = []

        logger.info(f"Retrieved {total} total channels")
        return result
