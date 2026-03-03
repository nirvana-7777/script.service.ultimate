# ============================================================================
# streaming_providers/base/event_operations.py
"""
Event-related operations separated from core registry.
"""

from datetime import datetime
from typing import Dict, List, Optional

from .models import Event
from .utils.logger import logger


class EventOperations:
    """Handles all event-related operations."""

    def __init__(self, registry):
        self.registry = registry
        logger.debug("EventOperations: Initialized")

    def get_events(
        self,
        provider_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Event]:
        """Get events from a specific provider."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        events = provider.get_events(start_time=start_time, end_time=end_time)
        logger.info(f"Retrieved {len(events)} events from '{provider_name}'")
        return events

    def get_all_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, List[Event]]:
        """Get events from all enabled providers."""
        enabled = self.registry.get_enabled_providers()
        logger.info(f"Fetching events from {len(enabled)} providers")

        result = {}
        total = 0

        for name in enabled:
            try:
                events = self.get_events(name, start_time, end_time)
                result[name] = events
                total += len(events)
            except Exception as e:
                logger.error(f"Failed to get events from '{name}': {e}")
                result[name] = []

        logger.info(f"Retrieved {total} total events")
        return result

    def get_event_manifest(
        self, provider_name: str, event_id: str, **kwargs
    ) -> Optional[str]:
        """
        Get manifest URL for a specific event.

        Delegates to provider.get_manifest() — the same method used for
        channels — because manifest resolution is content-type-agnostic.
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        manifest_url = provider.get_manifest(content_id=event_id, **kwargs)
        if manifest_url:
            logger.debug(
                f"Retrieved manifest for event '{event_id}' from '{provider_name}'"
            )
        return manifest_url