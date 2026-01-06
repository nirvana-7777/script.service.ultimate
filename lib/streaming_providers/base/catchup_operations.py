# ============================================================================
# streaming_providers/base/catchup_operations.py
"""
Catchup/timeshift operations.
"""

from typing import Dict, List, Optional

from .utils.logger import logger


class CatchupOperations:
    """Handles all catchup-related operations."""

    def __init__(self, registry, drm_operations):
        self.registry = registry
        self.drm_operations = drm_operations
        logger.debug("CatchupOperations: Initialized")

    def get_catchup_manifest(
        self,
        provider_name: str,
        channel_id: str,
        start_time: int,
        end_time: int,
        epg_id: Optional[str] = None,
        country: Optional[str] = None,
    ) -> Optional[str]:
        """Get catchup manifest URL."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if not provider.supports_catchup:
            logger.warning(f"Provider '{provider_name}' doesn't support catchup")
            return None

        is_valid, error = provider.validate_catchup_request(start_time, end_time)
        if not is_valid:
            logger.error(f"Invalid catchup request: {error}")
            return None

        try:
            return provider.get_catchup_manifest(
                channel_id=channel_id,
                start_time=start_time,
                end_time=end_time,
                epg_id=epg_id,
                country=country,
            )
        except NotImplementedError:
            logger.error(f"Provider '{provider_name}' hasn't implemented catchup")
            return None

    def get_catchup_drm_configs(
        self,
        provider_name: str,
        channel_id: str,
        start_time: int,
        end_time: int,
        epg_id: Optional[str] = None,
        country: Optional[str] = None,
    ) -> List:
        """Get DRM configs for catchup content."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if not provider.supports_catchup:
            return self.drm_operations.get_channel_drm_configs(
                provider_name, channel_id, country=country
            )

        try:
            return provider.get_catchup_drm(
                channel_id=channel_id,
                start_time=start_time,
                end_time=end_time,
                epg_id=epg_id,
                country=country,
            )
        except NotImplementedError:
            return self.drm_operations.get_channel_drm_configs(
                provider_name, channel_id, country=country
            )

    def get_catchup_window(
        self, provider_name: str, channel_id: Optional[str] = None
    ) -> int:
        """Get catchup window in hours."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if channel_id:
            try:
                return provider.get_catchup_window_for_channel(channel_id)
            except Exception as e:
                logger.warning(f"Error getting channel catchup window: {e}")

        return provider.catchup_window

    def supports_catchup(self, provider_name: str) -> bool:
        """Check if provider supports catchup."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")
        return provider.supports_catchup

    def get_all_catchup_capabilities(self) -> Dict[str, Dict]:
        """Get catchup capabilities for all providers."""
        capabilities = {}
        for name in self.registry.list_providers():
            try:
                provider = self.registry.get_provider(name)
                capabilities[name] = {
                    "supports_catchup": provider.supports_catchup,
                    "catchup_window": provider.catchup_window,
                    "catchup_enabled": provider.supports_catchup
                    and provider.catchup_window > 0,
                }
            except Exception as e:
                logger.warning(f"Error getting catchup for '{name}': {e}")
                capabilities[name] = {
                    "supports_catchup": False,
                    "catchup_window": 0,
                    "catchup_enabled": False,
                }
        return capabilities
