# ============================================================================
# streaming_providers/base/subscription_operations.py
"""
Subscription and package management operations.
"""

from typing import List, Optional

from .models import StreamingChannel, SubscriptionPackage, UserSubscription
from .utils.logger import logger


class SubscriptionOperations:
    """Handles all subscription-related operations."""

    def __init__(self, registry):
        self.registry = registry
        logger.debug("SubscriptionOperations: Initialized")

    def get_subscription_status(self, provider_name: str, **kwargs) -> Optional[UserSubscription]:
        """Get subscription status for a provider."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        try:
            subscription = provider.get_subscription_status(**kwargs)
            if subscription:
                logger.debug(
                    f"Got subscription for '{provider_name}': "
                    f"{subscription.package_count} packages"
                )
            return subscription
        except Exception as e:
            logger.warning(f"Error getting subscription for '{provider_name}': {e}")
            return None

    def get_subscribed_channels(self, provider_name: str, **kwargs) -> List[StreamingChannel]:
        """Get subscribed channels."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        try:
            channels = provider.get_subscribed_channels(**kwargs)
            logger.info(f"Got {len(channels)} subscribed channels from '{provider_name}'")
            return channels
        except Exception as e:
            logger.error(f"Error getting subscribed channels: {e}")
            return provider.get_channels(**kwargs)

    def get_available_packages(self, provider_name: str, **kwargs) -> List[SubscriptionPackage]:
        """Get available subscription packages."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        try:
            packages = provider.get_available_packages(**kwargs)
            logger.debug(f"Got {len(packages)} packages from '{provider_name}'")
            return packages
        except Exception as e:
            logger.warning(f"Error getting packages for '{provider_name}': {e}")
            return []

    def is_channel_accessible(self, provider_name: str, channel_id: str, **kwargs) -> bool:
        """Check if channel is accessible with current subscription."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        try:
            accessible = provider.is_channel_accessible(channel_id, **kwargs)
            logger.debug(f"Channel '{channel_id}' accessible: {accessible}")
            return accessible
        except Exception as e:
            logger.warning(f"Error checking accessibility: {e}")
            return True  # Assume accessible on error
