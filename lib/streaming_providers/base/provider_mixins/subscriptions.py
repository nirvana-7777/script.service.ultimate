"""Provider subscription/entitlement mixin."""

from typing import TYPE_CHECKING, List, Optional

from ..models import StreamingChannel
from ..models.subscription import SubscriptionPackage, UserSubscription


class ProviderSubscriptionsMixin:
    if TYPE_CHECKING:
        # Provided by StreamingProvider once this is composed into the
        # full class — declared here only for type checkers.
        def get_channels(self, **kwargs) -> List[StreamingChannel]: ...

    def get_subscription_status(self, **kwargs) -> Optional[UserSubscription]:
        """
        Get user's subscription status for this provider.

        Returns:
            UserSubscription object with subscription details, or
            None if provider doesn't support subscription queries or
            subscription info isn't available.

        Default implementation returns None (subscription not supported).
        Override in provider plugins that support subscription checking.

        Example usage in providers:
            # Query provider API for user entitlements
            # Parse response into SubscriptionPackage objects
            # Return UserSubscription with packages and accessible channels
        """
        return None

    def get_subscribed_channels(self, **kwargs) -> List[StreamingChannel]:
        """
        Get channels the current user is subscribed to.

        This method:
        1. Gets subscription status (if supported)
        2. Filters all channels based on accessible channel IDs
        3. Returns filtered list or all channels as fallback

        Returns:
            List of StreamingChannel objects that the user can access

        Note:
            Override get_subscription_status() in provider plugins
            to enable subscription filtering.
        """
        # Get all channels first
        all_channels = self.get_channels(**kwargs)

        # Try to get subscription status
        subscription = self.get_subscription_status(**kwargs)

        # If no subscription info or not active, return all channels
        if not subscription or not subscription.active:
            return all_channels

        # Filter channels based on accessible channel IDs
        if subscription.accessible_channel_ids:
            return [
                channel
                for channel in all_channels
                if channel.channel_id in subscription.accessible_channel_ids
            ]

        # No filtering possible, return all channels
        return all_channels

    def get_available_packages(self, **kwargs) -> List[SubscriptionPackage]:
        """
        Get all subscription packages available from this provider.

        Useful for:
        - Displaying upgrade options in UI
        - Showing package comparison
        - Subscription management interface

        Returns:
            List of available SubscriptionPackage objects
            Empty list if not implemented or no packages available

        Default implementation returns empty list.
        Override in provider plugins that have package information.
        """
        return []

    def is_channel_accessible(self, channel_id: str, **kwargs) -> bool:
        """
        Check if a specific channel is accessible with current subscription.

        Args:
            channel_id: ID of the channel to check
            **kwargs: Additional arguments passed to get_subscription_status()

        Returns:
            True if channel is accessible, False otherwise.
            Returns True if subscription checking is not supported.

        Note:
            This is a convenience method for quick checks.
        """
        subscription = self.get_subscription_status(**kwargs)

        # If no subscription info, assume accessible (backward compatibility)
        if not subscription or not subscription.active:
            return True

        # Check if channel is in accessible set
        return subscription.can_access_channel(channel_id)