"""Provider timer (scheduled recording) mixin."""

from typing import List

from ..models.timer import Timer
from ..models.timer_type import TimerType


class ProviderTimersMixin:
    @property
    def implements_timers(self) -> bool:
        """
        True if this provider supports scheduled recording timers.

        Return False (default) for providers that only offer live or VOD content
        and have no PVR/timer backend.  TimerOperations skips providers where
        this returns False when aggregating across all providers.
        """
        return False

    def get_timer_types(self) -> List["TimerType"]:
        """
        Return the timer types this provider supports.

        Providers that support timers MUST override this method and return at
        least one TimerType so that clients know what fields to present when
        creating a timer.

        Returns:
            List of TimerType objects, or [] if timers are not supported.
        """
        return []

    def get_timers(self, **kwargs) -> List["Timer"]:
        """
        Return all timers (scheduled recordings) for the authenticated user.

        Args:
            **kwargs: Provider-specific filtering options.

        Returns:
            List of Timer objects, or [] if timers are not supported.
        """
        return []

    def add_timer(self, timer: "Timer", **kwargs) -> "Timer":
        """
        Schedule a new timer on the provider's backend.

        Args:
            timer:    Timer to create.  timer.client_index is ignored — the
                      provider allocates and sets it on the returned object.
            **kwargs: Provider-specific arguments.

        Returns:
            The saved Timer with client_index populated by the provider.

        Raises:
            RuntimeError: If the provider rejects the timer (e.g. scheduling
                          conflict, unsupported timer type, insufficient
                          permissions).

        Default raises NotImplementedError so misconfigured providers fail
        loudly rather than silently doing nothing.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement add_timer(). "
            "Override this method to support timer creation."
        )

    def update_timer(self, timer: "Timer", **kwargs) -> "Timer":
        """
        Update an existing timer on the provider's backend.

        Args:
            timer:    Timer with updated fields. timer.client_index identifies
                      the record to modify.
            **kwargs: Provider-specific arguments.

        Returns:
            The updated Timer as confirmed by the provider.

        Raises:
            KeyError:     If no timer with that client_index exists.
            RuntimeError: If the provider refuses the update (e.g. the timer
                          is currently recording).
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement update_timer(). "
            "Override this method to support timer updates."
        )

    def delete_timer(
            self, client_index: int, force_delete: bool = False, **kwargs
    ) -> None:
        """
        Delete a timer on the provider's backend.

        Args:
            client_index: Timer identifier to delete.
            force_delete: If True and the timer is currently recording, abort
                          the ongoing capture before deleting.
            **kwargs:     Provider-specific arguments.

        Returns:
            None on success.

        Raises:
            KeyError:     If no timer with that client_index exists.
            RuntimeError: If the provider refuses deletion (e.g. recording in
                          progress and force_delete is False).
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement delete_timer(). "
            "Override this method to support timer deletion."
        )