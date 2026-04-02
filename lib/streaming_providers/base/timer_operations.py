# streaming_providers/base/timer_operations.py
"""
Timer-related operations separated from core registry.
Mirrors the structure of RecordingOperations.
"""

from typing import Dict, List, Optional

from .models.timer import Timer
from .models.timer_type import TimerType
from .utils.logger import logger


class TimerOperations:
    """Handles all timer-related operations."""

    def __init__(self, registry):
        self.registry = registry
        logger.debug("TimerOperations: Initialized")

    # ------------------------------------------------------------------
    # Timer types
    # ------------------------------------------------------------------

    def get_timer_types(self, provider_name: str) -> List[TimerType]:
        """
        Get the timer types supported by a specific provider.

        Args:
            provider_name: Name of the provider to query.

        Returns:
            List of TimerType objects describing what kinds of timers
            the provider can accept.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        timer_types = provider.get_timer_types()
        logger.debug(
            f"Retrieved {len(timer_types)} timer types from '{provider_name}'"
        )
        return timer_types

    def get_all_timer_types(self) -> Dict[str, List[TimerType]]:
        """
        Get timer types from all enabled providers.

        Returns:
            Dict mapping provider name → list of TimerType objects.
        """
        enabled = self.registry.get_enabled_providers()
        result = {}

        for name in enabled:
            try:
                if self._provider_implements_timers(name):
                    result[name] = self.get_timer_types(name)
                else:
                    result[name] = []
            except Exception as e:
                logger.error(f"Failed to get timer types from '{name}': {e}")
                result[name] = []

        return result

    # ------------------------------------------------------------------
    # Listing timers
    # ------------------------------------------------------------------

    def get_timers(
        self,
        provider_name: str,
        include_inactive: bool = False,
    ) -> List[Timer]:
        """
        Get timers from a specific provider.

        Args:
            provider_name:    Name of the provider to query.
            include_inactive: If True, include completed, cancelled, and
                              error-state timers in addition to active ones.

        Returns:
            List of Timer objects.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        timers = provider.get_timers()

        if not include_inactive:
            timers = [t for t in timers if t.is_active]

        logger.info(
            f"Retrieved {len(timers)} timers from '{provider_name}' "
            f"(include_inactive={include_inactive})"
        )
        return timers

    def get_all_timers(
        self,
        include_inactive: bool = False,
    ) -> Dict[str, List[Timer]]:
        """
        Get timers from all enabled providers.

        Args:
            include_inactive: If True, include non-active timers.

        Returns:
            Dict mapping provider name → list of Timer objects.
        """
        enabled = self.registry.get_enabled_providers()
        logger.info(f"Fetching timers from {len(enabled)} providers")

        result = {}
        total = 0

        for name in enabled:
            try:
                if self._provider_implements_timers(name):
                    timers = self.get_timers(name, include_inactive=include_inactive)
                else:
                    timers = []
                result[name] = timers
                total += len(timers)
            except Exception as e:
                logger.error(f"Failed to get timers from '{name}': {e}")
                result[name] = []

        logger.info(f"Retrieved {total} total timers")
        return result

    def get_timer(
        self, provider_name: str, client_index: int
    ) -> Optional[Timer]:
        """
        Get a single timer by its client index.

        Args:
            provider_name: Name of the provider.
            client_index:  Timer identifier (== Timer.client_index).

        Returns:
            Timer object, or None if not found.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        # Fetch all (including inactive) so we can look up any timer by index
        timers = self.get_timers(provider_name, include_inactive=True)
        match = next((t for t in timers if t.client_index == client_index), None)
        if match:
            logger.debug(
                f"Found timer {client_index} from '{provider_name}'"
            )
        else:
            logger.debug(
                f"Timer {client_index} not found on '{provider_name}'"
            )
        return match

    # ------------------------------------------------------------------
    # Creating timers
    # ------------------------------------------------------------------

    def add_timer(
        self, provider_name: str, timer: Timer, **kwargs
    ) -> Timer:
        """
        Schedule a new timer on the provider.

        The provider assigns client_index and returns the saved Timer (which
        may differ from the input if the provider normalises fields).

        Args:
            provider_name: Name of the provider.
            timer:         Timer object to create.  client_index is ignored —
                           the provider allocates one.
            **kwargs:      Additional provider-specific arguments.

        Returns:
            The saved Timer as confirmed by the provider.

        Raises:
            ValueError:   If the provider is not found or disabled.
            RuntimeError: If the provider rejects the timer (e.g. conflict,
                          insufficient permissions, unsupported timer type).
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        saved_timer = provider.add_timer(timer, **kwargs)
        logger.info(
            f"Added timer '{saved_timer.title}' (index={saved_timer.client_index}) "
            f"on '{provider_name}'"
        )
        return saved_timer

    # ------------------------------------------------------------------
    # Updating timers
    # ------------------------------------------------------------------

    def update_timer(
        self, provider_name: str, timer: Timer, **kwargs
    ) -> Timer:
        """
        Update an existing timer on the provider.

        Args:
            provider_name: Name of the provider.
            timer:         Timer object with updated fields.
                           timer.client_index identifies the record to update.
            **kwargs:      Additional provider-specific arguments.

        Returns:
            The updated Timer as confirmed by the provider.

        Raises:
            ValueError:   If the provider is not found or disabled.
            KeyError:     If no timer with that client_index exists.
            RuntimeError: If the provider refuses the update (e.g. the timer
                          is currently recording and cannot be modified).
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        updated_timer = provider.update_timer(timer, **kwargs)
        logger.info(
            f"Updated timer {timer.client_index} ('{timer.title}') "
            f"on '{provider_name}'"
        )
        return updated_timer

    # ------------------------------------------------------------------
    # Deleting timers
    # ------------------------------------------------------------------

    def delete_timer(
        self,
        provider_name: str,
        client_index: int,
        force_delete: bool = False,
        **kwargs,
    ) -> None:
        """
        Delete a timer on the provider.

        Args:
            provider_name: Name of the provider.
            client_index:  Timer identifier to delete.
            force_delete:  If True and the timer is currently recording, abort
                           the ongoing capture and delete.  If False and the
                           timer is recording, the provider should raise
                           RuntimeError.
            **kwargs:      Additional provider-specific arguments.

        Returns:
            None on success.

        Raises:
            ValueError:   If the provider is not found or disabled.
            KeyError:     If no timer with that client_index exists.
            RuntimeError: If the provider refuses deletion (e.g. timer is
                          recording and force_delete is False).
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        provider.delete_timer(client_index, force_delete=force_delete, **kwargs)
        logger.info(
            f"Deleted timer {client_index} from '{provider_name}' "
            f"(force={force_delete})"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _provider_implements_timers(self, provider_name: str) -> bool:
        """Return True if the named provider declares timer support."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            return False
        return getattr(provider, "implements_timers", False)