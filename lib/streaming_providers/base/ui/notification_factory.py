# ============================================================================
# FILE 5: streaming_providers/base/ui/notification_factory.py
# ============================================================================
"""
Factory for creating appropriate notification adapters
Auto-detects environment (Kodi vs standalone) and creates correct adapter
"""

from typing import Optional, Dict

from ..utils.logger import logger
from .notification_interface import NotificationInterface


class NotificationFactory:
    """
    Factory for creating notification adapters

    Automatically detects the runtime environment and creates
    the appropriate adapter:
    - KodiNotificationAdapter if running in Kodi
    - ConsoleNotificationAdapter if running standalone

    Supports provider-specific configuration for UI text.
    """

    _cached_adapters: Dict[str, NotificationInterface] = {}  # Cache by provider name
    _environment_detected: Optional[str] = None

    @classmethod
    def create(
            cls,
            force_environment: Optional[str] = None,
            http_manager=None,
            provider_name: str = "Service",
            success_message: Optional[str] = None,
            failure_template: Optional[str] = None
    ) -> NotificationInterface:
        """
        Create appropriate notification adapter

        Args:
            force_environment: Force specific environment ('kodi' or 'console')
                             If None, auto-detects
            http_manager: Optional HTTPManager instance for network requests
            provider_name: Name of the provider (e.g., "MagentaTV", "Netflix")
            success_message: Custom success message (optional)
            failure_template: Template for failure messages (optional)

        Returns:
            NotificationInterface: Appropriate adapter for current environment
        """
        # Create cache key based on provider configuration
        cache_key = f"{provider_name}:{success_message}:{failure_template}"

        # Return cached adapter if available and no environment/http_manager change
        if cache_key in cls._cached_adapters and force_environment is None and http_manager is None:
            logger.debug(f"Using cached notification adapter: {cls._environment_detected} for {provider_name}")
            return cls._cached_adapters[cache_key]

        # Detect environment
        if force_environment:
            environment = force_environment.lower()
            logger.info(f"Forced notification environment: {environment}")
        else:
            environment = cls._detect_environment()
            logger.info(f"Detected notification environment: {environment}")

        # Create appropriate adapter with provider configuration
        if environment == "kodi":
            adapter = cls._create_kodi_adapter(
                http_manager=http_manager,
                provider_name=provider_name,
                success_message=success_message,
                failure_template=failure_template
            )
        else:
            adapter = cls._create_console_adapter(
                provider_name=provider_name,
                success_message=success_message,
                failure_template=failure_template
            )

        # Cache the adapter
        cls._cached_adapters[cache_key] = adapter
        cls._environment_detected = environment

        return adapter

    @classmethod
    def _detect_environment(cls) -> str:
        """
        Auto-detect runtime environment

        Returns:
            str: 'kodi' or 'console'
        """
        try:
            # Try to import xbmcgui
            import xbmcgui

            # If import succeeds, we're in Kodi
            logger.debug("Kodi modules available - using Kodi notification adapter")
            return "kodi"

        except ImportError:
            # If import fails, we're standalone
            logger.debug("Kodi modules not available - using console notification adapter")
            return "console"

    @classmethod
    def _create_kodi_adapter(
            cls,
            http_manager=None,
            provider_name: str = "Service",
            success_message: Optional[str] = None,
            failure_template: Optional[str] = None
    ) -> NotificationInterface:
        """
        Create Kodi notification adapter

        Args:
            http_manager: Optional HTTPManager for QR code download
            provider_name: Name of the provider
            success_message: Custom success message
            failure_template: Template for failure messages

        Returns:
            KodiNotificationAdapter
        """
        try:
            from .kodi_notification_adapter import KodiNotificationAdapter

            adapter = KodiNotificationAdapter(
                http_manager=http_manager,
                provider_name=provider_name,
                success_message=success_message,
                failure_template=failure_template
            )
            logger.info(f"✓ Kodi notification adapter created for {provider_name}")
            return adapter

        except Exception as e:
            logger.error(f"Failed to create Kodi adapter: {e}")
            logger.warning("Falling back to console adapter")
            return cls._create_console_adapter(
                provider_name=provider_name,
                success_message=success_message,
                failure_template=failure_template
            )

    @classmethod
    def _create_console_adapter(
            cls,
            provider_name: str = "Service",
            success_message: Optional[str] = None,
            failure_template: Optional[str] = None
    ) -> NotificationInterface:
        """
        Create console notification adapter

        Args:
            provider_name: Name of the provider
            success_message: Custom success message
            failure_template: Template for failure messages

        Returns:
            ConsoleNotificationAdapter
        """
        from .console_notification_adapter import ConsoleNotificationAdapter

        adapter = ConsoleNotificationAdapter(
            provider_name=provider_name,
            success_message=success_message,
            failure_template=failure_template
        )
        logger.info(f"✓ Console notification adapter created for {provider_name}")
        return adapter

    @classmethod
    def reset_cache(cls):
        """Reset cached adapters (useful for testing)"""
        cls._cached_adapters.clear()
        cls._environment_detected = None
        logger.debug("Notification adapter cache reset")

    @classmethod
    def get_current_environment(cls) -> Optional[str]:
        """
        Get currently detected environment

        Returns:
            str: 'kodi', 'console', or None if not yet detected
        """
        return cls._environment_detected

    @classmethod
    def is_kodi_available(cls) -> bool:
        """
        Check if Kodi environment is available

        Returns:
            bool: True if Kodi modules can be imported
        """
        try:
            import xbmcgui
            return True
        except ImportError:
            return False