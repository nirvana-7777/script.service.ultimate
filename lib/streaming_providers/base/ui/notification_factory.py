# ============================================================================
# FILE 5: streaming_providers/base/ui/notification_factory.py
# ============================================================================
"""
Factory for creating appropriate notification adapters
Auto-detects environment (Kodi vs standalone) and creates correct adapter
"""
from typing import Optional
from .notification_interface import NotificationInterface
from ..utils.logger import logger


class NotificationFactory:
    """
    Factory for creating notification adapters

    Automatically detects the runtime environment and creates
    the appropriate adapter:
    - KodiNotificationAdapter if running in Kodi
    - ConsoleNotificationAdapter if running standalone
    """

    _cached_adapter: Optional[NotificationInterface] = None
    _environment_detected: Optional[str] = None

    @classmethod
    def create(cls, force_environment: Optional[str] = None,
               http_manager=None) -> NotificationInterface:
        """
        Create appropriate notification adapter

        Args:
            force_environment: Force specific environment ('kodi' or 'console')
                             If None, auto-detects
            http_manager: Optional HTTPManager instance for network requests

        Returns:
            NotificationInterface: Appropriate adapter for current environment
        """
        # Return cached adapter if available and no http_manager change
        if cls._cached_adapter is not None and force_environment is None and http_manager is None:
            logger.debug(f"Using cached notification adapter: {cls._environment_detected}")
            return cls._cached_adapter

        # Detect environment
        if force_environment:
            environment = force_environment.lower()
            logger.info(f"Forced notification environment: {environment}")
        else:
            environment = cls._detect_environment()
            logger.info(f"Detected notification environment: {environment}")

        # Create appropriate adapter
        if environment == 'kodi':
            adapter = cls._create_kodi_adapter(http_manager=http_manager)
        else:
            adapter = cls._create_console_adapter()

        # Cache the adapter
        cls._cached_adapter = adapter
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
            return 'kodi'

        except ImportError:
            # If import fails, we're standalone
            logger.debug("Kodi modules not available - using console notification adapter")
            return 'console'

    @classmethod
    def _create_kodi_adapter(cls, http_manager=None) -> NotificationInterface:
        """
        Create Kodi notification adapter

        Args:
            http_manager: Optional HTTPManager for QR code download

        Returns:
            KodiNotificationAdapter
        """
        try:
            from .kodi_notification_adapter import KodiNotificationAdapter
            adapter = KodiNotificationAdapter(http_manager=http_manager)
            logger.info("✓ Kodi notification adapter created")
            return adapter

        except Exception as e:
            logger.error(f"Failed to create Kodi adapter: {e}")
            logger.warning("Falling back to console adapter")
            return cls._create_console_adapter()

    @classmethod
    def _create_console_adapter(cls) -> NotificationInterface:
        """
        Create console notification adapter

        Returns:
            ConsoleNotificationAdapter
        """
        from .console_notification_adapter import ConsoleNotificationAdapter
        adapter = ConsoleNotificationAdapter()
        logger.info("✓ Console notification adapter created")
        return adapter

    @classmethod
    def reset_cache(cls):
        """Reset cached adapter (useful for testing)"""
        cls._cached_adapter = None
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