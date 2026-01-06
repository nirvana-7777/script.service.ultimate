# ============================================================================
# FILE 1: streaming_providers/base/ui/__init__.py
# ============================================================================
"""
UI notification system for streaming providers
Provides adapters for different UI environments (Kodi, console, web, etc.)
"""

from .notification_factory import NotificationFactory
from .notification_interface import NotificationInterface, NotificationResult

# Conditional imports - only import if environment supports them
try:
    from .kodi_notification_adapter import KodiNotificationAdapter

    __all__ = [
        "NotificationInterface",
        "NotificationResult",
        "NotificationFactory",
        "KodiNotificationAdapter",
        "ConsoleNotificationAdapter",
    ]
except ImportError:
    # Kodi not available
    __all__ = [
        "NotificationInterface",
        "NotificationResult",
        "NotificationFactory",
        "ConsoleNotificationAdapter",
    ]

from .console_notification_adapter import ConsoleNotificationAdapter
