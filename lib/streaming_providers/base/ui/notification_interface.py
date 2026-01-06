# ============================================================================
# FILE 2: streaming_providers/base/ui/notification_interface.py
# ============================================================================
"""
Abstract notification interface for displaying authentication prompts
Supports multiple UI backends (Kodi, console, web, etc.)
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional


class NotificationResult(Enum):
    """Result of notification display"""

    CONTINUE = "continue"  # User wants to continue
    CANCELLED = "cancelled"  # User cancelled
    TIMEOUT = "timeout"  # Notification timed out
    ERROR = "error"  # Error displaying notification


class NotificationInterface(ABC):
    """
    Abstract interface for displaying remote login notifications

    Implementations must handle:
    - Displaying login information (code, QR, URL)
    - Countdown updates during polling
    - User cancellation
    - Cleanup on completion
    """

    def __init__(self):
        """Initialize notification interface"""
        self._is_active = False
        self._is_cancelled = False

    @abstractmethod
    def show_remote_login(
        self, login_code: str, qr_target_url: str, expires_in: int, interval: int = 10
    ) -> NotificationResult:
        """
        Show remote login notification to user

        This method should:
        1. Display the login code and QR target URL
        2. Show countdown timer
        3. Allow user cancellation
        4. Return when done or cancelled

        Args:
            login_code: Short code user can type (e.g., "PY48E62Q")
            qr_target_url: The actual URL to encode in QR code / display to user
                          (e.g., "https://telekom.de/tv-login?login_code=PY48E62Q")
            expires_in: Total seconds until expiration
            interval: Polling interval in seconds (for countdown updates)

        Returns:
            NotificationResult indicating outcome
        """
        pass

    @abstractmethod
    def update_countdown(self, remaining_seconds: int) -> bool:
        """
        Update countdown display

        Args:
            remaining_seconds: Seconds remaining until expiration

        Returns:
            bool: True to continue, False if user cancelled
        """
        pass

    @abstractmethod
    def close(self, success: bool = False, message: Optional[str] = None):
        """
        Close/cleanup the notification

        Args:
            success: Whether authentication succeeded
            message: Optional message to display
        """
        pass

    @abstractmethod
    def is_cancelled(self) -> bool:
        """
        Check if user has cancelled

        Returns:
            bool: True if user cancelled
        """
        pass

    def mark_cancelled(self):
        """Mark notification as cancelled"""
        self._is_cancelled = True

    @property
    def is_active(self) -> bool:
        """Check if notification is currently active"""
        return self._is_active

    @property
    def supports_qr_display(self) -> bool:
        """
        Check if this notifier can display QR codes

        Returns:
            bool: True if QR code display is supported
        """
        return False

    @property
    def supports_countdown(self) -> bool:
        """
        Check if this notifier supports live countdown updates

        Returns:
            bool: True if countdown updates are supported
        """
        return False

    @property
    def is_blocking(self) -> bool:
        """
        Check if this notifier blocks the calling thread

        Returns:
            bool: True if blocking, False if non-blocking
        """
        return True

    def get_capabilities(self) -> dict:
        """
        Get notifier capabilities

        Returns:
            dict: Capability information
        """
        return {
            "type": self.__class__.__name__,
            "supports_qr_display": self.supports_qr_display,
            "supports_countdown": self.supports_countdown,
            "is_blocking": self.is_blocking,
            "is_active": self.is_active,
        }
