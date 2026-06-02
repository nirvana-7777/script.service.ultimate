# ============================================================================
# FILE 3: streaming_providers/base/ui/console_notification_adapter.py
# ============================================================================
"""
Console notification adapter for non-Kodi environments
Displays remote login information as simple text output
"""

import time
from typing import Optional

from ..utils.logger import logger
from .notification_interface import NotificationInterface, NotificationResult


class ConsoleNotificationAdapter(NotificationInterface):
    """
    Console-based notification adapter

    Displays remote login information as text output
    Suitable for:
    - Standalone script execution
    - Headless environments
    - Development/testing
    - CI/CD pipelines
    """

    def __init__(self, provider_name: str = "Service",
                 success_message: Optional[str] = None,
                 failure_template: Optional[str] = None):
        """
        Initialize console notification adapter

        Args:
            provider_name: Name of the provider (e.g., "MagentaTV")
            success_message: Custom success message (optional)
            failure_template: Template for failure messages (optional)
        """
        super().__init__()
        self._start_time = None
        self._expires_in = 0
        self._last_update = 0

        # Provider-specific configuration
        self.provider_name = provider_name
        self.success_message = success_message or f"{provider_name} login successful!"
        self.failure_template = failure_template or f"{provider_name} login failed: {{}}"

    @property
    def supports_qr_display(self) -> bool:
        """Console cannot display QR codes"""
        return False

    @property
    def supports_countdown(self) -> bool:
        """Console supports text-based countdown"""
        return True

    @property
    def is_blocking(self) -> bool:
        """Console output is non-blocking"""
        return False

    def show_remote_login(
            self, login_code: str, qr_target_url: str, expires_in: int, interval: int = 10
    ) -> NotificationResult:
        """
        Show remote login information in console

        Args:
            login_code: Short login code
            qr_target_url: The URL to encode in QR (displayed to user)
            expires_in: Expiration time in seconds
            interval: Update interval

        Returns:
            NotificationResult.CONTINUE (always, as console can't cancel)
        """
        self._is_active = True
        self._start_time = time.time()
        self._expires_in = expires_in
        self._last_update = 0

        # Print header
        print("\n" + "=" * 70)
        print(f"  {self.provider_name} - REMOTE LOGIN REQUIRED")
        print("=" * 70)
        print()

        # Print instructions
        print(f"Please authenticate using your mobile device for {self.provider_name}:")
        print()
        print(f"  Option 1: Scan QR Code")
        print(f"  Visit this URL on your mobile device:")
        print(f"  {qr_target_url}")
        print()
        print(f"  Option 2: Manual Entry")
        print(f"  Login Code: {login_code}")
        print()
        print(f"  This code expires in {expires_in} seconds")
        print()
        print("=" * 70)
        print()

        logger.info(f"Remote login started for {self.provider_name}: code={login_code}, expires_in={expires_in}s")
        logger.info(f"QR target URL: {qr_target_url}")

        return NotificationResult.CONTINUE

    def update_countdown(self, remaining_seconds: int) -> bool:
        """
        Update countdown in console

        Only prints updates at reasonable intervals to avoid spam

        Args:
            remaining_seconds: Seconds remaining

        Returns:
            bool: Always True (console can't be cancelled by user)
        """
        if not self._is_active:
            return True

        # Print milestone updates (every 30 seconds, or at key intervals)
        if remaining_seconds <= 0:
            print(f"⏰ {self.provider_name} remote login expired")
            return True

        # Print at: 240s, 180s, 120s, 60s, 30s, 10s
        milestones = [240, 180, 120, 60, 30, 10]

        if remaining_seconds in milestones or remaining_seconds <= 10:
            minutes = remaining_seconds // 60
            seconds = remaining_seconds % 60

            if minutes > 0:
                time_str = f"{minutes}m {seconds}s"
            else:
                time_str = f"{seconds}s"

            print(f"⏳ {self.provider_name}: Waiting for authentication... {time_str} remaining")

        return True

    def close(self, success: bool = False, message: Optional[str] = None):
        """
        Close console notification

        Args:
            success: Whether authentication succeeded
            message: Optional message
        """
        if not self._is_active:
            return

        self._is_active = False

        print()
        print("=" * 70)

        if success:
            print(f"✓ {self.success_message}")
        elif message:
            failure_msg = self.failure_template.format(message)
            print(f"✗ {failure_msg}")
        else:
            print(f"✗ {self.failure_template.format('unknown error')}")

        print("=" * 70)
        print()

    def is_cancelled(self) -> bool:
        """
        Check if cancelled (always False for console)

        Returns:
            bool: Always False (console can't be cancelled interactively)
        """
        return False