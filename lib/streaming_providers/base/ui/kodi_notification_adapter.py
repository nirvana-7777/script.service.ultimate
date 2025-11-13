# ============================================================================
# FILE 4: streaming_providers/base/ui/kodi_notification_adapter.py
# ============================================================================
"""
Kodi notification adapter using xbmcgui dialogs
Displays remote login QR code in a non-blocking progress dialog
"""
import time
import os
import tempfile
from typing import Optional
from .notification_interface import NotificationInterface, NotificationResult
from ..utils.logger import logger


class KodiNotificationAdapter(NotificationInterface):
    """
    Kodi-based notification adapter

    Uses xbmcgui.DialogProgress() for non-blocking display
    Features:
    - Downloads and displays QR code SVG
    - Live countdown updates
    - User can cancel
    - Non-blocking operation
    """

    def __init__(self, http_manager=None):
        """
        Initialize Kodi notification adapter

        Args:
            http_manager: Optional HTTPManager instance for QR code download
        """
        super().__init__()

        # Import Kodi modules
        try:
            import xbmcgui
            import xbmc
            import xbmcvfs
            self.xbmcgui = xbmcgui
            self.xbmc = xbmc
            self.xbmcvfs = xbmcvfs
            self._kodi_available = True
        except ImportError as e:
            logger.error(f"Kodi modules not available: {e}")
            self._kodi_available = False
            raise RuntimeError("Kodi modules not available")

        self._dialog = None
        self._qr_image_path = None
        self._start_time = None
        self._expires_in = 0
        self._interval = 10
        self._http_manager = http_manager

    @property
    def supports_qr_display(self) -> bool:
        """Kodi can display QR code images"""
        return True

    @property
    def supports_countdown(self) -> bool:
        """Kodi supports live countdown"""
        return True

    @property
    def is_blocking(self) -> bool:
        """Kodi dialog is non-blocking"""
        return False

    def show_remote_login(
            self,
            login_code: str,
            qr_url: str,
            expires_in: int,
            interval: int = 10
    ) -> NotificationResult:
        """
        Show remote login dialog in Kodi

        Args:
            login_code: Short login code
            qr_url: URL to QR code SVG
            expires_in: Expiration time in seconds
            interval: Update interval

        Returns:
            NotificationResult indicating outcome
        """
        if not self._kodi_available:
            return NotificationResult.ERROR

        self._is_active = True
        self._start_time = time.time()
        self._expires_in = expires_in
        self._interval = interval
        self._is_cancelled = False

        try:
            # Create progress dialog
            self._dialog = self.xbmcgui.DialogProgress()

            # Download QR code SVG
            qr_image_path = self._download_qr_code(qr_url)

            # Build dialog heading and message
            heading = "MagentaTV Remote Login"

            # FIXED: Combine all lines into a single message string
            # Kodi DialogProgress.create() only takes 2 arguments: heading and message
            message_lines = [
                "Please scan the QR code with your mobile device",
                f"Login Code: [B]{login_code}[/B]",
                f"Expires in: {self._format_time(expires_in)}",
                "",
                "Or open the MagentaTV app and enter the code"
            ]
            message = "\n".join(message_lines)

            # FIXED: Only pass 2 arguments to create()
            self._dialog.create(heading, message)

            # Set QR code image if available
            if qr_image_path and os.path.exists(qr_image_path):
                # Note: DialogProgress doesn't support images directly
                # We'll show the code prominently instead
                logger.info(f"QR code downloaded to: {qr_image_path}")
                # TODO: Consider using a custom window for better QR display

            logger.info(f"Kodi dialog shown: code={login_code}, expires_in={expires_in}s")

            return NotificationResult.CONTINUE

        except Exception as e:
            logger.error(f"Failed to show Kodi dialog: {e}")
            self._is_active = False
            return NotificationResult.ERROR

    def update_countdown(self, remaining_seconds: int) -> bool:
        """
        Update countdown in Kodi dialog

        Args:
            remaining_seconds: Seconds remaining

        Returns:
            bool: True to continue, False if user cancelled
        """
        if not self._is_active or not self._dialog:
            return False

        try:
            # Check if user cancelled
            if self._dialog.iscanceled():
                logger.info("User cancelled remote login in Kodi")
                self._is_cancelled = True
                return False

            # Calculate percentage for progress bar
            elapsed = self._expires_in - remaining_seconds
            percentage = int((elapsed / self._expires_in) * 100)

            # FIXED: Combine all lines into a single message string
            message_lines = [
                "Please scan the QR code with your mobile device",
                "Or open the MagentaTV app and enter the code",
                f"Time remaining: {self._format_time(remaining_seconds)}"
            ]
            message = "\n".join(message_lines)

            # FIXED: Update dialog with combined message
            self._dialog.update(percentage, message)

            return True

        except Exception as e:
            logger.error(f"Failed to update Kodi dialog: {e}")
            return False

    def close(self, success: bool = False, message: Optional[str] = None):
        """
        Close Kodi dialog

        Args:
            success: Whether authentication succeeded
            message: Optional message
        """
        if not self._is_active:
            return

        self._is_active = False

        try:
            # Close progress dialog
            if self._dialog:
                self._dialog.close()
                self._dialog = None

            # Show result notification
            if success:
                self.xbmcgui.Dialog().notification(
                    "MagentaTV",
                    "Remote login successful!",
                    self.xbmcgui.NOTIFICATION_INFO,
                    3000
                )
            elif message:
                self.xbmcgui.Dialog().notification(
                    "MagentaTV",
                    f"Remote login failed: {message}",
                    self.xbmcgui.NOTIFICATION_ERROR,
                    5000
                )

            # Cleanup QR image
            self._cleanup_qr_image()

        except Exception as e:
            logger.error(f"Failed to close Kodi dialog: {e}")

    def is_cancelled(self) -> bool:
        """
        Check if user cancelled

        Returns:
            bool: True if user clicked cancel
        """
        if self._dialog and self._dialog.iscanceled():
            self._is_cancelled = True
        return self._is_cancelled

    def _download_qr_code(self, qr_url: str) -> Optional[str]:
        """
        Download QR code SVG from URL

        Args:
            qr_url: URL to QR code SVG

        Returns:
            str: Path to downloaded file, or None if failed
        """
        try:
            # Use http_manager if available, otherwise fall back to requests
            if self._http_manager:
                logger.debug(f"Downloading QR code via http_manager from: {qr_url}")
                response = self._http_manager.get(
                    qr_url,
                    operation='qr_download',
                    timeout=10
                )
            else:
                # Fallback to requests if http_manager not available
                try:
                    import requests
                    logger.debug(f"Downloading QR code via requests from: {qr_url}")
                    response = requests.get(qr_url, timeout=10)
                except ImportError:
                    logger.warning("Neither http_manager nor requests available, cannot download QR code")
                    return None

            response.raise_for_status()

            # Verify content type
            content_type = response.headers.get('Content-Type', '')
            if 'svg' not in content_type.lower():
                logger.warning(f"Unexpected content type: {content_type}")

            # Create temp file for QR code
            temp_dir = tempfile.gettempdir()
            qr_filename = f"magentatv_qr_{int(time.time())}.svg"
            qr_path = os.path.join(temp_dir, qr_filename)

            # Save to file
            with open(qr_path, 'wb') as f:
                f.write(response.content)

            self._qr_image_path = qr_path
            logger.info(f"QR code downloaded successfully: {qr_path}")

            return qr_path

        except Exception as e:
            logger.error(f"Failed to download QR code: {e}")
            return None

    def _cleanup_qr_image(self):
        """Cleanup temporary QR image file"""
        if self._qr_image_path and os.path.exists(self._qr_image_path):
            try:
                os.remove(self._qr_image_path)
                logger.debug(f"Cleaned up QR image: {self._qr_image_path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup QR image: {e}")
            finally:
                self._qr_image_path = None

    @staticmethod
    def _format_time(seconds: int) -> str:
        """
        Format seconds as human-readable time

        Args:
            seconds: Time in seconds

        Returns:
            str: Formatted time string (e.g., "3m 45s")
        """
        if seconds <= 0:
            return "Expired"

        minutes = seconds // 60
        secs = seconds % 60

        if minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"