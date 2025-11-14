"""
Kodi notification adapter with threaded polling support
Displays QR code in WindowDialog while polling happens in background thread
"""
import time
import os
import tempfile
import threading
from typing import Optional, Callable
from .notification_interface import NotificationInterface, NotificationResult
from ..utils.logger import logger

# Import the lightweight SVG converter
try:
    from .svg_to_png import convert_svg_to_png
except ImportError:
    logger.warning("svg_to_png not available, will try to use SVG directly")
    convert_svg_to_png = None


class QRCodeDialog:
    """
    WindowDialog for displaying QR code
    Non-blocking when used with threading
    """

    def __init__(self, xbmcgui, qr_image_path: str, login_code: str, qr_url: str,
                 expires_in: int, poll_callback: Optional[Callable] = None):
        """
        Initialize QR code dialog

        Args:
            xbmcgui: xbmcgui module
            qr_image_path: Path to QR code PNG file
            login_code: Login code for manual entry
            qr_url: Full QR code URL
            expires_in: Expiration time in seconds
            poll_callback: Optional callback function that returns True if auth completed
        """
        self.xbmcgui = xbmcgui
        self.qr_image_path = qr_image_path
        self.login_code = login_code
        self.qr_url = qr_url
        self.expires_in = expires_in
        self.poll_callback = poll_callback

        self.dialog = None
        self.start_time = time.time()
        self.user_closed = False
        self.auth_completed = False

    def show(self):
        """Show the QR code dialog"""
        try:
            # Create WindowDialog
            self.dialog = self.xbmcgui.WindowDialog()

            screen_width = self.dialog.getWidth()
            screen_height = self.dialog.getHeight()

            # Calculate positions and sizes
            qr_size = min(screen_width // 3, screen_height // 3, 600)
            qr_x = (screen_width - qr_size) // 2
            qr_y = 80

            # Background panel
            bg_width = screen_width - 200
            bg_height = screen_height - 160
            bg_x = 100
            bg_y = 80

            # Semi-transparent background
            bg = self.xbmcgui.ControlImage(
                bg_x, bg_y, bg_width, bg_height,
                ''  # No image, just uses aspect for background
            )
            bg.setColorDiffuse('0xDD000000')
            self.dialog.addControl(bg)

            # Title
            title_y = bg_y + 20
            title = self.xbmcgui.ControlLabel(
                x=bg_x + 50, y=title_y,
                width=bg_width - 100, height=40,
                label='[B]MagentaTV Remote Login[/B]',
                font='font13_title',
                textColor='0xFFFFFFFF',
                alignment=0x00000002  # Center aligned
            )
            self.dialog.addControl(title)

            # QR Code image
            qr_y_pos = title_y + 60
            if os.path.exists(self.qr_image_path):
                qr_image = self.xbmcgui.ControlImage(
                    qr_x, qr_y_pos, qr_size, qr_size,
                    self.qr_image_path
                )
                self.dialog.addControl(qr_image)
            else:
                logger.error(f"QR code image not found: {self.qr_image_path}")

            # Instructions
            instructions_y = qr_y_pos + qr_size + 30

            # Line 1: Scan QR code
            line1 = self.xbmcgui.ControlLabel(
                x=bg_x + 50, y=instructions_y,
                width=bg_width - 100, height=30,
                label='[B]Scan QR code with your MagentaTV app[/B]',
                font='font13',
                textColor='0xFFFFFFFF',
                alignment=0x00000002
            )
            self.dialog.addControl(line1)

            # Line 2: Or enter code manually
            line2_y = instructions_y + 35
            line2 = self.xbmcgui.ControlLabel(
                x=bg_x + 50, y=line2_y,
                width=bg_width - 100, height=30,
                label=f'Or enter code manually: [B][COLOR yellow]{self.login_code}[/COLOR][/B]',
                font='font13',
                textColor='0xFFCCCCCC',
                alignment=0x00000002
            )
            self.dialog.addControl(line2)

            # Line 3: Time remaining (will be updated)
            line3_y = line2_y + 40
            self.time_label = self.xbmcgui.ControlLabel(
                x=bg_x + 50, y=line3_y,
                width=bg_width - 100, height=30,
                label=f'Time remaining: {self._format_time(self.expires_in)}',
                font='font12',
                textColor='0xFFFF8800',
                alignment=0x00000002
            )
            self.dialog.addControl(self.time_label)

            # Line 4: Waiting message
            line4_y = line3_y + 35
            line4 = self.xbmcgui.ControlLabel(
                x=bg_x + 50, y=line4_y,
                width=bg_width - 100, height=30,
                label='Waiting for authentication...',
                font='font12',
                textColor='0xFFAAAAAA',
                alignment=0x00000002
            )
            self.dialog.addControl(line4)

            # Line 5: Close instruction
            line5_y = line4_y + 30
            line5 = self.xbmcgui.ControlLabel(
                x=bg_x + 50, y=line5_y,
                width=bg_width - 100, height=25,
                label='(Press any key to cancel)',
                font='font10',
                textColor='0xFF888888',
                alignment=0x00000002
            )
            self.dialog.addControl(line5)

            # Show dialog (blocking call)
            logger.info("Showing QR code dialog")
            self.dialog.doModal()

            # Dialog closed by user
            self.user_closed = True
            logger.info("User closed QR code dialog")

        except Exception as e:
            logger.error(f"Failed to show QR code dialog: {e}", exc_info=True)
        finally:
            self._cleanup()

    def close(self, success: bool = False):
        """Close the dialog programmatically"""
        self.auth_completed = success
        if self.dialog:
            try:
                self.dialog.close()
            except:
                pass

    def _cleanup(self):
        """Cleanup dialog resources"""
        if self.dialog:
            try:
                del self.dialog
            except:
                pass
            self.dialog = None

    def _format_time(self, seconds: int) -> str:
        """Format seconds as MM:SS"""
        if seconds <= 0:
            return "Expired"
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes:02d}:{secs:02d}"


class KodiNotificationAdapter(NotificationInterface):
    """
    Kodi-based notification adapter with threading support

    Features:
    - Shows QR code in WindowDialog
    - Polls in background thread
    - Auto-closes on auth success
    - User can cancel anytime
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

        self._qr_dialog = None
        self._qr_image_path = None
        self._http_manager = http_manager

        # Threading
        self._poll_thread = None
        self._poll_callback = None
        self._auth_completed = False
        self._stop_polling = threading.Event()

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
        """With threading, operation is non-blocking from caller's perspective"""
        return False

    def show_remote_login(
            self,
            login_code: str,
            qr_url: str,
            expires_in: int,
            interval: int = 10
    ) -> NotificationResult:
        """
        Show remote login dialog with QR code

        This starts a background thread and shows the QR dialog.
        The dialog is blocking but polling happens in background.

        Args:
            login_code: Short login code
            qr_url: URL to QR code SVG
            expires_in: Expiration time in seconds
            interval: Update interval (not used in threaded mode)

        Returns:
            NotificationResult indicating outcome
        """
        if not self._kodi_available:
            return NotificationResult.ERROR

        self._is_active = True
        self._is_cancelled = False
        self._auth_completed = False
        self._stop_polling.clear()

        try:
            # Download and convert QR code to PNG
            qr_image_path = self._download_and_convert_qr(qr_url)

            if not qr_image_path:
                logger.error("Failed to download/convert QR code")
                return NotificationResult.ERROR

            self._qr_image_path = qr_image_path

            # Create QR dialog
            self._qr_dialog = QRCodeDialog(
                self.xbmcgui,
                qr_image_path,
                login_code,
                qr_url,
                expires_in
            )

            # Show dialog (this is blocking, but that's okay)
            # The polling will happen in the remote_login_handler
            self._qr_dialog.show()

            # Check if user closed dialog (cancelled)
            if self._qr_dialog.user_closed and not self._qr_dialog.auth_completed:
                logger.info("User cancelled login via dialog close")
                self._is_cancelled = True
                return NotificationResult.CANCELLED

            return NotificationResult.CONTINUE

        except Exception as e:
            logger.error(f"Failed to show Kodi QR dialog: {e}", exc_info=True)
            self._is_active = False
            return NotificationResult.ERROR

    def update_countdown(self, remaining_seconds: int) -> bool:
        """
        Update countdown (called by polling loop)

        Args:
            remaining_seconds: Seconds remaining

        Returns:
            bool: True to continue, False if user cancelled
        """
        # Check if user closed dialog
        if self._qr_dialog and self._qr_dialog.user_closed:
            self._is_cancelled = True
            return False

        return not self._is_cancelled

    def close(self, success: bool = False, message: Optional[str] = None):
        """
        Close QR dialog and show result notification

        Args:
            success: Whether authentication succeeded
            message: Optional message
        """
        if not self._is_active:
            return

        self._is_active = False
        self._stop_polling.set()

        try:
            # Close QR dialog if open
            if self._qr_dialog:
                self._qr_dialog.close(success)
                self._qr_dialog = None

            # Show result notification
            if success:
                self.xbmcgui.Dialog().notification(
                    "MagentaTV",
                    "Remote login successful!",
                    self.xbmcgui.NOTIFICATION_INFO,
                    3000
                )
            elif message and not self._is_cancelled:
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
            bool: True if user closed dialog
        """
        if self._qr_dialog and self._qr_dialog.user_closed and not self._qr_dialog.auth_completed:
            self._is_cancelled = True
        return self._is_cancelled

    def _download_and_convert_qr(self, qr_url: str) -> Optional[str]:
        """
        Download QR code SVG and convert to PNG

        Args:
            qr_url: URL to SVG QR code

        Returns:
            Path to PNG file or None if failed
        """
        try:
            logger.info(f"Downloading QR code from: {qr_url}")

            # Download SVG
            if self._http_manager:
                response = self._http_manager.get(
                    qr_url,
                    operation='qr_download',
                    timeout=10
                )
            else:
                try:
                    import requests
                    response = requests.get(qr_url, timeout=10)
                except ImportError:
                    logger.error("Neither http_manager nor requests available")
                    return None

            response.raise_for_status()
            svg_data = response.content

            logger.info(f"Downloaded SVG: {len(svg_data)} bytes")

            # Convert SVG to PNG
            if convert_svg_to_png:
                logger.info("Converting SVG to PNG...")
                png_data = convert_svg_to_png(svg_data, output_size=512)
                logger.info(f"Converted to PNG: {len(png_data)} bytes")
            else:
                logger.error("SVG to PNG converter not available")
                return None

            # Save PNG to temp file
            temp_dir = tempfile.gettempdir()
            png_filename = f"magentatv_qr_{int(time.time())}.png"
            png_path = os.path.join(temp_dir, png_filename)

            with open(png_path, 'wb') as f:
                f.write(png_data)

            logger.info(f"QR code saved to: {png_path}")
            return png_path

        except Exception as e:
            logger.error(f"Failed to download/convert QR code: {e}", exc_info=True)
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