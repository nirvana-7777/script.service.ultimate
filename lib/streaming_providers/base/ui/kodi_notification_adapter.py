"""
Kodi notification adapter with threaded polling support
Architecture:
1. Starts polling in background thread
2. Shows QR code dialog (blocking)
3. Dialog monitors thread status and auto-closes on success
4. User can cancel by closing dialog
"""

import os
import tempfile
import threading
import time
from typing import Callable, Optional

from ..utils.logger import logger
from .notification_interface import NotificationInterface, NotificationResult

# Import QR generator
try:
    from .qr_generator import generate_qr_code_png

    QR_GENERATOR_AVAILABLE = True
except ImportError:
    logger.warning("qr_generator not available")
    QR_GENERATOR_AVAILABLE = False


class PollingThread(threading.Thread):
    """
    Background thread for polling authentication status
    """

    def __init__(self, poll_callback: Callable, expires_in: int, interval: int):
        """
        Initialize polling thread

        Args:
            poll_callback: Function to call for polling (returns token_data or None)
            expires_in: Total time before expiration
            interval: Polling interval in seconds
        """
        super().__init__(daemon=True)
        self.poll_callback = poll_callback
        self.expires_in = expires_in
        self.interval = interval

        self.auth_completed = False
        self.token_data = None
        self.error = None
        self.stop_event = threading.Event()
        self.start_time = None

    def run(self):
        """Run polling loop"""
        self.start_time = time.time()
        logger.info("Polling thread started")

        try:
            # Call the polling callback (blocking)
            self.token_data = self.poll_callback()

            if self.token_data:
                self.auth_completed = True
                logger.info("Polling thread: Authentication successful")
            else:
                logger.warning("Polling thread: Authentication failed/timed out")

        except Exception as e:
            logger.error(f"Polling thread error: {e}", exc_info=True)
            self.error = str(e)

    def stop(self):
        """Signal thread to stop"""
        self.stop_event.set()

    def get_remaining_time(self) -> int:
        """Get remaining time in seconds"""
        if not self.start_time:
            return self.expires_in
        elapsed = time.time() - self.start_time
        return max(0, int(self.expires_in - elapsed))


class QRCodeDialog:
    """
    WindowDialog for displaying QR code with status monitoring
    """

    def __init__(
        self,
        xbmcgui,
        xbmc,
        qr_image_path: str,
        login_code: str,
        expires_in: int,
        polling_thread: Optional[PollingThread] = None,
    ):
        """
        Initialize QR code dialog

        Args:
            xbmcgui: xbmcgui module
            xbmc: xbmc module
            qr_image_path: Path to QR code PNG file
            login_code: Login code for manual entry
            expires_in: Expiration time in seconds
            polling_thread: Optional polling thread to monitor
        """
        self.xbmcgui = xbmcgui
        self.xbmc = xbmc
        self.qr_image_path = qr_image_path
        self.login_code = login_code
        self.expires_in = expires_in
        self.polling_thread = polling_thread

        self.dialog = None
        self.user_closed = False
        self.time_label = None
        self.status_label = None

        # Background monitoring thread
        self.monitor_thread = None
        self.monitor_stop = threading.Event()

    def show(self):
        """Show the QR code dialog"""
        try:
            # Create WindowDialog
            self.dialog = self.xbmcgui.WindowDialog()

            screen_width = self.dialog.getWidth()
            screen_height = self.dialog.getHeight()

            # Calculate layout
            dialog_width = int(screen_width * 0.8)
            dialog_height = int(screen_height * 0.8)
            dialog_x = (screen_width - dialog_width) // 2
            dialog_y = (screen_height - dialog_height) // 2

            # Background - Use a solid color label instead of ControlImage
            bg = self.xbmcgui.ControlLabel(
                dialog_x, dialog_y, dialog_width, dialog_height, label=""
            )
            # Set semi-transparent black background
            try:
                bg.setColorDiffuse("0xE0000000")
            except:
                pass  # Ignore if method not available
            self.dialog.addControl(bg)

            # Title
            title_y = dialog_y + 30
            title = self.xbmcgui.ControlLabel(
                x=dialog_x + 50,
                y=title_y,
                width=dialog_width - 100,
                height=50,
                label="[B]MagentaTV Remote Login[/B]",
                font="font30",
                textColor="0xFFFFFFFF",
                alignment=0x00000002,  # Center
            )
            self.dialog.addControl(title)

            # QR Code
            qr_size = min(dialog_width // 2, dialog_height // 2, 400)
            qr_x = (screen_width - qr_size) // 2
            qr_y = title_y + 70

            if os.path.exists(self.qr_image_path):
                qr_image = self.xbmcgui.ControlImage(
                    qr_x, qr_y, qr_size, qr_size, self.qr_image_path
                )
                self.dialog.addControl(qr_image)
            else:
                logger.error(f"QR image not found: {self.qr_image_path}")

            # Instructions
            instructions_y = qr_y + qr_size + 40

            inst1 = self.xbmcgui.ControlLabel(
                x=dialog_x + 50,
                y=instructions_y,
                width=dialog_width - 100,
                height=30,
                label="[B]Scan QR code with your MagentaTV app[/B]",
                font="font13",
                textColor="0xFFFFFFFF",
                alignment=0x00000002,
            )
            self.dialog.addControl(inst1)

            inst2_y = instructions_y + 35
            inst2 = self.xbmcgui.ControlLabel(
                x=dialog_x + 50,
                y=inst2_y,
                width=dialog_width - 100,
                height=30,
                label=f"Or enter code: [COLOR yellow]{self.login_code}[/COLOR]",
                font="font13",
                textColor="0xFFCCCCCC",
                alignment=0x00000002,
            )
            self.dialog.addControl(inst2)

            # Time remaining label
            time_y = inst2_y + 45
            self.time_label = self.xbmcgui.ControlLabel(
                x=dialog_x + 50,
                y=time_y,
                width=dialog_width - 100,
                height=30,
                label=f"Time remaining: {self._format_time(self.expires_in)}",
                font="font12",
                textColor="0xFFFF8800",
                alignment=0x00000002,
            )
            self.dialog.addControl(self.time_label)

            # Status label
            status_y = time_y + 35
            self.status_label = self.xbmcgui.ControlLabel(
                x=dialog_x + 50,
                y=status_y,
                width=dialog_width - 100,
                height=30,
                label="Waiting for authentication...",
                font="font12",
                textColor="0xFFAAAAAA",
                alignment=0x00000002,
            )
            self.dialog.addControl(self.status_label)

            # Cancel hint
            cancel_y = status_y + 35
            cancel = self.xbmcgui.ControlLabel(
                x=dialog_x + 50,
                y=cancel_y,
                width=dialog_width - 100,
                height=25,
                label="(Press any key to cancel)",
                font="font10",
                textColor="0xFF888888",
                alignment=0x00000002,
            )
            self.dialog.addControl(cancel)

            # Start background monitor if we have polling thread
            if self.polling_thread:
                self._start_monitor()

            # Show dialog (blocking)
            logger.info("Showing QR code dialog")
            self.dialog.doModal()

            # Dialog closed
            self.user_closed = True
            self._stop_monitor()
            logger.info("QR code dialog closed by user")

        except Exception as e:
            logger.error(f"Failed to show QR code dialog: {e}", exc_info=True)
        finally:
            self._cleanup()

    def _start_monitor(self):
        """Start background monitor thread"""
        self.monitor_stop.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.debug("Started dialog monitor thread")

    def _stop_monitor(self):
        """Stop background monitor thread"""
        self.monitor_stop.set()
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        logger.debug("Stopped dialog monitor thread")

    def _monitor_loop(self):
        """Monitor polling thread status and update UI"""
        while not self.monitor_stop.is_set():
            try:
                # Update countdown
                if self.polling_thread:
                    remaining = self.polling_thread.get_remaining_time()
                    if self.time_label:
                        self.time_label.setLabel(
                            f"Time remaining: {self._format_time(remaining)}"
                        )

                    # Check if auth completed
                    if self.polling_thread.auth_completed:
                        logger.info("Monitor: Authentication completed, closing dialog")
                        if self.status_label:
                            self.status_label.setLabel(
                                "[COLOR green]Authentication successful![/COLOR]"
                            )
                        time.sleep(1)  # Show success message briefly
                        self.close_dialog()
                        break

                    # Check for errors
                    if self.polling_thread.error:
                        logger.error(
                            f"Monitor: Polling error: {self.polling_thread.error}"
                        )
                        if self.status_label:
                            self.status_label.setLabel(
                                "[COLOR red]Authentication failed[/COLOR]"
                            )
                        time.sleep(2)
                        self.close_dialog()
                        break

                # Sleep briefly
                time.sleep(0.5)

            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                break

    def close_dialog(self):
        """Close dialog programmatically"""
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

    @staticmethod
    def _format_time(seconds: int) -> str:
        """Format seconds as MM:SS"""
        if seconds <= 0:
            return "Expired"
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes:02d}:{secs:02d}"


class KodiNotificationAdapter(NotificationInterface):
    """
    Kodi notification adapter with fast QR generation and threading

    Architecture:
    1. Generate QR code directly from target URL (fast)
    2. Start polling in background thread
    3. Show dialog that monitors thread and auto-closes on success
    """

    def __init__(self, http_manager=None):
        """
        Initialize Kodi notification adapter

        Args:
            http_manager: Optional HTTPManager instance
        """
        super().__init__()

        # Import Kodi modules
        try:
            import xbmc
            import xbmcgui
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
        self._polling_thread = None

    @property
    def supports_qr_display(self) -> bool:
        """Kodi can display QR codes"""
        return True

    @property
    def supports_countdown(self) -> bool:
        """Kodi supports countdown via monitor thread"""
        return True

    @property
    def is_blocking(self) -> bool:
        """Dialog is blocking but polling happens in thread"""
        return True  # From caller's perspective, it blocks

    def show_remote_login_with_polling(
        self,
        login_code: str,
        qr_target_url: str,
        expires_in: int,
        interval: int,
        poll_callback: Callable,
    ) -> NotificationResult:
        """
        Show remote login with integrated polling

        This is the main method that coordinates everything:
        1. Generate QR code from target URL (fast!)
        2. Start polling thread
        3. Show dialog (blocking, but thread runs)
        4. Return result based on outcome

        Args:
            login_code: Short login code
            qr_target_url: The URL to encode in QR code (NOT the SVG URL!)
            expires_in: Expiration time in seconds
            interval: Polling interval
            poll_callback: Function to call for polling

        Returns:
            NotificationResult
        """
        if not self._kodi_available:
            return NotificationResult.ERROR

        self._is_active = True
        self._is_cancelled = False

        try:
            # Step 1: Generate QR code (fast!)
            qr_image_path = self._generate_qr_code(qr_target_url)

            if not qr_image_path:
                logger.error("Failed to generate QR code")
                return NotificationResult.ERROR

            self._qr_image_path = qr_image_path

            # Step 2: Start polling thread
            self._polling_thread = PollingThread(poll_callback, expires_in, interval)
            self._polling_thread.start()
            logger.info("Started polling thread")

            # Step 3: Show dialog (blocking, but thread runs)
            self._qr_dialog = QRCodeDialog(
                self.xbmcgui,
                self.xbmc,
                qr_image_path,
                login_code,
                expires_in,
                self._polling_thread,
            )

            self._qr_dialog.show()

            # Step 4: Determine outcome
            if self._polling_thread.auth_completed:
                logger.info("Authentication successful")
                return NotificationResult.CONTINUE
            elif self._qr_dialog.user_closed:
                logger.info("User cancelled")
                self._is_cancelled = True
                return NotificationResult.CANCELLED
            else:
                logger.warning("Authentication timed out")
                return NotificationResult.TIMEOUT

        except Exception as e:
            logger.error(f"Failed to show remote login: {e}", exc_info=True)
            return NotificationResult.ERROR
        finally:
            self._is_active = False
            self._cleanup_qr_image()

    def show_remote_login(
        self, login_code: str, qr_target_url: str, expires_in: int, interval: int = 10
    ) -> NotificationResult:
        """
        Simplified version without polling (for backward compatibility)
        Just shows the dialog, no polling

        Args:
            login_code: Short login code
            qr_target_url: The URL to encode in QR code
            expires_in: Expiration time
            interval: Update interval (unused in this version)
        """
        if not self._kodi_available:
            return NotificationResult.ERROR

        self._is_active = True
        self._is_cancelled = False

        try:
            qr_image_path = self._generate_qr_code(qr_target_url)

            if not qr_image_path:
                return NotificationResult.ERROR

            self._qr_image_path = qr_image_path

            self._qr_dialog = QRCodeDialog(
                self.xbmcgui,
                self.xbmc,
                qr_image_path,
                login_code,
                expires_in,
                None,  # No polling thread
            )

            self._qr_dialog.show()

            if self._qr_dialog.user_closed:
                self._is_cancelled = True
                return NotificationResult.CANCELLED

            return NotificationResult.CONTINUE

        except Exception as e:
            logger.error(f"Failed to show QR dialog: {e}", exc_info=True)
            return NotificationResult.ERROR
        finally:
            self._is_active = False
            self._cleanup_qr_image()

    def update_countdown(self, remaining_seconds: int) -> bool:
        """Check if user cancelled"""
        if self._qr_dialog and self._qr_dialog.user_closed:
            self._is_cancelled = True
            return False
        return not self._is_cancelled

    def close(self, success: bool = False, message: Optional[str] = None):
        """Close and show notification"""
        if not self._is_active:
            return

        self._is_active = False

        try:
            if self._qr_dialog:
                self._qr_dialog.close_dialog()
                self._qr_dialog = None

            # Show result
            if success:
                self.xbmcgui.Dialog().notification(
                    "MagentaTV",
                    "Remote login successful!",
                    self.xbmcgui.NOTIFICATION_INFO,
                    3000,
                )
            elif message and not self._is_cancelled:
                self.xbmcgui.Dialog().notification(
                    "MagentaTV",
                    f"Remote login failed: {message}",
                    self.xbmcgui.NOTIFICATION_ERROR,
                    5000,
                )

            self._cleanup_qr_image()

        except Exception as e:
            logger.error(f"Failed to close dialog: {e}")

    def is_cancelled(self) -> bool:
        """Check if cancelled"""
        return self._is_cancelled

    def get_token_data(self) -> Optional[dict]:
        """Get token data from polling thread"""
        if self._polling_thread:
            return self._polling_thread.token_data
        return None

    @staticmethod
    def _generate_qr_code(target_url: str) -> Optional[str]:
        """
        Generate QR code PNG file from target URL

        This is GENERIC - works for any provider!
        No provider-specific logic here.

        Args:
            target_url: The URL to encode in the QR code

        Returns:
            Path to PNG file
        """
        try:
            if not QR_GENERATOR_AVAILABLE:
                logger.error("QR generator not available")
                return None

            logger.info(f"Generating QR code for: {target_url}")
            start_time = time.time()

            # Generate QR code directly from target URL
            png_data = generate_qr_code_png(target_url, size=512)

            if not png_data:
                logger.error("Failed to generate QR code PNG")
                return None

            elapsed = time.time() - start_time
            logger.info(f"Generated QR code in {elapsed:.2f}s: {len(png_data)} bytes")

            # Save to temp file
            temp_dir = tempfile.gettempdir()
            png_filename = f"magentatv_qr_{int(time.time())}.png"
            png_path = os.path.join(temp_dir, png_filename)

            with open(png_path, "wb") as f:
                f.write(png_data)

            logger.info(f"QR code saved to: {png_path}")
            return png_path

        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}", exc_info=True)
            return None

    def _cleanup_qr_image(self):
        """Cleanup temporary QR image"""
        if self._qr_image_path and os.path.exists(self._qr_image_path):
            try:
                os.remove(self._qr_image_path)
                logger.debug(f"Cleaned up QR image: {self._qr_image_path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup QR image: {e}")
            finally:
                self._qr_image_path = None
