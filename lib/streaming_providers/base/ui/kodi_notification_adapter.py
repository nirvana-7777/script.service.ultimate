"""
Kodi notification adapter with threaded polling support
Architecture:
1. Starts polling in background thread
2. Shows QR code dialog (blocking)
3. Dialog monitors thread status and auto-closes on success
4. User can cancel by closing dialog
"""

import os
import threading
import time
from typing import Callable, Optional

from ..utils.logger import logger
from ..utils.vfs import get_vfs  # Import VFS
from .notification_interface import NotificationInterface, NotificationResult

# Import QR generator
try:
    from .qr_generator import generate_qr_code_png

    QR_GENERATOR_AVAILABLE = True
except ImportError:
    logger.warning("qr_generator not available")
    QR_GENERATOR_AVAILABLE = False


class PollingThread(threading.Thread):
    def __init__(self, poll_callback: Callable, expires_in: int, interval: int):
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
        self.start_time = time.time()
        logger.info("Polling thread started")
        try:
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
        self.stop_event.set()

    def get_remaining_time(self) -> int:
        if not self.start_time:
            return self.expires_in
        elapsed = time.time() - self.start_time
        return max(0, int(self.expires_in - elapsed))


class QRCodeDialog:
    def __init__(self, xbmcgui, xbmc, qr_image_path, login_code, expires_in,
                 polling_thread=None, provider_name: str = "Service"):
        self.xbmcgui = xbmcgui
        self.xbmc = xbmc
        self.qr_image_path = qr_image_path
        self.login_code = login_code
        self.expires_in = expires_in
        self.polling_thread = polling_thread
        self.provider_name = provider_name

        self.dialog = None
        self.user_closed = False
        self.closed_by_auth = False  # FIX #2: separate flag for auth-triggered close
        self.time_label = None
        self.status_label = None

        self.monitor_thread = None
        self.monitor_stop = threading.Event()

    def show(self):
        try:
            self.dialog = self.xbmcgui.WindowDialog()

            screen_width = self.dialog.getWidth()
            screen_height = self.dialog.getHeight()

            dialog_width = int(screen_width * 0.8)
            dialog_height = int(screen_height * 0.8)
            dialog_x = (screen_width - dialog_width) // 2
            dialog_y = (screen_height - dialog_height) // 2

            bg = self.xbmcgui.ControlLabel(dialog_x, dialog_y, dialog_width, dialog_height, label="")
            try:
                bg.setColorDiffuse("0xE0000000")
            except:
                pass
            self.dialog.addControl(bg)

            title_y = dialog_y + 30
            title = self.xbmcgui.ControlLabel(
                x=dialog_x + 50, y=title_y, width=dialog_width - 100, height=50,
                label=f"[B]{self.provider_name} Remote Login[/B]", font="font30",
                textColor="0xFFFFFFFF", alignment=0x00000002,
            )
            self.dialog.addControl(title)

            qr_size = min(dialog_width // 2, dialog_height // 2, 400)
            qr_x = (screen_width - qr_size) // 2
            qr_y = title_y + 70

            if self._file_exists(self.qr_image_path):
                qr_image = self.xbmcgui.ControlImage(qr_x, qr_y, qr_size, qr_size, self.qr_image_path)
                self.dialog.addControl(qr_image)
            else:
                logger.error(f"QR image not found: {self.qr_image_path}")

            instructions_y = qr_y + qr_size + 40
            inst1 = self.xbmcgui.ControlLabel(
                x=dialog_x + 50, y=instructions_y, width=dialog_width - 100, height=30,
                label="[B]Scan QR code with your app[/B]", font="font13",
                textColor="0xFFFFFFFF", alignment=0x00000002,
            )
            self.dialog.addControl(inst1)

            inst2_y = instructions_y + 35
            inst2 = self.xbmcgui.ControlLabel(
                x=dialog_x + 50, y=inst2_y, width=dialog_width - 100, height=30,
                label=f"Or enter code: [COLOR yellow]{self.login_code}[/COLOR]", font="font13",
                textColor="0xFFCCCCCC", alignment=0x00000002,
            )
            self.dialog.addControl(inst2)

            time_y = inst2_y + 45
            self.time_label = self.xbmcgui.ControlLabel(
                x=dialog_x + 50, y=time_y, width=dialog_width - 100, height=30,
                label=f"Time remaining: {self._format_time(self.expires_in)}", font="font12",
                textColor="0xFFFF8800", alignment=0x00000002,
            )
            self.dialog.addControl(self.time_label)

            status_y = time_y + 35
            self.status_label = self.xbmcgui.ControlLabel(
                x=dialog_x + 50, y=status_y, width=dialog_width - 100, height=30,
                label="Waiting for authentication...", font="font12",
                textColor="0xFFAAAAAA", alignment=0x00000002,
            )
            self.dialog.addControl(self.status_label)

            cancel_y = status_y + 35
            cancel = self.xbmcgui.ControlLabel(
                x=dialog_x + 50, y=cancel_y, width=dialog_width - 100, height=25,
                label="(Press any key to cancel)", font="font10",
                textColor="0xFF888888", alignment=0x00000002,
            )
            self.dialog.addControl(cancel)

            if self.polling_thread:
                self._start_monitor()

            logger.info(f"Showing QR code dialog for {self.provider_name}")
            self.dialog.doModal()

            # FIX #2: only mark as user_closed if auth didn't trigger the close
            self.user_closed = not self.closed_by_auth
            self._stop_monitor()
            logger.info(f"QR code dialog closed (user_closed={self.user_closed})")

        except Exception as e:
            logger.error(f"Failed to show QR code dialog: {e}", exc_info=True)
        finally:
            self._cleanup()

    @staticmethod
    def _file_exists(filepath: str) -> bool:
        try:
            from ..utils.vfs import exists as vfs_exists
            return vfs_exists(filepath)
        except:
            return os.path.exists(filepath)

    def _start_monitor(self):
        self.monitor_stop.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.debug("Started dialog monitor thread")

    def _stop_monitor(self):
        self.monitor_stop.set()
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        logger.debug("Stopped dialog monitor thread")

    def _monitor_loop(self):
        while not self.monitor_stop.is_set():
            try:
                if self.polling_thread:
                    remaining = self.polling_thread.get_remaining_time()

                    if self.time_label:
                        self.time_label.setLabel(f"Time remaining: {self._format_time(remaining)}")

                    # FIX (new): handle expiry explicitly
                    if remaining <= 0:
                        logger.info("Monitor: Time expired, closing dialog")
                        if self.status_label:
                            self.status_label.setLabel("[COLOR red]Session expired[/COLOR]")
                        time.sleep(1)
                        self.close_dialog()
                        break

                    if self.polling_thread.auth_completed:
                        logger.info("Monitor: Authentication completed, closing dialog")
                        if self.status_label:
                            self.status_label.setLabel("[COLOR green]Authentication successful![/COLOR]")
                        time.sleep(1)
                        self.close_dialog(by_auth=True)  # FIX #2: pass flag
                        break

                    if self.polling_thread.error:
                        logger.error(f"Monitor: Polling error: {self.polling_thread.error}")
                        if self.status_label:
                            self.status_label.setLabel("[COLOR red]Authentication failed[/COLOR]")
                        time.sleep(2)
                        self.close_dialog()
                        break

                time.sleep(0.5)

            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                break

    def close_dialog(self, by_auth: bool = False):
        """Close dialog programmatically"""
        # FIX #2: set closed_by_auth BEFORE calling close() so show() sees it
        if by_auth:
            self.closed_by_auth = True
        if self.dialog:
            try:
                self.dialog.close()
            except:
                pass

    def _cleanup(self):
        if self.dialog:
            try:
                del self.dialog
            except:
                pass
            self.dialog = None

    @staticmethod
    def _format_time(seconds: int) -> str:
        if seconds <= 0:
            return "Expired"
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes:02d}:{secs:02d}"


class KodiNotificationAdapter(NotificationInterface):
    def __init__(self, http_manager=None, provider_name: str = "Service",
                 success_message: str = None, failure_template: str = None):
        super().__init__()
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

        self._vfs = get_vfs(addon_subdir="temp")

        # Provider-specific configuration
        self.provider_name = provider_name
        self.success_message = success_message or f"{provider_name} login successful!"
        self.failure_template = failure_template or f"{provider_name} login failed: {{}}"

    @property
    def supports_qr_display(self) -> bool:
        return True

    @property
    def supports_countdown(self) -> bool:
        return True

    @property
    def is_blocking(self) -> bool:
        return True

    def show_remote_login_with_polling(
        self, login_code, qr_target_url, expires_in, interval, poll_callback
    ) -> NotificationResult:
        if not self._kodi_available:
            return NotificationResult.ERROR

        self._is_active = True
        self._is_cancelled = False

        try:
            qr_image_path = self._generate_qr_code(qr_target_url)
            if not qr_image_path:
                logger.error("Failed to generate QR code")
                return NotificationResult.ERROR

            self._qr_image_path = qr_image_path

            self._polling_thread = PollingThread(poll_callback, expires_in, interval)
            self._polling_thread.start()
            logger.info("Started polling thread")

            self._qr_dialog = QRCodeDialog(
                self.xbmcgui, self.xbmc,
                qr_image_path, login_code, expires_in,
                self._polling_thread,
                provider_name=self.provider_name,
            )
            self._qr_dialog.show()

            # FIX #4: stop the polling thread if the user cancelled
            if self._qr_dialog.user_closed and self._polling_thread.is_alive():
                logger.info("User cancelled — stopping polling thread")
                self._polling_thread.stop()
                self._polling_thread.join(timeout=2.0)

            if self._polling_thread.auth_completed:
                logger.info("Authentication successful")
                return NotificationResult.CONTINUE
            elif self._qr_dialog.user_closed:
                logger.info("User cancelled")
                self._is_cancelled = True
                return NotificationResult.CANCELLED
            else:
                logger.warning("Authentication timed out or failed")
                return NotificationResult.TIMEOUT

        except Exception as e:
            logger.error(f"Failed to show remote login: {e}", exc_info=True)
            return NotificationResult.ERROR
        finally:
            self._is_active = False
            self._cleanup_qr_image()

    def show_remote_login(
        self, login_code, qr_target_url, expires_in, interval=10
    ) -> NotificationResult:
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
                self.xbmcgui, self.xbmc,
                qr_image_path, login_code, expires_in,
                None,
                provider_name=self.provider_name,
            )
            self._qr_dialog.show()

            if self._qr_dialog.user_closed:
                self._is_cancelled = True
                return NotificationResult.CANCELLED

            # FIX #5: no polling thread means no auth — dialog expired naturally
            return NotificationResult.TIMEOUT

        except Exception as e:
            logger.error(f"Failed to show QR dialog: {e}", exc_info=True)
            return NotificationResult.ERROR
        finally:
            self._is_active = False
            self._cleanup_qr_image()

    def update_countdown(self, remaining_seconds: int) -> bool:
        if self._qr_dialog and self._qr_dialog.user_closed:
            self._is_cancelled = True
            return False
        return not self._is_cancelled

    def close(self, success: bool = False, message: Optional[str] = None):
        if not self._is_active:
            return

        self._is_active = False

        try:
            if self._qr_dialog:
                self._qr_dialog.close_dialog()
                self._qr_dialog = None

            if success:
                self.xbmcgui.Dialog().notification(
                    self.provider_name, self.success_message,
                    self.xbmcgui.NOTIFICATION_INFO, 3000,
                )
            elif message and not self._is_cancelled:
                failure_msg = self.failure_template.format(message)
                self.xbmcgui.Dialog().notification(
                    self.provider_name, failure_msg,
                    self.xbmcgui.NOTIFICATION_ERROR, 5000,
                )

            self._cleanup_qr_image()

        except Exception as e:
            logger.error(f"Failed to close dialog: {e}")

    def is_cancelled(self) -> bool:
        return self._is_cancelled

    def get_token_data(self) -> Optional[dict]:
        if self._polling_thread:
            return self._polling_thread.token_data
        return None

    def _generate_qr_code(self, target_url: str) -> Optional[str]:
        """
        Generate QR code PNG file using VFS for cross-platform compatibility.
        Uses write_binary to avoid data corruption from text encoding roundtrips.
        """
        try:
            if not QR_GENERATOR_AVAILABLE:
                logger.error("QR generator not available")
                return None

            logger.info(f"Generating QR code for: {target_url}")
            start_time = time.time()

            png_data = generate_qr_code_png(target_url, size=512)
            if not png_data:
                logger.error("Failed to generate QR code PNG")
                return None

            elapsed = time.time() - start_time
            logger.info(f"Generated QR code in {elapsed:.2f}s: {len(png_data)} bytes")

            filename = f"qr_{self.provider_name.lower()}_{int(time.time())}.png"
            # Sanitize filename - remove any problematic characters
            filename = "".join(c for c in filename if c.isalnum() or c in '._-')
            filepath = self._vfs.join_path(filename)

            # FIX #1: write raw bytes via write_binary, not text
            if self._vfs.write_binary(filepath, png_data):
                if self._vfs.exists(filepath):
                    logger.info(f"QR code saved using VFS: {filepath}")
                    return filepath
                else:
                    logger.error(f"QR code file not found after write: {filepath}")
                    return None
            else:
                logger.error(f"Failed to write QR code using VFS: {filepath}")
                return None

        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}", exc_info=True)
            return None

    def _cleanup_qr_image(self):
        if not self._qr_image_path:
            return
        try:
            if self._vfs.exists(self._qr_image_path):
                if self._vfs.delete(self._qr_image_path):
                    logger.debug(f"Cleaned up QR image using VFS: {self._qr_image_path}")
                else:
                    logger.warning(f"Failed to delete QR image: {self._qr_image_path}")
            else:
                logger.debug(f"QR image already cleaned up: {self._qr_image_path}")
        except Exception as e:
            logger.warning(f"Error during QR image cleanup: {e}")
        finally:
            self._qr_image_path = None