# streaming_providers/base/auth/remote_login_extension.py
"""
Remote Login Extension for BaseOAuth2Authenticator
Provides a production-ready method to handle device/remote login flows
with QR display, background polling, and proper timeout/cancellation handling.
Encapsulated to avoid modifying core OAuth2 or UI files.
"""
import threading
import time
from typing import Any, Callable, Dict, Optional

from ..ui.notification_factory import NotificationFactory
from ..utils.logger import logger


class _RemoteLoginPollingWorker(threading.Thread):
    """
    Internal polling worker that loops at the specified interval until
    authentication succeeds, times out, or is cancelled.

    Designed so the main thread drives cancellation by calling stop(); the
    worker never blocks longer than `interval` seconds at a time, so
    cancellation latency is bounded.
    """

    def __init__(
        self,
        callback: Callable[[], Optional[Dict[str, Any]]],
        expires_in: int,
        interval: int,
    ):
        super().__init__(daemon=True, name="RemoteLoginPollingWorker")
        self.callback = callback
        self.expires_in = max(1, expires_in)
        self.interval = max(1, interval)

        # Results — read only after join()
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.completed: bool = False
        self.timed_out: bool = False

        self._stop_event = threading.Event()
        self._start_time: float = 0.0  # Set in run() for accuracy

    def run(self) -> None:
        self._start_time = time.monotonic()

        while not self._stop_event.is_set():
            elapsed = time.monotonic() - self._start_time
            remaining = self.expires_in - elapsed

            if remaining <= 0:
                self.timed_out = True
                break

            try:
                token_data = self.callback()
            except Exception as e:
                self.error = str(e)
                break

            if token_data is not None:
                self.result = token_data
                self.completed = True
                break

            # Sleep in small increments so stop() cancels promptly.
            # Cap at `remaining` so we don't sleep past the deadline.
            sleep_time = min(self.interval, max(0.5, remaining))
            self._stop_event.wait(timeout=sleep_time)

    def stop(self, timeout: float = 2.0) -> None:
        """Signal the worker to stop and wait for it to exit."""
        self._stop_event.set()
        self.join(timeout=timeout)


class OAuth2RemoteLoginMixin:
    """
    Mixin that adds remote/device login capabilities to BaseOAuth2Authenticator.
    Handles QR display, polling lifecycle, cancellation, and timeout gracefully.

    Usage:
        class BaseOAuth2Authenticator(OAuth2RemoteLoginMixin, BaseAuthenticator):
            ...
    """

    def show_remote_login_and_wait_for_auth(
            self,
            login_code: str,
            qr_target_url: str,
            expires_in: int,
            interval: int = 5,
            auth_callback: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
            provider_name: str = "Service",  # ← new
            success_message: Optional[str] = None,  # ← new
            failure_template: Optional[str] = None,  # ← new
    ) -> Dict[str, Any]:
        """
        Show remote login UI and block until authentication completes,
        times out, or is cancelled.

        Args:
            login_code:     Short code for manual entry fallback.
            qr_target_url:  URL to encode in the QR code.
            expires_in:     Total timeout in seconds before the session expires.
            interval:       Polling interval in seconds (minimum 1).
            auth_callback:  Callable that checks authentication status.
                            Must return token data (dict) if complete, or None
                            if still pending.

        Returns:
            Dict containing token data on successful authentication.

        Raises:
            ValueError:   If input parameters are invalid.
            TypeError:    If auth_callback is not callable.
            TimeoutError: If the authentication session expires.
            RuntimeError: If the user cancels or a polling error occurs.
        """
        # --- Input Validation ---
        if not login_code or not isinstance(login_code, str):
            raise ValueError("login_code must be a non-empty string")
        if not qr_target_url or not isinstance(qr_target_url, str):
            raise ValueError("qr_target_url must be a non-empty string")
        if not isinstance(expires_in, int) or expires_in <= 0:
            raise ValueError("expires_in must be a positive integer")
        if not callable(auth_callback):
            raise TypeError("auth_callback must be a callable returning Dict or None")

        logger.info(
            f"Initializing remote login flow: code={login_code}, expires_in={expires_in}s"
        )

        # --- Get environment-appropriate UI adapter ---
        adapter = NotificationFactory.create(
            provider_name=provider_name,
            success_message=success_message,
            failure_template=failure_template,
        )

        worker: Optional[_RemoteLoginPollingWorker] = None

        try:
            # Show UI (handles QR generation & display internally)
            adapter.show_remote_login(
                login_code=login_code,
                qr_target_url=qr_target_url,
                expires_in=expires_in,
                interval=interval,
            )

            # --- Start polling worker ---
            worker = _RemoteLoginPollingWorker(auth_callback, expires_in, interval)
            worker.start()

            # --- Main loop: wait for completion, timeout, or cancellation ---
            while worker.is_alive():
                if adapter.is_cancelled():
                    worker.stop()
                    adapter.close(success=False, message="Cancelled by user")
                    raise RuntimeError("Remote login cancelled by user")

                if worker.error:
                    worker.stop()
                    adapter.close(success=False, message=worker.error)
                    raise RuntimeError(f"Polling failed: {worker.error}")

                # Small sleep to avoid busy-waiting while staying UI-responsive
                time.sleep(0.2)

            # Worker has exited — inspect its terminal state

            if worker.completed and worker.result is not None:
                adapter.close(success=True)
                logger.info("Remote login authentication completed successfully")
                return worker.result

            if worker.timed_out:
                adapter.close(success=False, message="Session expired")
                raise TimeoutError(
                    "Remote login session expired before authentication completed"
                )

            # Worker exited cleanly but without a result and without timing out —
            # this means an error was set (handled above) or the stop event fired
            # (cancellation already handled above). Reaching here is unexpected.
            adapter.close(success=False, message="Authentication failed")
            raise RuntimeError("Remote login failed unexpectedly")

        except BaseException as exc:
            # Ensure the worker is always stopped and the adapter is always
            # closed, even on KeyboardInterrupt or SystemExit.
            # We close the adapter only if it hasn't been closed yet; any
            # exception raised by adapter.close() is suppressed so the
            # original exception propagates cleanly.
            if worker is not None and worker.is_alive():
                worker.stop()
            try:
                adapter.close(success=False)
            except Exception:
                pass
            raise