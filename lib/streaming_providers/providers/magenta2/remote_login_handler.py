# streaming_providers/providers/magenta2/remote_login_handler.py
"""
Remote Login Handler for Magenta2 Backchannel Authentication
Implements QR code-based authentication flow as fallback when line auth fails

This handler contains provider-specific logic for MagentaTV.

Two execution models are supported:
- Blocking: start_remote_login() / poll_for_token() / perform_complete_flow()
- Background: start_background_login() / get_background_status() /
  wait_for_background_login() / cancel_background_login()

The background API is a bridge for callers (e.g. the Magenta2 auth flow and
channel warm-up) that expect fire-and-forget login with later status polling.
It runs the proven blocking perform_complete_flow() on a daemon thread.
Cancellation of a background login uses an explicit threading.Event that the
polling loop checks every second — it never relies on side effects of the
notifier's close() — and both the event and the bridge state are reset on
every start_background_login() call.
"""

import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

from ...base.network import HTTPManager
from ...base.ui import NotificationFactory, NotificationInterface, NotificationResult
from ...base.utils.logger import logger
from .constants import DEFAULT_PLATFORM, DEFAULT_REQUEST_TIMEOUT, GRANT_TYPES, MAGENTA2_PLATFORMS, render_user_agent

# Default OAuth scope for the MagentaTV backchannel (remote login) flow.
# Kept as a named constant so the blocking and background entry points can
# never drift apart.
DEFAULT_REMOTE_LOGIN_SCOPE = "tvhubs offline_access"


@dataclass
class RemoteLoginSession:
    """Remote login session data"""

    initial_login_code: str
    auth_req_id: str
    auth_req_sec: str
    interval: int
    expires_in: int
    qr_code_url: str
    qr_target_url: Optional[str]  # The actual URL to encode in QR
    started_at: float


class RemoteLoginHandler:
    """
    Handles backchannel authentication / remote login flow for MagentaTV

    Responsibilities:
    - Start backchannel auth session
    - Extract QR target URL (provider-specific)
    - Poll for token
    - Coordinate with notification system (generic)
    """

    def __init__(
            self,
            http_manager: HTTPManager,
            sam3_client_id: str,
            backchannel_start_url: str,
            token_endpoint: str,
            qr_code_url_template: str,
            notifier: Optional[NotificationInterface] = None,
            provider_name: str = "MagentaTV",  # Add this parameter with default
            platform: str = DEFAULT_PLATFORM,
    ):
        """
        Initialize remote login handler

        Args:
            http_manager: HTTP manager for requests
            sam3_client_id: SAM3 client ID
            backchannel_start_url: Backchannel auth start endpoint
            token_endpoint: OAuth token endpoint for polling
            qr_code_url_template: QR code URL template with {code} placeholder
            notifier: Optional notification interface (auto-created if None)
            provider_name: Provider name for notifications (default: "MagentaTV")
            platform: Emulated client platform, selects config and User-Agent
        """
        self.http_manager = http_manager
        self.sam3_client_id = sam3_client_id
        self.backchannel_start_url = backchannel_start_url
        self.token_endpoint = token_endpoint
        self.qr_code_url_template = qr_code_url_template
        self.provider_name = provider_name  # Store it

        self.platform_config = MAGENTA2_PLATFORMS.get(platform)
        if self.platform_config is None:
            raise ValueError(f"Unknown platform: {platform}")
        # The platform config has no static "user_agent" key - the UA is
        # rendered from the platform's templates via render_user_agent().
        self.user_agent = render_user_agent(platform)

        # Get or create notifier with http_manager
        if notifier:
            self._notifier = notifier
        else:
            self._notifier = NotificationFactory.create(
                http_manager=http_manager,
                provider_name=provider_name,  # Use the passed provider_name
                success_message=f"{provider_name} login successful",
                failure_template=f"{provider_name} login failed: {{reason}}",
            )

        self._current_session: Optional[RemoteLoginSession] = None

        # --- Background login bridge state (always initialized so
        # get_background_status() is safe before any login was started) ---
        self._bg_lock = threading.Lock()
        self._bg_thread: Optional[threading.Thread] = None
        self._bg_result: Optional[Dict[str, Any]] = None
        self._bg_error: Optional[str] = None
        self._bg_done = threading.Event()
        # Explicit cancellation signal for background logins. poll_for_token()
        # checks this every second, so cancellation does not depend on any
        # side effect of the notifier's close().
        self._bg_cancel = threading.Event()

        logger.debug(f"RemoteLoginHandler initialized with {self._notifier.__class__.__name__}")

    def set_notifier(self, notifier: NotificationInterface) -> None:
        """Set custom notification interface"""
        self._notifier = notifier
        logger.debug(f"Notifier set to: {notifier.__class__.__name__}")

    def start_remote_login(self, scope: str = DEFAULT_REMOTE_LOGIN_SCOPE) -> RemoteLoginSession:
        """
        Start backchannel authentication flow

        Args:
            scope: OAuth scopes to request

        Returns:
            RemoteLoginSession with login code and polling parameters

        Raises:
            Exception: If backchannel auth start fails
        """
        try:
            logger.info("Starting remote login (backchannel auth)")

            payload = {"client_id": self.sam3_client_id, "scope": scope}

            headers = {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "User-Agent": self.user_agent,
            }

            logger.debug(f"Backchannel auth request:")
            logger.debug(f"  URL: {self.backchannel_start_url}")
            logger.debug(f"  Payload: {payload}")

            response = self.http_manager.post(
                self.backchannel_start_url,
                operation="backchannel_start",
                headers=headers,
                data=payload,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()

            data = response.json()

            # Extract session data
            initial_login_code = data.get("initial_login_code")
            auth_req_id = data.get("auth_req_id")
            auth_req_sec = data.get("auth_req_sec")
            interval = int(data.get("interval", 10))
            expires_in = int(data.get("expires_in", 300))

            if not all([initial_login_code, auth_req_id, auth_req_sec]):
                raise Exception("Incomplete backchannel auth response")

            # Build QR code SVG URL
            qr_code_url = self.qr_code_url_template.format(code=initial_login_code)

            # Extract the actual target URL for the QR code (provider-specific)
            qr_target_url = self._extract_qr_target_url(qr_code_url, initial_login_code)

            # Create session
            session = RemoteLoginSession(
                initial_login_code=initial_login_code,
                auth_req_id=auth_req_id,
                auth_req_sec=auth_req_sec,
                interval=interval,
                expires_in=expires_in,
                qr_code_url=qr_code_url,
                qr_target_url=qr_target_url,
                started_at=time.time(),
            )

            self._current_session = session

            logger.info(
                f"Remote login started: code={initial_login_code}, "
                f"interval={interval}s, expires_in={expires_in}s"
            )
            if qr_target_url:
                logger.info(f"QR target URL: {qr_target_url}")

            return session

        except Exception as e:
            logger.error(f"Failed to start remote login: {e}")
            raise Exception(f"Remote login start failed: {e}")

    def _extract_qr_target_url(self, qr_code_url: str, login_code: str) -> str:
        """
        Extract the actual target URL from QR code redirect

        PROVIDER-SPECIFIC LOGIC for MagentaTV:
        The qr_code_url redirects (302) to:
        https://wcps.t-online.de/usqrg/v1/default/QrCode?target=<encoded_url>

        We extract the 'target' parameter which is the actual URL to encode in QR.

        Args:
            qr_code_url: QR code SVG URL
            login_code: Login code (for fallback)

        Returns:
            Target URL to encode in QR code
        """
        try:
            logger.debug(f"Extracting QR target URL from: {qr_code_url}")

            # Make GET request without following redirects
            response = self.http_manager.get(
                qr_code_url,
                operation="qr_redirect",
                allow_redirects=False,  # Don't follow redirects automatically
                timeout=5,
            )

            # Check for redirect
            if response.status_code in (301, 302, 303, 307, 308):
                redirect_url = response.headers.get("Location")

                if redirect_url:
                    logger.debug(f"Got redirect to: {redirect_url}")

                    # Parse the redirect URL
                    parsed = urlparse(redirect_url)
                    query_params = parse_qs(parsed.query)

                    # Extract 'target' parameter
                    if "target" in query_params:
                        target_url = query_params["target"][0]
                        # URL decode it
                        decoded_url = unquote(target_url)

                        # Truncate at the last dot in the URL
                        if "." in decoded_url:
                            shortened_url = decoded_url.rsplit(".", 1)[0]
                            logger.info(f"Extracted QR target URL: {shortened_url}")
                            return shortened_url

                        logger.info(f"Extracted QR target URL: {decoded_url}")
                        return decoded_url
                    else:
                        logger.warning("No 'target' parameter in redirect URL")
            else:
                logger.warning(f"No redirect found (status: {response.status_code})")

        except Exception as e:
            logger.warning(f"Failed to extract QR target URL: {e}")

        # Fallback: construct URL from login code
        fallback_url = f"https://telekom.de/tv-login?login_code={login_code}"
        logger.info(f"Using fallback QR target URL: {fallback_url}")
        return fallback_url

    def poll_for_token(self, session: RemoteLoginSession) -> Optional[Dict[str, Any]]:
        """
        Poll token endpoint until user completes authentication

        This method is called by the polling thread in the notification adapter.
        It checks for cancellation periodically.

        Args:
            session: Active remote login session

        Returns:
            Token data dict if successful, None if timed out/cancelled
        """
        try:
            logger.info("Starting token polling")

            start_time = session.started_at
            next_poll_time = start_time
            last_countdown_update = start_time

            headers = {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "User-Agent": self.user_agent,
            }

            payload = {
                "client_id": self.sam3_client_id,
                "grant_type": GRANT_TYPES["REMOTE_LOGIN"],
                "auth_req_id": session.auth_req_id,
                "auth_req_sec": session.auth_req_sec,
            }

            poll_count = 0
            max_polls = session.expires_in // session.interval + 1

            while True:
                current_time = time.time()
                elapsed = current_time - start_time
                remaining = max(0, int(session.expires_in - elapsed))

                # Check if session expired
                if elapsed >= session.expires_in:
                    logger.warning(f"Session expired after {elapsed:.1f}s")
                    return None

                # Check if user cancelled (every second)
                if current_time - last_countdown_update >= 1.0:
                    if self._bg_cancel.is_set():
                        logger.info("Background remote login cancelled")
                        return None

                    if self._notifier.is_cancelled():
                        logger.info("User cancelled remote login")
                        return None

                    # Update countdown in notifier
                    if not self._notifier.update_countdown(int(remaining)):
                        logger.info("Countdown update returned False - cancelled")
                        return None

                    last_countdown_update = current_time

                # Wait until next poll time
                if current_time < next_poll_time:
                    sleep_time = min(1.0, next_poll_time - current_time)
                    time.sleep(sleep_time)
                    continue

                # Perform poll
                poll_count += 1
                logger.debug(f"Poll {poll_count}/{max_polls} (remaining: {remaining:.0f}s)")

                try:
                    response = self.http_manager.post(
                        self.token_endpoint,
                        operation="remote_login_poll",
                        headers=headers,
                        data=payload,
                        timeout=DEFAULT_REQUEST_TIMEOUT,
                    )

                    # 202 = Not yet completed
                    if response.status_code == 202:
                        logger.debug("Authentication not yet completed (202)")
                        next_poll_time = time.time() + session.interval
                        continue

                    # 200 = Success
                    if response.status_code == 200:
                        token_data = response.json()
                        logger.info(
                            f"✓ Authentication successful after {elapsed:.1f}s ({poll_count} polls)"
                        )
                        return token_data

                    # Other = error
                    response.raise_for_status()

                except Exception as e:
                    if elapsed < session.expires_in:
                        logger.debug(f"Poll error (will retry): {e}")
                        next_poll_time = time.time() + session.interval
                        continue
                    else:
                        raise

        except Exception as e:
            logger.error(f"Polling failed: {e}")
            return None

    def perform_complete_flow(
        self, scope: str = DEFAULT_REMOTE_LOGIN_SCOPE
    ) -> Optional[Dict[str, Any]]:
        """
        Perform complete remote login flow with integrated polling

        Flow:
        1. Start session (gets login code + extracts QR target URL)
        2. Check if notifier supports integrated polling
        3. If yes: Pass polling callback to notifier (threaded)
        4. If no: Show notification, then poll manually (console)

        Args:
            scope: OAuth scopes to request

        Returns:
            Token data dict if successful, None if failed
        """
        try:
            # Step 1: Start session and extract QR target URL
            session = self.start_remote_login(scope)

            # Step 2: Check if notifier supports integrated polling (Kodi adapter)
            if hasattr(self._notifier, "show_remote_login_with_polling"):
                # Kodi adapter with threading support
                logger.info("Using integrated polling (threaded)")

                # Create polling callback
                def poll_callback():
                    return self.poll_for_token(session)

                # Show with integrated polling
                # Pass the EXTRACTED TARGET URL, not the SVG URL!
                result = self._notifier.show_remote_login_with_polling(
                    login_code=session.initial_login_code,
                    qr_target_url=session.qr_target_url,
                    expires_in=session.expires_in,
                    interval=session.interval,
                    poll_callback=poll_callback,
                )

                if result == NotificationResult.CONTINUE:
                    # Get token data from adapter (if supported)
                    if hasattr(self._notifier, "get_token_data"):
                        token_data = self._notifier.get_token_data()
                        if token_data:
                            logger.info("✓ Remote login completed successfully")
                            self._notifier.close(success=True)
                            return token_data
                        else:
                            logger.warning("No token data available")
                            return None
                    else:
                        logger.error("Notifier doesn't support get_token_data()")
                        return None
                else:
                    logger.warning(f"Remote login result: {result}")
                    return None

            else:
                # Console adapter or other - manual polling
                logger.info("Using manual polling")

                # Show notification with extracted target URL
                result = self._notifier.show_remote_login(
                    login_code=session.initial_login_code,
                    qr_target_url=session.qr_target_url,
                    expires_in=session.expires_in,
                    interval=session.interval,
                )

                if result != NotificationResult.CONTINUE:
                    logger.warning(f"Failed to show notification: {result}")
                    return None

                # Poll manually
                token_data = self.poll_for_token(session)

                if token_data:
                    logger.info("✓ Remote login completed successfully")
                    self._notifier.close(success=True)
                else:
                    logger.warning("Remote login timed out or cancelled")
                    self._notifier.close(success=False, message="Timeout or cancelled")

                return token_data

        except Exception as e:
            logger.error(f"Remote login flow failed: {e}")
            self._notifier.close(success=False, message=str(e))
            return None
        finally:
            self._current_session = None

    def cancel_current_session(self) -> None:
        """Cancel current remote login session"""
        if self._current_session:
            logger.info("Cancelling remote login session")
            self._current_session = None
            self._notifier.close(success=False, message="Cancelled")

    # ========================================================================
    # Background login bridge (start_background_login / get_background_status)
    # ========================================================================

    def start_background_login(self, scope: Optional[str] = None, **_compat_kwargs: Any) -> None:
        """
        Start the remote login flow on a background (daemon) thread.

        Bridge for callers that expect the background API:
        start the worker, return immediately, poll get_background_status().

        Runs the proven blocking perform_complete_flow() internally, so QR
        display, polling, timeout and cancellation behave identically to the
        synchronous path.

        Args:
            scope: OAuth scopes to request (default: tvhubs offline_access)
            **_compat_kwargs: Ignored, accepted for forward compatibility with
                callers passing extra options; logged at debug level.

        Raises:
            RuntimeError: If a background login is already in progress
        """
        if _compat_kwargs:
            logger.debug(
                f"Ignoring unsupported kwargs in start_background_login: "
                f"{sorted(_compat_kwargs)}"
            )

        effective_scope = scope or DEFAULT_REMOTE_LOGIN_SCOPE

        with self._bg_lock:
            if self._bg_thread is not None and self._bg_thread.is_alive():
                raise RuntimeError("Remote login already in progress")

            # Reset bridge state from any previous run
            self._bg_result = None
            self._bg_error = None
            self._bg_done.clear()
            self._bg_cancel.clear()

            def _run() -> None:
                try:
                    token_data = self.perform_complete_flow(effective_scope)
                    with self._bg_lock:
                        self._bg_result = token_data
                except Exception as e:
                    error_text = f"{type(e).__name__}: {e}"
                    logger.error(f"Background remote login failed: {error_text}")
                    with self._bg_lock:
                        self._bg_error = error_text
                finally:
                    self._bg_done.set()

            self._bg_thread = threading.Thread(
                target=_run, daemon=True, name="Magenta2RemoteLogin"
            )
            self._bg_thread.start()

        logger.info(
            f"Background remote login started (scope={effective_scope!r}, "
            f"thread=Magenta2RemoteLogin)"
        )

    def get_background_status(self) -> Dict[str, Any]:
        """
        Get the status of the background login (safe to call at any time,
        including before a login was ever started).

        Returns:
            Dict with:
            - "status":    "not_started" | "in_progress" | "success" |
                           "error" | "no_token"
                           ("no_token" = finished without a token: timed out,
                           cancelled, or the flow failed internally)
            - "done":      True once the background thread has finished
            - "in_progress": True while the background login is running
            - "result":    Token data dict on success, else None
            - "error":     Error string if the worker raised, else None
            - "session":   Live session info (login code, QR target URL,
                           remaining seconds) while a login is active,
                           else None
        """
        with self._bg_lock:
            thread = self._bg_thread
            result = self._bg_result
            error = self._bg_error
            done = self._bg_done.is_set()

        if result is not None:
            status = "success"
        elif error is not None:
            status = "error"
        elif done:
            status = "no_token"
        elif thread is None:
            status = "not_started"
        else:
            status = "in_progress"

        return {
            "status": status,
            "done": done,
            # Derived from `status`, not from thread.is_alive(): the worker
            # sets _bg_done as its last action, but the thread object stays
            # "alive" briefly during teardown. Deriving from the snapshot
            # keeps status and in_progress from contradicting each other in
            # that window.
            "in_progress": status == "in_progress",
            "result": result,
            "error": error,
            "session": self.get_session_status(),
        }

    def wait_for_background_login(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Block until the background login finishes (or timeout elapses).

        Args:
            timeout: Maximum seconds to wait; None = wait indefinitely

        Returns:
            Token data dict on success; None if not finished in time, if no
            login was ever started, or if the login failed. Call
            get_background_status() to distinguish these cases.
        """
        with self._bg_lock:
            thread = self._bg_thread

        if thread is None:
            return None

        thread.join(timeout=timeout)

        with self._bg_lock:
            return self._bg_result

    def cancel_background_login(self) -> None:
        """
        Best-effort cancellation of a running background login.

        Sets an explicit cancel event that poll_for_token() checks every
        second, so cancellation does not depend on the notifier's close()
        having any particular side effect. The background thread then exits
        and the status becomes "no_token". No-op if nothing is running.
        """
        with self._bg_lock:
            thread = self._bg_thread

        if thread is not None and thread.is_alive():
            logger.info("Cancelling background remote login")
            self._bg_cancel.set()
            self.cancel_current_session()
        else:
            logger.debug("No background remote login to cancel")

    def get_session_status(self) -> Optional[Dict[str, Any]]:
        """Get current session status"""
        # Read once: the background login thread may clear
        # _current_session concurrently with this status poll.
        session = self._current_session
        if session is None:
            return None
        elapsed = time.time() - session.started_at
        remaining = max(0, int(session.expires_in - elapsed))

        # Best-effort: notifier implementations are not guaranteed thread-safe
        # and may be closed concurrently by the login worker, so a raising
        # is_cancelled() must not take down a status poll.
        try:
            notifier_cancelled = self._notifier.is_cancelled()
        except Exception:
            notifier_cancelled = False

        return {
            "login_code": session.initial_login_code,
            "qr_code_url": session.qr_code_url,
            "qr_target_url": session.qr_target_url,
            "elapsed_seconds": elapsed,
            "remaining_seconds": remaining,
            "is_expired": remaining <= 0,
            "interval": session.interval,
            "is_cancelled": notifier_cancelled or self._bg_cancel.is_set(),
        }