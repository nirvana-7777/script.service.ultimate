# streaming_providers/providers/magenta2/remote_login_handler.py
"""
Remote Login Handler for Magenta2 Backchannel Authentication
Implements QR code-based authentication flow as fallback when line auth fails
"""
import time
from typing import Dict, Optional, Any
from dataclasses import dataclass

from ...base.network import HTTPManager
from ...base.utils.logger import logger
from ...base.ui import NotificationFactory, NotificationInterface, NotificationResult
from .constants import (
    SSO_USER_AGENT,
    DEFAULT_REQUEST_TIMEOUT,
    GRANT_TYPES,
)


@dataclass
class RemoteLoginSession:
    """Remote login session data"""
    initial_login_code: str
    auth_req_id: str
    auth_req_sec: str
    interval: int
    expires_in: int
    qr_code_url: str
    started_at: float


class RemoteLoginHandler:
    """
    Handles the complete backchannel authentication / remote login flow

    Flow:
    1. Start backchannel auth -> get login code and QR URL
    2. Display QR code to user (via notification adapter)
    3. Poll token endpoint until user completes mobile authentication
    4. Handle countdown internally with notification updates
    """

    def __init__(self, http_manager: HTTPManager, sam3_client_id: str,
                 backchannel_start_url: str, token_endpoint: str,
                 qr_code_url_template: str,
                 notifier: Optional[NotificationInterface] = None):
        """
        Initialize remote login handler

        Args:
            http_manager: HTTP manager for requests
            sam3_client_id: SAM3 client ID
            backchannel_start_url: Backchannel auth start endpoint
            token_endpoint: OAuth token endpoint for polling
            qr_code_url_template: QR code URL template with {code} placeholder
            notifier: Optional notification interface (auto-created if None)
        """
        self.http_manager = http_manager
        self.sam3_client_id = sam3_client_id
        self.backchannel_start_url = backchannel_start_url
        self.token_endpoint = token_endpoint
        self.qr_code_url_template = qr_code_url_template

        # Get or create notifier with http_manager
        if notifier:
            self._notifier = notifier
        else:
            self._notifier = NotificationFactory.create(http_manager=http_manager)

        self._current_session: Optional[RemoteLoginSession] = None

        logger.debug(f"RemoteLoginHandler initialized with {self._notifier.__class__.__name__}")

    def set_notifier(self, notifier: NotificationInterface) -> None:
        """
        Set custom notification interface

        Args:
            notifier: Notification interface to use
        """
        self._notifier = notifier
        logger.debug(f"Notifier set to: {notifier.__class__.__name__}")

    def start_remote_login(self, scope: str = "tvhubs offline_access") -> RemoteLoginSession:
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

            # Build request payload
            payload = {
                'client_id': self.sam3_client_id,
                'scope': scope
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'User-Agent': SSO_USER_AGENT
            }

            # Start backchannel auth
            response = self.http_manager.post(
                self.backchannel_start_url,
                operation='backchannel_start',
                headers=headers,
                data=payload,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            data = response.json()

            # Extract session data
            initial_login_code = data.get('initial_login_code')
            auth_req_id = data.get('auth_req_id')
            auth_req_sec = data.get('auth_req_sec')
            interval = int(data.get('interval', 10))
            expires_in = int(data.get('expires_in', 300))

            if not all([initial_login_code, auth_req_id, auth_req_sec]):
                raise Exception("Incomplete backchannel auth response")

            # Build QR code URL
            qr_code_url = self.qr_code_url_template.format(code=initial_login_code)

            # Create session
            session = RemoteLoginSession(
                initial_login_code=initial_login_code,
                auth_req_id=auth_req_id,
                auth_req_sec=auth_req_sec,
                interval=interval,
                expires_in=expires_in,
                qr_code_url=qr_code_url,
                started_at=time.time()
            )

            self._current_session = session

            logger.info(
                f"Remote login started: code={initial_login_code}, "
                f"interval={interval}s, expires_in={expires_in}s"
            )

            return session

        except Exception as e:
            logger.error(f"Failed to start remote login: {e}")
            raise Exception(f"Remote login start failed: {e}")

    def poll_for_token(self, session: RemoteLoginSession) -> Optional[Dict[str, Any]]:
        """
        Poll token endpoint until user completes authentication or timeout
        NOW HANDLES COUNTDOWN UPDATES INTERNALLY

        Args:
            session: Active remote login session

        Returns:
            Token data dict if successful, None if timed out/cancelled

        Raises:
            Exception: If polling fails with unexpected error
        """
        try:
            logger.info("Starting token polling for remote login")

            start_time = session.started_at
            next_poll_time = start_time
            last_countdown_update = start_time

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'User-Agent': SSO_USER_AGENT
            }

            payload = {
                'client_id': self.sam3_client_id,
                'grant_type': GRANT_TYPES['REMOTE_LOGIN'],
                'auth_req_id': session.auth_req_id,
                'auth_req_sec': session.auth_req_sec
            }

            poll_count = 0
            max_polls = session.expires_in // session.interval + 1

            while True:
                current_time = time.time()
                elapsed = current_time - start_time
                remaining = max(0, session.expires_in - elapsed)

                # Check if session expired
                if elapsed >= session.expires_in:
                    logger.warning(
                        f"Remote login session expired after {elapsed:.1f}s "
                        f"(limit: {session.expires_in}s)"
                    )
                    self._notifier.close(success=False, message="Session expired")
                    return None

                # Update countdown display (every second or as needed)
                if current_time - last_countdown_update >= 1.0:
                    # Check if user cancelled
                    if self._notifier.is_cancelled():
                        logger.info("User cancelled remote login")
                        self._notifier.close(success=False, message="Cancelled by user")
                        return None

                    # Update countdown
                    if not self._notifier.update_countdown(int(remaining)):
                        logger.info("Countdown update returned False - user cancelled")
                        self._notifier.close(success=False, message="Cancelled by user")
                        return None

                    last_countdown_update = current_time

                # Wait until next poll time
                if current_time < next_poll_time:
                    sleep_time = min(1.0, next_poll_time - current_time)  # Sleep max 1 second for countdown updates
                    time.sleep(sleep_time)
                    continue

                # Perform poll
                poll_count += 1
                logger.debug(
                    f"Polling attempt {poll_count}/{max_polls} "
                    f"(remaining: {remaining:.0f}s)"
                )

                try:
                    response = self.http_manager.post(
                        self.token_endpoint,
                        operation='remote_login_poll',
                        headers=headers,
                        data=payload,
                        timeout=DEFAULT_REQUEST_TIMEOUT
                    )

                    # 202 = User hasn't completed authentication yet
                    if response.status_code == 202:
                        logger.debug("Authentication not yet completed (202)")
                        next_poll_time = time.time() + session.interval
                        continue

                    # Success - user completed authentication
                    if response.status_code == 200:
                        token_data = response.json()
                        logger.info(
                            f"✓ Remote login successful after {elapsed:.1f}s "
                            f"({poll_count} polls)"
                        )
                        self._notifier.close(success=True)
                        return token_data

                    # Other status codes = error
                    response.raise_for_status()

                except Exception as e:
                    # If we get an error during polling, check if we should retry
                    if elapsed < session.expires_in:
                        logger.debug(f"Poll error (will retry): {e}")
                        next_poll_time = time.time() + session.interval
                        continue
                    else:
                        # Session expired, give up
                        raise

        except Exception as e:
            logger.error(f"Remote login polling failed: {e}")
            self._notifier.close(success=False, message=str(e))
            raise Exception(f"Remote login polling failed: {e}")

    def perform_complete_flow(self, scope: str = "tvhubs offline_access") -> Optional[Dict[str, Any]]:
        """
        Perform complete remote login flow:
        1. Start session
        2. Display QR code via notifier
        3. Poll for completion with automatic countdown updates

        Args:
            scope: OAuth scopes to request

        Returns:
            Token data dict if successful, None if failed/timeout/cancelled
        """
        try:
            # Step 1: Start session
            session = self.start_remote_login(scope)

            # Step 2: Display QR code to user via notifier
            result = self._notifier.show_remote_login(
                login_code=session.initial_login_code,
                qr_url=session.qr_code_url,
                expires_in=session.expires_in,
                interval=session.interval
            )

            if result != NotificationResult.CONTINUE:
                logger.warning(f"Failed to show notification: {result}")
                return None

            # Step 3: Poll for completion (handles countdown internally)
            token_data = self.poll_for_token(session)

            if token_data:
                logger.info("✓ Remote login flow completed successfully")
            else:
                logger.warning("Remote login flow timed out or was cancelled")

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

    def get_session_status(self) -> Optional[Dict[str, Any]]:
        """Get current session status"""
        if not self._current_session:
            return None

        session = self._current_session
        elapsed = time.time() - session.started_at
        remaining = max(0, session.expires_in - elapsed)

        return {
            'login_code': session.initial_login_code,
            'qr_code_url': session.qr_code_url,
            'elapsed_seconds': elapsed,
            'remaining_seconds': remaining,
            'is_expired': remaining <= 0,
            'interval': session.interval,
            'is_cancelled': self._notifier.is_cancelled()
        }