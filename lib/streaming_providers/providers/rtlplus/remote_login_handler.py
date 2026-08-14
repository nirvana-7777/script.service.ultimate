# streaming_providers/providers/rtlplus/remote_login_handler.py
"""
Remote Login Handler for RTL+ — OAuth2 Device Authorization Grant (RFC 8628)

Same architecture as providers/magenta2/remote_login_handler.py: a
provider-specific handler that owns the protocol details, and delegates
QR display / countdown / polling-thread lifecycle to the generic
NotificationFactory adapters. No third-party QR service is used — the
Kodi adapter renders the QR locally via qr_generator.generate_qr_code_png,
and the console adapter just prints the URL/code.

Endpoint and client_id are confirmed against the working legacy Kodi
addon's _device_login() implementation:
  - device auth: POST {AUTH_BASE_URL}/auth/device  (NOT AUTH_REALM_BASE)
  - client_id:   'bedrock-androidtv'                 (NOT the web client)
  - token poll:  POST {AUTH_ENDPOINT} with
                 grant_type=urn:ietf:params:oauth:grant-type:device_code
"""

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ...base.network import HTTPManager
from ...base.ui import NotificationFactory, NotificationInterface, NotificationResult
from ...base.utils.logger import logger


@dataclass
class RTLDeviceLoginSession:
    """RTL+ device-code login session data"""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int
    started_at: float


class RTLRemoteLoginHandler:
    """
    Handles the OAuth2 Device Authorization Grant for RTL+.

    Responsibilities:
    - Start the device auth session (/auth/device)
    - Poll the token endpoint until the user completes login on another device
    - Coordinate with the generic notification system for QR/code display
    """

    def __init__(
            self,
            http_manager: HTTPManager,
            device_client_id: str,
            device_auth_url: str,
            token_endpoint: str,
            notifier: Optional[NotificationInterface] = None,
            provider_name: str = "RTL+",
            request_timeout: int = 15,
    ):
        self.http_manager = http_manager
        self.device_client_id = device_client_id
        self.device_auth_url = device_auth_url
        self.token_endpoint = token_endpoint
        self.provider_name = provider_name
        self.request_timeout = request_timeout

        if notifier:
            self._notifier = notifier
        else:
            self._notifier = NotificationFactory.create(
                http_manager=http_manager,
                provider_name=provider_name,
                success_message=f"{provider_name} login successful",
                failure_template=f"{provider_name} login failed: {{reason}}",
            )

        self._current_session: Optional[RTLDeviceLoginSession] = None

        logger.debug(f"RTLRemoteLoginHandler initialized with {self._notifier.__class__.__name__}")

    def set_notifier(self, notifier: NotificationInterface) -> None:
        """Set custom notification interface"""
        self._notifier = notifier

    # --------------------------------------------------------------------------
    # Device Authorization Grant
    # --------------------------------------------------------------------------

    def start_remote_login(self, scope: str = "openid") -> RTLDeviceLoginSession:
        """
        Start the device authorization request.

        Raises:
            Exception: If the device auth request fails or the response is
                       missing device_code/user_code.
        """
        logger.info("Starting RTL+ remote login (Device Authorization Grant)")

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = {"client_id": self.device_client_id, "scope": scope}

        try:
            response = self.http_manager.post(
                self.device_auth_url,
                operation="device_auth",
                headers=headers,
                data=payload,
                timeout=self.request_timeout,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"RTL+ device auth request failed: {e}")
            raise Exception(f"RTL+ remote login start failed: {e}")

        device_code = data.get("device_code", "")
        user_code = data.get("user_code", "")
        verification_uri = data.get("verification_uri", "")
        verification_uri_complete = data.get(
            "verification_uri_complete",
            f"{verification_uri}?user_code={user_code}" if verification_uri else "",
        )
        expires_in = int(data.get("expires_in", 600))
        interval = max(int(data.get("interval", 5)), 5)

        if not device_code or not user_code:
            raise Exception("RTL+ device auth response missing device_code/user_code")

        session = RTLDeviceLoginSession(
            device_code=device_code,
            user_code=user_code,
            verification_uri=verification_uri,
            verification_uri_complete=verification_uri_complete,
            expires_in=expires_in,
            interval=interval,
            started_at=time.time(),
        )
        self._current_session = session

        logger.info(
            f"RTL+ device login started: user_code={user_code}, "
            f"expires_in={expires_in}s, interval={interval}s"
        )
        return session

    def poll_for_token(self, session: RTLDeviceLoginSession) -> Optional[Dict[str, Any]]:
        """
        Poll the token endpoint until the device code is confirmed, expires,
        or is denied. Intended for use as a poll_callback: returns token
        data (dict) on success, None on timeout/denial/cancellation.
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = {
            "client_id": self.device_client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": session.device_code,
        }

        start_time = session.started_at
        deadline = start_time + session.expires_in
        interval = session.interval

        while True:
            now = time.time()
            if now >= deadline:
                logger.warning("RTL+ device login: session expired")
                return None

            if self._notifier.is_cancelled():
                logger.info("RTL+ device login: user cancelled")
                return None

            try:
                response = self.http_manager.post(
                    self.token_endpoint,
                    operation="device_poll",
                    headers=headers,
                    data=payload,
                    timeout=self.request_timeout,
                )
            except Exception as e:
                logger.debug(f"RTL+ device poll network error (will retry): {e}")
                time.sleep(min(interval, max(0.5, deadline - now)))
                continue

            if response.status_code == 200:
                logger.info("RTL+ device login: authentication confirmed")
                return response.json()

            if response.status_code == 400:
                try:
                    error_data = response.json()
                except Exception:
                    error_data = {}
                error = error_data.get("error", "")

                if error == "authorization_pending":
                    pass
                elif error == "slow_down":
                    interval = min(interval + 5, 30)
                    logger.debug(f"RTL+ device login: slow_down, new interval={interval}s")
                elif error == "expired_token":
                    logger.info("RTL+ device login: code expired")
                    return None
                elif error == "access_denied":
                    logger.info("RTL+ device login: user denied")
                    return None
                else:
                    logger.warning(f"RTL+ device login: unexpected error '{error}'")
                    return None
            else:
                logger.warning(
                    f"RTL+ device login: unexpected status {response.status_code}: {response.text[:200]}"
                )
                return None

            time.sleep(min(interval, max(0.5, deadline - time.time())))

    def perform_complete_flow(self, scope: str = "openid") -> Optional[Dict[str, Any]]:
        """
        Perform the complete device-code flow with QR display + polling.

        Mirrors providers/magenta2/remote_login_handler.py's
        perform_complete_flow(): uses the notifier's integrated polling
        support when available (Kodi — auto-closes the dialog on success),
        otherwise falls back to displaying the code/URL once and polling
        manually (console).
        """
        try:
            session = self.start_remote_login(scope)

            if hasattr(self._notifier, "show_remote_login_with_polling"):
                logger.info("Using integrated polling (threaded)")

                def poll_callback():
                    return self.poll_for_token(session)

                result = self._notifier.show_remote_login_with_polling(
                    login_code=session.user_code,
                    qr_target_url=session.verification_uri_complete,
                    expires_in=session.expires_in,
                    interval=session.interval,
                    poll_callback=poll_callback,
                )

                if result == NotificationResult.CONTINUE:
                    if hasattr(self._notifier, "get_token_data"):
                        token_data = self._notifier.get_token_data()
                        if token_data:
                            logger.info("✓ RTL+ remote login completed")
                            self._notifier.close(success=True)
                            return token_data
                        logger.warning("No token data available")
                        return None
                    logger.error("Notifier doesn't support get_token_data()")
                    return None

                logger.warning(f"RTL+ remote login result: {result}")
                return None

            # Console adapter or other — manual polling
            logger.info("Using manual polling")

            result = self._notifier.show_remote_login(
                login_code=session.user_code,
                qr_target_url=session.verification_uri_complete,
                expires_in=session.expires_in,
                interval=session.interval,
            )

            if result != NotificationResult.CONTINUE:
                logger.warning(f"Failed to show notification: {result}")
                return None

            token_data = self.poll_for_token(session)

            if token_data:
                logger.info("✓ RTL+ remote login completed")
                self._notifier.close(success=True)
            else:
                logger.warning("RTL+ remote login timed out or cancelled")
                self._notifier.close(success=False, message="Timeout or cancelled")

            return token_data

        except Exception as e:
            logger.error(f"RTL+ remote login flow failed: {e}")
            self._notifier.close(success=False, message=str(e))
            return None
        finally:
            self._current_session = None

    def cancel(self) -> None:
        """Cancel current session"""
        if self._current_session:
            logger.info("Cancelling RTL+ remote login session")
            self._current_session = None
            self._notifier.close(success=False, message="Cancelled")