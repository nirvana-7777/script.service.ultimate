# streaming_providers/base/auth/remote_login_manager.py
"""
Remote Login Manager for OAuth2 Device/QR Code Flows
Encapsulates session state, polling logic, and external completion handlers.
Thread-safe, production-hardened, and environment-agnostic.
"""
import secrets
import string
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qs, urlparse

from ..utils.logger import logger


@dataclass
class RemoteLoginSession:
    """
    Mutable state for an active remote login session.

    All mutations must be performed while holding the manager's lock.
    The fields `authorization_code`, `completed`, `cancelled`, and `error`
    are intentionally mutable; callers are responsible for synchronisation.
    """
    session_id: str
    state: str
    code_verifier: str
    auth_url: str
    login_code: str
    created_at: float = field(default_factory=time.time)
    expires_in: int = 300  # 5 minutes default

    # Mutable completion fields (protected by external lock)
    authorization_code: Optional[str] = None
    completed: bool = False
    cancelled: bool = False
    error: Optional[str] = None

    def is_expired(self) -> bool:
        return time.time() > self.created_at + self.expires_in

    def get_remaining(self) -> int:
        return max(0, int((self.created_at + self.expires_in) - time.time()))

    def set_authorization_code(self, auth_code: str) -> bool:
        """
        Store the authorization code so the polling callback can exchange it.

        Intentionally does NOT set `completed`; that happens only after the
        token exchange succeeds (inside the polling callback, under lock).

        Caller must hold the manager lock.

        Returns:
            True if the code was stored, False if the session is ineligible.
        """
        if self.completed or self.cancelled or self.is_expired():
            return False
        self.authorization_code = auth_code
        return True

    def mark_cancelled(self) -> None:
        """Thread-safe cancellation marker (caller must hold lock)."""
        if not self.completed and not self.cancelled:
            self.cancelled = True


class RemoteLoginManager:
    """
    Manages remote login sessions for OAuth2 authenticators.

    Features:
    - Thread-safe session lifecycle management
    - Polling callback with proper lock release before network I/O
    - External completion via URL or raw code
    - Optional HTTP callback server with per-server session token auth
    - Automatic cleanup of expired sessions
    """

    # Readable alphabet excluding visually ambiguous characters (0/O/I/1)
    _LOGIN_CODE_ALPHABET = ''.join(
        c for c in (string.ascii_uppercase + string.digits)
        if c not in frozenset('0OI1')
    )

    def __init__(self, authenticator_ref: Any):
        """
        Initialize manager with reference to authenticator.

        Args:
            authenticator_ref: The BaseOAuth2Authenticator instance (or subclass)
        """
        self._authenticator = authenticator_ref
        self._sessions: Dict[str, RemoteLoginSession] = {}
        self._lock = threading.RLock()  # Reentrant for nested calls
        self._callback_server = None
        self._callback_thread = None
        self._server_token: Optional[str] = None

    # ========================================================================
    # Session Creation & Management
    # ========================================================================

    def create_session(
        self,
        auth_url: str,
        state: str,
        code_verifier: str,
        login_code: Optional[str] = None,
        expires_in: int = 300,
    ) -> RemoteLoginSession:
        """
        Create a new remote login session.

        Args:
            auth_url: Full authorization URL with PKCE params
            state: OAuth2 state parameter for CSRF protection
            code_verifier: PKCE code verifier
            login_code: Human-readable code for manual entry (auto-generated if None)
            expires_in: Session timeout in seconds

        Returns:
            RemoteLoginSession instance
        """
        session_id = secrets.token_urlsafe(16)
        code = login_code or self._generate_login_code()

        session = RemoteLoginSession(
            session_id=session_id,
            state=state,
            code_verifier=code_verifier,
            auth_url=auth_url,
            login_code=code,
            expires_in=expires_in,
        )

        with self._lock:
            self._cleanup_expired_sessions()
            self._sessions[session_id] = session

        logger.debug(f"Created remote login session {session_id[:8]}... with code {code}")
        return session

    def get_session(self, session_id: str) -> Optional[RemoteLoginSession]:
        """Get session by ID (thread-safe)."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session and session.is_expired():
                self._sessions.pop(session_id, None)
                return None
            return session

    def cancel_session(self, session_id: Optional[str] = None) -> int:
        """
        Cancel one or all pending sessions.

        Args:
            session_id: Specific session to cancel, or None for all

        Returns:
            Number of sessions cancelled
        """
        with self._lock:
            if session_id:
                session = self._sessions.get(session_id)
                if session and not session.completed:
                    session.mark_cancelled()
                    logger.info(f"Cancelled remote login session {session_id[:8]}...")
                    return 1
                return 0
            else:
                count = 0
                for sess in self._sessions.values():
                    if not sess.completed:
                        sess.mark_cancelled()
                        count += 1
                logger.info(f"Cancelled {count} pending remote login sessions")
                return count

    # ========================================================================
    # Polling Callback Factory
    # ========================================================================

    def create_polling_callback(
        self,
        session_id: str,
        token_exchange_func: Callable[[str, str, str], Dict[str, Any]],
    ) -> Callable[[], Optional[Dict[str, Any]]]:
        """
        Create a thread-safe polling callback for the UI adapter.

        The returned callback:
        1. Checks session status under lock
        2. Releases lock BEFORE calling network-sensitive token_exchange_func
        3. Marks the session as completed (not merely code-received) only after
           a successful token exchange
        4. Handles errors gracefully without crashing the polling thread

        Args:
            session_id: The session to monitor
            token_exchange_func: Function(auth_code, verifier, state) -> token_data

        Returns:
            Callable returning token_data on success, None if still waiting
        """
        def poll_callback() -> Optional[Dict[str, Any]]:
            auth_code: Optional[str] = None
            verifier: Optional[str] = None
            state: Optional[str] = None
            session: Optional[RemoteLoginSession] = None

            # Step 1: Read session state under lock (fast, no I/O)
            with self._lock:
                sess = self._sessions.get(session_id)
                if not sess:
                    logger.debug(f"Poll: Session {session_id[:8]}... not found")
                    return None

                if sess.completed:
                    return None  # Already done; shouldn't be called again
                if sess.cancelled:
                    logger.debug(f"Poll: Session {session_id[:8]}... cancelled")
                    return None
                if sess.is_expired():
                    logger.warning(f"Poll: Session {session_id[:8]}... expired")
                    return None

                if not sess.authorization_code:
                    return None  # Still waiting for the user to authorise

                # Capture all data needed for the exchange, then release lock
                auth_code = sess.authorization_code
                verifier = sess.code_verifier
                state = sess.state
                session = sess

            # Step 2: Exchange token OUTSIDE lock (network I/O — must not hold lock)
            try:
                logger.info(f"Exchanging authorization code for session {session_id[:8]}...")
                token_data = token_exchange_func(auth_code, verifier, state)

                # Step 3: Mark as fully completed under lock
                with self._lock:
                    # Re-check that the session wasn't cancelled/expired during exchange
                    live = self._sessions.get(session_id)
                    if live is session and not session.cancelled and not session.is_expired():
                        session.completed = True
                    else:
                        logger.warning(
                            f"Session {session_id[:8]}... state changed during token exchange; "
                            "discarding result"
                        )
                        return None

                logger.info(f"Token exchange successful for session {session_id[:8]}...")
                return token_data

            except Exception as e:
                logger.error(f"Token exchange failed for session {session_id[:8]}...: {e}")
                with self._lock:
                    live = self._sessions.get(session_id)
                    if live is session:
                        session.error = str(e)
                return None

        return poll_callback

    # ========================================================================
    # External Completion Handlers
    # ========================================================================

    def complete_from_callback_url(self, callback_url: str, session_id: Optional[str] = None) -> bool:
        """
        Complete a session using a full OAuth2 callback URL.

        Args:
            callback_url: URL containing ?code=xxx&state=yyy
            session_id: Optional specific session (auto-selects if None)

        Returns:
            True if completion succeeded, False otherwise
        """
        try:
            parsed = urlparse(callback_url)
            query = parse_qs(parsed.query)
            auth_code = query.get('code', [None])[0]
            received_state = query.get('state', [None])[0]

            if not auth_code:
                logger.warning("No authorization code in callback URL")
                return False

            return self.complete_with_authorization_code(auth_code, received_state, session_id)

        except Exception as e:
            logger.error(f"Failed to parse callback URL: {e}")
            return False

    def complete_with_authorization_code(
        self,
        auth_code: str,
        received_state: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> bool:
        """
        Complete a session using raw authorization code.

        Stores the code on the session so the next poll_callback invocation
        can perform the token exchange (outside the lock).

        Args:
            auth_code: The authorization code from provider
            received_state: Optional state param for validation
            session_id: Optional specific session (auto-selects first pending if None)

        Returns:
            True if completion succeeded, False otherwise
        """
        with self._lock:
            # Find target session
            target: Optional[RemoteLoginSession] = None
            target_id: Optional[str] = session_id

            if session_id:
                target = self._sessions.get(session_id)
            else:
                # Auto-select first valid pending session
                for sid, sess in self._sessions.items():
                    if sess.completed or sess.cancelled or sess.is_expired():
                        continue
                    if received_state and sess.state != received_state:
                        continue  # State mismatch, keep looking
                    target = sess
                    target_id = sid
                    break

            if not target:
                logger.warning("No eligible remote login session found for completion")
                return False

            if target.is_expired():
                logger.warning(f"Session {target_id[:8]}... expired before completion")
                return False

            if target.cancelled:
                logger.debug(f"Session {target_id[:8]}... was cancelled, ignoring completion")
                return False

            # Validate state if provided
            if received_state and target.state != received_state:
                logger.warning(
                    f"State mismatch for session {target_id[:8]}...: "
                    f"expected {target.state!r}, got {received_state!r}"
                )
                return False

            # Store the code; token exchange happens on the next poll_callback invocation
            stored = target.set_authorization_code(auth_code)
            if stored:
                logger.info(f"Session {target_id[:8]}... received authorization code; awaiting poll")
            else:
                logger.warning(f"Session {target_id[:8]}... could not accept authorization code")
            return stored

    # ========================================================================
    # Optional: Secure HTTP Callback Server
    # ========================================================================

    def start_callback_server(
        self,
        port: int = 8080,
        host: str = "127.0.0.1",  # Default to localhost for security
        session_token: Optional[str] = None,
    ) -> bool:
        """
        Start a minimal HTTP server to receive callbacks from mobile devices.

        SECURITY:
        - Defaults to localhost only to prevent external access
        - Requires session_token in URL query to prevent spoofing
        - Token is per-server-instance and cryptographically random
        - Handler class is created fresh per call to avoid class-level state sharing

        Phone would call: http://{host}:{port}/callback?code=xxx&token=yyy

        Args:
            port: Port to bind
            host: Host to bind (use "127.0.0.1" for security, "0.0.0.0" for network)
            session_token: Optional shared secret for auth (auto-generated if None)

        Returns:
            True if server started successfully, False otherwise
        """
        if self._callback_server:
            logger.warning("Callback server already running")
            return False

        try:
            from http.server import BaseHTTPRequestHandler, HTTPServer
            import urllib.parse

            # Generate secure token if not provided
            effective_token = session_token or secrets.token_urlsafe(32)
            self._server_token = effective_token

            # Capture manager and token in a closure rather than as class-level
            # attributes to avoid state sharing between server instances.
            manager_ref = self
            auth_token_ref = effective_token

            class _CallbackHandler(BaseHTTPRequestHandler):
                _manager = manager_ref
                _auth_token = auth_token_ref

                def log_message(self, format, *args):  # noqa: A002
                    logger.debug(f"Callback: {format % args}")

                def _send_response(self, code: int, html: bytes, content_type: str = "text/html; charset=utf-8"):
                    self.send_response(code)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(html)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    self.wfile.write(html)

                def _handle_callback(self, query: Dict[str, list]):
                    # Validate token first
                    token = query.get('token', [None])[0]
                    if not token or token != self._auth_token:
                        logger.warning("Callback rejected: invalid or missing token")
                        self._send_response(403, b"Unauthorized")
                        return

                    code = query.get('code', [None])[0]
                    session_id = query.get('session', [None])[0]

                    if not code:
                        self._send_response(400, b"Missing 'code' parameter")
                        return

                    success = self._manager.complete_with_authorization_code(
                        auth_code=code,
                        session_id=session_id,
                    )

                    if success:
                        self._send_response(200, (
                            b"<html><body style='font-family:sans-serif;text-align:center;padding:40px;'>"
                            b"<h1 style='color:#22c55e'>\xe2\x9c\x93 Login Successful</h1>"
                            b"<p>You may close this window and return to your device.</p>"
                            b"</body></html>"
                        ))
                        logger.info("Remote login completed via HTTP callback")
                    else:
                        self._send_response(400, (
                            b"<html><body style='font-family:sans-serif;text-align:center;padding:40px;'>"
                            b"<h1 style='color:#ef4444'>\xe2\x9c\x97 Login Failed</h1>"
                            b"<p>No active session found. Please restart the login process.</p>"
                            b"</body></html>"
                        ))
                        logger.warning("HTTP callback completion failed")

                def do_GET(self):
                    parsed = urllib.parse.urlparse(self.path)
                    if parsed.path == '/callback':
                        query = urllib.parse.parse_qs(parsed.query)
                        self._handle_callback(query)
                    else:
                        self._send_response(404, b"Not Found")

                def do_POST(self):
                    content_len = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(content_len).decode(errors='replace')
                    query = urllib.parse.parse_qs(body) if body else {}
                    if self.path == '/callback':
                        self._handle_callback(query)
                    else:
                        self._send_response(404, b"Not Found")

            self._callback_server = HTTPServer((host, port), _CallbackHandler)
            self._callback_thread = threading.Thread(
                target=self._callback_server.serve_forever,
                daemon=True,
                name="RemoteLoginCallbackServer",
            )
            self._callback_thread.start()

            token_param = f"&token={effective_token}" if effective_token else ""
            logger.info(
                f"Callback server started on {host}:{port} - "
                f"phones can POST to http://{host}:{port}/callback?code=xxx{token_param}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to start callback server: {e}")
            return False

    def stop_callback_server(self) -> None:
        """Gracefully stop the callback server."""
        if self._callback_server:
            try:
                self._callback_server.shutdown()
                if self._callback_thread and self._callback_thread.is_alive():
                    self._callback_thread.join(timeout=2.0)
                logger.info("Callback server stopped")
            except Exception as e:
                logger.warning(f"Error stopping callback server: {e}")
            finally:
                self._callback_server = None
                self._callback_thread = None
                self._server_token = None

    def get_callback_server_token(self) -> Optional[str]:
        """Get the current callback server token for embedding in QR URLs."""
        return self._server_token

    # ========================================================================
    # Utilities & Cleanup
    # ========================================================================

    @classmethod
    def _generate_login_code(cls, length: int = 8) -> str:
        """Generate human-readable login code excluding ambiguous characters."""
        return ''.join(secrets.choice(cls._LOGIN_CODE_ALPHABET) for _ in range(length))

    def _cleanup_expired_sessions(self) -> int:
        """
        Remove truly expired or completed sessions (caller must hold lock).

        Note: only sessions that are *both* completed AND expired are removed
        eagerly so that a just-completed session is not cleaned up before the
        caller can inspect it. Purely expired (never completed) sessions are
        always removed.

        Returns:
            Number of sessions removed
        """
        to_remove = [
            sid for sid, sess in self._sessions.items()
            if sess.is_expired() or (sess.completed and sess.is_expired())
        ]
        for sid in to_remove:
            self._sessions.pop(sid, None)
        if to_remove:
            logger.debug(f"Cleaned up {len(to_remove)} expired/completed sessions")
        return len(to_remove)

    def get_active_session_count(self) -> int:
        """Get count of non-expired, non-completed, non-cancelled sessions."""
        with self._lock:
            return sum(
                1 for s in self._sessions.values()
                if not s.completed and not s.cancelled and not s.is_expired()
            )

    def __del__(self):
        """Best-effort cleanup on GC collection. Does not acquire the lock."""
        try:
            self.stop_callback_server()
        except Exception:
            pass
        # Do not acquire self._lock here: the GC may run during interpreter
        # shutdown while the lock is held, causing a deadlock.
        self._sessions.clear()