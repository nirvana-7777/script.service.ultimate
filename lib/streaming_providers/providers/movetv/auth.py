# streaming_providers/providers/movetv/auth.py
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, cast

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.auth.credentials import UserPasswordCredentials
from ...base.utils.logger import logger
from .constants import MoveTVConfig


@dataclass
class MoveTVAuthToken(BaseAuthToken):
    """
    Concrete implementation of MoveTVAuthToken.
    Note: device_id is used here to store the persistent Move.tv UID.
    """
    customer_id: int = 0
    customer_profile_id: int = 0
    dedicated_server: str = ""
    uid: str = ""
    device_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Concrete implementation of abstract method."""
        return {
            # Stored under both keys: "access_token" for the base class and
            # "auth_token" to match the raw API shape, ensuring round-trip
            # whether reading from the live response or persisted session data.
            "access_token": self.access_token,
            "auth_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
            "refresh_token": self.refresh_token,
            "refresh_expires_in": self.refresh_expires_in,
            "auth_level": self.auth_level.value,
            "credential_type": self.credential_type,
            "customer_id": self.customer_id,
            "customer_profile_id": self.customer_profile_id,
            "dedicated_server": self.dedicated_server,
            "uid": self.uid,
            "device_id": self.device_id,
        }


class MoveTVAuthenticator(BaseAuthenticator):
    """
    Concrete implementation of MoveTVAuthenticator.
    """

    # Parameters accepted by BaseAuthenticator.__init__
    _BASE_INIT_PARAMS = {
        "provider_name", "settings_manager", "credentials",
        "country", "config_dir", "enable_kodi_integration",
    }

    def __init__(self, *args, **kwargs):
        # provider_name is a @property on the base class, so it must NOT be
        # passed as a constructor argument — pass the literal string directly.
        if args:
            # Positional: first arg is provider_name; replace with our value.
            args = ("movetv",) + args[1:]
        else:
            kwargs["provider_name"] = "movetv"

        # Consume kwargs unknown to BaseAuthenticator (e.g. proxy_config)
        # before forwarding, storing them as instance attributes.
        extra = {k: v for k, v in kwargs.items() if k not in self._BASE_INIT_PARAMS}
        for k in extra:
            kwargs.pop(k)

        super().__init__(*args, **kwargs)

        # Attach extra kwargs as attributes so subclass code can use them.
        for k, v in extra.items():
            setattr(self, k, v)

        self.http_manager: Any = getattr(self, "http_manager", None)

    # ------------------------------------------------------------------
    # Abstract methods required by BaseAuthenticator
    # ------------------------------------------------------------------

    @property
    def auth_endpoint(self) -> str:
        """Authentication endpoint URL."""
        return MoveTVConfig.login_url()

    def _get_auth_headers(self) -> Dict[str, str]:
        """Headers for the authentication request."""
        return MoveTVConfig.get_base_headers()

    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build the login payload from current credentials."""
        if not self.credentials or not isinstance(self.credentials, UserPasswordCredentials):
            raise ValueError("move.tv requires username/password credentials")
        uid = self.get_device_id()
        return {
            "username": self.credentials.username,
            "password": self.credentials.password,
            "partnerId": MoveTVConfig.PARTNER_ID,
            "deviceName": MoveTVConfig.DEVICE_NAME,
            "deviceModelId": MoveTVConfig.DEVICE_MODEL_ID,
            "uid": uid,
            "appVersion": MoveTVConfig.APP_VERSION,
        }

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> MoveTVAuthToken:
        """
        Create a MoveTVAuthToken from stored token data or a raw API response.
        Handles both shapes so that _load_session() works correctly.

        Stored sessions may be missing keys like 'access_token' (stored as
        'auth_token' only) or 'issued_at' (older sessions). Both are handled
        gracefully so that _load_session() never raises and discards the token.
        """
        uid = response_data.get("device_id") or response_data.get("uid", "")
        profile = response_data.get("profile", {})
        auth_level_raw = response_data.get("auth_level", TokenAuthLevel.USER_AUTHENTICATED.value)
        if isinstance(auth_level_raw, str):
            try:
                auth_level = TokenAuthLevel(auth_level_raw)
            except ValueError:
                auth_level = TokenAuthLevel.USER_AUTHENTICATED
        else:
            auth_level = auth_level_raw

        # 'access_token' and 'auth_token' are the same value; accept either.
        access_token = (
            response_data.get("access_token")
            or response_data.get("auth_token", "")
        )

        # 'issued_at' is absent from sessions saved before this field was
        # added.  Use a sentinel far in the future so is_expired stays False
        # and we always reach validate_token() rather than forcing a login.
        issued_at = response_data.get("issued_at")
        if issued_at is None:
            # No timestamp stored → treat token as freshly issued so the
            # base-class expiry check never fires.  validate_token() will
            # confirm liveness with the server instead.
            issued_at = time.time()
            logger.debug(
                "move.tv: Session has no issued_at; defaulting to now so "
                "validate_token() decides liveness"
            )

        # expires_in: use a very large value when absent so is_expired==False.
        # Again, the server-side validate call is the real freshness check.
        expires_in_raw = response_data.get("expires_in") or response_data.get("t")
        expires_in = int(expires_in_raw) if expires_in_raw is not None else 86400 * 365

        token = MoveTVAuthToken(
            access_token=access_token,
            token_type=response_data.get("token_type", "token"),
            expires_in=expires_in,
            issued_at=float(issued_at),
            refresh_token=response_data.get("refresh_token") or None,
            refresh_expires_in=int(response_data.get("refresh_expires_in", 0)),
            auth_level=auth_level,
            customer_id=response_data.get("customer_id", 0),
            customer_profile_id=(
                response_data.get("customer_profile_id") or profile.get("id", 0)
            ),
            dedicated_server=response_data.get("dedicated_server", ""),
            uid=uid,
            device_id=uid,
        )

        logger.debug(
            f"move.tv: Built token — access_token={'***' if token.access_token else '<empty>'}, "
            f"customer_id={token.customer_id}, uid={token.uid}, "
            f"is_expired={token.is_expired}"
        )
        return token

    def get_fallback_credentials(self):
        """No anonymous / fallback credentials for Move.tv — login is required."""
        return None

    def _perform_authentication(self) -> MoveTVAuthToken:
        """
        Execute the actual HTTP login request and return a token.
        Called by the base class authenticate() after credential validation.
        """
        payload = self._build_auth_payload()
        uid = payload["uid"]

        logger.debug(f"move.tv: Authenticating with slot UID: {uid}")

        response = self.http_manager.post(
            self.auth_endpoint,
            json=payload,
            headers=self._get_auth_headers(),
            operation="auth",
        )
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            message = data.get("message", "Unknown login error")
            raise RuntimeError(f"Move.tv auth failed: {message}")

        return self._create_token_from_response({**data, "uid": uid, "device_id": uid})

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """Concrete implementation of abstract method."""
        return TokenAuthLevel.USER_AUTHENTICATED

    # ------------------------------------------------------------------
    # Token validation
    # ------------------------------------------------------------------

    def validate_token(self, token: MoveTVAuthToken) -> bool:
        """
        Call the Move.tv token-validate endpoint to confirm the stored token
        is still accepted by the server.

        Returns True if the server reports "Token active.", False otherwise.
        The token fields (dedicated_server etc.) are NOT updated here because
        the validate response may contain fresh server URLs — callers that need
        those values should read them from get_session_info() after a successful
        validate, or trigger a full re-login on failure.
        """
        if not token.access_token:
            logger.debug("move.tv: validate_token called with empty access_token, skipping")
            return False

        headers = {
            **MoveTVConfig.get_base_headers(),
            "x-auth-token": token.access_token,
            "x-refresh-token": token.refresh_token or "",
        }
        payload = {
            "customerId": token.customer_id,
            "appVersion": MoveTVConfig.APP_VERSION,
        }

        logger.debug(
            f"move.tv: Validating token for customer_id={token.customer_id}"
        )

        try:
            response = self.http_manager.post(
                MoveTVConfig.validate_url(),
                json=payload,
                headers=headers,
                operation="token_validate",
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            logger.debug(f"move.tv: Token validation request failed: {exc}")
            return False

        if data.get("message") == "Token active.":
            logger.debug("move.tv: Token is active")
            return True

        # Token is not active — log the full response so we can diagnose
        # what the API returned (new tokens, error codes, etc.).
        logger.debug(f"move.tv: Token not active, server response: {data}")
        return False

    # ------------------------------------------------------------------
    # Override authenticate() to bypass expiry when session data exists
    # ------------------------------------------------------------------

    def authenticate(self, force_refresh: bool = False) -> MoveTVAuthToken:
        """
        Move.tv sessions do not carry an explicit server-side expiry we can
        rely on.  When we have a stored token we validate it with the API
        instead of checking the local is_expired flag.

        Flow:
          1. No stored token          → full login
          2. Stored token, valid      → return as-is
          3. Stored token, invalid    → full login (future: try refresh first)
          4. force_refresh=True       → full login unconditionally
        """
        logger.debug(
            f"move.tv: authenticate(force_refresh={force_refresh}) — "
            f"has_token={self._current_token is not None}"
        )

        if force_refresh or not self._current_token:
            logger.debug("move.tv: No stored token or force_refresh — proceeding to full login")
            return self._full_login()

        token = cast(MoveTVAuthToken, self._current_token)

        if self.validate_token(token):
            return token

        logger.info("move.tv: Stored token failed validation, performing full login")
        return self._full_login()

    def _full_login(self) -> MoveTVAuthToken:
        """Ensure credentials, run the login request, persist the session."""
        if not self._ensure_credentials():
            raise Exception("No valid credentials available for move.tv")

        token = self._perform_authentication()
        self._current_token = token
        self._save_session()
        logger.info("move.tv: Authentication successful")
        return token

    # ------------------------------------------------------------------
    # Public helpers (unchanged interface)
    # ------------------------------------------------------------------

    def get_auth_token(self, force_refresh: bool = False) -> str:
        return self.authenticate(force_refresh).access_token

    def get_session_info(self) -> Optional[Dict[str, Any]]:
        """
        Returns info required for playback.
        Casts the token to MoveTVAuthToken to resolve attribute errors.
        """
        if not self._current_token:
            return None

        t = cast(MoveTVAuthToken, self._current_token)
        return {
            "customer_id": t.customer_id,
            "customer_profile_id": t.customer_profile_id,
            "uid": t.device_id,
            "dedicated_server": t.dedicated_server,
            "auth_token": t.access_token,
        }