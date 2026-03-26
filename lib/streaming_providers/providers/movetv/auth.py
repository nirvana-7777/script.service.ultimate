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
            "access_token": self.access_token,
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
    # Abstract property required by BaseAuthenticator
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "movetv"

    # ------------------------------------------------------------------
    # Abstract properties / methods required by BaseAuthenticator
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

        return MoveTVAuthToken(
            access_token=response_data.get("access_token") or response_data.get("auth_token", ""),
            token_type=response_data.get("token_type", "token"),
            expires_in=int(response_data.get("expires_in", response_data.get("t", 32400))),
            issued_at=float(response_data.get("issued_at", time.time())),
            auth_level=auth_level,
            customer_id=response_data.get("customer_id", 0),
            customer_profile_id=response_data.get("customer_profile_id")
                or profile.get("id", 0),
            dedicated_server=response_data.get("dedicated_server", ""),
            uid=uid,
            device_id=uid,
        )

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
    # Public helpers (unchanged interface)
    # ------------------------------------------------------------------

    def get_auth_token(self, force_refresh: bool = False) -> str:
        return self.authenticate(force_refresh).access_token

    def get_session_info(self) -> Optional[Dict[str, Any]]:
        """
        Returns info required for playback.
        Casts the token to MoveTVAuthToken to resolve attribute errors.
        """
        if not self._current_token or self._current_token.is_expired:
            return None

        t = cast(MoveTVAuthToken, self._current_token)
        return {
            "customer_id": t.customer_id,
            "customer_profile_id": t.customer_profile_id,
            "uid": t.device_id,
            "dedicated_server": t.dedicated_server,
            "auth_token": t.access_token,
        }