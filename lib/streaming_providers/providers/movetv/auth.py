# streaming_providers/providers/movetv/auth.py
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.auth.credentials import UserPasswordCredentials
from ...base.utils.logger import logger
from .constants import MoveTVConfig


# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------

@dataclass
class MoveTVAuthToken(BaseAuthToken):
    """
    Holds all session state returned by the move.tv login endpoint.

    Fields beyond the BaseAuthToken contract:
      - auth_token        raw value of the X-Auth-Token header
      - customer_id       numeric customer identifier
      - customer_profile_id  active profile id (needed in manifest requests)
      - dedicated_server  CDN base URL (e.g. https://edge-mts-si-2.mts-si.tv)
      - device_id         server-assigned device identifier
      - uid               client-generated unique identifier (UUID)
      - widevine_url      Widevine license server URL (from drm_server block)
      - playready_url     PlayReady license server URL (from drm_server block)
    """

    auth_token: str = ""
    customer_id: int = 0
    customer_profile_id: int = 0
    dedicated_server: str = ""
    device_id: int = 0
    uid: str = ""
    widevine_url: str = ""
    playready_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
            "refresh_token": self.refresh_token,
            "refresh_expires_in": self.refresh_expires_in,
            "auth_level": self.auth_level.value,
            # move.tv specifics
            "auth_token": self.auth_token,
            "customer_id": self.customer_id,
            "customer_profile_id": self.customer_profile_id,
            "dedicated_server": self.dedicated_server,
            "device_id": self.device_id,
            "uid": self.uid,
            "widevine_url": self.widevine_url,
            "playready_url": self.playready_url,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MoveTVAuthToken":
        return cls(
            access_token=data.get("access_token", data.get("auth_token", "")),
            token_type=data.get("token_type", "token"),
            expires_in=data.get("expires_in", 86400),
            issued_at=data.get("issued_at", time.time()),
            refresh_token=data.get("refresh_token"),
            refresh_expires_in=data.get("refresh_expires_in", 0),
            auth_level=TokenAuthLevel(
                data.get("auth_level", TokenAuthLevel.USER_AUTHENTICATED.value)
            ),
            auth_token=data.get("auth_token", ""),
            customer_id=data.get("customer_id", 0),
            customer_profile_id=data.get("customer_profile_id", 0),
            dedicated_server=data.get("dedicated_server", ""),
            device_id=data.get("device_id", 0),
            uid=data.get("uid", ""),
            widevine_url=data.get("widevine_url", ""),
            playready_url=data.get("playready_url", ""),
        )


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

class MoveTVAuthenticator(BaseAuthenticator):
    """
    Authenticator for the move.tv / MTS-SI platform.

    Authentication flow
    -------------------
    1.  POST /api/v2/login  with username/password + fixed device constants.
    2.  On success the response carries:
          - auth_token      → used as X-Auth-Token on every subsequent request
          - refresh_token   → used to renew the session without re-entering credentials
          - dedicated_server → CDN base URL; manifest URLs are derived from it
          - customer_id / device_id / profile.id → required for manifest source requests
          - t               → token lifetime in seconds (32400 = 9 hours)
    3.  All of the above is stored on MoveTVAuthToken and persisted via the
        base-class settings_manager.
    """

    def __init__(
            self,
            proxy_config=None,
            http_manager=None,
            settings_manager=None,
            credentials: Optional[UserPasswordCredentials] = None,
            country: Optional[str] = None,
            config_dir: Optional[str] = None,
            enable_kodi_integration: bool = True,
    ):
        super().__init__(
            provider_name="movetv",
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=enable_kodi_integration,
        )
        self._proxy_config = proxy_config
        self._http_manager = http_manager
        self._uid: Optional[str] = None  # Will be loaded from stored token or generated
        self._current_token: Optional[MoveTVAuthToken] = None  # Override type to MoveTVAuthToken

        # Try to load existing token from storage
        self._load_and_restore_token()

    # ------------------------------------------------------------------
    # Token loading and restoration
    # ------------------------------------------------------------------

    def _load_and_restore_token(self) -> bool:
        """
        Load token from storage and restore state.
        Returns True if token was loaded and valid.
        """
        if not self.settings_manager:
            logger.debug("move.tv: No settings manager available for loading token")
            return False

        try:
            # Try to load the token using the base class method
            token_data = self.settings_manager.get_auth_token(self.provider_name)
            if token_data:
                logger.debug(f"move.tv: Found stored token data with keys: {list(token_data.keys())}")

                # Create token from stored data
                token = self._create_token_from_response(token_data)
                self._current_token = token

                # Restore UID from token
                if token.uid:
                    self._uid = token.uid
                    logger.info(f"move.tv: Restored UID from storage: {self._uid}")
                else:
                    logger.debug("move.tv: No UID found in stored token")

                # Check if token is expired
                if token.is_expired:
                    logger.debug(
                        f"move.tv: Stored token is expired (issued at {token.issued_at}, expires in {token.expires_in}s)")
                    self._current_token = None
                    self._uid = None
                    return False
                else:
                    logger.info(f"move.tv: Successfully loaded token from storage (expires in {token.expires_in}s)")
                    return True
            else:
                logger.debug("move.tv: No stored token found")
                return False
        except Exception as e:
            logger.warning(f"move.tv: Failed to load token from storage: {e}")
            return False

    # ------------------------------------------------------------------
    # UID management
    # ------------------------------------------------------------------

    def _get_or_generate_uid(self) -> str:
        """
        Get existing UID from stored token or generate a new UUID.
        The UID is persisted across sessions via the token storage.
        """
        if self._uid:
            logger.debug(f"move.tv: Using existing UID: {self._uid}")
            return self._uid

        # Try to load from current token if available (should have been restored already)
        if self._current_token and self._current_token.uid:
            self._uid = self._current_token.uid
            logger.debug(f"move.tv: Loaded UID from current token: {self._uid}")
            return self._uid

        # Generate new UUID as last resort
        self._uid = str(uuid.uuid4())
        logger.debug(f"move.tv: Generated new UID: {self._uid}")
        return self._uid

    # ------------------------------------------------------------------
    # BaseAuthenticator abstract contract
    # ------------------------------------------------------------------

    @property
    def auth_endpoint(self) -> str:
        return MoveTVConfig.login_url()

    def _get_auth_headers(self) -> dict:
        """Headers for the login request (X-Auth-Token: null sentinel)."""
        return MoveTVConfig.get_base_headers(auth_token=None)

    def _build_auth_payload(self) -> dict:
        """
        Build the login POST body.

        Called by the base class only when credentials are already validated,
        so self.credentials is safe to access here.
        """
        uid = self._get_or_generate_uid()
        payload = {
            "username": self.credentials.username,
            "password": self.credentials.password,
            "partnerId": MoveTVConfig.PARTNER_ID,
            "deviceName": MoveTVConfig.DEVICE_NAME,
            "deviceModelId": MoveTVConfig.DEVICE_MODEL_ID,
            "uid": uid,
            "appVersion": MoveTVConfig.APP_VERSION,
        }

        # Log payload with password redacted
        safe_payload = payload.copy()
        safe_payload["password"] = "***REDACTED***"
        logger.debug(f"move.tv: Login payload: {safe_payload}")

        return payload

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """move.tv only issues user-authenticated tokens."""
        return TokenAuthLevel.USER_AUTHENTICATED

    def get_fallback_credentials(self):
        """move.tv has no anonymous / client-credentials fallback."""
        return None

    def has_user_credentials(self) -> bool:
        return (
                isinstance(self.credentials, UserPasswordCredentials)
                and self.credentials.validate()
        )

    def get_current_token_level(self) -> TokenAuthLevel:
        if self._current_token:
            return self._current_token.auth_level
        return TokenAuthLevel.UNKNOWN

    # ------------------------------------------------------------------
    # Token persistence helpers
    # ------------------------------------------------------------------

    def _create_token_from_response(self, data: Dict[str, Any]) -> MoveTVAuthToken:
        """Reconstruct a MoveTVAuthToken from persisted dict data."""
        return MoveTVAuthToken.from_dict(data)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self, force_refresh: bool = False) -> MoveTVAuthToken:
        """
        Override authenticate to ensure we check for existing valid token first.
        """
        # If we have a valid token and not forcing refresh, return it
        if not force_refresh and self._current_token and not self._current_token.is_expired:
            logger.debug("move.tv: Using existing valid token")
            return self._current_token

        # If we have a token but it's expired, try to refresh
        if self._current_token and self._current_token.is_expired:
            logger.debug("move.tv: Token expired, attempting refresh")
            refreshed = self._refresh_token()
            if refreshed:
                return refreshed

        # Otherwise perform full authentication
        logger.info("move.tv: Performing new authentication")
        token = self._perform_authentication()
        self._current_token = token
        return token

    def _perform_authentication(self) -> MoveTVAuthToken:
        """
        Full username / password login against /api/v2/login.
        Delegates payload and header construction to the abstract helpers so
        the base class can call them consistently.
        """
        if not self.credentials or not self.credentials.validate():
            raise ValueError("move.tv: No valid credentials available for authentication")

        payload = self._build_auth_payload()
        headers = self._get_auth_headers()

        logger.debug(f"move.tv: POST {self.auth_endpoint}")
        logger.debug(f"move.tv: Request headers: {headers}")

        # Log payload with password redacted
        safe_payload = payload.copy()
        safe_payload["password"] = "***REDACTED***"
        logger.debug(f"move.tv: Request payload: {safe_payload}")

        response = self._http_manager.post(
            self.auth_endpoint,
            operation="auth",
            json=payload,
            headers=headers,
        )

        logger.debug(f"move.tv: Response status: {response.status_code}")
        logger.debug(f"move.tv: Response headers: {dict(response.headers)}")

        response.raise_for_status()
        data = response.json()

        # Log response summary
        if data.get("success"):
            logger.info(f"move.tv: Login successful - customer_id={data.get('customer_id')}, "
                        f"device_id={data.get('device_id')}, "
                        f"uid={data.get('uid')}, "
                        f"token_expiry={data.get('t')}s")
        else:
            logger.warning(f"move.tv: Login failed - {data}")

        if not data.get("success"):
            raise ValueError(f"move.tv: Login failed – API returned success=false: {data}")

        token = self._parse_login_response(data)

        # Store the UID from the response
        self._uid = token.uid

        # Persist the token
        if self.settings_manager:
            try:
                self.settings_manager.save_auth_token(self.provider_name, token.to_dict())
                logger.debug("move.tv: Token saved to storage")
            except Exception as e:
                logger.warning(f"move.tv: Failed to save token to storage: {e}")

        return token

    def _refresh_token(self) -> Optional[MoveTVAuthToken]:
        """
        The MTS-SI API does not expose a dedicated token-refresh endpoint in
        the captured traffic.  We fall back to a full re-authentication using
        the stored credentials.  If credentials are unavailable (e.g. the
        refresh_token value can be used in a future update), None is returned
        and the base class will trigger _perform_authentication().
        """
        if not self.has_user_credentials():
            logger.debug("move.tv: No credentials available for token refresh")
            return None

        logger.info("move.tv: Refreshing session via full re-authentication")
        try:
            return self._perform_authentication()
        except Exception as e:
            logger.warning(f"move.tv: Re-authentication during refresh failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_login_response(data: Dict[str, Any]) -> MoveTVAuthToken:
        """
        Map the raw /api/v2/login JSON response onto a MoveTVAuthToken.

        The API returns token lifetime in the 't' field (in seconds).
        If not present, defaults to 32400 (9 hours) based on observed responses.
        """
        auth_token: str = data.get("auth_token", "")
        refresh_token: str = data.get("refresh_token", "")
        customer_id: int = data.get("customer_id", 0)
        device_id: int = data.get("device_id", 0)
        dedicated_server: str = data.get("dedicated_server", "")
        uid: str = data.get("uid", "")

        # Get token expiry from 't' field (in seconds)
        token_expiry: int = data.get("t", 32400)  # Default to 9 hours if not present

        profile: Dict = data.get("profile", {})
        customer_profile_id: int = profile.get("id", 0)

        drm_server: Dict = data.get("drm_server", {})
        widevine_url: str = drm_server.get("widevine", "")
        playready_url: str = drm_server.get("playready", "")

        logger.debug(
            f"move.tv: Parsing login response - customer_id={customer_id}, "
            f"device_id={device_id}, uid={uid}, dedicated_server={dedicated_server}, "
            f"token_expires_in={token_expiry}s"
        )

        return MoveTVAuthToken(
            # BaseAuthToken fields
            access_token=auth_token,  # used as bearer / X-Auth-Token
            token_type="token",
            expires_in=token_expiry,  # Use actual token lifetime from API
            issued_at=time.time(),
            refresh_token=refresh_token if refresh_token else None,
            refresh_expires_in=0,
            auth_level=TokenAuthLevel.USER_AUTHENTICATED,
            credential_type="user_password",
            # move.tv specifics
            auth_token=auth_token,
            customer_id=customer_id,
            customer_profile_id=customer_profile_id,
            dedicated_server=dedicated_server,
            device_id=device_id,
            uid=uid,
            widevine_url=widevine_url,
            playready_url=playready_url,
        )

    # ------------------------------------------------------------------
    # Accessors used by the provider
    # ------------------------------------------------------------------

    def get_auth_token(self, force_refresh: bool = False) -> str:
        """
        Return the raw X-Auth-Token string (not a Bearer prefix).
        Authenticates if no valid token is held.
        """
        token = self.authenticate(force_refresh=force_refresh)
        return token.auth_token

    def get_session_info(self) -> Optional[Dict[str, Any]]:
        """
        Return the session identifiers needed for manifest source requests.
        Returns None when not authenticated.
        """
        if not self._current_token or self._current_token.is_expired:
            return None
        return {
            "customer_id": self._current_token.customer_id,
            "customer_profile_id": self._current_token.customer_profile_id,
            "device_id": self._current_token.device_id,
            "uid": self._current_token.uid,
            "dedicated_server": self._current_token.dedicated_server,
            "auth_token": self._current_token.auth_token,
        }