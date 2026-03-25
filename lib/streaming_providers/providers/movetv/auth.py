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
                          NOTE: the UID identifies a device slot on the platform
                          and must be preserved independently of session/token
                          lifetime.  Never clear it on token expiry or invalidation.
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
        base-class _save_session() → save_token_data() path.

    UID / device-slot lifecycle
    ---------------------------
    The UID is a client-generated UUID that represents this client's registered
    device slot on the platform.  It is NOT a session credential — its lifecycle
    is completely independent of the auth token's expiry or invalidation.  The
    platform enforces a maximum number of concurrent device slots per account
    (appCode 403007 = "No slots available").  Generating a new UID on every
    re-auth would consume an additional slot (or fail if the limit is reached).
    Therefore:
      - _uid is declared before super().__init__() and seeded from
        self._current_token immediately after super().__init__() returns.
        The base class __init__ calls _load_session() → load_token_data() →
        _create_token_from_response(), which populates self._current_token
        with the persisted MoveTVAuthToken (uid included) before any login
        attempt can reach _get_or_generate_uid().
      - Expiring or invalidating the auth token must never clear _uid.
      - A new UUID is only generated on the very first run (no prior session).
    """

    # Redeclare with the concrete subtype so all attribute access is type-safe.
    _current_token: Optional[MoveTVAuthToken]

    # appCode returned by the API when the device-slot limit is reached.
    _APPCODE_NO_SLOTS = "403007"

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
        # Declare _uid before super().__init__() in case any base-class code
        # path references it during initialisation.
        self._uid: Optional[str] = None
        self._proxy_config = proxy_config
        self._http_manager = http_manager

        # super().__init__() calls _load_session() → load_token_data() →
        # _create_token_from_response(), populating self._current_token with
        # the previously persisted MoveTVAuthToken (uid field included).
        super().__init__(
            provider_name="movetv",
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=enable_kodi_integration,
        )

        # Seed _uid from the token the base class just loaded.  This must
        # happen before any call that could trigger _get_or_generate_uid()
        # (i.e. before the first login attempt).  We extract the UID even
        # from an expired token — the UID outlives the session.
        if isinstance(self._current_token, MoveTVAuthToken) and self._current_token.uid:
            self._uid = self._current_token.uid
            logger.info(f"move.tv: Restored UID from persisted session: {self._uid}")

    # ------------------------------------------------------------------
    # UID management
    # ------------------------------------------------------------------

    def _get_or_generate_uid(self) -> str:
        """
        Return the persisted UID, or generate a new UUID on very first run.

        By the time this is called (from _build_auth_payload during login),
        __init__ has already seeded self._uid from the stored token via the
        base class _load_session() path.  A fresh UUID is only created when
        absolutely no prior session exists for this provider.
        """
        if self._uid:
            logger.debug(f"move.tv: Using existing UID: {self._uid}")
            return self._uid

        # True first run — no persisted session at all.
        self._uid = str(uuid.uuid4())
        logger.debug(f"move.tv: Generated new UID (first run): {self._uid}")
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
    # Token invalidation — UID must be preserved
    # ------------------------------------------------------------------

    def invalidate_token(self) -> None:
        """
        Override base-class token invalidation to preserve the UID.

        The base class wipes all stored state when a token is invalidated
        (e.g. after an HTTP error).  That is correct for the session token,
        but must never apply to the UID, which represents a registered device
        slot.  Clearing the UID would cause the next login to register a new
        device slot, potentially hitting the platform's concurrent-slot limit
        (appCode 403007).
        """
        uid_to_preserve = self._uid
        super().invalidate_token()
        # Restore UID that super() may have wiped via storage/state reset.
        self._uid = uid_to_preserve
        logger.debug(f"move.tv: Token invalidated — UID preserved: {self._uid}")

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self, force_refresh: bool = False) -> MoveTVAuthToken:
        """
        Override authenticate to ensure we check for existing valid token first.
        """
        if not force_refresh and self._current_token and not self._current_token.is_expired:
            logger.debug("move.tv: Using existing valid token")
            return self._current_token

        if self._current_token and self._current_token.is_expired:
            logger.debug("move.tv: Token expired, attempting refresh")
            refreshed = self._refresh_token()
            if refreshed:
                return refreshed

        logger.info("move.tv: Performing new authentication")
        token = self._perform_authentication()
        self._current_token = token
        return token

    def _perform_authentication(self) -> MoveTVAuthToken:
        """
        Full username / password login against /api/v2/login.

        Error handling
        --------------
        HTTP 406 with appCode 403007 ("No slots available") is treated as a
        distinct, non-fatal condition: it does NOT represent a bad credential
        or a bad token, so we raise a specific RuntimeError without touching
        the UID or triggering the base-class token-invalidation path.
        """
        if not self.credentials or not self.credentials.validate():
            raise ValueError("move.tv: No valid credentials available for authentication")

        payload = self._build_auth_payload()
        headers = self._get_auth_headers()

        logger.debug(f"move.tv: POST {self.auth_endpoint}")
        logger.debug(f"move.tv: Request headers: {headers}")

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

        # Parse the body before raise_for_status() so we can inspect appCode
        # and avoid mis-classifying a slot-limit error as an auth failure.
        data: Dict[str, Any] = {}
        if response.content:
            try:
                data = response.json()
            except ValueError:
                pass

        # "No slots available" — the UID / device slot is still valid.
        # Do NOT call raise_for_status() here; that would trigger the base
        # class's generic token-invalidation path and wipe the UID.
        if not response.ok and data.get("appCode") == self._APPCODE_NO_SLOTS:
            logger.error(
                f"move.tv: Device slot limit reached (appCode {self._APPCODE_NO_SLOTS}). "
                f"UID {self._uid!r} is retained. "
                "To resolve: log out another device from your move.tv account, then retry."
            )
            raise RuntimeError(
                "move.tv: No device slots available (appCode 403007). "
                "Log out another device from your account and retry."
            )

        response.raise_for_status()

        if data.get("success"):
            logger.info(
                f"move.tv: Login successful - customer_id={data.get('customer_id')}, "
                f"device_id={data.get('device_id')}, "
                f"uid={data.get('uid')}, "
                f"token_expiry={data.get('t')}s"
            )
        else:
            logger.warning(f"move.tv: Login failed - {data}")

        if not data.get("success"):
            raise ValueError(f"move.tv: Login failed – API returned success=false: {data}")

        token = self._parse_login_response(data)

        # Store the UID from the response and persist via base class path.
        self._uid = token.uid
        self._current_token = token
        self._save_session()

        return token

    def _refresh_token(self) -> Optional[MoveTVAuthToken]:
        """
        The MTS-SI API does not expose a dedicated token-refresh endpoint in
        the captured traffic.  We fall back to a full re-authentication using
        the stored credentials.  Returns None if credentials are unavailable.
        """
        if not self.has_user_credentials():
            logger.debug("move.tv: No credentials available for token refresh")
            return None

        logger.info("move.tv: Refreshing session via full re-authentication")
        try:
            return self._perform_authentication()
        except (ValueError, RuntimeError, OSError) as e:
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
        token_expiry: int = data.get("t", 32400)

        profile: Dict[str, Any] = data.get("profile", {})
        customer_profile_id: int = profile.get("id", 0)

        drm_server: Dict[str, Any] = data.get("drm_server", {})
        widevine_url: str = drm_server.get("widevine", "")
        playready_url: str = drm_server.get("playready", "")

        logger.debug(
            f"move.tv: Parsing login response - customer_id={customer_id}, "
            f"device_id={device_id}, uid={uid}, dedicated_server={dedicated_server}, "
            f"token_expires_in={token_expiry}s"
        )

        return MoveTVAuthToken(
            access_token=auth_token,
            token_type="token",
            expires_in=token_expiry,
            issued_at=time.time(),
            refresh_token=refresh_token if refresh_token else None,
            refresh_expires_in=0,
            auth_level=TokenAuthLevel.USER_AUTHENTICATED,
            credential_type="user_password",
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