# streaming_providers/providers/_template/auth.py
"""
{TODO: Provider name} authentication.

Implements the three shared Auth methods (get_access_token, build_headers,
invalidate), the credential surface (has_credentials, set_credentials,
clear_credentials), and any optional extensions the provider needs.

Auth is a protocol, not an ABC. See base/protocols.py for the runtime
shape; see ../_template/README.md ("The Auth protocol") for the contract.

Constructor contract (recommended, not enforced):
    __init__(*, http_manager, country, settings_manager=None,
             credentials=None, **provider_opts)

Credentials source priority (README, "Credentials"):
    1. constructor argument (CLI, tests)
    2. injected settings_manager (may be None -- the registry usually
       constructs providers WITHOUT one)
    3. CredentialManager (direct credentials.json read) -- the path that
       actually works in the normal runtime
    4. fallback credentials (anonymous/free tier), if any
Credentials are re-read on every authenticate, so a user who stores them
after the provider was constructed does not need an app restart.

Deviations to document HERE (module docstring) if your provider has them:
  * Token NOT in a header (query param / body field): build_headers()
    returns base headers only; callers attach the token via
    with_token(url, param=...) / auth_body(). Put the param names in
    constants.py (they can differ per endpoint) and add a one-line
    comment at every manager call site that uses build_headers().
  * Content-Type quirks (e.g. a login endpoint that needs text/plain with
    a JSON body): send data=json.dumps(payload) with the header set for
    THAT call only, and comment why, or someone will "fix" it.

Thread safety: the host is multi-threaded. get_access_token() and the
other stateful accessors hold an RLock so two threads on a cold cache do
not run the (multi-step) login twice. Providers whose login is a single
HTTP call can drop the lock.
"""

import threading
from typing import Any, Dict, Optional

from ...base.auth.credential_manager import CredentialManager
from ...base.auth.credentials import UserPasswordCredentials
from ...base.errors import CredentialsError
from ...base.utils.logger import logger

from .constants import YourDefaults
from .models import YourAuthToken


class YourProviderAuth:
    """
    Authenticator for {TODO: provider name}.

    Not a subclass of any base class -- matches AuthProtocol by shape.
    """

    def __init__(
        self,
        *,
        http_manager,
        country: str,
        settings_manager=None,
        credentials=None,
        config=None,
        **provider_opts,
    ):
        """
        Args:
            http_manager:      Shared HTTPManager instance (owned by provider).
            country:           Two-letter country code.
            settings_manager:  Base settings manager. May be None; the auth
                               class must work without it.
            credentials:       Pre-supplied credentials (source #1).
            config:            The provider's YourConfig (URLs, base headers).
            **provider_opts:   Provider-specific state (device_id,
                               client_version, platform, ...). Document what
                               you use; the base ignores everything here.
        """
        self.http_manager = http_manager
        self.country = country
        self.settings_manager = settings_manager
        self.config = config
        self._credentials = credentials
        self._lock = threading.RLock()
        # TODO: store provider_opts you need, e.g.:
        # self.device_id = provider_opts.get("device_id") or self._load_device_id()

        # Optional persistence: restore a stored token (no network I/O).
        self._cached_token = self._load_session()

    # ------------------------------------------------------------------
    # The three shared methods -- every provider implements these
    # ------------------------------------------------------------------

    def get_access_token(self, force_refresh: bool = False) -> str:
        """
        Return the raw token string (no scheme prefix).

        If a cached token exists and is not near expiry, return it.
        Otherwise authenticate, cache, and return.
        """
        with self._lock:
            if (
                not force_refresh
                and self._cached_token
                and not self._cached_token.is_expired
            ):
                return self._cached_token.access_token

            token = self._perform_authentication()
            self._cached_token = token
            self._save_session(token)
            return token.access_token

    def build_headers(
        self, token: Optional[str] = None, **opts
    ) -> Dict[str, str]:
        """
        Return request-ready headers.

        If token is None, fetch it via get_access_token(). Providers add
        their own non-auth headers (device id, client version, session
        state, origin, referer) here.
        """
        if token is None:
            token = self.get_access_token()

        headers = (
            self.config.get_base_headers()
            if self.config is not None
            else {"Accept": "application/json"}
        )

        # TODO: pick the auth scheme your provider uses:
        #   MoveTV      "X-Auth-Token": token
        #   Magenta     "Bff_token": token
        #   RTL+        "Authorization": f"Bearer {token}"
        #   HRTi        "authorization": f"Client {token}"
        #   Discovery   "Authorization": f"Bearer {token}" + session headers
        headers["Authorization"] = f"Bearer {token}"

        # TODO: add non-auth headers the API requires. Examples:
        #   "X-Device-Id": self.device_id
        #   "X-Client-Version": self.client_version
        #   "Origin": ..., "Referer": ...
        # Discovery-style session state, Magenta-style guest ids, etc. also
        # go here.

        return headers

    def invalidate(self) -> None:
        """
        Drop cached token and session state. Called after 401s.

        The next get_access_token() call must perform full
        re-authentication. Callers: on a 401, call invalidate() and retry
        the request once -- never in a loop.
        """
        with self._lock:
            self._cached_token = None
            self._clear_session()
            # TODO: clear provider-specific session state, e.g.:
            # self._session_state = None
            # self._cookies.clear()

    # ------------------------------------------------------------------
    # Credential surface (providers with user credentials)
    #
    # Providers WITHOUT user credentials: has_credentials() returns True,
    # set_/clear_credentials() are no-ops returning False, and
    # _ensure_credentials() is not needed in _perform_authentication().
    # ------------------------------------------------------------------

    def has_credentials(self) -> bool:
        """True if this auth can authenticate right now."""
        if self._credentials and self._credentials.validate():
            return True
        fresh = self._load_stored_credentials()
        if fresh and fresh.validate():
            return True
        fallback = self.get_fallback_credentials()
        return bool(fallback and fallback.validate())

    def set_credentials(self, username: str, password: str) -> bool:
        """Persist credentials (called by the settings UI)."""
        if not self.settings_manager:
            return False
        try:
            self.settings_manager.save_provider_credentials(
                YourDefaults.PROVIDER_NAME,
                UserPasswordCredentials(username, password),
                self.country,
            )
        except Exception as e:
            logger.warning(f"Could not store credentials: {e}")
            return False
        with self._lock:
            self._credentials = None   # force a re-read on next login
            self.invalidate()
        return True

    def clear_credentials(self) -> bool:
        """Clear stored credentials and drop the cached token."""
        try:
            if self.settings_manager:
                self.settings_manager.clear_provider_credentials(
                    YourDefaults.PROVIDER_NAME, self.country
                )
            else:
                CredentialManager().delete_credentials(
                    YourDefaults.PROVIDER_NAME, self.country
                )
        except Exception as e:
            logger.warning(f"Could not clear credentials: {e}")
            return False
        with self._lock:
            self._credentials = None
            self.invalidate()
        return True

    def get_fallback_credentials(self):
        """
        Credentials for an anonymous / limited free tier, or None.

        Override for providers that work without user configuration.
        """
        return None

    def _load_stored_credentials(self):
        """Sources #2 and #3: settings_manager first, then CredentialManager."""
        if self.settings_manager and hasattr(
            self.settings_manager, "get_provider_credentials"
        ):
            try:
                creds = self.settings_manager.get_provider_credentials(
                    YourDefaults.PROVIDER_NAME, self.country
                )
                if creds:
                    return creds
            except Exception as e:
                logger.debug(f"settings_manager credentials failed: {e}")
        try:
            # Covers both the country-nested and flat storage layouts.
            return CredentialManager().load_credentials(
                YourDefaults.PROVIDER_NAME, self.country
            )
        except Exception as e:
            logger.debug(f"CredentialManager load failed: {e}")
            return None

    def _ensure_credentials(self) -> bool:
        """
        Make self._credentials valid, re-reading storage if needed.

        Call at the START of _perform_authentication(). Without it the
        auth class silently depends on the caller having passed
        credentials at construction -- which the registry never does.
        """
        if self._credentials and self._credentials.validate():
            return True
        fresh = self._load_stored_credentials()
        if fresh and fresh.validate():
            self._credentials = fresh
            return True
        self._credentials = self.get_fallback_credentials()
        return self._credentials is not None and self._credentials.validate()

    # ------------------------------------------------------------------
    # Provider-specific implementation
    # ------------------------------------------------------------------

    def _perform_authentication(self) -> YourAuthToken:
        """
        Do the actual login HTTP call and return a YourAuthToken.

        (A concrete AuthToken subclass is mandatory: BaseAuthToken is an
        ABC. See models.py.)
        """
        if not self._ensure_credentials():
            raise CredentialsError(
                f"no credentials available for {YourDefaults.PROVIDER_NAME}"
            )
        payload = self._build_login_payload(self._credentials)
        resp = self.http_manager.post(
            self._login_url(), json=payload, headers=self._login_headers()
        )
        return self._create_token_from_response(resp.json())

    def _login_url(self) -> str:
        return self.config.login_url()

    def _login_headers(self) -> Dict[str, str]:
        # Base headers only: build_headers() would try to fetch a token.
        return self.config.get_base_headers()

    def _build_login_payload(self, credentials) -> Dict[str, Any]:
        # Custom credentials classes provide to_auth_payload().
        # TODO: adapt to your provider's login payload.
        return {
            "username": credentials.username,
            "password": credentials.password,
        }

    def _create_token_from_response(self, data: Dict[str, Any]) -> YourAuthToken:
        # TODO: parse the login response. Check base/auth/base_auth.py for
        # any additional required BaseAuthToken fields.
        raise NotImplementedError(
            "YourProviderAuth._create_token_from_response"
        )

    # ------------------------------------------------------------------
    # Session persistence (OPTIONAL)
    #
    # Skip it for providers with cheap re-auth (opaque token, no refresh
    # flow -- simpliTV does). Keep it for expensive flows (multi-step,
    # rate-limited, device codes). If you skip it, delete _load_session /
    # _save_session / _clear_session and the call in __init__.
    # ------------------------------------------------------------------

    def _load_session(self) -> Optional[YourAuthToken]:
        if not self.settings_manager:
            return None
        try:
            stored = self.settings_manager.load_token_data(
                YourDefaults.PROVIDER_NAME, self.country
            )
            return YourAuthToken.from_dict(stored) if stored else None
        except Exception as e:
            logger.debug(f"Could not restore stored token: {e}")
            return None

    def _save_session(self, token) -> None:
        if not self.settings_manager:
            return
        try:
            self.settings_manager.save_token_data(
                YourDefaults.PROVIDER_NAME, token.to_dict(), self.country
            )
        except Exception as e:
            logger.debug(f"Could not persist token: {e}")

    def _clear_session(self) -> None:
        if not self.settings_manager:
            return
        try:
            self.settings_manager.clear_token(
                YourDefaults.PROVIDER_NAME, self.country
            )
        except Exception as e:
            logger.debug(f"Could not clear stored token: {e}")

    # ------------------------------------------------------------------
    # Optional extensions -- uncomment and implement only if needed
    # ------------------------------------------------------------------

    # def get_scoped_token(self, scope: str, **opts) -> Optional[str]:
    #     """Secondary token for the given scope (RTL+: bedrock / upfront)."""
    #     return None

    # def get_session_context(self) -> Optional[Dict[str, Any]]:
    #     """
    #     Opaque session state needed by build_headers. Magenta returns
    #     {"device_id": ..., "session_id": ...}; Discovery the current
    #     session headers.
    #     """
    #     return None

    # def authorize_playback(
    #     self, content_id: str, **opts
    # ) -> Dict[str, Any]:
    #     """
    #     Provider-specific pre-playback step (HRTi AuthorizeSession,
    #     MoveTV live-source fetch, Discovery playbackInfo POST, RTL+
    #     upfront token, Magenta persona JWT). No fixed interface; the
    #     name is a convention, the shape is provider-specific.
    #     """
    #     return {}

    # def with_token(self, url: str, param: Optional[str] = None) -> str:
    #     """Token-in-URL providers: append the token. Take the parameter
    #     name from constants.py (YourDefaults.TOKEN_PARAM), never hardcode."""
    #     ...