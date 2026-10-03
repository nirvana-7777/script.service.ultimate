# streaming_providers/providers/_template/auth.py
"""
{TODO: Provider name} authentication.

Implements the three shared Auth methods (get_access_token, build_headers,
invalidate) and any optional extensions the provider needs.

Auth is a protocol, not an ABC. See base/protocols.py for the runtime
shape; see ../_template/README.md for the contract.

Constructor contract (recommended, not enforced):
    __init__(*, http_manager, country, settings_manager=None,
             credentials=None, **provider_opts)

The provider's _build_auth() factory calls this. Extra kwargs are for
provider-specific state (device_id, client_version, platform, ...).
"""

from typing import Any, Dict, Optional

from ...base.utils.logger import logger


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
        **provider_opts,
    ):
        """
        Args:
            http_manager:      Shared HTTPManager instance (owned by provider).
            country:           Two-letter country code.
            settings_manager:  Base settings manager for credential storage.
                               May be None; the auth class must work without it.
            credentials:       Pre-supplied credentials (overrides storage).
            **provider_opts:   Provider-specific state (device_id,
                               client_version, platform, ...). Document what
                               you use; the base ignores everything here.
        """
        self.http_manager = http_manager
        self.country = country
        self.settings_manager = settings_manager
        self._credentials = credentials
        self._cached_token = None
        # TODO: store provider_opts you need, e.g.:
        # self.device_id = provider_opts.get("device_id") or self._load_device_id()

    # ------------------------------------------------------------------
    # The three shared methods -- every provider implements these
    # ------------------------------------------------------------------

    def get_access_token(self, force_refresh: bool = False) -> str:
        """
        Return the raw token string (no scheme prefix).

        If a cached token exists and is not near expiry, return it. Otherwise
        authenticate, cache, and return.
        """
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

        headers = {
            "User-Agent": "TODO: your UA",
            "Accept": "application/json",
            # TODO: pick the auth scheme your provider uses:
            #   MoveTV      "X-Auth-Token": token
            #   Magenta     "Bff_token": token
            #   RTL+        "Authorization": f"Bearer {token}"
            #   HRTi        "authorization": f"Client {token}"
            #   Discovery   "Authorization": f"Bearer {token}" + session headers
            "Authorization": f"Bearer {token}",
        }

        # TODO: add non-auth headers the API requires. Examples:
        #   "X-Device-Id": self.device_id
        #   "X-Client-Version": self.client_version
        #   "Origin": self.config.base_website
        #   "Referer": f"{self.config.base_website}/"
        # Discovery-style session state, Magenta-style guest ids, etc. also
        # go here (built from self._session_state or equivalent).

        return headers

    def invalidate(self) -> None:
        """
        Drop cached token and session state. Called after 401s.

        The next get_access_token() call must perform full re-authentication.
        """
        self._cached_token = None
        self._clear_session()
        # TODO: clear provider-specific session state, e.g.:
        # self._session_state = None
        # self._disco_id = None
        # self._cookies.clear()

    # ------------------------------------------------------------------
    # Provider-specific implementation
    # ------------------------------------------------------------------

    def _perform_authentication(self):
        """
        Do the actual login HTTP call. Return a token object with at least
        access_token, expires_in, and is_expired attributes.

        Return your custom AuthToken subclass if you have one, otherwise
        return a BaseAuthToken.
        """
        # TODO:
        # 1. Ensure credentials (self._credentials, else load from
        #    settings_manager).
        # 2. Build the login payload (from .models.YourCredentials if you
        #    have a custom one, else the plain username/password dict).
        # 3. POST to the login endpoint via self.http_manager.
        # 4. Parse the response into your token class.
        # 5. Return the token.
        raise NotImplementedError(
            "YourProviderAuth._perform_authentication"
        )

    def _save_session(self, token) -> None:
        """
        Persist the token via settings_manager (optional).

        Called after a successful authentication. If settings_manager is
        None (e.g. in unit tests), do nothing.
        """
        if self.settings_manager:
            try:
                self.settings_manager.save_token_data(
                    "TODO: provider_name",
                    token.to_dict(),
                    self.country,
                )
            except Exception as e:
                logger.debug(f"Could not persist token: {e}")

    def _clear_session(self) -> None:
        """Clear any persisted session data."""
        if self.settings_manager:
            try:
                self.settings_manager.clear_token(
                    "TODO: provider_name", self.country
                )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Optional extensions -- uncomment and implement only if needed
    # ------------------------------------------------------------------

    # def get_scoped_token(self, scope: str, **opts) -> Optional[str]:
    #     """
    #     Return a secondary token for the given scope, or None.
    #
    #     RTL+ uses this for "bedrock" and "upfront" tokens. Providers
    #     without secondary tokens should leave this uncommented-out and
    #     returning None, or simply not define it at all (the base protocol
    #     only requires the three shared methods).
    #     """
    #     return None

    # def get_session_context(self) -> Optional[Dict[str, Any]]:
    #     """
    #     Return opaque session state needed by build_headers.
    #
    #     Magenta returns {"device_id": ..., "session_id": ...} from this.
    #     Discovery returns the current session headers. Providers without
    #     session state leave this returning None.
    #     """
    #     return None

    # def authorize_playback(
    #     self, content_id: str, **opts
    # ) -> Dict[str, Any]:
    #     """
    #     Provider-specific pre-playback step.
    #
    #     HRTi's AuthorizeSession, MoveTV's live-source fetch, Discovery's
    #     playbackInfo POST, RTL+'s upfront token, Magenta's persona JWT
    #     retrieval. Return whatever your channel/vod managers need
    #     downstream.
    #
    #     There is no fixed interface for this. The name is a convention;
    #     the shape is provider-specific.
    #     """
    #     return {}