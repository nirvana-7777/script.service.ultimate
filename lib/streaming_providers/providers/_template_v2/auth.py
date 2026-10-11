# streaming_providers/providers/example/auth.py
"""
Example authentication -- VARIANT A: the auth class itself satisfies
AuthProtocol (get_access_token / build_headers / invalidate), so managers
receive it directly as their `auth` collaborator.

Use Variant B (optional/session_adapter.py) instead when you already have
a stateful BaseAuthenticator with persisted sessions (see the Allente
provider): the adapter sits in front of it.

Rules (all of them learned the hard way):
  * LAZY: no network call in __init__. The first caller that needs a token
    triggers the login.
  * One login for concurrent callers (lock + re-check after acquiring it).
  * Typed errors, never None/[]: AuthError for credentials problems,
    GeoBlockError for geo blocks, ServerError for everything unexpected.
  * The token travels in a header HERE; if your API wants it in the query
    string or body, add with_token()/auth_body() helpers and keep headers
    token-free (simpli does this).
  * invalidate() must also drop anything persisted, or a restart resurrects
    the old session.
"""

import threading
import time
from typing import Dict, Optional

from ...base.errors import AuthError
from ...base.utils.logger import logger
from ...base.utils.transport import transport_errors
from .constants import ExampleConfig, ExampleDefaults

_PROVIDER = ExampleDefaults.PROVIDER_LABEL


class ExampleAuth:
    def __init__(self, *, http_manager, config: ExampleConfig, credentials=None):
        self._http = http_manager
        self._config = config
        self._credentials = credentials      # object with .username / .password
        self._token: Optional[str] = None
        self._expires_at: float = 0.0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------
    @property
    def has_credentials(self) -> bool:
        c = self._credentials
        return bool(c and getattr(c, "username", None) and getattr(c, "password", None))

    def set_credentials(self, credentials) -> None:
        """Replace the credentials and drop the current session."""
        self._credentials = credentials
        self.invalidate()

    # ------------------------------------------------------------------
    # AuthProtocol
    # ------------------------------------------------------------------
    def get_access_token(self, force_refresh: bool = False) -> str:
        if not force_refresh and self._token_valid():
            return self._token
        with self._lock:
            if not force_refresh and self._token_valid():   # another thread logged in
                return self._token
            self._login()
            return self._token

    def build_headers(self) -> Dict[str, str]:
        """API headers incl. the bearer token (not for CDN requests)."""
        return self._config.api_headers(self.get_access_token())

    def invalidate(self) -> None:
        self._token = None
        self._expires_at = 0.0
        # Variant with persistence: also clear the persisted session here.

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _token_valid(self) -> bool:
        return bool(
            self._token
            and time.time() < self._expires_at - ExampleDefaults.TOKEN_REFRESH_BUFFER_SECONDS
        )

    def _login(self) -> None:
        if not self.has_credentials:
            raise AuthError(
                f"{_PROVIDER}: no credentials configured. "
                f"Set username and password in the addon settings."
            )
        with transport_errors("login", _PROVIDER):
            # TODO: map your HTTP layer's 401/403 to AuthError here (and a
            # geo-block answer to GeoBlockError); transport_errors lets
            # typed errors through and wraps everything else in ServerError.
            resp = self._http.post(
                self._config.url(ExampleDefaults.PATH_LOGIN),
                json={
                    "username": self._credentials.username,
                    "password": self._credentials.password,
                },
                headers=self._config.api_headers(),
                operation="auth",
            )
            data = resp.json()
            self._token = data["accessToken"]
            lifetime = float(data.get("expiresIn") or ExampleDefaults.TOKEN_LIFETIME_SECONDS)
            self._expires_at = time.time() + lifetime
        logger.info(f"{_PROVIDER}: authenticated")
