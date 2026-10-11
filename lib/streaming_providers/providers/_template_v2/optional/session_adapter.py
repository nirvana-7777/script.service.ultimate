# streaming_providers/providers/example/session.py
"""
AUTH VARIANT B -- an AuthProtocol adapter in front of a stateful
authenticator (a BaseAuthenticator with persisted sessions, multi-step login,
profiles ...). Worked example: providers/allente/session.py.

    managers --(AuthProtocol)--> Session --> YourAuthenticator

Use it when the login is a flow you do not want to rewrite. The session owns
the auth-derived state (token, entitlement, profile, last error) and gives the
managers three things: get_access_token(), build_headers(), invalidate().

Error contract
  ensure()  -> bool, NEVER raises (opportunistic pre-login, settings UI)
  require() -> raises typed errors (AuthError / GeoBlockError / ServerError)
  last_error keeps the ORIGINAL exception (the auth-status UI shows its type)

Retry policy (the part the Allente constants describe but the provider never
implemented -- every failing call retried a full login):
  * PERMANENT failure (PERMANENT_ERRORS: wrong credentials, OTP, unsupported
    account) -> no retry until the credentials change (reset()).
  * TRANSIENT failure (network, 5xx, WAF) -> exponential backoff
    base * 2^(n-1) seconds, capped. Hammering an SSO risks lockout / WAF bans.

Concurrency: one login for concurrent callers (RLock + re-check).

--- WIRING ---
(in provider.__init__, instead of ExampleAuth:)
    self.authenticator = YourAuthenticator(config=self.provider_config,
                                           http_manager=self.http_manager)
    self.session = ExampleSession(authenticator=self.authenticator,
                                  config=self.provider_config)
(and pass auth=self.session to the managers)
--- END WIRING ---
"""

import threading
import time
from typing import Callable, Dict, Optional, Tuple, Type

from ....base.errors import AuthError, ProviderError, ServerError
from ....base.utils.logger import logger

BACKOFF_BASE_SECONDS = 30
BACKOFF_MAX_SECONDS = 900


class ExampleSession:
    PERMANENT_ERRORS: Tuple[Type[Exception], ...] = ()   # e.g. (YourAuthError,)

    def __init__(self, *, authenticator, config, clock: Callable[[], float] = time.monotonic):
        self.authenticator = authenticator
        self.config = config
        self._clock = clock
        self.access_token: Optional[str] = None
        self.last_error: Optional[Exception] = None
        self._failure: Optional[Tuple[Type[ProviderError], str]] = None
        self._permanent = False
        self._failures = 0
        self._retry_at = 0.0
        self._lock = threading.RLock()

    # ---- state ---------------------------------------------------------
    def reset(self) -> None:
        """Credentials changed: forget everything, including the backoff."""
        self.access_token = None
        self.last_error = None
        self._failure = None
        self._permanent = False
        self._failures = 0
        self._retry_at = 0.0

    def _ready(self) -> bool:
        token = self.authenticator.current_token
        return bool(self.access_token and token is not None and not token.is_expired)

    # ---- gate ----------------------------------------------------------
    def ensure(self) -> bool:
        if self._ready():
            return True
        with self._lock:
            if self._ready():
                return True
            if self._permanent:
                return False                      # until reset()
            if self._clock() < self._retry_at:
                return False                      # still backing off
            return self._login()

    def require(self) -> None:
        if self.ensure():
            return
        kind, message = self._failure or (AuthError, "not authenticated")
        raise kind(message) from self.last_error

    def _login(self) -> bool:
        if not self.authenticator.has_user_credentials():
            return self._fail(RuntimeError("no credentials configured"), AuthError,
                              permanent=True)
        try:
            token = self.authenticator.authenticate()
            if token is None:
                return self._fail(RuntimeError("authentication returned no token"), AuthError)
            self.access_token = token.access_token
            self.last_error, self._failure = None, None
            self._failures, self._retry_at = 0, 0.0
            return True
        except self.PERMANENT_ERRORS as exc:
            return self._fail(exc, AuthError, permanent=True)
        except Exception as exc:
            return self._fail(exc, ServerError)

    def _fail(self, exc: Exception, kind: Type[ProviderError], *, permanent: bool = False) -> bool:
        self.last_error = exc
        self._failure = (kind, f"authentication failed — {exc}")
        self._permanent = permanent
        if not permanent:
            self._failures += 1
            delay = min(BACKOFF_BASE_SECONDS * 2 ** (self._failures - 1), BACKOFF_MAX_SECONDS)
            self._retry_at = self._clock() + delay
        logger.error(self._failure[1])
        return False

    # ---- AuthProtocol --------------------------------------------------
    def get_access_token(self) -> str:
        self.require()
        return self.access_token  # type: ignore[return-value]

    def build_headers(self) -> Dict[str, str]:
        self.require()
        return self.config.api_headers(self.access_token)

    def invalidate(self) -> None:
        self.authenticator.invalidate_token()   # memory AND persisted storage
        self.reset()
