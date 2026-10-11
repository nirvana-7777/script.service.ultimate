# streaming_providers/providers/joyn/session.py
# -*- coding: utf-8 -*-
"""
Auth Variant B — a session adapter in front of the stateful JoynAuthenticator.

    managers --(AuthProtocol)--> JoynSession --> JoynAuthenticator

The managers consume JoynSession through AuthProtocol (get_access_token /
build_headers / invalidate). The raw authenticator stays on the provider for one
reason: ProviderAuthMixin reaches for `self.authenticator.get_bearer_token()`
directly (shared with v1 providers). The managers never touch it.

Error contract
--------------
  ensure()  -> bool, never raises (settings UI, opportunistic pre-login)
  require() -> raises typed errors
  last_error keeps the ORIGINAL exception for the auth-status UI

  * The TYPE of a ProviderError raised by the authenticator is preserved
    (JoynMfaRequiredException -> stays an AuthError, a WAF block stays whatever
    the authenticator made it). Only unexpected, untyped exceptions become
    ServerError. README §9: "the session keeps its type".
  * PERMANENT (MFA, rejected credentials): no retry until reset(). The 7pass
    login is rate-limited and locks accounts on repeated failures.
  * TRANSIENT (network, WAF, 5xx, rate limit): exponential backoff
    BACKOFF_BASE_SECONDS * 2^(n-1), capped at BACKOFF_MAX_SECONDS.

Concurrency: one login for concurrent callers (RLock + re-check).

Invalidation: invalidate() clears the authenticator (memory + persisted), resets
the backoff state and then runs the registered `on_invalidate` callbacks — the
provider uses that to clear its playout / entitlement / VOD caches, which are
account-specific.
"""

import threading
import time
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Tuple, Type

from ...base.errors import AuthError, ProviderError, ServerError
from ...base.utils.logger import logger
from .models import JoynAuthError, JoynMfaRequiredException

if TYPE_CHECKING:  # the session depends on the authenticator's *shape*, not its module
    from .auth import JoynAuthenticator

BACKOFF_BASE_SECONDS = 30
BACKOFF_MAX_SECONDS = 900


class JoynSession:
    # Failures that retrying with the same input cannot fix.
    #   JoynMfaRequiredException — the user must disable MFA.
    #   JoynAuthError            — 7pass rejected the credentials / no auth code.
    PERMANENT_ERRORS: Tuple[Type[Exception], ...] = (
        JoynMfaRequiredException,
        JoynAuthError,
    )

    def __init__(
        self,
        *,
        authenticator: "JoynAuthenticator",
        config,
        clock: Callable[[], float] = time.monotonic,
        on_invalidate: Optional[Callable[[], None]] = None,
    ):
        self.authenticator = authenticator
        self.config = config
        self._clock = clock
        self.last_error: Optional[Exception] = None

        self._failures = 0
        self._retry_at = 0.0
        self._permanent = False
        self._failure_kind: Optional[Tuple[Type[Exception], str]] = None

        self._on_invalidate: List[Callable[[], None]] = []
        if on_invalidate is not None:
            self._on_invalidate.append(on_invalidate)

        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # AuthProtocol
    # ------------------------------------------------------------------

    def get_access_token(self) -> str:
        self.require()
        token = self.authenticator.current_token
        if token is None or token.is_expired:
            # Expired between require() and here (clock edge): one more gate pass.
            self.require()
            token = self.authenticator.current_token
        if token is None:
            raise AuthError("not authenticated")
        return token.access_token

    def build_headers(self) -> Dict[str, str]:
        """ABC default header set (Joyn API headers + bearer). Managers needing
        the CDN / entitlement / DRM sets call JoynConfig directly."""
        return self.config.api_headers(self.get_access_token())

    def invalidate(self) -> None:
        """Clear memory and persisted storage, reset backoff, drop account caches."""
        self.authenticator.invalidate_token()   # memory + persisted
        self.reset()
        for callback in list(self._on_invalidate):
            try:
                callback()
            except Exception as exc:  # a broken cache hook must not block a logout
                logger.warning(f"Joyn: invalidate callback failed: {exc!r}")

    # ------------------------------------------------------------------
    # Gate
    # ------------------------------------------------------------------

    def ensure(self) -> bool:
        """Never raises. True if a usable token exists afterwards."""
        if self._ready():
            return True
        with self._lock:
            if self._ready():
                return True
            if self._permanent:
                return False
            if self._clock() < self._retry_at:
                return False
            return self._login()

    def require(self) -> None:
        """Raises a typed error if no usable token can be produced."""
        if self.ensure():
            return
        kind, message = self._failure_kind or (AuthError, "not authenticated")
        try:
            error = kind(message)
        except TypeError:           # exotic constructor on a provider-specific type
            error = ServerError(message)
        raise error from self.last_error

    def reset(self) -> None:
        """Credentials changed: forget everything, including backoff."""
        with self._lock:
            self.last_error = None
            self._failure_kind = None
            self._permanent = False
            self._failures = 0
            self._retry_at = 0.0

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _ready(self) -> bool:
        token = self.authenticator.current_token
        return token is not None and not token.is_expired

    def _login(self) -> bool:
        # With no stored credentials the authenticator falls back to the anonymous
        # flow: Joyn works without a login (v1 behaviour, preserved).
        try:
            self._fetch_token()
        except Exception as exc:
            permanent = isinstance(exc, self.PERMANENT_ERRORS)
            kind: Type[Exception] = type(exc) if isinstance(exc, ProviderError) else ServerError
            return self._fail(exc, kind, permanent=permanent)

        if not self._ready():
            return self._fail(
                RuntimeError("authenticator returned no usable token"),
                AuthError,
                permanent=False,
            )

        self.last_error = None
        self._failure_kind = None
        self._permanent = False
        self._failures = 0
        self._retry_at = 0.0
        return True

    def _fetch_token(self) -> None:
        """
        Let the authenticator produce a token.

        First WITHOUT force_refresh: a valid persisted token (or a refresh-token
        refresh) must not trigger a full 7pass login at every process start. Only
        if that still leaves no usable token do we force a fresh login.
        """
        self.authenticator.get_bearer_token()
        if not self._ready():
            self.authenticator.get_bearer_token(force_refresh=True)

    def _fail(self, exc: Exception, kind: Type[Exception], *, permanent: bool) -> bool:
        self.last_error = exc
        self._failure_kind = (kind, f"authentication failed — {exc}")
        self._permanent = permanent
        if not permanent:
            self._failures += 1
            delay = min(
                BACKOFF_BASE_SECONDS * 2 ** (self._failures - 1),
                BACKOFF_MAX_SECONDS,
            )
            self._retry_at = self._clock() + delay
        logger.error(self._failure_kind[1])
        return False