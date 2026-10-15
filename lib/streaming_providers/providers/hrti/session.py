# streaming_providers/providers/hrti/session.py
"""
HRTiSession -- VARIANT B auth adapter in front of the stateful HRTiAuthenticator.

Managers see ``auth`` (= this session) satisfying AuthProtocol
(get_access_token / build_headers / invalidate) plus the auth-derived state
they need (device_id, ip_address, user_id) and the two session calls of the
playback flow (authorize_session, report_session_event). They never touch the
raw authenticator. The provider keeps BOTH objects (``self.authenticator``
for the legacy auth mixin, ``self.auth`` for the managers).

Behaviour
---------
* LAZY: nothing here makes a network call at construction.
* ``get_access_token`` / ``require`` raise typed errors; ``ensure`` never
  raises (opportunistic pre-login, settings UI); ``last_error`` keeps the
  ORIGINAL exception.
* Retry policy: PERMANENT failures (AuthError incl. CredentialsError,
  ConfigurationError) are not retried until ``reset()`` / ``invalidate()``;
  TRANSIENT ones (network, 5xx, rate limit, anything untyped -> ServerError)
  back off exponentially, base * 2**(n-1) s, capped. Injectable clock.
* The anonymous fallback of the authenticator is deliberate and unchanged:
  rejected USER credentials degrade to an anonymous token (they do not raise).
* ``invalidate()`` clears memory AND persisted storage (authenticator) and
  runs the registered callbacks (the provider clears its caches there).
  ``refresh()`` is the 401 recovery: invalidate + one forced fresh login.
"""

import threading
import time
from typing import Any, Callable, Dict, List, Optional

from ...base.errors import AuthError, ConfigurationError, ProviderError, ServerError
from ...base.utils.logger import logger
from .constants import HRTiConfig, HRTiDefaults

_PERMANENT = (AuthError, ConfigurationError)


class HRTiSession:
    def __init__(
        self,
        *,
        authenticator: Any,
        config: HRTiConfig,
        clock: Callable[[], float] = time.monotonic,
        backoff_base: float = HRTiDefaults.SESSION_BACKOFF_BASE,
        backoff_cap: float = HRTiDefaults.SESSION_BACKOFF_CAP,
    ):
        self._authenticator = authenticator
        self._config = config
        self._clock = clock
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap
        self._lock = threading.RLock()
        self._callbacks: List[Callable[[], None]] = []
        self._last_error: Optional[BaseException] = None
        self._typed_error: Optional[ProviderError] = None
        self._permanent = False
        self._failures = 0
        self._retry_at = 0.0

    # ------------------------------------------------------------------
    # AuthProtocol
    # ------------------------------------------------------------------
    def get_access_token(self, force_refresh: bool = False) -> str:
        with self._lock:
            self._raise_if_blocked()
            try:
                token = self._authenticator.get_bearer_token(force_refresh=force_refresh)
            except Exception as exc:
                typed = self._record_failure(exc)
                if typed is exc:
                    raise
                raise typed from exc
            if not token:
                error = AuthError("HRTi: login returned an empty access token")
                raise self._record_failure(error) from None
            self._clear_failure()
            return token

    def build_headers(self) -> Dict[str, str]:
        """API headers incl. the token (not for CDN requests)."""
        return self._config.api_headers(
            token=self.get_access_token(),
            device_id=self.device_id,
            ip_address=self.ip_address,
        )

    def invalidate(self) -> None:
        """Drop the session (memory + persisted) and everything derived from it."""
        with self._lock:
            self._authenticator.invalidate_token()
            self._clear_failure()
        for callback in list(self._callbacks):
            try:
                callback()
            except Exception as exc:  # a cache callback must not break the recovery
                logger.warning(f"HRTi: on_invalidate callback failed: {exc!r}")

    # ------------------------------------------------------------------
    # Session API for the UI and the 401 recovery
    # ------------------------------------------------------------------
    def refresh(self) -> str:
        """401 recovery: invalidate, then one forced fresh login."""
        self.invalidate()
        return self.get_access_token(force_refresh=True)

    def require(self) -> str:
        return self.get_access_token()

    def ensure(self) -> bool:
        try:
            self.get_access_token()
            return True
        except Exception:
            return False

    def reset(self) -> None:
        """Forget failures (credentials changed): the next call logs in again."""
        with self._lock:
            self._clear_failure()

    def on_invalidate(self, callback: Callable[[], None]) -> None:
        self._callbacks.append(callback)

    @property
    def last_error(self) -> Optional[BaseException]:
        return self._last_error

    # ------------------------------------------------------------------
    # Auth-derived state read by the managers
    # ------------------------------------------------------------------
    @property
    def device_id(self) -> str:
        return self._authenticator.get_device_id()

    @property
    def ip_address(self) -> str:
        return self._authenticator.get_ip_address()

    @property
    def user_id(self) -> str:
        return self._authenticator.get_user_id() or ""

    def has_user_credentials(self) -> bool:
        return self._authenticator.has_user_credentials()

    # ------------------------------------------------------------------
    # Playback-session calls (authenticator owns the protocol details)
    # ------------------------------------------------------------------
    def authorize_session(self, **kw: Any) -> Dict[str, Any]:
        self.get_access_token()           # typed login errors, backoff, lazy login
        try:
            return self._authenticator.authorize_session(**kw)
        except AuthError:                 # stale token: one refresh, one retry
            self.refresh()
            return self._authenticator.authorize_session(**kw)

    def report_session_event(self, session_id: str, channel_id: Optional[str] = None) -> bool:
        return self._authenticator.report_session_event(session_id, channel_id)

    # ------------------------------------------------------------------
    # Failure bookkeeping
    # ------------------------------------------------------------------
    def _raise_if_blocked(self) -> None:
        if self._typed_error is None:
            return
        if self._permanent or self._clock() < self._retry_at:
            raise self._typed_error

    def _record_failure(self, exc: BaseException) -> ProviderError:
        typed = exc if isinstance(exc, ProviderError) else ServerError(f"HRTi login failed: {exc}")
        self._last_error = exc
        self._typed_error = typed
        if isinstance(typed, _PERMANENT):
            self._permanent = True
        else:
            self._failures += 1
            delay = min(self._backoff_cap, self._backoff_base * (2 ** (self._failures - 1)))
            self._retry_at = self._clock() + delay
        logger.warning(
            f"HRTi: login failed ({type(typed).__name__}, "
            f"{'permanent' if self._permanent else f'retry in {self._retry_at - self._clock():.0f}s'}): {typed}"
        )
        return typed

    def _clear_failure(self) -> None:
        self._last_error = None
        self._typed_error = None
        self._permanent = False
        self._failures = 0
        self._retry_at = 0.0
