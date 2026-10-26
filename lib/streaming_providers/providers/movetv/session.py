# streaming_providers/providers/movetv/session.py
"""
AUTH VARIANT B -- AuthProtocol adapter in front of MoveTVAuthenticator
(README §9). Managers talk to this object; the raw authenticator stays on the
provider (`self.authenticator`).

    managers --(AuthProtocol)--> MoveTvSession --> MoveTVAuthenticator

Differences to the v1 usage (each is a recorded behaviour change):
  * the token is validated against the server ONCE per process (first login of
    the stored session) and afterwards only when the server answers 401
    (`recover()`), instead of a validate POST in every authenticate() call;
  * rejected credentials / missing credentials are PERMANENT (typed AuthError):
    no retry until reset() -- no login loop, no account lock;
  * any other typed ProviderError keeps its type and backs off (transient);
    untyped errors become ServerError;
  * `ensure()` is for the settings UI only; managers use require()/info().

Error contract: ensure() -> bool, never raises. require()/info()/recover()
raise typed errors. last_error keeps the ORIGINAL exception.
"""

import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from ...base.errors import AuthError, ProviderError, ServerError
from ...base.utils.logger import logger

BACKOFF_BASE_SECONDS = 30
BACKOFF_MAX_SECONDS = 900


class MoveTvSession:
    PERMANENT_ERRORS: Tuple[Type[Exception], ...] = (AuthError,)

    def __init__(self, *, authenticator: Any, config: Any,
                 clock: Callable[[], float] = time.monotonic):
        self.authenticator = authenticator
        self.config = config
        self._clock = clock
        self.last_error: Optional[Exception] = None
        self._failure: Optional[Tuple[Type[ProviderError], str]] = None
        self._logged_in = False
        self._permanent = False
        self._failures = 0
        self._retry_at = 0.0
        self._lock = threading.RLock()
        self._on_invalidate: List[Callable[[], None]] = []

    # ---- state ---------------------------------------------------------
    def on_invalidate(self, callback: Callable[[], None]) -> None:
        """Register a callback run by invalidate() (the provider clears its
        account-specific caches there)."""
        self._on_invalidate.append(callback)

    def reset(self) -> None:
        """Credentials changed: forget everything, including the backoff."""
        self._logged_in = False
        self.last_error = None
        self._failure = None
        self._permanent = False
        self._failures = 0
        self._retry_at = 0.0

    def _token(self) -> Any:
        return self.authenticator.get_current_token()

    def _ready(self) -> bool:
        # No local is_expired check: the token's real lifetime is decided by
        # the server (401 -> recover()). A locally "expired" but server-valid
        # token would otherwise be re-validated on every call.
        token = self._token()
        return bool(
            self._logged_in and token is not None
            and getattr(token, "access_token", None)
        )

    # ---- failure bookkeeping ---------------------------------------------
    def _typed(self, exc: Exception) -> Tuple[Type[ProviderError], bool]:
        if isinstance(exc, ProviderError):
            return type(exc), isinstance(exc, self.PERMANENT_ERRORS)
        return ServerError, False

    def _record_failure(self, exc: Exception) -> None:
        kind, permanent = self._typed(exc)
        self.last_error = exc
        self._failure = (kind, f"authentication failed -- {exc}")
        self._logged_in = False
        self._permanent = permanent
        if not permanent:
            self._failures += 1
            delay = min(BACKOFF_BASE_SECONDS * 2 ** (self._failures - 1), BACKOFF_MAX_SECONDS)
            self._retry_at = self._clock() + delay
        logger.error(f"move.tv: {self._failure[1]}")

    def _record_success(self) -> None:
        self._logged_in = True
        self.last_error, self._failure = None, None
        self._permanent = False
        self._failures, self._retry_at = 0, 0.0

    def _raise_failure(self) -> None:
        kind, message = self._failure or (AuthError, "not authenticated")
        try:
            error: ProviderError = kind(message)
        except TypeError:                      # exotic constructor shape
            error = ServerError(message)
        raise error from self.last_error

    # ---- gate ----------------------------------------------------------
    def ensure(self) -> bool:
        if self._ready():
            return True
        with self._lock:
            if self._ready():
                return True
            if self._permanent:
                return False                    # until reset()
            if self._clock() < self._retry_at:
                return False                    # still backing off
            return self._login()

    def require(self) -> None:
        if self.ensure():
            return
        self._raise_failure()

    def _login(self) -> bool:
        try:
            token = self.authenticator.authenticate()
            if token is None:
                raise AuthError("move.tv: authentication returned no token")
        except Exception as exc:
            self._record_failure(exc)
            return False
        self._record_success()
        return True

    def recover(self) -> None:
        """The server rejected the token (401): refresh it, else log in again.
        Raises typed errors; a failed full login is permanent (AuthError)."""
        with self._lock:
            try:
                token = self._token()
                renewed = self.authenticator.refresh_token(token) if token else None
                if renewed is None:
                    renewed = self.authenticator.authenticate(force_refresh=True)
                if renewed is None:
                    raise AuthError("move.tv: re-authentication returned no token")
            except Exception as exc:
                self._record_failure(exc)
                self._raise_failure()
            self._record_success()

    def info(self, *, need_profile: bool = True) -> Dict[str, Any]:
        """Session data the API payloads need (customer ids, token)."""
        self.require()
        info = self.authenticator.get_session_info()
        if (not info or not info.get("customer_id") or not info.get("auth_token")
                or (need_profile and not info.get("customer_profile_id"))):
            raise AuthError("move.tv: incomplete session data")
        return info

    # ---- AuthProtocol --------------------------------------------------
    def get_access_token(self) -> str:
        self.require()
        return self._token().access_token

    def build_headers(self) -> Dict[str, str]:
        access_token = self.get_access_token()
        dev_id = getattr(self._token(), "device_id", None)
        return self.config.get_api_headers(access_token, dev_id=dev_id)

    def invalidate(self) -> None:
        self.authenticator.invalidate_token()   # memory AND persisted storage
        self.reset()
        for callback in list(self._on_invalidate):
            try:
                callback()
            except Exception as exc:            # a cache-clearing bug must not block logout
                logger.warning(f"move.tv: on_invalidate callback failed: {exc}")