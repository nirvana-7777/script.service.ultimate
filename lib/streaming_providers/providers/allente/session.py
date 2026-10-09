# streaming_providers/providers/allente/session.py
"""
AllenteSession -- the auth state of one Allente provider instance.

It exists because the manager ABCs take an `auth` collaborator that
satisfies AuthProtocol (get_access_token / build_headers / invalidate),
while Allente's login is a stateful, multi-step flow owned by
AllenteAuthenticator (a BaseAuthenticator). The session sits between the
two:

    managers  --(AuthProtocol)-->  AllenteSession  --->  AllenteAuthenticator

and owns everything the provider used to keep next to the auth gate:
bearer token, entitlement tag, selected profile, last error.

Error contract
--------------
`ensure()` returns True/False and never raises (used for the opportunistic
pre-login and by the settings UI). `require()` -- and therefore
get_access_token() / build_headers() -- raises typed errors from
base.errors instead, as the manager contract demands:

    no credentials, wrong password, OTP, unsupported account -> AuthError
    geoblocked account                                       -> GeoBlockError
    network / WAF / unexpected response                      -> ServerError

`last_error` keeps the ORIGINAL exception (AllenteOTPRequiredError, ...)
because the auth-status UI shows its type name.

Thread-safety: the login runs under an RLock and re-checks readiness after
acquiring it, so concurrent callers produce one login, not N.
"""

import threading
from typing import Dict, Optional, Tuple, Type

from ...base.errors import AuthError, GeoBlockError, ProviderError, ServerError
from ...base.utils.logger import logger
from .auth import AllenteAuthError, AllenteOTPRequiredError
from .models import AllenteProfile


class AllenteSession:
    """Auth state + AuthProtocol adapter for Allente."""

    def __init__(self, *, authenticator, config):
        self.authenticator = authenticator
        self.config = config
        self.bearer_token: Optional[str] = None
        self.entitlement_tag: Optional[str] = None
        self.profile: Optional[AllenteProfile] = None
        self.last_error: Optional[Exception] = None
        self._failure: Optional[Tuple[Type[ProviderError], str]] = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def has_credentials(self) -> bool:
        return self.authenticator.has_user_credentials()

    def reset(self) -> None:
        """Clear all auth-derived state (used when credentials change)."""
        self.bearer_token = None
        self.entitlement_tag = None
        self.profile = None
        self.last_error = None
        self._failure = None

    def _is_ready(self) -> bool:
        # The token's own is_expired (the base's fixed 300 s buffer) -- the
        # same check BaseAuthenticator.authenticate() uses in step 1, so
        # the two can never disagree.
        token = self.authenticator.current_token
        return bool(
            self.bearer_token
            and self.entitlement_tag
            and self.profile
            and token is not None
            and not token.is_expired
        )

    def _fail(
        self,
        exc: Exception,
        kind: Type[ProviderError],
        *,
        message: Optional[str] = None,
        warning: bool = False,
    ) -> bool:
        """Record a failure: `exc` stays visible as last_error, `kind` is
        what require() raises."""
        message = message or str(exc)
        self.last_error = exc
        self._failure = (kind, message)
        (logger.warning if warning else logger.error)(message)
        return False

    # ------------------------------------------------------------------
    # Auth gate
    # ------------------------------------------------------------------

    def ensure(self) -> bool:
        """
        Ensure a valid Zulu token, entitlement tag and profile.
        Idempotent; True when ready, False (with last_error set) otherwise.
        """
        if self._is_ready():
            return True
        with self._lock:
            if self._is_ready():  # another thread may have just logged in
                return True
            return self._authenticate()

    def require(self) -> None:
        """ensure() or raise the typed error for the recorded failure."""
        if self.ensure():
            return
        kind, message = self._failure or (AuthError, "Allente: not authenticated")
        raise kind(message) from self.last_error

    def _authenticate(self) -> bool:
        if not self.authenticator.has_user_credentials():
            return self._fail(
                RuntimeError(
                    "Allente: no credentials configured. "
                    "Set username and password in the addon settings."
                ),
                AuthError,
                warning=True,
            )

        try:
            # BaseAuthenticator: cached token -> refresh -> full login.
            token = self.authenticator.authenticate()

            # A persisted token from an older schema may be missing the
            # entitlement tag. authenticate() would keep returning it
            # forever, so discard it once (invalidate_token() also clears
            # persisted storage) and force a fresh login.
            if token is not None and not getattr(token, "entitlement_tag", None):
                logger.warning(
                    "Allente: cached token missing entitlementTag — forcing re-login"
                )
                self.authenticator.invalidate_token()
                token = self.authenticator.authenticate(force_refresh=True)

            if token is None:
                return self._fail(
                    RuntimeError("Allente: authentication returned no token."),
                    AuthError,
                )

            if getattr(token, "geoblocked", False):
                return self._fail(
                    RuntimeError(
                        f"Allente: account is geoblocked for "
                        f"{getattr(token, 'content_domain_id', 'unknown')}"
                    ),
                    GeoBlockError,
                )

            if not token.entitlement_tag:
                return self._fail(
                    RuntimeError(
                        "Allente: login response is missing entitlementTag — "
                        "cannot fetch channels."
                    ),
                    ServerError,
                )

            self.bearer_token = token.access_token
            self.entitlement_tag = token.entitlement_tag

            # Lazy profile fetch (also covers restart with a restored token).
            if self.profile is None:
                self.profile = self.authenticator.ensure_profile(token)

            if not self.profile:
                return self._fail(
                    RuntimeError("Allente: no profile available for this account."),
                    ServerError,
                )

            self.last_error = None
            self._failure = None
            logger.info(
                f"Allente: authenticated (userId={token.user_id}, "
                f"profile={self.profile.id})"
            )
            return True

        except AllenteOTPRequiredError as exc:
            return self._fail(
                exc, AuthError, message=f"Allente: account requires OTP — {exc}"
            )
        except AllenteAuthError as exc:  # wrong credentials, unsupported account
            return self._fail(
                exc, AuthError, message=f"Allente: authentication failed — {exc}"
            )
        except Exception as exc:  # network, 5xx, WAF, unexpected SSO response
            return self._fail(
                exc, ServerError, message=f"Allente: authentication failed — {exc}"
            )

    # ------------------------------------------------------------------
    # AuthProtocol (what the managers see)
    # ------------------------------------------------------------------

    def get_access_token(self) -> str:
        self.require()
        return self.bearer_token  # type: ignore[return-value]

    def build_headers(self) -> Dict[str, str]:
        """Zulu API headers incl. the bearer token."""
        self.require()
        return self.config.zulu_headers(self.bearer_token)

    def invalidate(self) -> None:
        """Drop the token everywhere (memory + persisted) and the state."""
        self.authenticator.invalidate_token()
        self.reset()

    # ------------------------------------------------------------------
    # Status UI
    # ------------------------------------------------------------------

    def details(self) -> Dict:
        """Provider-specific details for the auth-status UI (free-form)."""
        details: Dict = {}
        if self.last_error is not None:
            details["last_error"] = str(self.last_error)
            details["last_error_type"] = type(self.last_error).__name__
        if self.profile is not None:
            details["profile_id"] = self.profile.id
            details["profile_kids"] = self.profile.kids
        return details