# streaming_providers/providers/allente/auth.py
"""
Allente authenticator.

Two-tier flow:

  Tier 1 — SSO (logon.allente.tv), client_id = "go-web-cdse":
      * GET  /oauth/authorize               -> sets cookies, redirects
      * POST /user/login/go-web-cdse        -> {"authenticated": true, "customers": [...]}
      * GET  /oauth/continue/go-web-cdse    -> 302 with ?code=... in Location

  Tier 2 — Zulu (w-sgprod-zulu.api-canaldigital.com):
      * POST /v1/authentication/login {clientId, authCode}
          -> {accessToken, refreshToken, entitlementTag, ...}

Refresh:
      * POST /v1/authentication/login {clientId, refreshToken}
          -> new accessToken (refreshToken MAY be rotated by the server;
             identity fields MAY be omitted — they are carried over from
             the previous token)

Error model (used by the provider's retry/backoff policy):
      * AllenteAuthError subclasses are PERMANENT: retrying with the same
        credentials cannot succeed (wrong password, OTP required,
        unsupported account shape).
      * Everything else (network, 5xx, WafBlockedException, unexpected
        SSO responses) is treated as TRANSIENT and retried with backoff.

Framework contracts honored here (verified against base source):

  * HTTPManager wraps a requests/curl_cffi Session that maintains its own
    cookie jar — Set-Cookie from /oauth/authorize is stored and replayed
    automatically. We do NOT use SessionAwareHTTPManager: it hardcodes
    operation="oauth" (which cannot be overridden — duplicate kwarg), and
    its explicit Cookie header is superseded by the session jar anyway.
    Instead, _sso_login() calls http_manager.clear_cookies() first so every
    login starts clean (stale cdse cookies from a previous session cannot
    leak into a new authorize flow).

  * HTTPManager._make_request() calls response.raise_for_status()
    UNCONDITIONALLY — every response reaching provider code is 1xx–3xx.
    Therefore: (a) status-based branching (401 -> bad credentials,
    403/429 -> WafBlockedException) happens on the EXCEPTION, never on the
    response object; (b) there are no resp.raise_for_status() calls in
    provider code — they are dead.

  * JSON POST bodies use json_data= (HTTPManager.post's parameter).
    GET query strings use params= (kwargs pass-through).

  * _load_session() restores persisted tokens via _create_token_from_
    response() with the dict produced by to_dict() (snake_case). Raw Zulu
    responses are camelCase. Dispatch on key shape handles both.

  * The base's invalidate_token() is used as-is (clears memory + the
    persisted session via SessionManager.clear_token).

  * CredentialManager restores stored credentials as a GENERIC
    UserPasswordCredentials — never AllenteUserCredentials — so all
    isinstance checks accept the base type.

  * 429 responses are auto-retried with backoff inside HTTPManager on the
    plain-requests path (status_forcelist=[429]); only the final failure
    raises. The curl_cffi path does not retry.

THREADING: this class is NOT thread-safe by itself. The provider
serializes every call into authenticate()/invalidate_token() with its
auth lock. Do not call the authenticator from other threads directly.

Abstract stubs (_build_auth_payload, auth_endpoint) exist only to satisfy
the BaseAuthenticator ABC; they are never invoked for Allente.
"""

import uuid
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.auth.base_oauth2_auth import WafBlockedException
from ...base.auth.credentials import UserPasswordCredentials
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .constants import AllenteConfig, AllenteDefaults, AllenteHeaders
from .models import (
    AllenteAuthToken,
    AllenteEntitlements,
    AllenteProfile,
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class AllenteAuthError(Exception):
    """
    Base class for authentication failures that retrying cannot fix.

    The provider stops attempting logins after one of these until the
    credentials change. The message is written to be shown to the user.
    """

    permanent: bool = True


class AllenteCredentialsError(AllenteAuthError):
    """The username/password was rejected."""


class AllenteOTPRequiredError(AllenteAuthError):
    """Raised when the SSO backend insists on OTP confirmation."""


class AllenteUnsupportedAccountError(AllenteAuthError):
    """The account shape is not supported in v1 (e.g. multiple customers)."""


class AllenteAuthenticator(BaseAuthenticator):
    """
    Two-tier authenticator for Allente.

    Inherits BaseAuthenticator (NOT BaseOAuth2Authenticator): Allente's SSO
    is not OIDC-compliant and the Zulu login/refresh scheme is a custom
    JSON contract that doesn't fit the standard grant model the OAuth2 base
    hardwires. The HTTP manager is a hard requirement, owned by the provider
    and shared with this class. The AllenteConfig instance is shared too —
    one source of truth, no header drift.
    """

    def __init__(
        self,
        config: AllenteConfig,
        credentials=None,
        settings_manager=None,
        config_dir=None,
        proxy_config: Optional[ProxyConfig] = None,
        http_manager=None,
    ):
        super().__init__(
            provider_name="allente",
            settings_manager=settings_manager,
            credentials=credentials,
            country=config.country,
            config_dir=config_dir,
        )

        # SHARED config — the same instance the provider uses.
        self._config = config
        self._proxy_config = proxy_config  # informational; http_manager owns proxies

        if http_manager is None:
            raise RuntimeError(
                "AllenteAuthenticator requires an http_manager. "
                "Construct one in the provider via _setup_http_manager() "
                "and pass it in."
            )
        self._http_manager = http_manager

        # Cached default profile (populated after login or lazily later)
        self._selected_profile: Optional[AllenteProfile] = None

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------
    @property
    def http_manager(self):
        return self._http_manager

    @http_manager.setter
    def http_manager(self, value):
        self._http_manager = value

    @property
    def config(self) -> AllenteConfig:
        return self._config

    @property
    def auth_endpoint(self) -> str:
        # Required by the BaseAuthenticator ABC. Unused in practice.
        return AllenteDefaults.ZULU_AUTH_LOGIN

    # ------------------------------------------------------------------
    # Required abstract methods
    # ------------------------------------------------------------------
    def _get_auth_headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/json"}

    def _build_auth_payload(self) -> Dict[str, Any]:
        # ABC stub — never called for Allente. Defensive in case a restored
        # generic UserPasswordCredentials lacks to_auth_payload().
        if self.credentials is not None and hasattr(self.credentials, "to_auth_payload"):
            return self.credentials.to_auth_payload()
        return {}

    def get_fallback_credentials(self):
        # Allente has no anonymous/client-credentials tier.
        return None

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        if isinstance(token, AllenteAuthToken) and token.access_token and token.user_id:
            return TokenAuthLevel.USER_AUTHENTICATED
        return TokenAuthLevel.UNKNOWN

    # ------------------------------------------------------------------
    # Token creation / restoration
    # ------------------------------------------------------------------
    def _create_token_from_response(self, response_data: Dict[str, Any]) -> AllenteAuthToken:
        """
        *** LOAD-BEARING: this is the persistence round-trip. ***

        BaseAuthenticator._load_session() calls this with the dict produced
        by AllenteAuthToken.to_dict() (snake_case). Raw Zulu responses are
        camelCase. Dispatch on key shape so both parse correctly — wiring
        from_zulu_response() here unconditionally silently breaks token
        restore and forces a full re-login on every restart.
        """
        if "accessToken" in response_data:
            return AllenteAuthToken.from_zulu_response(response_data)
        return AllenteAuthToken.from_dict(response_data)

    # ------------------------------------------------------------------
    # Main authentication (called by BaseAuthenticator.authenticate())
    # ------------------------------------------------------------------
    def _perform_authentication(self) -> BaseAuthToken:
        # Accept ANY UserPasswordCredentials: CredentialManager restores
        # stored credentials as the generic base type (verified), and the
        # SSO flow only needs username + password.
        if not isinstance(self.credentials, UserPasswordCredentials):
            raise AllenteCredentialsError(
                "Allente requires username/password credentials."
            )

        auth_code = self._sso_login(
            username=self.credentials.username,
            password=self.credentials.password,
        )
        zulu_response = self._zulu_login(auth_code)
        token = AllenteAuthToken.from_zulu_response(zulu_response)
        token.auth_level = self._classify_token(token)  # USER_AUTHENTICATED

        # Eagerly cache the default profile so channels/playout work right
        # away. Safe to skip if it fails — the provider calls ensure_profile.
        try:
            self._load_default_profile(token)
        except Exception as exc:
            logger.warning(f"Allente: could not load profiles after login: {exc}")

        return token

    # ------------------------------------------------------------------
    # Tier 1 — SSO
    # ------------------------------------------------------------------
    @staticmethod
    def _status_of(exc: BaseException) -> Optional[int]:
        """HTTP status of an exception raised by HTTPManager, if any.

        Duck-typed via getattr so it works for both the requests and
        curl_cffi backends (their HTTPError classes are distinct).
        """
        return getattr(getattr(exc, "response", None), "status_code", None)

    def _sso_login(self, username: str, password: str) -> str:
        """
        Run the SSO login flow and return the OAuth2 `code`.

        Raises:
            AllenteCredentialsError: credentials rejected (permanent).
            AllenteOTPRequiredError: account requires OTP (permanent).
            AllenteUnsupportedAccountError: unsupported account shape (permanent).
            WafBlockedException: if any SSO call is blocked (403/429).
            RuntimeError: on any other failure (treated as transient).
        """
        # Fresh login, fresh cookies. The http_manager is provider-scoped
        # ("allente"), so this cannot affect other providers, and Zulu calls
        # authenticate via bearer token, not cookies. Without this, a stale
        # cdse cookie from a previous session could short-circuit or corrupt
        # the new authorize flow.
        self.http_manager.clear_cookies()

        try:
            return self._run_sso_flow(username, password)
        except AllenteAuthError:
            raise
        except Exception as exc:
            # HTTPManager raises for ALL 4xx/5xx internally, so error-status
            # branching happens HERE, on the exception.
            status = self._status_of(exc)
            if status in (403, 429):
                raise WafBlockedException(
                    f"Allente SSO blocked with HTTP {status} "
                    f"(possible WAF/bot detection)"
                ) from exc
            raise

    def _run_sso_flow(self, username: str, password: str) -> str:
        # 1. Kick off the OAuth authorize flow. The cdse session cookie from
        #    Set-Cookie is stored in the manager's session jar automatically
        #    and replayed on the two calls below — no manual cookie handling.
        state = str(uuid.uuid4())
        authorize_params = {
            "client_id": AllenteDefaults.SSO_CLIENT_ID_TV,
            "scope": "profile",
            "response_type": "code",
            "redirect_uri": AllenteDefaults.SSO_REDIRECT_URI_TV,
            "state": state,
        }
        self.http_manager.get(
            f"{AllenteDefaults.SSO_REST_AUTHORIZE}?{urlencode(authorize_params)}",
            headers=AllenteHeaders.sso_oauth_headers(
                user_agent=self._config.user_agent,
                accept_language=self._config.accept_language,
            ),
            allow_redirects=False,
            timeout=self._config.timeout,
            operation="auth",
        )

        # 2. Post credentials (json_data= is HTTPManager.post's parameter).
        login_url = (
            f"{AllenteDefaults.SSO_REST_USER_LOGIN}"
            f"/{AllenteDefaults.SSO_CLIENT_ID_TV}"
        )
        login_body = {
            "username": username,
            "password": password,
            "isRegistrationRequired": False,
        }
        try:
            login_resp = self.http_manager.post(
                login_url,
                json_data=login_body,
                headers=AllenteHeaders.sso_login_headers(
                    user_agent=self._config.user_agent,
                    accept_language=self._config.accept_language,
                ),
                allow_redirects=False,
                timeout=self._config.timeout,
                operation="auth",
            )
        except Exception as exc:
            # Only the credential POST maps 401 to "wrong password"; a 401 on
            # authorize/continue would be a session problem, not credentials.
            if self._status_of(exc) == 401:
                raise AllenteCredentialsError(
                    "Allente rejected the username or password."
                ) from exc
            raise

        # A response reaching here is guaranteed 1xx–3xx (HTTPManager raises
        # for 4xx/5xx). With redirects disabled, a 3xx means the SSO
        # redirected instead of returning JSON — fail clearly before
        # .json() chokes on an HTML body.
        if login_resp.status_code != 200:
            raise RuntimeError(
                f"Allente SSO login failed: HTTP {login_resp.status_code} "
                f"(expected 200 with JSON body)"
            )

        login_data = login_resp.json()
        if not login_data.get("authenticated"):
            raise AllenteCredentialsError(
                "Allente rejected the username or password."
            )

        customers = login_data.get("customers") or []
        if not customers:
            raise AllenteUnsupportedAccountError(
                "Allente login succeeded but the account has no customers."
            )

        if len(customers) > 1:
            # v1 does not support multi-customer accounts. Fail loudly
            # rather than silently picking customers[0].
            raise AllenteUnsupportedAccountError(
                f"This Allente account has {len(customers)} customers. "
                "Multi-customer accounts are not supported yet."
            )

        action = customers[0].get("action")
        logger.debug(f"Allente SSO: action={action!r}")

        if action == "confirm-otp":
            raise AllenteOTPRequiredError(
                "This Allente account requires OTP confirmation for TV login, "
                "which this addon does not support."
            )
        if action != "select-customer":
            # Unknown step (e.g. terms to accept on the website). Transient
            # on purpose: it may resolve once the user completes it in a
            # browser, so it is retried with backoff.
            raise RuntimeError(f"Allente SSO: unexpected action {action!r}")

        # 3. Continue the OAuth flow -> 302 with ?code=... in Location header.
        continue_url = (
            f"{AllenteDefaults.SSO_REST_CONTINUE}"
            f"/{AllenteDefaults.SSO_CLIENT_ID_TV}"
        )
        continue_resp = self.http_manager.get(
            continue_url,
            headers=AllenteHeaders.sso_oauth_headers(
                user_agent=self._config.user_agent,
                accept_language=self._config.accept_language,
            ),
            allow_redirects=False,
            timeout=self._config.timeout,
            operation="auth",
        )

        location = continue_resp.headers.get("Location", "")

        # If the server echoes `state`, it must match ours.
        returned_state = self._extract_query_param(location, "state")
        if returned_state is not None and returned_state != state:
            raise RuntimeError("Allente SSO: OAuth state mismatch in redirect")

        code = self._extract_code_from_location(location)
        if not code:
            raise RuntimeError(
                "Allente SSO: could not extract auth code from redirect "
                f"{self._redact_location(location)}"
            )
        logger.debug("Allente SSO: obtained auth code")
        return code

    # ------------------------------------------------------------------
    # Tier 2 — Zulu
    # ------------------------------------------------------------------
    def _zulu_login(self, auth_code: str) -> Dict[str, Any]:
        """Exchange the SSO auth code for a Zulu access token."""
        body = {
            "clientId": AllenteDefaults.SSO_CLIENT_ID_TV,
            "authCode": auth_code,
        }
        # 4xx/5xx raise inside HTTPManager and propagate with a full log
        # trail (including the response body at DEBUG) — no raise_for_status
        # needed here; it would be dead code.
        resp = self.http_manager.post(
            AllenteDefaults.ZULU_AUTH_LOGIN,
            json_data=body,
            headers=self._config.zulu_headers(),
            timeout=self._config.timeout,
            operation="auth",
        )
        data = resp.json()
        if "accessToken" not in data:
            raise RuntimeError(
                f"Allente Zulu login: unexpected response keys {list(data)}"
            )
        logger.info(f"Allente Zulu login OK (domain={data.get('contentDomainId')})")
        return data

    # ------------------------------------------------------------------
    # Token refresh (custom scheme, same endpoint as login)
    # ------------------------------------------------------------------
    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """
        Refresh the Zulu access token using the stored refresh token.

        Same endpoint as login, with `refreshToken` instead of `authCode`.
        Not standard OAuth2 — Allente's custom scheme, which is why we
        override the base hook instead of using the OAuth2 base class.

        The base's authenticate() saves the returned token via _save_session().
        """
        previous = self._current_token
        if not previous or not previous.refresh_token:
            return None

        body = {
            "clientId": AllenteDefaults.SSO_CLIENT_ID_TV,
            "refreshToken": previous.refresh_token,
        }
        try:
            resp = self.http_manager.post(
                AllenteDefaults.ZULU_AUTH_LOGIN,
                json_data=body,
                headers=self._config.zulu_headers(),
                timeout=self._config.timeout,
                operation="auth",
            )
            data = resp.json()
            if "accessToken" not in data:
                logger.warning(f"Allente refresh: unexpected response keys {list(data)}")
                return None
            new_token = AllenteAuthToken.from_zulu_response(data)
            # The server may omit the refresh token (not rotated) and identity
            # fields (entitlementTag, userId, ...). Carry them over from the
            # previous token — otherwise the NEXT refresh would fail
            # permanently, and the refreshed token would classify as UNKNOWN
            # and trigger a full SSO re-login every time.
            new_token.inherit_missing_from(previous)
            new_token.auth_level = self._classify_token(new_token)
            logger.info("Allente Zulu token refreshed")
            return new_token
        except Exception as exc:
            # Covers HTTP errors (raised by the manager), timeouts, and
            # transport errors: return None so the base falls back to a
            # full re-login instead of crashing.
            logger.warning(f"Allente token refresh failed: {exc}")
            return None

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------
    def _load_default_profile(self, token: AllenteAuthToken) -> Optional[AllenteProfile]:
        """Fetch and cache the default profile. Idempotent."""
        resp = self.http_manager.get(
            AllenteDefaults.ZULU_USER_PROFILES,
            headers=self._config.zulu_headers(token.access_token),
            timeout=self._config.timeout,
            operation="api",
        )
        data = resp.json()

        profiles = [
            AllenteProfile.from_api_response(p)
            for p in data.get("profiles", [])
        ]
        if not profiles:
            logger.warning("Allente: no profiles returned")
            self._selected_profile = None
            return None

        default = next((p for p in profiles if p.default), profiles[0])
        self._selected_profile = default
        logger.debug(
            f"Allente: selected profile {default.id} "
            f"(kids={default.kids}, parental={default.parental_level})"
        )
        return default

    def get_selected_profile(self) -> Optional[AllenteProfile]:
        return self._selected_profile

    def get_profile_id(self) -> Optional[str]:
        return self._selected_profile.id if self._selected_profile else None

    def ensure_profile(self, token: AllenteAuthToken) -> Optional[AllenteProfile]:
        """
        Ensure a profile is selected. Lazy-fetches after restart if the
        in-memory cache is empty. Called by the provider during
        _ensure_authenticated().
        """
        if self._selected_profile is None:
            try:
                self._load_default_profile(token)
            except Exception as exc:
                logger.warning(f"Allente: failed to load profile lazily: {exc}")
                return None
        return self._selected_profile

    # ------------------------------------------------------------------
    # Entitlements (informational — the entitlementTag is on the token)
    # ------------------------------------------------------------------
    def get_entitlements(self) -> Optional[AllenteEntitlements]:
        if not self._current_token:
            return None
        resp = self.http_manager.get(
            AllenteDefaults.ZULU_USER_ENTITLEMENTS,
            params={"includeActiveTvods": "true"},
            headers=self._config.zulu_headers(self._current_token.access_token),
            timeout=self._config.timeout,
            operation="api",
        )
        return AllenteEntitlements.from_api_response(resp.json())

    # ------------------------------------------------------------------
    # Token state (public accessor — the provider must NOT reach into
    # _current_token). No local needs_refresh()/invalidate_token(): the
    # base's is_expired (fixed 300s buffer) is the single source of truth
    # for expiry, and the base's invalidate_token() also clears persisted
    # storage, which set_user_credentials depends on.
    # ------------------------------------------------------------------
    @property
    def current_token(self) -> Optional[AllenteAuthToken]:
        return self._current_token

    # ------------------------------------------------------------------
    # Credential check (used by the provider for the lazy-auth decision)
    # ------------------------------------------------------------------
    def has_user_credentials(self) -> bool:
        # Generic type on purpose: CredentialManager restores stored
        # credentials as a plain UserPasswordCredentials (verified in
        # credential_manager.py — _create_credential_from_data).
        return isinstance(self.credentials, UserPasswordCredentials) and bool(
            self.credentials.username and self.credentials.password
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_query_param(location: str, name: str) -> Optional[str]:
        if not location:
            return None
        try:
            values = parse_qs(urlparse(location).query).get(name)
            return values[0] if values else None
        except Exception:
            return None

    @staticmethod
    def _extract_code_from_location(location: str) -> Optional[str]:
        return AllenteAuthenticator._extract_query_param(location, "code")

    @staticmethod
    def _redact_location(location: str) -> str:
        """Describe a redirect target for error messages WITHOUT its query
        values (which may contain the auth code)."""
        if not location:
            return "<empty Location header>"
        try:
            parsed = urlparse(location)
            keys = sorted(parse_qs(parsed.query).keys())
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path} (query keys: {keys})"
        except Exception:
            return "<unparseable Location header>"