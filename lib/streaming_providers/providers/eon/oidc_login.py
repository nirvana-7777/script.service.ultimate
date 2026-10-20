# streaming_providers/providers/eon/oidc_login.py
"""
Browser-equivalent login for Eon brands whose accounts live at an external
identity provider (Vivacom BG: login.vivacom.bg, WSO2 Identity Server).

The web app (eontv.bg) does NOT use the password grant there. What its
network trace shows, and what this module replays:

  1. GET  <api>/oauth2/authorize?client_id&redirect_uri&response_type=code
          &state&scope=openid&code_challenge&code_challenge_method=S256
          -> a chain of 302s through the platform's own OAuth client
             (api.<cdn>/login/oauth2/code/idp) to the IdP's login page,
             which carries a `sessionDataKey`
  2. POST <idp>/commonauth  usernameUserInput, username, password,
          sessionDataKey      (plain credentials, no hashing)
          -> 302 chain back through the platform to
             https://eontv.bg/?code=...&state=...&identity_key=...
  3. (done by EonAuth) POST <api>/oauth2/token  grant_type=authorization_code
          + code_verifier + serial_number + device_type + platform_identifier

This class does steps 1-2 and stops at the redirect to the app's
redirect_uri WITHOUT requesting it. Redirects are followed by hand
(allow_redirects=False): the login page itself is never fetched, it is
recognised from the Location that points at it.

Failure mapping:
  * IdP sends the user back with authFailure=true  -> EonLoginRejected
    (permanent in EonAuth's gate: wrong password, locked account, ...)
  * anything unexpected (unknown page, WAF 403/429, redirect loop) -> ServerError
    (transient: exponential backoff)

Logging: host + path of each hop, never a query string (codes, state and
session keys live there). Nothing secret is logged.
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from ...base.errors import ServerError
from ...base.utils.logger import logger
from ...base.utils.transport import transport_errors
from .constants import EonConfig, EonDefaults
from .errors import EonLoginRejected

_PROVIDER = EonDefaults.PROVIDER_LABEL
_MAX_HOPS = 20


@dataclass(frozen=True)
class OidcAuthorization:
    code: str
    code_verifier: str
    identity_key: str       # "" when the server did not send one


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_pkce_pair() -> "tuple[str, str]":
    """(code_verifier, S256 code_challenge), RFC 7636."""
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def generate_state() -> str:
    """Same shape the web app sends: base64url({"path":"/","nonce":"..."})."""
    nonce = _b64url(secrets.token_bytes(16))
    return _b64url(f'{{"path":"/","nonce":"{nonce}"}}'.encode("ascii"))


def _where(url: str) -> str:
    """host + path only, safe to log."""
    p = urlparse(url)
    return f"{p.netloc}{p.path}"


def _query(url: str) -> Dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items() if v}


class EonOidcLogin:
    def __init__(self, *, http_manager: Any, config: EonConfig, endpoints: Any):
        self._http = http_manager
        self._config = config
        self._endpoints = endpoints

    # ------------------------------------------------------------------
    def authorize(self, username: str, password: str) -> OidcAuthorization:
        client = self._config.oidc_client
        if client is None:
            raise ServerError(f"{_PROVIDER}: no OIDC client configured")

        verifier, challenge = generate_pkce_pair()
        state = generate_state()
        start = self._endpoints.url(EonDefaults.PATH_OAUTH2_AUTHORIZE) + "?" + urlencode({
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": client.scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })

        self._clear_cookies()   # never inherit another user's IdP session
        with transport_errors("oidc login", _PROVIDER):
            callback = self._walk(start, client.redirect_uri, username, password)

        params = _query(callback)
        if "error" in params:
            raise ServerError(f"{_PROVIDER}: authorization failed ({params['error']})")
        if not secrets.compare_digest(params.get("state", ""), state):
            raise ServerError(f"{_PROVIDER}: authorization response has a wrong state")
        code = params.get("code")
        if not code:
            raise ServerError(f"{_PROVIDER}: authorization response has no code")
        return OidcAuthorization(
            code=code, code_verifier=verifier, identity_key=params.get("identity_key", ""),
        )

    # ------------------------------------------------------------------
    def _walk(self, start: str, redirect_uri: str, username: str, password: str) -> str:
        """Follow redirects, submit the login form once, return the callback URL."""
        current = start
        referer: Optional[str] = None
        submitted = False
        for _ in range(_MAX_HOPS):
            if self._is_callback(current, redirect_uri):
                return current
            if self._is_login_page(current):
                if submitted:
                    # The IdP showed the form again without an explicit failure flag.
                    raise EonLoginRejected(f"{_PROVIDER}: the identity provider refused the login")
                current = self._submit(current, username, password)
                submitted = True
                continue

            logger.debug(f"{_PROVIDER}: oidc GET {_where(current)}")
            resp = self._http.get(
                current, headers=self._headers(referer), operation="auth",
                allow_redirects=False, raise_for_status=False,
            )
            location = resp.headers.get("Location")
            if 300 <= resp.status_code < 400 and location:
                referer, current = current, urljoin(current, location)
                continue
            raise ServerError(
                f"{_PROVIDER}: login flow stopped at HTTP {resp.status_code} on {_where(current)}"
            )
        raise ServerError(f"{_PROVIDER}: login flow did not finish within {_MAX_HOPS} redirects")

    def _submit(self, login_url: str, username: str, password: str) -> str:
        """POST the credentials to the IdP's /commonauth; return the next URL."""
        key = _query(login_url).get("sessionDataKey", "")
        parsed = urlparse(login_url)
        target = f"{parsed.scheme}://{parsed.netloc}/commonauth"
        body = urlencode({
            "usernameUserInput": username,
            "username": username,
            "password": password,
            "sessionDataKey": key,
        }).encode("utf-8")
        headers = self._headers(login_url)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Origin"] = f"{parsed.scheme}://{parsed.netloc}"

        logger.debug(f"{_PROVIDER}: oidc POST {_where(target)}")
        resp = self._http.post(
            target, data=body, headers=headers, operation="auth",
            allow_redirects=False, raise_for_status=False,
        )
        if resp.status_code in (403, 429):
            raise ServerError(f"{_PROVIDER}: login blocked by the identity provider (HTTP {resp.status_code})")
        location = resp.headers.get("Location")
        if not (300 <= resp.status_code < 400 and location):
            raise ServerError(f"{_PROVIDER}: unexpected login answer (HTTP {resp.status_code})")
        nxt = urljoin(target, location)
        q = _query(nxt)
        if q.get("authFailure", "").lower() == "true":
            # authFailureMsg is a short code (login.fail.message, user.account.locked, ...).
            raise EonLoginRejected(
                f"{_PROVIDER}: the identity provider rejected the login "
                f"({q.get('authFailureMsg') or 'no reason given'})"
            )
        return nxt

    # ------------------------------------------------------------------
    @staticmethod
    def _is_callback(url: str, redirect_uri: str) -> bool:
        a, b = urlparse(url), urlparse(redirect_uri)
        return (a.scheme, a.netloc) == (b.scheme, b.netloc) and (
            "code" in _query(url) or "error" in _query(url)
        )

    @staticmethod
    def _is_login_page(url: str) -> bool:
        """The IdP's login page: carries a sessionDataKey and is neither the
        OAuth authorize continuation nor /commonauth itself."""
        path = urlparse(url).path
        return (
            "sessionDataKey" in _query(url)
            and "oauth2/authorize" not in path
            and "commonauth" not in path
        )

    def _headers(self, referer: Optional[str]) -> Dict[str, str]:
        headers = {
            "User-Agent": self._config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if referer:
            headers["Referer"] = referer
        return headers

    def _clear_cookies(self) -> None:
        """Best effort: drop the cookie jar so a stale IdP SSO session cannot log
        in as somebody else. TODO(wire to the real HTTPManager API): the guards
        below only cover the common shapes."""
        for owner in (self._http, getattr(self._http, "session", None)):
            jar = getattr(owner, "cookies", None)
            if jar is not None and hasattr(jar, "clear"):
                try:
                    jar.clear()
                    return
                except Exception as exc:     # pragma: no cover
                    logger.debug(f"{_PROVIDER}: could not clear cookies: {exc!r}")
        clear = getattr(self._http, "clear_cookies", None)
        if callable(clear):
            try:
                clear()
            except Exception as exc:         # pragma: no cover
                logger.debug(f"{_PROVIDER}: could not clear cookies: {exc!r}")